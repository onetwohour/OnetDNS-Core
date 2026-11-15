//! Authoritative zone store: builds it, watches zone sources and swaps changed zones, and applies
//! zone edits from the management API.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use onetdns_authority::source::SourceDigest;
use onetdns_config::Config;
use onetdns_core::MutexExt;

use crate::config_apply::config_write_lock;
use crate::error::{BoxResult, Context};
use crate::native_config::{build_authority_settings, private_resource_id, NativeHotState};
use crate::notify::{start_notify_dispatcher, NotifySender};
use crate::secondary::load_secondary_cache;
use crate::zone_signing::{
    load_zone_signer, sign_authority_zone, SharedZoneSigners, ZoneKeyReload, ZoneSigningCtx,
};
use crate::{
    native, read_bytes_limited, sleep_or_retire, sleep_or_shutdown, track_service_thread,
    tsig_for_secondary, unix_now, upstream, ServiceCleanup, LOCAL_CA_MAX_BYTES,
};

#[derive(Clone, Copy, PartialEq, Eq)]
/// How ZONEMD is checked before a zone loads; the same for zones from files, directories, external
/// stores, and zone transfers.
pub(crate) struct ZonemdPolicy {
    check: bool,
    reject_absence: bool,
}

impl ZonemdPolicy {
    pub(crate) fn of(cfg: &Config) -> Self {
        ZonemdPolicy {
            check: cfg.zonemd_check,
            reject_absence: cfg.zonemd_reject_absence,
        }
    }
}

/// A mismatch means the zone changed in transit.
pub(crate) fn zonemd_ok(zone: &onetdns_authority::Zone, policy: ZonemdPolicy) -> bool {
    if !policy.check {
        return true;
    }
    let records = zone.axfr_records();
    let serial = records
        .iter()
        .find_map(|r| match &r.rdata {
            onetdns_proto::RData::Soa(s) => Some(s.serial),
            _ => None,
        })
        .unwrap_or(0);
    let origin = zone.origin().to_ascii_lower();
    match onetdns_dnssec::verify_zonemd(&records, zone.origin(), serial) {
        onetdns_dnssec::ZonemdResult::Verified => {
            onetdns_core::info!(event = "authority.zonemd_verified", origin = %origin, "ZONEMD verification passed");
            true
        }
        onetdns_dnssec::ZonemdResult::Absent => {
            if policy.reject_absence {
                onetdns_core::error!(event = "authority.zonemd_missing_rejected", origin = %origin, "DNS zone rejected because it has no ZONEMD record, as configured");
                false
            } else {
                onetdns_core::warn!(event = "authority.zonemd_missing_allowed", origin = %origin, "DNS zone has no ZONEMD record but was accepted, as configured");
                true
            }
        }
        other => {
            onetdns_core::error!(event = "authority.zonemd_failed", origin = %origin, result = ?other, "ZONEMD verification failed; not serving the DNS zone");
            false
        }
    }
}

pub(crate) fn build_zone_store(
    cfg: &Config,
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    zone_signers: &[(onetdns_proto::Name, ZoneSigningCtx)],
) -> Result<onetdns_authority::ZoneStore, String> {
    let mut store = onetdns_authority::ZoneStore::new();
    for z in &cfg.zones {
        let path = z
            .file
            .as_ref()
            .ok_or_else(|| format!("DNS zone '{}' has no file setting", z.origin))?;
        let text = onetdns_authority::source::read_zone_text(path).map_err(|error| {
            format!("Could not read DNS zone file '{}': {error}", path.display())
        })?;
        let origin = if z.origin.is_empty() { "." } else { &z.origin };
        let zone = onetdns_authority::parse_zone(&text, origin).map_err(|error| {
            format!(
                "Could not parse DNS zone file '{}': {error}",
                path.display()
            )
        })?;
        let zone = if z.dnssec_sign {
            let signer = zone_signers
                .iter()
                .find(|(signer_origin, _)| signer_origin.eq_ignore_case(zone.origin()))
                .map(|(_, signer)| signer)
                .ok_or_else(|| {
                    format!(
                        "Could not prepare the signing keys for DNS zone '{}'",
                        z.origin
                    )
                })?;
            sign_authority_zone(zone, signer)
                .ok_or_else(|| format!("Could not sign DNS zone '{}'", z.origin))?
        } else {
            zone
        };
        if !zonemd_ok(&zone, ZonemdPolicy::of(cfg)) {
            return Err(format!(
                "ZONEMD verification failed for DNS zone '{}'",
                z.origin
            ));
        }
        onetdns_core::info!(event = "authority.zones_loaded_config", origin = %zone.origin().to_ascii_lower(), "Loaded authoritative DNS zone from the configuration file");
        // Signing builds a new zone, so the source digest is attached after it.
        store.add(zone.with_source_digest(SourceDigest::of(text.as_bytes())));
    }

    if let Some(dir) = &cfg.zones_dir {
        let src = onetdns_authority::DirZoneSource::new(dir.clone());
        match onetdns_authority::ZoneSource::load(&src) {
            Ok(dir_store) => {
                for z in dir_store.zones() {
                    if zonemd_ok(z, ZonemdPolicy::of(cfg)) {
                        onetdns_core::info!(event = "authority.zones_loaded_dir", origin = %z.origin().to_ascii_lower(), dir = %dir.display(), "Loaded authoritative DNS zones from directory");
                        store.add(z.clone());
                    }
                }
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.zone_dir_read_failed", dir = %dir.display(), error = %e, "Could not read the DNS zone directory")
            }
        }
    }

    if let Some(db) = &cfg.zones_db {
        let src =
            onetdns_authority::SqliteZoneSource::with_table(db.clone(), cfg.zones_db_table.clone());
        match onetdns_authority::ZoneSource::load(&src) {
            Ok(db_store) => {
                for z in db_store.zones() {
                    if zonemd_ok(z, ZonemdPolicy::of(cfg)) {
                        onetdns_core::info!(event = "authority.zones_loaded_sqlite", origin = %z.origin().to_ascii_lower(), db = %db.display(), "Loaded authoritative DNS zones from SQLite");
                        store.add(z.clone());
                    }
                }
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.sqlite_read_failed", db = %db.display(), error = %e, "Could not read DNS zones from SQLite")
            }
        }
    }

    if let Some(ep) = &cfg.zones_etcd {
        if let Some(src) = build_etcd_source(cfg) {
            match onetdns_authority::ZoneSource::load(&src) {
                Ok(etcd_store) => {
                    for z in etcd_store
                        .zones()
                        .iter()
                        .filter(|z| zonemd_ok(z, ZonemdPolicy::of(cfg)))
                    {
                        onetdns_core::info!(event = "authority.zones_loaded_etcd", origin = %z.origin().to_ascii_lower(), endpoint = %ep, "Loaded authoritative DNS zones from etcd");
                        store.add(z.clone());
                    }
                }
                Err(e) => {
                    onetdns_core::error!(event = "authority.etcd_read_failed", endpoint = %ep, error = %e, "Could not read DNS zones from etcd; retrying next check")
                }
            }
        }
    }

    let sql_table = cfg.zones_sql_table.clone();
    let mut sql_sources: Vec<(String, Box<dyn onetdns_authority::ZoneSource>)> = Vec::new();
    if let Some(url) = &cfg.zones_postgres {
        if let Some(s) = onetdns_authority::PostgresZoneSource::from_url(url, &sql_table) {
            sql_sources.push((
                format!("postgres({})", onetdns_config::redact_url_credentials(url)),
                Box::new(s),
            ));
        }
    }
    if let Some(url) = &cfg.zones_mysql {
        if let Some(s) = onetdns_authority::MysqlZoneSource::from_url(url, &sql_table) {
            sql_sources.push((
                format!("mysql({})", onetdns_config::redact_url_credentials(url)),
                Box::new(s),
            ));
        }
    }
    if let Some(path) = &cfg.zones_lmdb {
        sql_sources.push((
            format!("lmdb({})", path.display()),
            Box::new(onetdns_authority::LmdbZoneSource::new(path.clone())),
        ));
    }
    for (label, src) in &sql_sources {
        match onetdns_authority::ZoneSource::load(src.as_ref()) {
            Ok(db_store) => {
                for z in db_store
                    .zones()
                    .iter()
                    .filter(|z| zonemd_ok(z, ZonemdPolicy::of(cfg)))
                {
                    onetdns_core::info!(event = "authority.zones_loaded_db", origin = %z.origin().to_ascii_lower(), backend = %label, "Loaded authoritative DNS zones from the database");
                    store.add(z.clone());
                }
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.db_read_failed", backend = %label, error = %e, "Could not read DNS zones from the database; retrying next check")
            }
        }
    }

    for s in &cfg.secondary {
        let Some(primary) = s.primary else {
            onetdns_core::warn!(event = "authority.secondary_no_primary", origin = %s.origin, "Skipped a secondary zone that has no primary server");
            continue;
        };
        let origin = match onetdns_proto::Name::from_str(&s.origin) {
            Ok(n) => n,
            Err(_) => {
                onetdns_core::error!(event = "authority.secondary_name_invalid", origin = %s.origin, "Invalid secondary DNS zone name");
                continue;
            }
        };
        let key = tsig_for_secondary(tsig_keys, &s.tsig_key);
        if s.tsig_key.is_some() && key.is_none() {
            onetdns_core::error!(event = "authority.secondary_tsig_missing", origin = %s.origin, "Skipped a secondary zone whose TSIG key was not found");
            continue;
        }
        if let Some(zone) = load_secondary_cache(s, cfg, &origin) {
            onetdns_core::info!(event = "authority.secondary_cache_path_missing", origin = %s.origin, file = %s.file.as_ref().expect("The secondary DNS zone cache path must be set").display(), "Restored saved secondary DNS zone and scheduled its refresh");
            store.add(zone);
            continue;
        }
        onetdns_core::info!(event = "authority.secondary_initial_transfer_scheduled", origin = %s.origin, %primary, "Scheduled the first transfer of secondary DNS zone in the background");
    }

    if let Some(cat) = &cfg.catalog_serve {
        match onetdns_proto::Name::from_str(cat) {
            Ok(cat_origin) => {
                let cat_lc = cat_origin.to_ascii_lower();
                let members: Vec<String> = store
                    .zones()
                    .iter()
                    .map(|z| z.origin().to_ascii_lower())
                    .filter(|o| o != &cat_lc)
                    .collect();
                match build_catalog_zone(&cat_origin, &members, catalog_serial(unix_now())) {
                    Ok(z) => {
                        onetdns_core::info!(event = "authority.catalog_published", catalog = %cat, members = members.len(), "Published catalog DNS zone");
                        store.add(z);
                    }
                    Err(e) => {
                        onetdns_core::error!(event = "authority.catalog_build_failed", catalog = %cat, error = %e, "Could not build the catalog DNS zone")
                    }
                }
            }
            Err(_) => {
                onetdns_core::error!(event = "authority.catalog_name_invalid", catalog = %cat, "Invalid catalog zone name")
            }
        }
    }
    Ok(store)
}

pub(crate) fn catalog_members(records: &[onetdns_proto::Record], catalog: &str) -> Vec<String> {
    let catalog = catalog.trim_end_matches('.').to_ascii_lowercase();
    let zones_suffix = format!(".zones.{catalog}");
    let mut out = Vec::new();
    for r in records {
        if let onetdns_proto::RData::Ptr(member) = &r.rdata {
            let owner = r.name.to_ascii_lower();
            if owner.ends_with(&zones_suffix) {
                out.push(member.to_ascii_lower());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Must not change between builds: a consumer resets a member whose ID changes. Zero keys and the
/// 0xff terminator keep the IDs earlier releases published.
fn catalog_member_id(member: &str) -> String {
    let mut h = onetdns_security::siphash::SipHasher13::new_with_keys(0, 0);
    h.write(member.trim_end_matches('.').to_ascii_lowercase().as_bytes());
    h.write(&[0xff]);
    format!("m{:016x}", h.finish())
}

/// The catalog is rebuilt with every zone store rebuild. With an unchanged serial, consumers
/// checking only the SOA would not fetch new members, so the serial comes from the clock and keeps
/// rising.
pub(crate) fn catalog_serial(now: u64) -> u32 {
    (now & u64::from(u32::MAX)) as u32
}

fn build_catalog_zone(
    origin: &onetdns_proto::Name,
    members: &[String],
    serial: u32,
) -> Result<onetdns_authority::Zone, String> {
    use onetdns_proto::{Name, RData, Record, Soa};
    let apex = origin.to_ascii_lower();
    let mut recs = vec![
        Record::new(
            origin.clone(),
            3600,
            RData::soa(Soa {
                mname: origin.clone(),
                rname: origin.clone(),
                serial,
                refresh: 3600,
                retry: 600,
                expire: 604_800,
                minimum: 0,
            }),
        ),
        Record::new(
            origin.clone(),
            3600,
            RData::Ns(Name::from_str("invalid.").map_err(|_| "NS")?),
        ),
        Record::new(
            Name::from_str(&format!("version.{apex}")).map_err(|_| "version name")?,
            0,
            RData::Txt(vec![b"2".to_vec()]),
        ),
    ];
    for m in members {
        let id = catalog_member_id(m);
        let owner = Name::from_str(&format!("{id}.zones.{apex}")).map_err(|_| "member name")?;
        let member = Name::from_str(m).map_err(|_| "member origin")?;
        recs.push(Record::new(owner, 0, RData::Ptr(member)));
    }
    onetdns_authority::Zone::from_records(recs)
}

fn spawn_zones_dir_watcher(
    dir: std::path::PathBuf,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: ZoneJournals,
    notify: NotifySender,
    zonemd: ZonemdPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    retire: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zones-dir-watch".into())
        .spawn(move || {
        use onetdns_authority::{DirZoneSource, ZoneSource};
        let src = DirZoneSource::new(dir.clone());
        let mut last = std::time::SystemTime::now();
        let mut prev_origins: Vec<String> = Vec::new();
        loop {
            if sleep_or_retire(10, &shutdown, &retire) {
                break;
            }
            if !src.changed_since(last) {
                continue;
            }
            last = std::time::SystemTime::now();
            match src.load() {
                Ok(new_store) => {
                    let new_origins = apply_source_reload(&store, &journal, &notify, zonemd, &prev_origins, &new_store, |gone| {
                        onetdns_core::info!(event = "authority.zone_file_removed", origin = %gone, "Removed DNS zone because its zone file was deleted");
                    });
                    onetdns_core::info!(event = "authority.zones_reloaded_dir", dir = %dir.display(), zones = new_origins.len(), "Replaced running DNS zones with the directory's current contents");
                    prev_origins = new_origins;
                }
                Err(e) => {
                    onetdns_core::warn!(event = "authority.zone_dir_reload_failed", dir = %dir.display(), error = %e, "Could not reread the DNS zone directory; keeping the existing zones")
                }
            }
        }
        })
}

/// Reading the source finishes outside the lock; only comparing and swapping take the zone change
/// lock. IXFR journals of zones whose serial changed are dropped, since they do not lead to the new
/// serial.
///
/// `prev_origins`: zones this source gave last time; those missing now are removed, calling
/// `on_removed` for each. Returns the zones this source gave this time.
fn apply_source_reload(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    journal: &ZoneJournals,
    notify: &NotifySender,
    zonemd: ZonemdPolicy,
    prev_origins: &[String],
    new_store: &onetdns_authority::ZoneStore,
    on_removed: impl Fn(&str),
) -> Vec<String> {
    let new_origins: Vec<String> = new_store
        .zones()
        .iter()
        .map(|z| z.origin().to_ascii_lower())
        .collect();
    let mut journals = journal.lock_recover();
    for gone in prev_origins.iter().filter(|o| !new_origins.contains(o)) {
        if let Ok(n) = onetdns_proto::Name::from_str(gone) {
            remove_zone(store, &mut journals, &n);
            on_removed(gone);
        }
    }
    let current = store.load();
    for z in new_store.zones().iter().filter(|z| zonemd_ok(z, zonemd)) {
        let changed = current
            .zones()
            .iter()
            .find(|old| old.origin().eq_ignore_case(z.origin()))
            .is_none_or(|old| old.soa().serial != z.soa().serial);
        if changed {
            journals.remove(&z.origin().canonical_key());
        }
        swap_zone(store, &mut journals, z.clone());
        if changed {
            notify.enqueue_zone(z);
        }
    }
    new_origins
}

/// Running zone source watchers, each with its own stop signal, so a source removed from the config
/// stops and a new one starts without restarting the server.
#[derive(Default)]
pub(crate) struct ZoneWatchers {
    running: Mutex<Vec<(String, Arc<std::sync::atomic::AtomicBool>)>>,
}

/// Configured zone sources by name: the same name is the same source, and a changed name stops the
/// old watcher and starts a new one. Returns (name, constructor) pairs; a source that cannot be
/// built has no constructor.
pub(crate) fn zone_source_specs(
    cfg: &Config,
) -> Vec<(String, Option<Arc<dyn onetdns_authority::ZoneSource>>)> {
    let mut specs: Vec<(String, Option<Arc<dyn onetdns_authority::ZoneSource>>)> = Vec::new();
    if let Some(db) = &cfg.zones_db {
        specs.push((
            format!("sqlite:{}:{}", db.display(), cfg.zones_db_table),
            Some(Arc::new(onetdns_authority::SqliteZoneSource::with_table(
                db.clone(),
                cfg.zones_db_table.clone(),
            ))),
        ));
    }
    if let Some(endpoint) = &cfg.zones_etcd {
        let credentials = format!(
            "{}\n{}",
            cfg.zones_etcd_password
                .as_ref()
                .map(|password| password.as_str())
                .unwrap_or(""),
            cfg.zones_etcd_ca
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        );
        let key = format!(
            "etcd:{endpoint}:{}:{}:{}",
            cfg.zones_etcd_prefix,
            cfg.zones_etcd_user.as_deref().unwrap_or(""),
            private_resource_id("etcd-source", &credentials)
        );
        specs.push((
            key,
            build_etcd_source(cfg)
                .map(|src| Arc::new(src) as Arc<dyn onetdns_authority::ZoneSource>),
        ));
    }
    if let Some(url) = &cfg.zones_postgres {
        let redacted = onetdns_config::redact_url_credentials(url.as_str());
        let identity = private_resource_id("postgres-source", url.as_str());
        specs.push((
            format!("postgres:{redacted}:{identity}:{}", cfg.zones_sql_table),
            onetdns_authority::PostgresZoneSource::from_url(url, &cfg.zones_sql_table)
                .map(|src| Arc::new(src) as Arc<dyn onetdns_authority::ZoneSource>),
        ));
    }
    if let Some(url) = &cfg.zones_mysql {
        let redacted = onetdns_config::redact_url_credentials(url.as_str());
        let identity = private_resource_id("mysql-source", url.as_str());
        specs.push((
            format!("mysql:{redacted}:{identity}:{}", cfg.zones_sql_table),
            onetdns_authority::MysqlZoneSource::from_url(url, &cfg.zones_sql_table)
                .map(|src| Arc::new(src) as Arc<dyn onetdns_authority::ZoneSource>),
        ));
    }
    if let Some(path) = &cfg.zones_lmdb {
        specs.push((
            format!("lmdb:{}", path.display()),
            Some(Arc::new(onetdns_authority::LmdbZoneSource::new(
                path.clone(),
            ))),
        ));
    }
    specs
}

/// Startup and config swaps both go through this alone; starting watchers in two places would leave
/// one watching the old source after a swap and bring deleted zones back. Fails when a source
/// address is wrong; watchers already running stay.
pub(crate) fn reconcile_zone_watchers(
    cfg: &Config,
    watchers: &ZoneWatchers,
    store: &Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: &ZoneJournals,
    notify: &NotifySender,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    tracker: &Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut wanted: Vec<(String, Option<Arc<dyn onetdns_authority::ZoneSource>>)> =
        zone_source_specs(cfg);
    if let Some(dir) = &cfg.zones_dir {
        wanted.push((format!("dir:{}", dir.display()), None));
    }
    let zonemd = ZonemdPolicy::of(cfg);
    let zonemd_tag = format!("#zonemd={}{}", zonemd.check, zonemd.reject_absence);

    let mut running = watchers.running.lock_recover();
    running.retain(|(key, retire)| {
        let keep = wanted
            .iter()
            .any(|(want, _)| format!("{want}{zonemd_tag}") == *key);
        if !keep {
            retire.store(true, Ordering::Release);
            onetdns_core::info!(
                event = "authority.source_watch_retired",
                source = %key,
                "Stopped watching DNS zone sources removed from the configuration"
            );
        }
        keep
    });

    for (key, source) in wanted {
        let tagged = format!("{key}{zonemd_tag}");
        if running.iter().any(|(have, _)| have == &tagged) {
            continue;
        }
        let retire = Arc::new(AtomicBool::new(false));
        let thread = if let Some(dir) = key.strip_prefix("dir:") {
            spawn_zones_dir_watcher(
                std::path::PathBuf::from(dir),
                store.clone(),
                journal.clone(),
                notify.clone(),
                ZonemdPolicy::of(cfg),
                shutdown.clone(),
                retire.clone(),
            )
        } else {
            let Some(source) = source else {
                return Err(format!("DNS zone source '{key}' has an invalid address"));
            };
            spawn_zone_source_watcher(
                source,
                store.clone(),
                journal.clone(),
                notify.clone(),
                ZonemdPolicy::of(cfg),
                shutdown.clone(),
                retire.clone(),
            )
        }
        .map_err(|error| format!("Could not start the DNS zone watch task: {error}"))?;
        track_service_thread(tracker, thread);
        onetdns_core::info!(
            event = "authority.source_watch_started",
            source = %key,
            "Started watching DNS zone sources"
        );
        running.push((tagged, retire));
    }
    Ok(())
}

fn build_etcd_source(cfg: &Config) -> Option<onetdns_authority::EtcdZoneSource> {
    let ep = cfg.zones_etcd.as_ref()?;
    let mut src = onetdns_authority::EtcdZoneSource::new(ep.clone(), cfg.zones_etcd_prefix.clone());
    let (host, port) = match src.endpoint_host_port() {
        Ok(parts) => parts,
        Err(error) => {
            onetdns_core::error!(event = "authority.etcd_addr_invalid", endpoint = %ep, %error, "Invalid etcd server address");
            return None;
        }
    };
    let ip = if host.eq_ignore_ascii_case("localhost") {
        std::net::Ipv4Addr::LOCALHOST.into()
    } else {
        match upstream::resolve_host_via_bootstrap(&host, &cfg.bootstrap) {
            Some(ip) => ip,
            None => {
                onetdns_core::error!(event = "authority.etcd_bootstrap_missing", endpoint = %ep, %host, "Could not resolve the etcd server name; a bootstrap setting is needed");
                return None;
            }
        }
    };
    src = src.with_connect_addr(SocketAddr::new(ip, port));
    if let Some(ca) = &cfg.zones_etcd_ca {
        match read_bytes_limited(ca, LOCAL_CA_MAX_BYTES) {
            Ok(pem) => {
                let store = match onetdns_tls::TrustStore::try_from_pem(&pem) {
                    Ok(store) => store,
                    Err(error) => {
                        onetdns_core::error!(event = "authority.etcd_ca_invalid", ca = %ca.display(), %error, "etcd TLS CA file contains a corrupted or unsupported certificate");
                        return None;
                    }
                };
                src = src.with_tls(store);
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.etcd_ca_read_failed", ca = %ca.display(), error = %e, "Could not read the etcd TLS CA file");
                return None;
            }
        }
    }
    if let (Some(user), Some(pass)) = (&cfg.zones_etcd_user, &cfg.zones_etcd_password) {
        src = src.with_auth(user.clone(), pass.clone());
    }
    Some(src)
}

fn spawn_zone_source_watcher(
    src: std::sync::Arc<dyn onetdns_authority::ZoneSource>,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: ZoneJournals,
    notify: NotifySender,
    zonemd: ZonemdPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    retire: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zone-source-watch".into())
        .spawn(move || {
        let mut last = std::time::SystemTime::now();

        let mut prev_origins: Vec<String> = match src.load() {
            Ok(s) => s.zones().iter().map(|z| z.origin().to_ascii_lower()).collect(),
            Err(error) => {
                onetdns_core::error!(event = "authority.source_initial_load_failed", source = %src.describe(), %error, "Could not load DNS zones from the store; zones from this store are not answered yet");
                Vec::new()
            }
        };
        let mut consecutive_failures = 0u64;
        loop {
            if sleep_or_retire(10, &shutdown, &retire) {
                break;
            }
            if !src.changed_since(last) {
                continue;
            }
            last = std::time::SystemTime::now();
            match src.load() {
                Ok(new_store) => {
                    if consecutive_failures > 0 {
                        onetdns_core::info!(event = "authority.source_recovered", source = %src.describe(), failures = consecutive_failures, "Store is readable again");
                        consecutive_failures = 0;
                    }
                    let new_origins = apply_source_reload(&store, &journal, &notify, zonemd, &prev_origins, &new_store, |gone| {
                        onetdns_core::info!(event = "authority.zone_removed_source", origin = %gone, source = %src.describe(), "Removed DNS zone deleted at the source");
                    });
                    onetdns_core::info!(event = "authority.zones_reloaded_source", source = %src.describe(), zones = new_origins.len(), "Replaced running DNS zones with the store's current contents");
                    prev_origins = new_origins;
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if consecutive_failures == 1 || consecutive_failures % 60 == 0 {
                        onetdns_core::warn!(event = "authority.source_reload_failed", source = %src.describe(), error = %e, failures = consecutive_failures, "Could not reread the DNS zone store; keeping the existing zones");
                    }
                }
            }
        }
        })
}

/// RFC 1982 serial arithmetic: serials wrap, so a plain comparison is wrong.
pub(crate) fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

/// `_held` is the locked ZoneJournals, taken only as proof. Every path that changes a zone must
/// read, compute, and swap under this lock; swapping outside it would let a dynamic update
/// overwrite a change that arrived between its read and its swap.
pub(crate) fn swap_zone(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    _held: &mut ZoneJournalMap,
    zone: onetdns_authority::Zone,
) {
    store.update(|current| {
        let mut next = onetdns_authority::ZoneStore::new();
        for current_zone in current.zones() {
            if !current_zone.origin().eq_ignore_case(zone.origin()) {
                next.add(current_zone.clone());
            }
        }
        next.add(zone);
        next
    });
}

/// Also drops the zone's IXFR journal. `journals` is the locked ZoneJournals, under the same rule
/// as `swap_zone`.
pub(crate) fn remove_zone(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    journals: &mut ZoneJournalMap,
    origin: &onetdns_proto::Name,
) {
    journals.remove(&origin.canonical_key());
    store.update(|current| {
        let mut next = onetdns_authority::ZoneStore::new();
        for zone in current.zones() {
            if !zone.origin().eq_ignore_case(origin) {
                next.add(zone.clone());
            }
        }
        next
    });
}

pub(crate) struct ZoneApplyResult {
    pub(crate) origin: String,
    pub(crate) serial: u32,
    pub(crate) records: usize,
    /// Written to the zone file.
    pub(crate) persisted: bool,
    pub(crate) signed: bool,
}

/// Presentation format.
pub(crate) fn zone_record_value(record: &onetdns_proto::Record) -> String {
    let line = onetdns_authority::record_to_master_line(record);
    line.trim_end()
        .splitn(5, ' ')
        .nth(4)
        .unwrap_or("")
        .to_string()
}

/// Names are absolute, with the trailing dot. The record delete API reads a name without the dot as
/// relative to the zone, so a listed name sent back without the dot would get the zone name
/// appended twice and never match.
pub(crate) fn zone_record_json(record: &onetdns_proto::Record) -> String {
    format!(
        "{{\"name\":{},\"type\":{},\"ttl\":{},\"value\":{}}}",
        onetdns_core::json::escape(&format!("{}.", record.name.to_ascii_lower())),
        onetdns_core::json::escape(record.rtype.name()),
        record.ttl,
        onetdns_core::json::escape(&zone_record_value(record))
    )
}

pub(crate) fn zone_records_without_closing_soa(
    zone: &onetdns_authority::Zone,
) -> Vec<onetdns_proto::Record> {
    let mut recs = zone.axfr_records();
    recs.pop();
    recs
}

/// Moves the serial past `old_serial` when the edit did not; otherwise secondaries would not notice
/// the change.
fn bump_soa_serial_if_needed(recs: &mut [onetdns_proto::Record], old_serial: Option<u32>) {
    let Some(old) = old_serial else { return };
    for r in recs.iter_mut() {
        if r.rtype == onetdns_proto::RecordType::SOA {
            if let onetdns_proto::RData::Soa(soa) = &mut r.rdata {
                if !serial_gt(soa.serial, old) {
                    soa.serial = old.wrapping_add(1);
                }
            }
            break;
        }
    }
}

/// Usable as a file name; rejects names that escape the directory.
fn safe_zone_key(origin: &str) -> Result<String, String> {
    let key = origin.trim_end_matches('.').to_ascii_lowercase();
    if key.is_empty() {
        return Err("The zone origin is empty".to_string());
    }
    let valid = key.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if !valid {
        return Err(format!(
            "Invalid DNS zone name (path or disallowed characters): {origin}"
        ));
    }
    Ok(key)
}

pub(crate) struct ZoneApiTarget {
    pub(crate) key: String,
    /// None keeps the edit in memory only.
    pub(crate) path: Option<std::path::PathBuf>,
}

/// Whether the current config lets the management API edit this zone. A secondary zone's content
/// belongs to the primary. Zones from external stores (DB, etcd, LMDB, catalog) revert to the
/// store's content on the next read, so only file-managed zones are edited.
///
/// The config is read on every call: a value held from boot would allow editing a later-added
/// secondary zone, and would write to the old zone directory after it changed. `verb` names the
/// action in error messages.
pub(crate) fn zone_api_target(
    cfg: &Config,
    store: &onetdns_authority::ZoneStore,
    origin: &str,
    verb: &str,
) -> Result<ZoneApiTarget, String> {
    let key = safe_zone_key(origin)?;
    let same = |configured: &str| {
        configured
            .trim()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&key)
    };
    if cfg.secondary.iter().any(|zone| same(&zone.origin)) {
        return Err(format!(
            "This API cannot {verb} a secondary DNS zone: {key}"
        ));
    }
    let file = cfg
        .zones
        .iter()
        .find(|zone| same(&zone.origin))
        .and_then(|zone| zone.file.clone());
    let dir_file = cfg
        .zones_dir
        .as_ref()
        .map(|dir| dir.join(format!("{key}.zone")));
    let file_backed = file.is_some() || dir_file.as_ref().is_some_and(|path| path.exists());
    let external = cfg.zones_db.is_some()
        || cfg.zones_etcd.is_some()
        || cfg.zones_postgres.is_some()
        || cfg.zones_mysql.is_some()
        || cfg.zones_lmdb.is_some()
        || !cfg.catalog.is_empty();
    let exists = onetdns_proto::Name::from_str(origin)
        .ok()
        .is_some_and(|name| store.zone_exact(&name).is_some());
    if exists && external && !file_backed {
        return Err(format!(
            "Zone {key} comes from an external store (database, etcd, LMDB, or catalog). A {verb} through this API would be undone on the next read, so change it in that store"
        ));
    }
    Ok(ZoneApiTarget {
        key,
        path: file.or(dir_file),
    })
}

pub(crate) fn resolve_zone_name(s: &str, origin: &str) -> Option<onetdns_proto::Name> {
    let o = origin.trim_end_matches('.');
    if s == "@" {
        return onetdns_proto::Name::from_str(o).ok();
    }
    if s.ends_with('.') {
        onetdns_proto::Name::from_str(s).ok()
    } else {
        onetdns_proto::Name::from_str(&format!("{s}.{o}")).ok()
    }
}

/// Whether the file is as this server last saw it. `base` is the zone in memory: if it came from
/// the file, the file's digest must still match; if not, the file must not exist. Otherwise someone
/// edited the file outside; writing or deleting would lose that edit, and the watcher would later
/// read an already overwritten file.
///
/// Does not stop an outside write that lands between this check and the write.
pub(crate) fn ensure_zone_file_unchanged(
    path: &std::path::Path,
    base: Option<&onetdns_authority::Zone>,
) -> Result<(), String> {
    if SourceDigest::of_file(path)? == base.and_then(onetdns_authority::Zone::source_digest) {
        return Ok(());
    }
    Err(format!(
        "DNS zone file '{}' was changed outside this server after it was last loaded, so the change was not saved. The file is reloaded shortly; retry after that",
        path.display()
    ))
}

/// Writes only when the file is as this server last saw it. `base` is the zone in memory, None for
/// a new zone. Returns the zone with the written content's digest attached.
pub(crate) fn persist_zone(
    path: &std::path::Path,
    base: Option<&onetdns_authority::Zone>,
    zone: onetdns_authority::Zone,
) -> Result<onetdns_authority::Zone, String> {
    ensure_zone_file_unchanged(path, base)?;
    let text = zone.to_master_file();
    crate::atomic_file::atomic_write(path, text.as_bytes())
        .map_err(|e| format!("Could not save to the file ({}): {e}", path.display()))?;
    Ok(zone.with_source_digest(SourceDigest::of(text.as_bytes())))
}

pub(crate) fn apply_zone_mutation(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    zone: onetdns_authority::Zone,
    signers: &[(onetdns_proto::Name, ZoneSigningCtx)],
    journal: &Arc<Mutex<std::collections::HashMap<Vec<u8>, native::ZoneJournal>>>,
    persist_path: Option<&std::path::Path>,
    notify: &NotifySender,
    source: &str,
) -> Result<ZoneApplyResult, String> {
    let mut journals = journal.lock().unwrap_or_else(|e| e.into_inner());
    apply_zone_mutation_locked(
        store,
        zone,
        signers,
        &mut journals,
        persist_path,
        notify,
        source,
    )
}

/// Reverts the store and the journal when saving fails; otherwise the file and memory would
/// disagree.
pub(crate) fn apply_zone_mutation_locked(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    zone: onetdns_authority::Zone,
    signers: &[(onetdns_proto::Name, ZoneSigningCtx)],
    journals: &mut std::collections::HashMap<Vec<u8>, native::ZoneJournal>,
    persist_path: Option<&std::path::Path>,
    notify: &NotifySender,
    source: &str,
) -> Result<ZoneApplyResult, String> {
    let origin_name = zone.origin().clone();
    let origin = origin_name.to_ascii_lower();
    let origin_key = origin_name.canonical_key();
    let cur = store.load();
    let old_zone = cur
        .zones()
        .iter()
        .find(|z| z.origin().eq_ignore_case(&origin_name))
        .cloned();
    let old_serial = old_zone.as_ref().map(|z| z.soa().serial);
    let old_recs = old_zone
        .as_ref()
        .map(zone_records_without_closing_soa)
        .unwrap_or_default();

    let mut recs = zone_records_without_closing_soa(&zone);
    bump_soa_serial_if_needed(&mut recs, old_serial);
    let mut signed = false;
    if let Some((_, ctx)) = signers.iter().find(|(o, _)| o.eq_ignore_case(&origin_name)) {
        // The previous signatures were made by this server and kept in the store. Only changed
        // RRsets and new denial proofs are signed, so editing one record does not cost in
        // proportion to zone size.
        recs = ctx.sign_reusing(&recs, &old_recs);
        signed = true;
    }
    let new_zone = onetdns_authority::Zone::from_records(recs)
        .map_err(|e| format!("Could not rebuild the DNS zone: {e}"))?;
    let new_recs = zone_records_without_closing_soa(&new_zone);
    let serial = new_zone.soa().serial;
    let records = new_zone.axfr_records().len().saturating_sub(2);

    let (new_zone, persisted) = match persist_path {
        Some(path) => (persist_zone(path, old_zone.as_ref(), new_zone)?, true),
        None => (new_zone, false),
    };

    swap_zone(store, journals, new_zone.clone());
    if let Some(old) = old_serial {
        journals
            .entry(origin_key)
            .or_default()
            .record(old, serial, &old_recs, &new_recs);
    }
    notify.enqueue_zone(&new_zone);
    onetdns_core::info!(event = "authority.zone_hooks_applied", origin = %origin, serial, source = %source, signed, persisted, "Applied DNS zone change");
    Ok(ZoneApplyResult {
        origin,
        serial,
        records,
        persisted,
        signed,
    })
}

/// For zone files named directly in the config; same as the directory watch.
const ZONE_FILE_WATCH_SECS: u64 = 10;

/// Zone files named directly in the config are edited like those in zones_dir. Unwatched, this
/// server would keep answering the old zone after a serial bump, and secondaries would never get
/// the change. `reload` rebuilds the edited zones from the whole config.
pub(crate) fn spawn_zone_file_watch(
    runtime_cfg: Arc<onetdns_core::ArcSwap<Config>>,
    reload: ZoneKeyReload,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zones-file-watch".into())
        .spawn(move || {
            let mut seen: std::collections::HashMap<PathBuf, std::time::SystemTime> =
                zone_file_mtimes(&runtime_cfg.load());
            loop {
                if sleep_or_shutdown(ZONE_FILE_WATCH_SECS, &shutdown) {
                    break;
                }
                let cfg = runtime_cfg.load();
                let now = zone_file_mtimes(&cfg);
                let origins = zones_with_edited_files(&cfg, &seen, &now);
                if origins.is_empty() {
                    seen = now;
                    continue;
                }
                match reload(&origins) {
                    Ok(()) => {
                        seen = now;
                        onetdns_core::info!(
                            event = "authority.zones_reloaded_file",
                            zones = origins.len(),
                            "Reloaded changed zone files and replaced the running zones"
                        );
                    }
                    // Keeping the old mtime retries next period, so a half-written file being
                    // edited recovers by itself.
                    Err(error) => onetdns_core::warn!(
                        event = "authority.zone_file_reload_failed",
                        %error,
                        "Could not read the changed zone file; still answering from the previous zone"
                    ),
                }
            }
        })
}

/// Fails when a zone has no file.
pub(crate) fn configured_zone_files(
    cfg: &Config,
) -> Result<Vec<(onetdns_proto::Name, PathBuf)>, String> {
    cfg.zones
        .iter()
        .map(|zone| {
            let origin = onetdns_proto::Name::from_str(&zone.origin)
                .map_err(|_| format!("Invalid DNS zone name: {}", zone.origin))?;
            let file = zone
                .file
                .clone()
                .ok_or_else(|| format!("DNS zone '{}' has no file setting", zone.origin))?;
            Ok((origin, file))
        })
        .collect()
}

/// Zones whose file mtime changed, or whose file appears for the first time: a new file means the
/// config just added that zone, so it is read once. Only files named in the config count.
fn zones_with_edited_files(
    cfg: &Config,
    previous: &std::collections::HashMap<PathBuf, std::time::SystemTime>,
    current: &std::collections::HashMap<PathBuf, std::time::SystemTime>,
) -> Vec<onetdns_proto::Name> {
    cfg.zones
        .iter()
        .filter(|zone| {
            zone.file.as_ref().is_some_and(|file| {
                current
                    .get(file)
                    .is_some_and(|stamp| previous.get(file) != Some(stamp))
            })
        })
        .filter_map(|zone| onetdns_proto::Name::from_str(&zone.origin).ok())
        .collect()
}

/// Unreadable files are left out.
fn zone_file_mtimes(cfg: &Config) -> std::collections::HashMap<PathBuf, std::time::SystemTime> {
    cfg.zones
        .iter()
        .filter_map(|zone| zone.file.clone())
        .filter_map(|path| {
            let stamp = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()?;
            Some((path, stamp))
        })
        .collect()
}

/// Keyed by the zone name's wire form.
pub(crate) type ZoneJournalMap = std::collections::HashMap<Vec<u8>, native::ZoneJournal>;

/// The IXFR journals and the zone change lock. This Mutex is the only lock for changing the zone
/// store: dynamic update, the management API, source watchers, secondary transfers, and config
/// rebuilds all take it.
///
/// It may be taken while holding an outer lock such as the config lock. While holding it, take only
/// locks that never come back for it, such as the NOTIFY queue.
pub(crate) type ZoneJournals = Arc<Mutex<ZoneJournalMap>>;

/// The new store is reread from the sources, so old IXFR journals of changed zones do not lead to
/// the new serials; journals of zones whose serial changed or that disappeared are dropped.
///
/// `journals` must stay locked while the new store is built: a dynamic update arriving meanwhile is
/// lost unless saved before the sources are reread.
pub(crate) fn replace_zone_store(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    journals: &mut ZoneJournalMap,
    next: Arc<onetdns_authority::ZoneStore>,
) {
    journals.retain(|key, _| {
        let current = store
            .load()
            .zones()
            .iter()
            .find(|zone| zone.origin().canonical_key() == *key)
            .map(|zone| zone.soa().serial);
        let replacement = next
            .zones()
            .iter()
            .find(|zone| zone.origin().canonical_key() == *key)
            .map(|zone| zone.soa().serial);
        current.is_some() && current == replacement
    });
    store.store(next);
}

/// Authoritative zone state for one generation. Hot apply, the management API, re-signing, and file
/// watchers change the same store and signing keys. Every field is a shared handle, so clones point
/// at the same state.
#[derive(Clone)]
pub(crate) struct ZoneState {
    pub(crate) store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    pub(crate) signers: SharedZoneSigners,
    pub(crate) journal: ZoneJournals,
    pub(crate) notify: NotifySender,
    pub(crate) watchers: Arc<ZoneWatchers>,
}

impl ZoneState {
    /// Reads the signing keys, builds the store, then starts NOTIFY and the source watchers. Every
    /// zone loaded at start is queued for NOTIFY, so secondaries do not miss changes made while the
    /// server was down.
    pub(crate) fn start(
        cfg: &Config,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        shutdown: &Arc<std::sync::atomic::AtomicBool>,
        service_cleanup: &ServiceCleanup,
    ) -> BoxResult<Self> {
        let signers: SharedZoneSigners = Arc::new(onetdns_core::ArcSwap::new(Arc::new(
            cfg.zones
                .iter()
                .filter(|z| z.dnssec_sign)
                .map(|zone| {
                    let origin = onetdns_proto::Name::from_str(&zone.origin)
                        .map_err(|_| format!("Invalid DNS zone name: {}", zone.origin))?;
                    Ok((origin, load_zone_signer(zone)?))
                })
                .collect::<Result<Vec<_>, String>>()
                .map_err(|error| crate::anyhow!(error))?,
        )));
        let store = Arc::new(onetdns_core::ArcSwap::new(Arc::new(
            build_zone_store(cfg, tsig_keys, &signers.load())
                .map_err(|error| crate::anyhow!(error))?,
        )));

        let (notify, notify_thread) =
            start_notify_dispatcher(&cfg.notify, tsig_keys, shutdown.clone())
                .with_context(|| "Could not start the DNS NOTIFY sender task")?;
        if let Some(thread) = notify_thread {
            service_cleanup.track(thread);
        }
        {
            let loaded = store.load();
            for zone in loaded.zones() {
                notify.enqueue_zone(zone);
            }
        }

        let watchers = Arc::new(ZoneWatchers::default());
        let journal: ZoneJournals = Arc::new(Mutex::new(std::collections::HashMap::new()));
        reconcile_zone_watchers(
            cfg,
            &watchers,
            &store,
            &journal,
            &notify,
            shutdown,
            &service_cleanup.tracker(),
        )
        .map_err(std::io::Error::other)?;

        Ok(Self {
            store,
            signers,
            journal,
            notify,
            watchers,
        })
    }

    /// Returns a function that rebuilds the signing keys and store from the whole config and swaps
    /// them. Not one source alone, because signing, TSIG, and ZONEMD policy exist only on the
    /// config build path. Zones it gets are queued for NOTIFY with their new serial.
    ///
    /// `native_hot_state` also swaps the query handler's authority settings; before the handler
    /// exists, only the store is swapped.
    pub(crate) fn reload_from_config(
        &self,
        runtime_cfg: &Arc<onetdns_core::ArcSwap<Config>>,
        native_hot_state: &Arc<Mutex<Option<NativeHotState>>>,
    ) -> ZoneKeyReload {
        let runtime = runtime_cfg.clone();
        let signers = self.signers.clone();
        let store_slot = self.store.clone();
        let journal = self.journal.clone();
        let hot_state = native_hot_state.clone();
        let notify = self.notify.clone();
        Arc::new(
            move |rolled: &[onetdns_proto::Name]| -> Result<(), String> {
                let _write_guard = config_write_lock().lock_recover();
                let cfg = runtime.load();
                let settings = build_authority_settings(&cfg)?;
                let native = hot_state.lock_recover().clone();
                // The zone change lock is held while the sources are reread: a dynamic update
                // arriving after the read is not in the new store and would be lost by the swap.
                let mut journals = journal.lock_recover();
                let store = build_zone_store(&cfg, &settings.tsig_keys, &settings.zone_signers)?;
                signers.store(Arc::new(settings.zone_signers.clone()));
                if let Some(state) = native.as_ref() {
                    state.authority.store(Arc::new(settings));
                }
                for origin in rolled {
                    if let Some(zone) = store.zone_exact(origin) {
                        notify.enqueue(origin, zone.soa().serial);
                    }
                }
                replace_zone_store(&store_slot, &mut journals, Arc::new(store));
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use onetdns_config::Config;
    use onetdns_core::MutexExt;

    use crate::config_apply::config_changed_keys;
    use crate::notify::NotifySender;
    use crate::unix_now;

    #[test]
    /// If this server answers the old zone after a serial bump, secondaries never get the change;
    /// announcing untouched zones wakes secondaries that need no transfer.
    fn only_the_edited_zone_file_is_reloaded() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-zone-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("시험용 디렉터리");
        let first = dir.join("one.test.zone");
        let second = dir.join("two.test.zone");
        std::fs::write(
            &first,
            "@ IN SOA ns admin 1 7200 3600 1209600 3600
    ",
        )
        .expect("영역 하나");
        std::fs::write(
            &second,
            "@ IN SOA ns admin 1 7200 3600 1209600 3600
    ",
        )
        .expect("영역 둘");
        let cfg = Config {
            zones: vec![
                onetdns_config::ZoneConfig {
                    origin: "one.test".to_string(),
                    file: Some(first.clone()),
                    ..Default::default()
                },
                onetdns_config::ZoneConfig {
                    origin: "two.test".to_string(),
                    file: Some(second.clone()),
                    ..Default::default()
                },
            ],
            ..Config::default()
        };

        let empty = std::collections::HashMap::new();
        let start = zone_file_mtimes(&cfg);
        assert_eq!(start.len(), 2, "설정에 적힌 영역 파일을 모두 봐야 합니다");
        assert_eq!(
            zones_with_edited_files(&cfg, &empty, &start).len(),
            2,
            "처음 보는 파일은 한 번 읽어야 합니다"
        );
        assert!(
            zones_with_edited_files(&cfg, &start, &start).is_empty(),
            "손대지 않은 영역까지 다시 읽었습니다"
        );

        // The mtime is moved explicitly, to show a rewrite within the same second is noticed.
        let handle = std::fs::OpenOptions::new()
            .write(true)
            .open(&second)
            .expect("영역 둘 열기");
        handle
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)),
            )
            .expect("수정 시각 변경");
        let after = zone_file_mtimes(&cfg);
        let edited = zones_with_edited_files(&cfg, &start, &after);
        assert_eq!(edited.len(), 1, "편집한 영역 하나만 대상이어야 합니다");
        assert!(
            edited[0].eq_ignore_case(&onetdns_proto::Name::from_str("two.test").unwrap()),
            "편집하지 않은 영역을 다시 읽었습니다"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configured_authority_zone_cannot_disappear_silently() {
        let mut config = Config::default();
        config.zones.push(onetdns_config::ZoneConfig {
            origin: "example.test".to_string(),
            ..Default::default()
        });
        assert!(build_zone_store(&config, &[], &[]).is_err());

        config.zones[0].file = Some(std::env::temp_dir().join(format!(
            "onetdns-missing-zone-{}-{}.zone",
            std::process::id(),
            line!()
        )));
        assert!(build_zone_store(&config, &[], &[]).is_err());
    }

    #[test]
    /// A change to the SQL URL password alone replaces the watcher, while the identity key holds no
    /// plaintext.
    fn sql_source_credentials_are_redacted_and_change_source_identity() {
        let mut applied = Config {
            zones_postgres: Some("postgres://dns:old-postgres-secret@127.0.0.1/zones".into()),
            zones_mysql: Some("mysql://dns:old-mysql-secret@127.0.0.1/zones".into()),
            ..Config::default()
        };
        let old_keys: Vec<String> = zone_source_specs(&applied)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        for key in &old_keys {
            assert!(!key.contains("old-postgres-secret"));
            assert!(!key.contains("old-mysql-secret"));
        }

        let mut desired = applied.clone();
        desired.zones_postgres = Some("postgres://dns:new-postgres-secret@127.0.0.1/zones".into());
        desired.zones_mysql = Some("mysql://dns:new-mysql-secret@127.0.0.1/zones".into());
        let new_keys: Vec<String> = zone_source_specs(&desired)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_ne!(old_keys, new_keys, "자격증명 변경은 감시자를 교체한다");
        assert_eq!(
            config_changed_keys(&applied, &desired),
            vec!["zones_mysql".to_string(), "zones_postgres".to_string()]
        );

        applied.zones_postgres = desired.zones_postgres.clone();
        applied.zones_mysql = desired.zones_mysql.clone();
        assert!(config_changed_keys(&applied, &desired).is_empty());
    }

    #[test]
    /// Escaping would let a zone name overwrite any file.
    fn safe_zone_key_rejects_path_traversal() {
        assert_eq!(safe_zone_key("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            safe_zone_key("1.0.0.127.in-addr.arpa").unwrap(),
            "1.0.0.127.in-addr.arpa"
        );
        assert_eq!(
            safe_zone_key("xn--80ak6aa92e.com").unwrap(),
            "xn--80ak6aa92e.com"
        );

        for bad in [
            "/tmp/pwn",
            "..",
            "../../etc/passwd",
            "a/b",
            "a\\b",
            "c:\\windows\\temp\\x",
            "evil/../zone",
            "%2e%2e",
            "a/.zone",
            "",
            ".",
        ] {
            assert!(safe_zone_key(bad).is_err(), "{bad} 는 거부되어야 함");
        }
    }

    #[test]
    /// Later-added secondary zones and zones from external stores are refused, and edits go to the
    /// changed zone directory.
    fn zone_api_follows_live_config() {
        let dir = std::env::temp_dir().join(format!("onetdns-zone-api-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_text = dir.to_string_lossy().replace('\\', "/");
        let mut store = onetdns_authority::ZoneStore::new();
        store.add(
            onetdns_authority::parse_zone(
                "$ORIGIN db.test.\n@ 300 IN SOA ns1 h 1 3600 600 86400 300\n@ 300 IN NS ns1\n",
                "db.test",
            )
            .unwrap(),
        );
        let cfg = Config::from_toml_str(&format!(
            "zones_dir = \"{dir_text}\"\nzones_db = \"{dir_text}/zones.sqlite\"\n\n[[secondary]]\norigin = \"sec.test\"\nprimary = \"192.0.2.53\"\n"
        ))
        .unwrap();

        assert!(zone_api_target(&cfg, &store, "sec.test", "수정").is_err());
        assert!(
            zone_api_target(&cfg, &store, "db.test", "수정").is_err(),
            "외부 저장소에서 온 영역은 고치면 되돌아간다"
        );
        let fresh = zone_api_target(&cfg, &store, "new.test", "수정").unwrap();
        assert_eq!(fresh.path, Some(dir.join("new.test.zone")));

        std::fs::write(dir.join("db.test.zone"), "").unwrap();
        assert!(
            zone_api_target(&cfg, &store, "db.test", "수정").is_ok(),
            "파일로 관리되는 영역은 고칠 수 있다"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /// The dashboard sends a listed name back as is in delete requests.
    fn listed_zone_record_name_resolves_to_the_same_owner() {
        use onetdns_proto::{DnsClass, Name, RData, Record, RecordType};
        for owner in ["api.d.test", "d.test"] {
            let record = Record {
                name: Name::from_str(owner).unwrap(),
                rtype: RecordType::A,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 77)),
            };
            let json = onetdns_core::json::parse(&zone_record_json(&record)).unwrap();
            let listed = json.get("name").and_then(|v| v.as_str()).unwrap();
            let resolved = resolve_zone_name(listed, "d.test").unwrap();
            assert!(
                resolved.eq_ignore_case(&record.name),
                "목록 이름 {listed} 이 {} 로 읽혔습니다",
                resolved.to_ascii_lower()
            );
        }
    }

    #[test]
    fn resolve_zone_name_relative_absolute_apex() {
        use onetdns_proto::Name;
        let lc = |n: Name| n.to_ascii_lower();

        assert_eq!(
            lc(resolve_zone_name("www", "example.com").unwrap()),
            "www.example.com"
        );

        assert_eq!(
            lc(resolve_zone_name("ns.other.net.", "example.com").unwrap()),
            "ns.other.net"
        );

        assert_eq!(
            lc(resolve_zone_name("@", "example.com").unwrap()),
            "example.com"
        );

        assert_eq!(
            lc(resolve_zone_name("a", "example.com.").unwrap()),
            "a.example.com"
        );
    }

    #[test]
    /// Values earlier releases published; a consumer resets every member whose ID changes.
    fn catalog_member_ids_are_pinned() {
        assert_eq!(catalog_member_id("example.com."), "m48f6f9c480b4e2ac");
        assert_eq!(catalog_member_id("Example.COM"), "m48f6f9c480b4e2ac");
        assert_eq!(catalog_member_id("a.example."), "m510e234a2f16be7d");
        assert_eq!(catalog_member_id("b.test."), "mf13a2f9fee1ce3c8");
        assert_eq!(catalog_member_id("zone-1.internal."), "m102f777cd2f94aad");
    }

    #[test]
    fn catalog_producer_consumer_roundtrip() {
        use onetdns_proto::Name;
        let origin = Name::from_str("catalog.example").unwrap();
        let members = vec!["a.example.".to_string(), "b.test.".to_string()];
        let zone = build_catalog_zone(&origin, &members, 1).unwrap();
        let recs = zone.axfr_records();
        assert_eq!(
            catalog_members(&recs, "catalog.example"),
            vec!["a.example".to_string(), "b.test".to_string()]
        );

        assert!(recs.iter().any(|r| {
            r.name.to_ascii_lower() == "version.catalog.example"
                && matches!(&r.rdata, onetdns_proto::RData::Txt(t) if t == &vec![b"2".to_vec()])
        }));
    }

    #[test]
    fn catalog_members_extracts_ptr_under_zones() {
        use onetdns_proto::{Name, RData, Record};
        let recs = vec![
            Record::new(
                Name::from_str("a1.zones.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("alpha.test").unwrap()),
            ),
            Record::new(
                Name::from_str("b2.zones.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("beta.test").unwrap()),
            ),
            Record::new(
                Name::from_str("other.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("nope.test").unwrap()),
            ),
            Record::new(
                Name::from_str("evilzones.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("suffix-bypass.test").unwrap()),
            ),
        ];
        let m = catalog_members(&recs, "CATALOG.EXAMPLE.");
        assert_eq!(m, vec!["alpha.test".to_string(), "beta.test".to_string()]);
    }

    #[test]
    fn serial_gt_rfc1982() {
        assert!(serial_gt(2, 1));
        assert!(!serial_gt(1, 2));
        assert!(!serial_gt(5, 5));
        assert!(serial_gt(0, u32::MAX), "랩어라운드: 0 > MAX");
    }

    #[test]
    fn missing_secondary_cache_never_blocks_service_startup_on_network() {
        let primary = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        primary
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let address = primary.local_addr().unwrap();
        let mut config = Config::default();
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: "startup-secondary.test".to_string(),
            file: None,
            primary: Some(address.ip()),
            primary_port: Some(address.port()),
            tsig_key: None,
        });

        let started = std::time::Instant::now();
        let store = build_zone_store(&config, &[], &[]).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(store.zones().is_empty());
        let mut wire = [0u8; 512];
        let error = primary.recv_from(&mut wire).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }

    #[test]
    /// Otherwise the file and memory would disagree.
    fn failed_zone_persistence_keeps_store_and_ixfr_journal_unchanged() {
        let old = onetdns_authority::parse_zone(
            "$ORIGIN atomic.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "atomic.test",
        )
        .unwrap();
        let replacement = onetdns_authority::parse_zone(
            "$ORIGIN atomic.test.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nnew IN A 192.0.2.2\n",
            "atomic.test",
        )
        .unwrap();
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(old);
        let store = onetdns_core::ArcSwap::new(Arc::new(zones));
        let journal = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let missing_parent = std::env::temp_dir().join(format!(
            "onetdns-no-parent-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let path = missing_parent.join("atomic.test.zone");

        let result = apply_zone_mutation(
            &store,
            replacement,
            &[],
            &journal,
            Some(&path),
            &NotifySender::disabled(),
            "test",
        );
        assert!(result.is_err());
        assert_eq!(store.load().zones()[0].soa().serial, 1);
        assert!(journal.lock_recover().is_empty());
    }

    #[test]
    /// Also covers the management API and re-signing. When creating a zone not in memory, an
    /// existing file of the same name is not overwritten either: the watcher may not have read it
    /// yet.
    fn zone_mutation_refuses_to_overwrite_an_externally_edited_file() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-zone-digest-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("edit.test.zone");
        std::fs::write(
            &path,
            "$ORIGIN edit.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
        )
        .unwrap();
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(onetdns_authority::source::load_zone_file(&path, "edit.test").unwrap());
        let store = onetdns_core::ArcSwap::new(Arc::new(zones));
        let journal: ZoneJournals = Arc::default();
        let mutate = |serial| {
            apply_zone_mutation(
                &store,
                tiny_zone("edit.test", serial),
                &[],
                &journal,
                Some(&path),
                &NotifySender::disabled(),
                "test",
            )
        };

        assert_eq!(mutate(2).unwrap().serial, 2);
        assert_eq!(mutate(3).unwrap().serial, 3);

        let edited = "$ORIGIN edit.test.\n@ IN SOA ns admin 9 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.9\n";
        std::fs::write(&path, edited).unwrap();
        assert!(mutate(4).is_err_and(|error| error.contains("changed outside this server")));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
        assert_eq!(store.load().zones()[0].soa().serial, 3);

        let unseen = dir.join("new.test.zone");
        std::fs::write(&unseen, "not yet loaded\n").unwrap();
        let created = apply_zone_mutation(
            &store,
            tiny_zone("new.test", 1),
            &[],
            &journal,
            Some(&unseen),
            &NotifySender::disabled(),
            "test",
        );
        assert!(created.is_err());
        assert_eq!(
            std::fs::read_to_string(&unseen).unwrap(),
            "not yet loaded\n"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    fn tiny_zone(origin: &str, serial: u32) -> onetdns_authority::Zone {
        onetdns_authority::parse_zone(
            &format!("$ORIGIN {origin}.\n@ IN SOA ns admin {serial} 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"),
            origin,
        )
        .unwrap()
    }

    #[test]
    /// Dynamic update reads, computes, and swaps under the zone change lock. A watcher swapping the
    /// zone in between would have its change overwritten by the update's result, built from the
    /// older zone.
    fn source_reload_waits_for_an_in_flight_zone_mutation() {
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(tiny_zone("race.test", 1));
        let store = Arc::new(onetdns_core::ArcSwap::new(Arc::new(zones)));
        let journal: ZoneJournals = Arc::default();

        let mut held = journal.lock_recover();
        let reloader = {
            let store = store.clone();
            let journal = journal.clone();
            std::thread::spawn(move || {
                let mut source = onetdns_authority::ZoneStore::new();
                source.add(tiny_zone("race.test", 20));
                apply_source_reload(
                    &store,
                    &journal,
                    &NotifySender::disabled(),
                    ZonemdPolicy::of(&Config::default()),
                    &["race.test".to_string()],
                    &source,
                    |_| {},
                );
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            store.load().zones()[0].soa().serial,
            1,
            "감시가 진행 중인 변경 사이에 영역을 바꿨다"
        );
        swap_zone(&store, &mut held, tiny_zone("race.test", 2));
        drop(held);
        reloader.join().unwrap();
        assert_eq!(store.load().zones()[0].soa().serial, 20);
    }

    #[test]
    fn replacing_the_store_keeps_journals_only_for_unchanged_zones() {
        let mut zones = onetdns_authority::ZoneStore::new();
        for (origin, serial) in [("same.test", 1), ("bumped.test", 1), ("gone.test", 1)] {
            zones.add(tiny_zone(origin, serial));
        }
        let store = onetdns_core::ArcSwap::new(Arc::new(zones));
        let key = |origin: &str| {
            onetdns_proto::Name::from_str(origin)
                .unwrap()
                .canonical_key()
        };
        let mut journals = ZoneJournalMap::new();
        for origin in ["same.test", "bumped.test", "gone.test"] {
            journals.insert(key(origin), native::ZoneJournal::default());
        }

        let mut next = onetdns_authority::ZoneStore::new();
        next.add(tiny_zone("same.test", 1));
        next.add(tiny_zone("bumped.test", 2));
        replace_zone_store(&store, &mut journals, Arc::new(next));

        assert!(journals.contains_key(&key("same.test")));
        assert!(!journals.contains_key(&key("bumped.test")));
        assert!(!journals.contains_key(&key("gone.test")));
        assert_eq!(store.load().zones().len(), 2);
    }
}
