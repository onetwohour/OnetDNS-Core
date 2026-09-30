/*!
 * @brief 권한 영역 저장소.
 * @details 저장소를 만들고, 영역 원본을 감시해 바뀐 영역을 교체하며, 관리 API가
 *          보낸 영역 편집을 적용한다.
 */

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use onetdns_authority::source::SourceDigest;
use onetdns_config::Config;
use onetdns_core::MutexExt;

use crate::error::{BoxResult, Context};
use crate::native_config::private_resource_id;
use crate::notify::{start_notify_dispatcher, NotifySender};
use crate::secondary::load_secondary_cache;
use crate::zone_signing::{
    load_zone_signer, sign_authority_zone, SharedZoneSigners, ZoneSigningCtx,
};
use crate::{
    native, read_bytes_limited, sleep_or_retire, track_service_thread, tsig_for_secondary,
    unix_now, upstream, ServiceCleanup, LOCAL_CA_MAX_BYTES,
};

#[derive(Clone, Copy, PartialEq, Eq)]
/**
 * @brief 영역을 올리기 전에 ZONEMD를 어떻게 볼지.
 * @details 파일, 디렉터리, 외부 저장소, 영역 전송 어느 길로 들어온 영역이든 같은 방침을 쓴다.
 */
pub(crate) struct ZonemdPolicy {
    /** @brief ZONEMD를 검증할지. */
    check: bool,
    /** @brief ZONEMD가 없는 영역을 거부할지. */
    reject_absence: bool,
}

impl ZonemdPolicy {
    /** @brief 설정에서 방침을 읽는다. */
    pub(crate) fn of(cfg: &Config) -> Self {
        ZonemdPolicy {
            check: cfg.zonemd_check,
            reject_absence: cfg.zonemd_reject_absence,
        }
    }
}

/** @brief 영역이 제 안에 적어 둔 요약값과 맞는지. 맞지 않으면 오는 길에 바뀐 것이다. */
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

/** @brief 설정대로 권한 영역들을 올린다. */
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
        // 서명은 영역을 새로 만들므로 지문은 서명한 뒤에 붙인다.
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

/** @brief 목록 영역에 적힌 회원 영역들. */
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

/** @brief 회원 영역 하나를 가리키는 이름. */
fn catalog_member_id(member: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    member
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .hash(&mut h);
    format!("m{:016x}", h.finish())
}

/**
 * @brief 카탈로그 영역의 SOA serial.
 * @details 영역 저장소를 다시 만들 때마다 카탈로그도 다시 만든다. 구성원이 바뀌어도 serial이
 *          그대로면 소비자는 SOA만 보고 받아 가지 않으므로, 시각에서 계산해 늘 커지게 한다.
 */
pub(crate) fn catalog_serial(now: u64) -> u32 {
    (now & u64::from(u32::MAX)) as u32
}

/** @brief 이 서버가 내보낼 목록 영역을 만든다. */
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

/** @brief 영역 파일 디렉터리를 지켜보고 바뀌면 다시 올린다. */
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

/**
 * @brief 원본에서 다시 읽은 영역들을 저장소에 반영한다.
 * @details 원본을 읽는 일은 잠금 밖에서 끝내고, 저장소와 비교해 교체하는 일만 영역 변경 잠금
 *          아래에서 한다. 시리얼이 바뀐 영역의 IXFR 기록은 새 시리얼로 이어지지 않으므로 지운다.
 * @param prev_origins 지난번에 이 원본에서 읽은 영역들. 이번에 없으면 저장소에서 뺀다.
 * @param on_removed 뺀 영역마다 부른다.
 * @return 이번에 이 원본에서 읽은 영역들.
 */
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

/**
 * @brief 지금 실행 중인 영역 원본 감시 작업들.
 *
 * @details 원본마다 종료 신호를 하나씩 가지고 있어서, 설정에서 빠진 원본의 감시만 멈추고
 *          새로 생긴 원본의 감시를 시작할 수 있다. 서버를 내렸다 올리지 않는다.
 */
#[derive(Default)]
pub(crate) struct ZoneWatchers {
    /** @brief 원본 이름과 그 감시를 멈출 신호. */
    running: Mutex<Vec<(String, Arc<std::sync::atomic::AtomicBool>)>>,
}

/**
 * @brief 설정에 적힌 영역 원본들을 이름으로 늘어놓는다.
 *
 * @details 이름이 같으면 같은 원본이다. 이름이 달라지면 이전 감시를 멈추고 새로 시작한다.
 * @return (이름, 그 원본을 만드는 함수) 목록. 만들지 못하는 원본은 이름만 남고 함수가 없다.
 */
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

/**
 * @brief 설정에 맞춰 영역 원본 감시를 시작하고 멈춘다.
 *
 * @details 시작할 때와 설정을 교체할 때 모두 이 함수만 부른다. 두 곳에서 따로 시작하면
 *          교체한 뒤 이전 원본을 보는 감시가 남아 지운 영역이 되살아난다.
 * @param cfg      맞출 설정.
 * @param watchers 지금 실행 중인 감시들.
 * @return 원본 주소가 틀려 시작하지 못한 것이 있으면 실패. 이미 뜬 것은 그대로 둔다.
 */
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

/** @brief 외부 저장소에서 영역을 읽는 곳을 만든다. */
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

/** @brief 외부 저장소를 지켜보고 바뀌면 다시 올린다. */
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

/** @brief 시리얼이 더 새것인지. 한 바퀴 도는 값이라 크기만 비교하면 안 된다. */
pub(crate) fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

/**
 * @brief 영역 하나를 교체한다.
 * @param _held 잠근 ZoneJournals. 잡고 있다는 증거로만 받는다. 영역을 바꾸는 모든 경로가 이
 *              잠금 아래에서 읽고, 계산하고, 교체해야 한다. 잠금 밖에서 교체하면 동적 갱신이 읽은
 *              뒤 끼워 넣기 전에 들어온 변경을 그 갱신이 덮어 버린다.
 */
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

/**
 * @brief 영역 하나를 빼고 그 영역의 IXFR 기록도 지운다.
 * @param journals 잠근 ZoneJournals. swap_zone 과 같은 잠금 규칙을 따른다.
 */
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

/** @brief 영역을 고친 결과. */
pub(crate) struct ZoneApplyResult {
    /** @brief 고친 영역의 이름. */
    pub(crate) origin: String,
    /** @brief 고친 뒤의 시리얼. */
    pub(crate) serial: u32,
    /** @brief 고친 뒤의 기록 수. */
    pub(crate) records: usize,
    /** @brief 파일에 저장했는지. */
    pub(crate) persisted: bool,
    /** @brief 다시 서명했는지. */
    pub(crate) signed: bool,
}

/** @brief 기록 하나를 사람이 읽을 문자열로. */
pub(crate) fn zone_record_value(record: &onetdns_proto::Record) -> String {
    let line = onetdns_authority::record_to_master_line(record);
    line.trim_end()
        .splitn(5, ' ')
        .nth(4)
        .unwrap_or("")
        .to_string()
}

/**
 * @brief 기록 하나를 JSON으로.
 * @invariant 이름은 끝에 점을 붙인 절대 이름으로 낸다. 레코드 삭제 API는 점 없는 이름을
 *            영역 기준 상대 이름으로 읽는다. 목록이 점 없이 내보내면 목록에서 받은 이름을
 *            그대로 돌려준 삭제가 영역 이름이 두 번 붙은 이름을 찾아 늘 실패한다.
 */
pub(crate) fn zone_record_json(record: &onetdns_proto::Record) -> String {
    format!(
        "{{\"name\":{},\"type\":{},\"ttl\":{},\"value\":{}}}",
        onetdns_core::json::escape(&format!("{}.", record.name.to_ascii_lower())),
        onetdns_core::json::escape(record.rtype.name()),
        record.ttl,
        onetdns_core::json::escape(&zone_record_value(record))
    )
}

/** @brief 끝맺음 권한 기록을 뺀 기록들. */
pub(crate) fn zone_records_without_closing_soa(
    zone: &onetdns_authority::Zone,
) -> Vec<onetdns_proto::Record> {
    let mut recs = zone.axfr_records();
    recs.pop();
    recs
}

/** @brief 내용이 바뀌었으면 시리얼을 올린다. 올리지 않으면 하위 서버가 바뀐 줄 모른다. */
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

/** @brief 영역 이름을 파일 이름으로 쓸 수 있는 형태로. 경로를 벗어나는 표기는 거부한다. */
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

/** @brief 관리 API가 고칠 영역과 고친 내용을 쓸 파일. */
pub(crate) struct ZoneApiTarget {
    /** @brief 소문자로 맞춘 영역 이름. */
    pub(crate) key: String,
    /** @brief 고친 영역을 쓸 파일. 없으면 메모리에만 남는다. */
    pub(crate) path: Option<std::path::PathBuf>,
}

/**
 * @brief 이 영역을 관리 API로 고칠 수 있는지 지금 설정으로 가린다.
 * @details 보조 영역은 주 서버가 내용을 정한다. 외부 저장소(DB, etcd, LMDB, 카탈로그)에서
 *          온 영역은 다음 읽기에서 저장소 내용으로 되돌아가므로, 파일로 관리되는 영역이
 *          아니면 고치지 않는다. 설정은 부를 때마다 읽는다. 부팅 때 값을 붙잡으면 나중에
 *          더한 보조 영역을 고칠 수 있게 되고, 바꾼 영역 디렉터리 대신 이전 디렉터리에 쓴다.
 * @param verb 오류 문구에 넣을 동작 이름.
 */
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

/** @brief 영역 기준으로 이름을 푼다. */
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

/**
 * @brief 파일이 이 서버가 마지막으로 본 내용 그대로인지 확인한다.
 * @details base 는 지금 메모리에 있는 영역이다. 그 영역이 파일에서 왔으면 지금 파일의 지문이
 *          그 지문과 같아야 하고, 파일에서 오지 않았으면 파일이 없어야 한다. 다르면 밖에서
 *          파일을 고친 것이다. 그대로 쓰거나 지우면 그 편집이 사라지고, 감시 작업이 나중에
 *          읽는 것도 이미 덮인 파일이다.
 * @warning 확인한 뒤 쓰기 전에 끼어드는 외부 쓰기까지 막지는 못한다.
 */
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

/**
 * @brief 고친 영역을 파일에 쓴다. 파일이 이 서버가 마지막으로 본 내용 그대로일 때만 쓴다.
 * @param base 지금 메모리에 있는 영역. 새로 만드는 영역이면 없다.
 * @return 쓴 내용의 지문을 붙인 영역.
 */
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

/** @brief 영역을 고친다. */
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

/** @brief 영역을 고친다. 저장에 실패하면 저장소와 변경 기록을 되돌린다. 안 되돌리면 파일과 메모리가 어긋난다. */
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
        // 지난 서명은 이 서버가 만들어 저장소에 가지고 있던 것이다. 바뀐 RRset과 새 부재 증명만
        // 새로 서명하면 레코드 하나를 고치는 값이 영역 크기에 비례하지 않는다.
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

/** @brief 설정에 직접 적은 영역 파일을 다시 확인하는 주기(초). 디렉터리 감시와 같다. */
pub(crate) const ZONE_FILE_WATCH_SECS: u64 = 10;

/**
 * @brief 파일이 편집된 영역들의 이름.
 *
 * @details 설정에 적힌 파일만 본다. 수정 시각이 달라진 파일과 이번에 처음 보이는 파일이
 *          대상이다. 처음 보이는 파일은 설정이 방금 그 영역을 더했다는 뜻이라 한 번 읽는다.
 * @param previous 지난 주기에 본 수정 시각.
 * @param current 이번 주기에 본 수정 시각.
 */
pub(crate) fn zones_with_edited_files(
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

/** @brief 설정에 직접 적은 영역 파일들의 지금 수정 시각. 읽지 못하는 파일은 빠진다. */
pub(crate) fn zone_file_mtimes(
    cfg: &Config,
) -> std::collections::HashMap<PathBuf, std::time::SystemTime> {
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

/** @brief 영역별 IXFR 기록. 영역 이름의 wire 표기로 찾는다. */
pub(crate) type ZoneJournalMap = std::collections::HashMap<Vec<u8>, native::ZoneJournal>;

/**
 * @brief 영역별 IXFR 기록과 영역 변경 잠금.
 * @details 이 Mutex 가 영역 저장소를 바꾸는 유일한 잠금이다. 동적 갱신, 관리 API, 원본 감시,
 *          secondary 전송, 설정으로 저장소 전체를 다시 만드는 경로가 모두 이것을 잡는다. 설정
 *          잠금처럼 바깥 잠금을 잡은 채 이것을 잡을 수는 있다. 이것을 잡은 채로는 NOTIFY 대기열처럼
 *          이 잠금을 다시 찾지 않는 잠금만 잡는다.
 */
pub(crate) type ZoneJournals = Arc<Mutex<ZoneJournalMap>>;

/**
 * @brief 설정으로 새로 만든 저장소로 통째로 바꾼다.
 * @details 새 저장소는 원본에서 다시 읽은 것이라, 바뀐 영역의 이전 IXFR 기록은 새 시리얼로
 *          이어지지 않는다. 시리얼이 달라졌거나 사라진 영역의 기록을 지운다.
 * @param journals 잠근 ZoneJournals. 새 저장소를 만드는 동안에도 잡고 있어야 한다. 만드는 사이에
 *                 들어온 동적 갱신은 원본을 다시 읽기 전에 저장까지 끝나 있어야 사라지지 않는다.
 */
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

/**
 * @brief 한 세대 동안의 권한 영역 상태.
 * @details 핫 적용, 관리 API, 재서명, 파일 감시가 같은 저장소와 서명 키를 고친다. 모든 필드가
 *          공유 핸들이므로 복제해도 같은 상태를 가리킨다.
 */
#[derive(Clone)]
pub(crate) struct ZoneState {
    /** @brief 지금 답하는 영역 저장소. */
    pub(crate) store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    /** @brief 서명하는 영역의 키. */
    pub(crate) signers: SharedZoneSigners,
    /** @brief 영역별 IXFR 기록. */
    pub(crate) journal: ZoneJournals,
    /** @brief 영역이 바뀌었을 때 NOTIFY 를 보낸다. */
    pub(crate) notify: NotifySender,
    /** @brief 영역 원본 감시 작업. */
    pub(crate) watchers: Arc<ZoneWatchers>,
}

impl ZoneState {
    /**
     * @brief 서명 키를 읽고 저장소를 만든 뒤, NOTIFY 발신과 원본 감시를 시작한다.
     * @details 시작할 때 올린 영역은 모두 NOTIFY 대기열에 넣는다. 서버가 멈춰 있던 동안의
     *          변경을 세컨더리가 놓치지 않게 하려는 것이다.
     */
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
}

#[cfg(test)]
/** @brief 영역 저장소 구성과 영역 편집. */
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
    /**
     * @brief 편집된 영역 파일만 다시 읽을 대상이 되는지.
     *
     * @details 직렬 번호를 올려도 이 서버가 옛 영역을 답하면 세컨더리는 변경을 영영 받지
     *          못한다. 반대로 손대지 않은 영역까지 알리면 전송이 필요 없는 세컨더리를 깨운다.
     */
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

        // 같은 초 안에 다시 써도 알아채는지 보려고 수정 시각을 명시적으로 옮긴다.
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
    /** @brief 설정한 권한 영역이 조용히 빠지지 않는지. */
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
    /** @brief SQL URL의 비밀번호만 바뀌어도 감시를 교체하되 식별 키에는 원문을 남기지 않는지. */
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
            config_changed_keys(&applied, &desired).unwrap(),
            vec!["zones_mysql".to_string(), "zones_postgres".to_string()]
        );

        applied.zones_postgres = desired.zones_postgres.clone();
        applied.zones_mysql = desired.zones_mysql.clone();
        assert!(config_changed_keys(&applied, &desired).unwrap().is_empty());
    }

    #[test]
    /** @brief 영역 이름으로 경로를 벗어나지 못하는지. 벗어나면 아무 파일이나 덮는다. */
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
    /**
     * @brief 관리 API가 지금 설정으로 고칠 수 있는 영역만 고치는지.
     * @details 나중에 더한 보조 영역과 외부 저장소에서 온 영역은 거절하고, 바꾼 영역
     *          디렉터리에 쓴다.
     */
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
    /**
     * @brief 영역 목록이 내보낸 이름을 삭제 API가 같은 레코드로 읽는지.
     * @details 대시보드는 목록에서 받은 이름을 그대로 삭제 요청에 담는다.
     */
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
    /** @brief 상대·절대·꼭대기 이름이 모두 풀리는지. */
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
    /** @brief 목록 영역을 내보내고 받아 오는 왕복. */
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
    /** @brief 목록 영역에서 회원 영역들을 추출하는지. */
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
    /** @brief 시리얼 비교가 한 바퀴 도는 것을 제대로 다루는지. */
    fn serial_gt_rfc1982() {
        assert!(serial_gt(2, 1));
        assert!(!serial_gt(1, 2));
        assert!(!serial_gt(5, 5));
        assert!(serial_gt(0, u32::MAX), "랩어라운드: 0 > MAX");
    }

    #[test]
    /** @brief 받아 둔 것이 없어도 시작이 망을 기다리며 멈추지 않는지. */
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
    /** @brief 저장에 실패하면 저장소와 변경 기록을 되돌리는지. 안 되돌리면 파일과 메모리가 어긋난다. */
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
    /**
     * @brief 관리 API 와 재서명도 밖에서 고친 영역 파일을 덮어쓰지 않는지.
     * @details 메모리에 없는 영역을 새로 만들 때도, 같은 이름의 파일이 이미 있으면 쓰지 않는다.
     *          감시 작업이 아직 읽지 않은 파일일 수 있다.
     */
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

    /** @brief 이름과 시리얼만 다른 작은 영역. */
    fn tiny_zone(origin: &str, serial: u32) -> onetdns_authority::Zone {
        onetdns_authority::parse_zone(
            &format!("$ORIGIN {origin}.\n@ IN SOA ns admin {serial} 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"),
            origin,
        )
        .unwrap()
    }

    #[test]
    /**
     * @brief 원본 감시가 진행 중인 영역 변경이 끝날 때까지 기다리는지.
     * @details 동적 갱신은 영역 변경 잠금을 잡고 읽고, 계산하고, 교체한다. 감시가 그 사이에 끼어들어
     *          영역을 바꾸면 갱신이 오래된 영역으로 만든 결과로 그 변경을 덮는다.
     */
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
    /** @brief 저장소를 통째로 바꿀 때 시리얼이 그대로인 영역의 IXFR 기록만 남기는지. */
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
