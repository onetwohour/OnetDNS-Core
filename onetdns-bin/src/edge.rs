//! Builds DHCP, RA and PXE services from config, and syncs leases with the control API and the
//! cluster.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;

use crate::atomic_file::atomic_write;
use crate::config_apply::SecondaryRestart;
use crate::{
    dhcp, dhcp6, http, mac, ra, read_text_limited, sleep_or_shutdown, tftp, track_service_thread,
    unix_now,
};

/// Most leases accepted in one sync.
const MAX_SYNCED_LEASES: usize = 16_384;

/// Converts the shared DHCP lease lifetime to the 32-bit value both wire formats carry, without
/// loss.
fn wire_dhcp_lease_secs(value: u64) -> Result<u32, String> {
    let value = u32::try_from(value).map_err(|_| {
        "dhcp_lease_secs must not exceed 4294967295 seconds, the DHCP wire limit".to_string()
    })?;
    if value == 0 {
        return Err("dhcp_lease_secs must be at least 1 second".to_string());
    }
    Ok(value)
}

fn build_dhcp_config(cfg: &Config) -> Result<dhcp::DhcpConfig, String> {
    use std::net::Ipv4Addr;
    let p = |o: &Option<String>, name: &str| -> Result<Ipv4Addr, String> {
        o.as_deref()
            .ok_or_else(|| format!("{name} is required"))?
            .parse()
            .map_err(|_| format!("{name} is malformed"))
    };
    let opt = |o: &Option<String>, name: &str, default: Ipv4Addr| -> Result<Ipv4Addr, String> {
        match o.as_deref() {
            None => Ok(default),
            Some(s) => s.parse().map_err(|_| format!("{name} is malformed")),
        }
    };
    let server_ip = p(&cfg.dhcp_server_ip, "dhcp_server_ip")?;
    let range_start = p(&cfg.dhcp_range_start, "dhcp_range_start")?;
    let range_end = p(&cfg.dhcp_range_end, "dhcp_range_end")?;
    let subnet_mask = opt(
        &cfg.dhcp_subnet_mask,
        "dhcp_subnet_mask",
        Ipv4Addr::new(255, 255, 255, 0),
    )?;
    let router = opt(&cfg.dhcp_router, "dhcp_router", server_ip)?;

    if u32::from(range_start) > u32::from(range_end) {
        return Err("dhcp_range_start must be less than or equal to dhcp_range_end".to_string());
    }
    let mask = u32::from(subnet_mask);

    let inv = !mask;
    if mask == 0 || (inv & inv.wrapping_add(1)) != 0 {
        return Err("dhcp_subnet_mask must be a valid netmask with contiguous bits".to_string());
    }
    let net = u32::from(server_ip) & mask;
    let bcast = net | inv;
    let in_subnet = |ip: Ipv4Addr| (u32::from(ip) & mask) == net;
    for (ip, name) in [
        (range_start, "dhcp_range_start"),
        (range_end, "dhcp_range_end"),
    ] {
        if !in_subnet(ip) {
            return Err(format!(
                "{name} is not in the DHCP server subnet ({})",
                Ipv4Addr::from(net)
            ));
        }
        let v = u32::from(ip);
        if v == net || v == bcast {
            return Err(format!("{name} is the network or broadcast address"));
        }
    }
    if !in_subnet(router) {
        return Err("dhcp_router is not in the DHCP server subnet".to_string());
    }
    let in_range = |ip: Ipv4Addr| {
        let value = u32::from(ip);
        value >= u32::from(range_start) && value <= u32::from(range_end)
    };
    for (ip, name) in [(server_ip, "dhcp_server_ip"), (router, "dhcp_router")] {
        if in_range(ip) {
            return Err(format!("{name} cannot be inside the DHCP dynamic range"));
        }
    }
    let static_file = cfg.dhcp_static_file.as_ref().map(std::path::PathBuf::from);
    if let Some(path) = &static_file {
        dhcp::read_reservations(path)?;
    }
    let dns: Vec<Ipv4Addr> = if cfg.dhcp_dns.is_empty() {
        vec![server_ip]
    } else {
        let mut out = Vec::with_capacity(cfg.dhcp_dns.len());
        for s in &cfg.dhcp_dns {
            out.push(
                s.parse()
                    .map_err(|_| format!("dhcp_dns needs valid IPv4 addresses: {s}"))?,
            );
        }
        out
    };
    Ok(dhcp::DhcpConfig {
        server_ip,
        range_start,
        range_end,
        subnet_mask,
        router,
        dns,
        lease_secs: wire_dhcp_lease_secs(cfg.dhcp_lease_secs)?,
        tftp_server: cfg.dhcp_tftp_server.as_deref().and_then(|s| s.parse().ok()),
        boot_file: cfg.dhcp_boot_file.clone(),
        domain_name: (!cfg.dhcp_local_domain.is_empty())
            .then(|| cfg.dhcp_local_domain.trim_end_matches('.').to_string()),
        lease_file: cfg.dhcp_lease_file.as_ref().map(std::path::PathBuf::from),
        static_file,
    })
}

/// Fails without a readable `ra_prefix`; config validation already checks value ranges.
fn build_ra_config(cfg: &Config) -> Result<ra::RaConfig, String> {
    let missing = || "ra_enable needs ra_prefix, written like fd00:1::/64".to_string();
    let spec = cfg.ra_prefix.as_deref().ok_or_else(missing)?;
    let (addr_s, len_s) = spec.split_once('/').ok_or_else(missing)?;
    let prefix: std::net::Ipv6Addr = addr_s.trim().parse().map_err(|_| missing())?;
    let prefix_len: u8 = len_s
        .trim()
        .parse()
        .ok()
        .filter(|l| *l <= 128)
        .ok_or_else(missing)?;
    Ok(ra::RaConfig {
        prefix,
        prefix_len,
        managed: cfg.ra_managed,
        other: cfg.ra_other,
        router_lifetime: cfg.ra_router_lifetime,
        valid_lifetime: 86_400,
        preferred_lifetime: 14_400,
        mtu: (cfg.ra_mtu != 0).then_some(cfg.ra_mtu),
        source_mac: None,
        interval: cfg.ra_interval,
        interface_index: cfg.ra_interface_index,
    })
}

/// May create the server identifier file; checks use `dhcp6_addresses` instead.
fn build_dhcp6_config(cfg: &Config) -> Result<dhcp6::Dhcp6Config, String> {
    let (range_start, range_end, dns) = dhcp6_addresses(cfg)?;
    Ok(dhcp6::Dhcp6Config {
        server_duid: load_or_create_server_duid6(cfg.dhcp6_lease_file.as_deref())?,
        range_start,
        range_end,
        dns,
        interface_index: cfg.dhcp6_interface_index,
        lease_secs: wire_dhcp_lease_secs(cfg.dhcp_lease_secs)?,
        lease_file: cfg.dhcp6_lease_file.as_ref().map(std::path::PathBuf::from),
    })
}

/// Range start, range end and DNS servers; touches no file. Fails on an unreadable address or an
/// inverted range.
#[allow(clippy::type_complexity)]
fn dhcp6_addresses(
    cfg: &Config,
) -> Result<
    (
        std::net::Ipv6Addr,
        std::net::Ipv6Addr,
        Vec<std::net::Ipv6Addr>,
    ),
    String,
> {
    use std::net::Ipv6Addr;
    let p = |o: &Option<String>, name: &str| -> Result<Ipv6Addr, String> {
        o.as_deref()
            .ok_or_else(|| format!("{name} is required"))?
            .parse()
            .map_err(|_| format!("{name} is malformed"))
    };
    let range_start = p(&cfg.dhcp6_range_start, "dhcp6_range_start")?;
    let range_end = p(&cfg.dhcp6_range_end, "dhcp6_range_end")?;
    if u128::from(range_start) > u128::from(range_end) {
        return Err(
            "`dhcp6_range_start` must be less than or equal to `dhcp6_range_end`".to_string(),
        );
    }
    let dns = cfg
        .dhcp6_dns
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|_| format!("dhcp6_dns needs IPv6 addresses: {s}"))
        })
        .collect::<Result<Vec<Ipv6Addr>, String>>()?;
    Ok((range_start, range_end, dns))
}

/// Checks that enabled edge services can start, without creating files. For state files only the
/// directory is checked; without it DHCPv4 loses leases and DHCPv6 does not start.
pub(crate) fn edge_service_preflight(cfg: &Config) -> Result<(), String> {
    let parent_exists = |path: &Option<String>, key: &str| -> Result<(), String> {
        let Some(path) = path else { return Ok(()) };
        let parent = std::path::Path::new(path)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        if parent.is_dir() {
            Ok(())
        } else {
            Err(format!(
                "The directory for {key} does not exist: {}",
                parent.display()
            ))
        }
    };
    if cfg.dhcp_enable {
        build_dhcp_config(cfg)?;
        parent_exists(&cfg.dhcp_lease_file, "dhcp_lease_file")?;
        parent_exists(&cfg.dhcp_static_file, "dhcp_static_file")?;
    }
    if cfg.dhcp6_enable {
        dhcp6_addresses(cfg)?;
        parent_exists(&cfg.dhcp6_lease_file, "dhcp6_lease_file")?;
    }
    if cfg.ra_enable {
        build_ra_config(cfg)?;
    }
    if cfg.tftp_enable {
        let root = cfg
            .tftp_root
            .as_deref()
            .ok_or("tftp_enable needs tftp_root")?;
        if !std::path::Path::new(root).is_dir() {
            return Err(format!("tftp_root directory does not exist: {root}"));
        }
        if std::net::UdpSocket::bind((cfg.tftp_listen.ip(), 0)).is_err() {
            return Err(format!(
                "tftp_listen address {} is not an address of this machine",
                cfg.tftp_listen.ip()
            ));
        }
    }
    #[cfg(unix)]
    for (enabled, index, key) in [
        (cfg.ra_enable, cfg.ra_interface_index, "ra_interface_index"),
        (
            cfg.dhcp6_enable,
            cfg.dhcp6_interface_index,
            "dhcp6_interface_index",
        ),
    ] {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `name` is IF_NAMESIZE bytes and if_indextoname writes only inside it.
        if enabled
            && index != 0
            && unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null()
        {
            return Err(format!("{key}: network interface {index} does not exist"));
        }
    }
    if cfg.dhcp_enable || cfg.dhcp6_enable {
        if let Some(path) = cfg.mac_vendor_db.as_deref() {
            if !std::path::Path::new(path).is_file() {
                return Err(format!("mac_vendor_db file does not exist: {path}"));
            }
        }
    }
    Ok(())
}

/// Clients recognize this server by its identifier, so the same one must survive restarts.
fn load_or_create_server_duid6(lease_file: Option<&str>) -> Result<Vec<u8>, String> {
    let generate = || {
        let mut seed = [0u8; 6];
        onetdns_tls::sys::fill_random(&mut seed);
        dhcp6::make_server_duid(&seed)
    };
    let Some(lease_file) = lease_file else {
        return Ok(generate());
    };
    let path = std::path::PathBuf::from(format!("{lease_file}.duid"));
    match read_text_limited(&path, 4096) {
        Ok(text) => {
            if let Some(duid) = parse_hex_bytes(text.trim()).filter(|duid| dhcp6::valid_duid(duid))
            {
                return Ok(duid);
            }
            onetdns_core::warn!(event = "dhcp6.duid_regenerated", path = %path.display(), "DHCPv6 DUID file was corrupted; created a new identifier");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Could not read the DHCPv6 DUID file ({}): {error}",
                path.display()
            ));
        }
    }
    let duid = generate();
    let hex: String = duid.iter().map(|byte| format!("{byte:02x}")).collect();
    atomic_write(&path, hex.as_bytes()).map_err(|error| {
        format!(
            "Could not save the DHCPv6 DUID to a file ({}): {error}. DHCPv6 is not started because the server identifier could not be kept across restarts",
            path.display()
        )
    })?;
    Ok(duid)
}

pub(crate) fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Keeps finite leases and wire infinity apart in JSON.
fn lease_time_json(expiry: u64, now: u64) -> String {
    if expiry == u64::MAX {
        "\"expires\":null,\"remaining\":null,\"infinite\":true".to_string()
    } else {
        let remaining = expiry.saturating_sub(now);
        format!("\"expires\":{expiry},\"remaining\":{remaining},\"infinite\":false")
    }
}

pub(crate) fn leases_json(
    v4: Option<&Arc<Mutex<dhcp::LeasePool>>>,
    v6: Option<&Arc<Mutex<dhcp6::Lease6Pool>>>,
    vendor: &mac::VendorDb,
) -> String {
    use onetdns_core::MutexExt;
    let now = unix_now();
    let esc = onetdns_core::json::escape;
    let v4_items: Vec<String> = match v4 {
        Some(p) => p
            .lock_recover()
            .snapshot()
            .iter()
            .map(|l| {
                let identity = onetdns_core::json::escape(&l.identity.to_text());
                let mac =
                    l.mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
                let vn =
                    vendor.lookup(l.mac).map(esc).unwrap_or_else(|| "null".to_string());
                let host =
                    l.hostname.as_deref().map(esc).unwrap_or_else(|| "null".to_string());
                let time = lease_time_json(l.expiry_unix, now);
                format!(
                    "{{\"ip\":\"{}\",\"identity\":{identity},\"mac\":\"{mac}\",\"vendor\":{vn},\"hostname\":{host},{time}}}",
                    l.ip
                )
            })
            .collect(),
        None => Vec::new(),
    };
    let v6_items: Vec<String> = match v6 {
        Some(p) => p
            .lock_recover()
            .snapshot()
            .iter()
            .map(|l| {
                let duid = l
                    .duid
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let iaid = l
                    .iaid
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let time = lease_time_json(l.expiry_unix, now);
                format!(
                    "{{\"ip\":\"{}\",\"duid\":\"{duid}\",\"iaid\":\"{iaid}\",{time}}}",
                    l.ip
                )
            })
            .collect(),
        None => Vec::new(),
    };
    format!(
        "{{\"v4\":[{}],\"v6\":[{}]}}",
        v4_items.join(","),
        v6_items.join(",")
    )
}

/// Reads a colon-separated hardware address.
fn parse_mac_colon(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Static reservations, and whether one can be added now. Reservations live only in the running
/// DHCPv4 pool; returning just an empty list without a pool would not tell no reservations from
/// nowhere to put one, so the dashboard would take input it cannot store and fail on submit.
pub(crate) fn static_reservations_json(pool: Option<&Arc<Mutex<dhcp::LeasePool>>>) -> String {
    use onetdns_core::MutexExt;
    let Some(pool) = pool else {
        return "{\"available\":false,\"reservations\":[]}".to_string();
    };
    let esc = onetdns_core::json::escape;
    let items: Vec<String> = pool
        .lock_recover()
        .reservations()
        .iter()
        .map(|r| {
            let identity = esc(&r.identity.to_text());
            let host = r
                .hostname
                .as_deref()
                .map(esc)
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"ip\":\"{}\",\"identity\":{identity},\"hostname\":{host}}}",
                r.ip
            )
        })
        .collect();
    format!(
        "{{\"available\":true,\"reservations\":[{}]}}",
        items.join(",")
    )
}

pub(crate) fn apply_static_add(
    pool: &Arc<Mutex<dhcp::LeasePool>>,
    body: &str,
) -> Result<String, String> {
    use onetdns_core::MutexExt;
    let j =
        onetdns_core::json::parse(body).map_err(|e| format!("Invalid JSON request body: {e}"))?;
    let identity_s = j
        .get("identity")
        .and_then(|v| v.as_str())
        .ok_or("identity is required")?;
    let ip_s = j
        .get("ip")
        .and_then(|v| v.as_str())
        .ok_or("ip is required")?;
    let hostname = j.get("hostname").and_then(|v| v.as_str()).map(String::from);
    if hostname
        .as_deref()
        .is_some_and(|value| !dhcp::valid_hostname(value))
    {
        return Err(
            "hostname must be 1 to 255 bytes and cannot contain spaces or control characters"
                .to_string(),
        );
    }
    let identity = dhcp::ClientIdentity::from_text(identity_s)
        .ok_or("identity must be mac:<12 hex digits> or id:<4 to 510 hex digits>")?;
    let ip: std::net::Ipv4Addr = ip_s.parse().map_err(|_| "ip is malformed")?;
    pool.lock_recover()
        .add_reservation(identity, u32::from(ip), hostname)?;
    Ok(format!(
        "{{\"added\":true,\"identity\":{},\"ip\":\"{ip}\"}}",
        onetdns_core::json::escape(identity_s)
    ))
}

pub(crate) fn apply_static_remove(
    pool: &Arc<Mutex<dhcp::LeasePool>>,
    identity_s: &str,
) -> Result<String, String> {
    use onetdns_core::MutexExt;
    let identity = dhcp::ClientIdentity::from_text(identity_s)
        .ok_or("identity must be mac:<12 hex digits> or id:<4 to 510 hex digits>")?;
    if pool.lock_recover().remove_reservation(&identity) {
        Ok(format!(
            "{{\"removed\":true,\"identity\":{}}}",
            onetdns_core::json::escape(identity_s)
        ))
    } else {
        Err(format!(
            "No static assignment for this client identifier: {identity_s}"
        ))
    }
}

/// Starts the thread exchanging leases with other servers.
pub(crate) fn spawn_lease_sync(
    pool: Arc<Mutex<dhcp::LeasePool>>,
    peers: Vec<String>,
    token: onetdns_core::SecretString,
    resolver: http::HostResolver,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    if peers.is_empty() || token.is_empty() {
        return Ok(None);
    }
    use onetdns_core::MutexExt;
    std::thread::Builder::new()
        .name("dhcp-sync".into())
        .spawn(move || loop {
            if sleep_or_shutdown(30, &shutdown) {
                break;
            }
            let snapshot = pool.lock_recover().snapshot();
            if snapshot.is_empty() {
                continue;
            }
            let leases: Vec<String> = snapshot
                .iter()
                .map(|l| {
                    let identity = onetdns_core::json::escape(&l.identity.to_text());
                    let mac = l
                        .mac
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    let host = l
                        .hostname
                        .as_deref()
                        .map(|h| format!(",\"hostname\":{}", onetdns_core::json::escape(h)))
                        .unwrap_or_default();
                    format!(
                        "{{\"identity\":{identity},\"mac\":\"{mac}\",\"ip\":\"{}\",\"expiry\":\"{}\"{host}}}",
                        l.ip, l.expiry_unix
                    )
                })
                .collect();
            let body = format!("[{}]", leases.join(","));
            for peer in &peers {
                let base = peer.trim_end_matches('/');
                match http::post(&format!("{base}/v1/dhcp/leases"))
                    .header("Authorization", &format!("Bearer {}", token.as_str()))
                    .header("Content-Type", "application/json")
                    .timeout(Duration::from_secs(3))
                    .resolver(resolver.clone())
                    .body_string(&body)
                    .call()
                {
                    Ok(_) => onetdns_core::debug!(
                        event = "dhcp.lease_sync_sent",
                        peer = %peer,
                        leases = snapshot.len(),
                        "Sent a DHCP lease snapshot to peer node"
                    ),
                    Err(error) => onetdns_core::warn!(
                        event = "dhcp.lease_sync_failed",
                        peer = %peer,
                        leases = snapshot.len(),
                        error = %error,
                        "Could not replicate DHCP leases to peer node"
                    ),
                }
            }
        })
        .map(Some)
}

/// Runs only with a DHCPv4 pool, cluster peers and a control token; a config change stops the
/// previous job and starts a new one.
pub(crate) fn lease_sync_restart(
    jobs: Arc<EdgeServices>,
    dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    resolver: http::HostResolver,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
) -> SecondaryRestart {
    Arc::new(move |next: &Config| -> Result<(), String> {
        let stop = jobs.restart_all();
        let Some(pool) = dhcp_slot.lock_recover().clone() else {
            return Ok(());
        };
        if next.cluster_peers.is_empty() || next.control_token.is_empty() {
            return Ok(());
        }
        let thread = spawn_lease_sync(
            pool,
            next.cluster_peers.clone(),
            next.control_token.clone(),
            resolver.clone(),
            stop,
        )
        .map_err(|error| format!("Could not start the DHCP lease sync thread: {error}"))?;
        if let Some(thread) = thread {
            track_service_thread(&threads, thread);
        }
        onetdns_core::info!(
            event = "dhcp.lease_sync_started",
            peers = next.cluster_peers.len(),
            "Starting DHCP lease sync (every 30 seconds)"
        );
        Ok(())
    })
}

/// Records received leases; one malformed entry rejects the whole batch.
pub(crate) fn apply_lease_sync(
    pool: &Arc<Mutex<dhcp::LeasePool>>,
    body: &str,
) -> Result<String, String> {
    use onetdns_core::MutexExt;
    let parsed =
        onetdns_core::json::parse(body).map_err(|e| format!("Invalid JSON request body: {e}"))?;
    let items: Vec<&onetdns_core::json::Json> = match &parsed {
        onetdns_core::json::Json::Arr(items) => items.iter().collect(),
        single => vec![single],
    };
    if items.is_empty() {
        return Ok("{\"synced\":0}".to_string());
    }
    if items.len() > MAX_SYNCED_LEASES {
        return Err(format!(
            "At most {MAX_SYNCED_LEASES} leases can be applied at once"
        ));
    }

    let mut pending = Vec::with_capacity(items.len());
    let mut seen_identities = std::collections::HashSet::with_capacity(items.len());
    let mut seen_ips = std::collections::HashSet::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let at = |what: &str| format!("Lease item {}: {what}", index + 1);
        let identity_s = item
            .get("identity")
            .and_then(|v| v.as_str())
            .ok_or_else(|| at("identity is required"))?;
        let mac_s = item
            .get("mac")
            .and_then(|v| v.as_str())
            .ok_or_else(|| at("mac is required"))?;
        let ip_s = item
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or_else(|| at("ip is required"))?;
        let expiry = item
            .get("expiry")
            .and_then(|v| v.as_str())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| at("expiry must be a decimal string within the u64 range"))?;
        let hostname = item
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from);
        if hostname
            .as_deref()
            .is_some_and(|value| !dhcp::valid_hostname(value))
        {
            return Err(at(
                "hostname must be 1 to 255 bytes and cannot contain spaces or control characters",
            ));
        }
        let mac = parse_mac_colon(mac_s).ok_or_else(|| at("mac is malformed"))?;
        let identity = dhcp::ClientIdentity::from_text(identity_s).ok_or_else(|| {
            at("identity must be mac:<12 hex digits> or id:<4 to 510 hex digits>")
        })?;
        if identity
            .hardware()
            .is_some_and(|identity_mac| identity_mac != mac)
        {
            return Err(at("The MAC fallback identity does not match mac"));
        }
        let ip: std::net::Ipv4Addr = ip_s.parse().map_err(|_| at("ip is malformed"))?;
        let ip = u32::from(ip);
        if !seen_identities.insert(identity.clone()) {
            return Err(at("identity is repeated in the same batch"));
        }
        if !seen_ips.insert(ip) {
            return Err(at("ip is repeated in the same batch"));
        }
        pending.push((identity, mac, ip, expiry, hostname));
    }

    let mut pool = pool.lock_recover();
    pool.validate_synced_batch(
        pending
            .iter()
            .map(|(identity, _, ip, expiry, _)| (identity.clone(), *ip, *expiry)),
    )?;
    let mut changed = 0usize;
    for (identity, mac, ip, expiry, hostname) in pending {
        if pool.insert(&identity, mac, ip, expiry, hostname) {
            changed += 1;
        }
    }

    if changed > 0 {
        pool.save();
    }
    Ok(format!("{{\"synced\":{changed}}}"))
}

/// Running DHCP, DHCPv6, router advertisement and TFTP services, each with its own stop signal.
/// A config change restarts only the services it touches; DNS sockets and workers are left
/// alone. When a generation ends, every registered signal is sent; a service left unregistered
/// keeps its port.
#[derive(Default)]
pub(crate) struct EdgeServices {
    pub(crate) running: Mutex<Vec<(String, Arc<std::sync::atomic::AtomicBool>)>>,
    /// Held to join a service before its port is opened again.
    threads: Mutex<std::collections::HashMap<String, std::thread::JoinHandle<()>>>,
}

impl EdgeServices {
    /// Stops every registered service and waits for the threads handed over by name.
    pub(crate) fn retire_all(&self) {
        for (_, stop) in self.running.lock_recover().iter() {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        let threads: Vec<_> = self.threads.lock_recover().drain().collect();
        for (_, thread) in threads {
            let _ = thread.join();
        }
    }

    /// The caller sends the signal.
    fn join_service(&self, key: &str) {
        let thread = self.threads.lock_recover().remove(key);
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }

    /// Returns the stop signal for the jobs started next. Jobs attached to the recursive resolver
    /// hold its anchor handle, so a new resolver must stop the old jobs, which would keep updating
    /// the old handle.
    pub(crate) fn restart_all(&self) -> Arc<std::sync::atomic::AtomicBool> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.replace_all(Some(stop.clone()));
        stop
    }

    /// Jobs for a new recursive resolver start before it is chosen; this swaps them in at that
    /// moment. `None` only stops the old jobs.
    pub(crate) fn replace_all(&self, stop: Option<Arc<std::sync::atomic::AtomicBool>>) {
        let mut running = self.running.lock_recover();
        for (_, old) in running.iter() {
            old.store(true, std::sync::atomic::Ordering::Release);
        }
        running.clear();
        if let Some(stop) = stop {
            running.push(("recursor-jobs".to_string(), stop));
        }
    }
}

/// One key per enabled service. Any setting change alters the key, which restarts that service;
/// an unchanged key leaves it running.
fn edge_service_keys(cfg: &Config) -> Vec<String> {
    let mut keys = Vec::new();
    if cfg.dhcp_enable {
        keys.push(format!(
            "dhcp4:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
            cfg.dhcp_server_ip,
            cfg.dhcp_range_start,
            cfg.dhcp_range_end,
            cfg.dhcp_subnet_mask,
            cfg.dhcp_router,
            cfg.dhcp_dns,
            cfg.dhcp_lease_secs,
            cfg.dhcp_tftp_server,
            cfg.dhcp_boot_file,
            cfg.dhcp_lease_file,
            cfg.dhcp_static_file,
            cfg.dhcp_local_domain,
        ));
    }
    if cfg.tftp_enable {
        keys.push(format!(
            "tftp:{:?}:{}:{:?}:{}:{:?}:{}",
            cfg.tftp_root,
            cfg.tftp_listen,
            cfg.tftp_read_allow,
            cfg.tftp_writable,
            cfg.tftp_write_allow,
            cfg.tftp_allow_overwrite,
        ));
    }
    if cfg.ra_enable {
        keys.push(format!(
            "ra:{:?}:{}:{}:{}:{}:{}:{:?}",
            cfg.ra_prefix,
            cfg.ra_managed,
            cfg.ra_other,
            cfg.ra_router_lifetime,
            cfg.ra_interval,
            cfg.ra_mtu,
            cfg.ra_interface_index,
        ));
    }
    if cfg.dhcp6_enable {
        keys.push(format!(
            "dhcp6:{:?}:{:?}:{:?}:{}:{}:{:?}",
            cfg.dhcp6_range_start,
            cfg.dhcp6_range_end,
            cfg.dhcp6_dns,
            cfg.dhcp6_interface_index,
            cfg.dhcp_lease_secs,
            cfg.dhcp6_lease_file,
        ));
    }
    keys
}

/// Fails without stopping anything when the config is invalid. When a port cannot be opened it
/// fails, and the caller must call again with the previous config. A port is never reopened
/// before the previous thread ends, and the lease pool is kept, so the control API and the DNS
/// layer see the same pool.
pub(crate) fn reconcile_edge_services(
    cfg: &Config,
    services: &EdgeServices,
    dhcp_slot: &Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    dhcp6_slot: &Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let wanted = edge_service_keys(cfg);
    let mut running = services.running.lock_recover();
    let starting: Vec<&String> = wanted
        .iter()
        .filter(|key| !running.iter().any(|(have, _)| have == *key))
        .collect();
    for key in &starting {
        match key.split(':').next().unwrap_or("") {
            "dhcp4" => {
                build_dhcp_config(cfg)?;
            }
            "tftp" => {
                cfg.tftp_root
                    .as_deref()
                    .ok_or("tftp_enable needs tftp_root")?;
            }
            "ra" => {
                build_ra_config(cfg)?;
            }
            "dhcp6" => {
                dhcp6_addresses(cfg)?;
            }
            _ => {}
        }
    }

    let mut retired = Vec::new();
    running.retain(|(key, stop)| {
        let keep = wanted.contains(key);
        if !keep {
            stop.store(true, Ordering::Release);
            retired.push(key.clone());
        }
        keep
    });
    for key in retired {
        services.join_service(&key);
        onetdns_core::info!(
            event = "edge.service_retired",
            service = %key.split(':').next().unwrap_or(&key),
            "Stopped edge services that were removed or changed in the configuration"
        );
    }
    if !wanted.iter().any(|key| key.starts_with("dhcp4:")) {
        *dhcp_slot.lock_recover() = None;
    }
    if !wanted.iter().any(|key| key.starts_with("dhcp6:")) {
        *dhcp6_slot.lock_recover() = None;
    }

    for key in wanted {
        if running.iter().any(|(have, _)| have == &key) {
            continue;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let kind = key.split(':').next().unwrap_or("").to_string();
        let thread = match kind.as_str() {
            "dhcp4" => {
                let dc = build_dhcp_config(cfg)?;
                let existing = dhcp_slot.lock_recover().clone();
                let pool = match existing {
                    Some(pool) => {
                        pool.lock_recover().reconfigure(&dc)?;
                        pool
                    }
                    None => {
                        let pool = Arc::new(Mutex::new(dhcp::LeasePool::new(&dc)));
                        *dhcp_slot.lock_recover() = Some(pool.clone());
                        pool
                    }
                };
                dhcp::spawn_dhcp(dc, 67, pool, stop.clone()).map_err(|error| {
                    format!("Could not open the DHCP listening address; check permission for UDP port 67: {error}")
                })?
            }
            "tftp" => {
                let root = cfg
                    .tftp_root
                    .as_deref()
                    .ok_or("tftp_enable needs tftp_root")?;
                tftp::spawn_tftp(
                    root.into(),
                    cfg.tftp_listen,
                    cfg.tftp_read_allow.clone(),
                    cfg.tftp_writable,
                    cfg.tftp_write_allow.clone(),
                    cfg.tftp_allow_overwrite,
                    stop.clone(),
                )
                .map_err(|error| format!("Could not open the TFTP listening address: {error}"))?
            }
            "ra" => {
                let ra_cfg = build_ra_config(cfg)?;
                match ra::spawn_ra(ra_cfg, stop.clone()).map_err(|error| {
                    format!("Could not start IPv6 router advertisements: {error}")
                })? {
                    Some(thread) => thread,
                    None => continue,
                }
            }
            "dhcp6" => {
                let dc = build_dhcp6_config(cfg)?;
                let existing = dhcp6_slot.lock_recover().clone();
                let pool = match existing {
                    Some(pool) => {
                        pool.lock_recover().reconfigure(&dc);
                        pool
                    }
                    None => Arc::new(Mutex::new(dhcp6::Lease6Pool::new(&dc))),
                };
                let thread = dhcp6::spawn_dhcp6(dc, 547, pool.clone(), stop.clone()).map_err(|error| {
                    format!("Could not open UDP port 547 for DHCPv6 or join the ff02::1:2 multicast group; check dhcp6_interface_index and port permissions: {error}")
                })?;
                *dhcp6_slot.lock_recover() = Some(pool);
                thread
            }
            _ => continue,
        };
        services.threads.lock_recover().insert(key.clone(), thread);
        onetdns_core::info!(
            event = "edge.service_started",
            service = %kind,
            "Started edge service"
        );
        running.push((key, stop));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use onetdns_config::Config;

    use crate::dhcp;

    #[test]
    fn dhcp_range_excludes_server_and_router_addresses() {
        let base = Config {
            dhcp_server_ip: Some("192.168.1.1".into()),
            dhcp_range_start: Some("192.168.1.10".into()),
            dhcp_range_end: Some("192.168.1.20".into()),
            dhcp_subnet_mask: Some("255.255.255.0".into()),
            dhcp_router: Some("192.168.1.2".into()),
            ..Config::default()
        };
        assert!(build_dhcp_config(&base).is_ok());

        let mut server_in_range = base.clone();
        server_in_range.dhcp_server_ip = Some("192.168.1.15".into());
        assert!(build_dhcp_config(&server_in_range)
            .unwrap_err()
            .contains("dhcp_server_ip"));

        let mut router_in_range = base;
        router_in_range.dhcp_router = Some("192.168.1.15".into());
        assert!(build_dhcp_config(&router_in_range)
            .unwrap_err()
            .contains("dhcp_router"));
    }

    #[test]
    fn dhcp_lease_lifetime_is_lossless_at_runtime_boundaries() {
        assert!(wire_dhcp_lease_secs(0).is_err());
        assert!(wire_dhcp_lease_secs(u64::from(u32::MAX) + 1).is_err());
        assert_eq!(wire_dhcp_lease_secs(u64::from(u32::MAX)), Ok(u32::MAX));
        assert_eq!(
            lease_time_json(u64::MAX, 123),
            "\"expires\":null,\"remaining\":null,\"infinite\":true"
        );
        assert_eq!(
            lease_time_json(200, 123),
            "\"expires\":200,\"remaining\":77,\"infinite\":false"
        );
    }

    #[test]
    fn persisted_server_duid_uses_the_exact_wire_length_range() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let lease_path = std::env::temp_dir().join(format!(
            "onetdns-dhcp6-duid-{}-{unique}",
            std::process::id()
        ));
        let duid_path = std::path::PathBuf::from(format!("{}.duid", lease_path.display()));

        std::fs::write(&duid_path, "123456").unwrap();
        assert_eq!(
            load_or_create_server_duid6(lease_path.to_str()).unwrap(),
            vec![0x12, 0x34, 0x56]
        );

        std::fs::write(&duid_path, "00".repeat(131)).unwrap();
        let regenerated = load_or_create_server_duid6(lease_path.to_str()).unwrap();
        assert!((3..=130).contains(&regenerated.len()));
        assert_ne!(regenerated.len(), 131);

        std::fs::remove_file(duid_path).unwrap();
    }

    fn lease_sync_pool() -> Arc<Mutex<dhcp::LeasePool>> {
        let dc = dhcp::DhcpConfig {
            server_ip: std::net::Ipv4Addr::new(192, 168, 1, 1),
            range_start: std::net::Ipv4Addr::new(192, 168, 1, 100),
            range_end: std::net::Ipv4Addr::new(192, 168, 1, 102),
            subnet_mask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            router: std::net::Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![std::net::Ipv4Addr::new(192, 168, 1, 1)],
            lease_secs: 3600,
            tftp_server: None,
            boot_file: None,
            domain_name: None,
            lease_file: None,
            static_file: None,
        };
        Arc::new(Mutex::new(dhcp::LeasePool::new(&dc)))
    }

    #[test]
    fn static_reservation_api_uses_one_identity_model() {
        let pool = lease_sync_pool();
        assert!(apply_static_add(
            &pool,
            "{\"identity\":\"id:0102\",\"ip\":\"192.168.1.90\",\"hostname\":\"printer\"}"
        )
        .is_ok());
        let listed = static_reservations_json(Some(&pool));
        assert!(listed.contains("\"available\":true"), "{listed}");
        assert!(listed.contains("\"identity\":\"id:0102\""), "{listed}");
        let absent = static_reservations_json(None);
        assert!(absent.contains("\"available\":false"), "{absent}");
        assert!(!listed.contains("\"mac\""), "{listed}");
        assert!(apply_static_add(
            &pool,
            "{\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":\"192.168.1.91\"}"
        )
        .is_err());
        assert!(apply_static_add(
            &pool,
            "{\"identity\":\"id:0304\",\"ip\":\"192.168.1.91\",\"hostname\":\"bad name\"}"
        )
        .is_err());
        assert!(apply_static_remove(&pool, "id:0102").is_ok());
    }

    #[test]
    fn lease_sync_accepts_batch_and_single() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;

        let batch = format!(
            "[{{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"mac:aabbccddee02\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"ip\":\"192.168.1.101\",\"expiry\":\"{expiry}\",\"hostname\":\"two\"}}]"
        );
        assert_eq!(
            apply_lease_sync(&pool, &batch).unwrap(),
            "{\"synced\":2}",
            "배열 스냅샷을 한 번에 반영해야"
        );
        assert_eq!(pool.lock_recover().snapshot().len(), 2);
        assert_eq!(
            pool.lock_recover().snapshot()[0].identity.to_text(),
            "id:0102"
        );

        let single = format!(
            "{{\"identity\":\"mac:aabbccddee03\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"ip\":\"192.168.1.102\",\"expiry\":\"{expiry}\"}}"
        );
        assert_eq!(apply_lease_sync(&pool, &single).unwrap(), "{\"synced\":1}");
        assert_eq!(pool.lock_recover().snapshot().len(), 3);

        assert_eq!(apply_lease_sync(&pool, &batch).unwrap(), "{\"synced\":0}");
    }

    #[test]
    fn lease_sync_preserves_infinite_expiry_exactly() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let body = format!(
            "{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{}\"}}",
            u64::MAX
        );

        assert_eq!(apply_lease_sync(&pool, &body).unwrap(), "{\"synced\":1}");
        assert_eq!(pool.lock_recover().snapshot()[0].expiry_unix, u64::MAX);
    }

    #[test]
    /// A half-applied batch would leave the lease records inconsistent.
    fn lease_sync_rejects_whole_batch_on_any_bad_item() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;

        let mixed = format!(
            "[{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"mac:aabbccddee02\",\"mac\":\"nonsense\",\"ip\":\"192.168.1.101\",\"expiry\":\"{expiry}\"}}]"
        );
        assert!(apply_lease_sync(&pool, &mixed).is_err());
        assert!(
            pool.lock_recover().snapshot().is_empty(),
            "한 항목이라도 틀리면 앞 항목도 반영하지 않아야"
        );

        assert!(apply_lease_sync(&pool, "[{\"ip\":\"192.168.1.100\"}]").is_err());
        assert!(apply_lease_sync(
            &pool,
            &format!("{{\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}}")
        )
        .is_err());
        assert!(apply_lease_sync(
            &pool,
            &format!("{{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\",\"hostname\":\"bad name\"}}")
        )
        .is_err());
        assert!(pool.lock_recover().snapshot().is_empty());
        assert!(apply_lease_sync(&pool, "not json").is_err());
        assert_eq!(apply_lease_sync(&pool, "[]").unwrap(), "{\"synced\":0}");
    }

    #[test]
    fn lease_sync_rejects_duplicate_ip_batch_atomically() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;
        let duplicate = format!(
            "[{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"mac:aabbccddee02\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}}]"
        );

        assert!(apply_lease_sync(&pool, &duplicate).is_err());
        assert!(
            pool.lock_recover().snapshot().is_empty(),
            "충돌 전 항목까지 반영하면 HA 노드의 임대 기록이 갈라집니다"
        );

        let duplicate_identity = format!(
            "[{{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"ip\":\"192.168.1.101\",\"expiry\":\"{expiry}\"}}]"
        );
        assert!(apply_lease_sync(&pool, &duplicate_identity).is_err());
        assert!(pool.lock_recover().snapshot().is_empty());
    }

    #[test]
    fn lease_sync_bounds_batch_size() {
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;
        let one = format!(
            "{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}}"
        );
        let body = format!(
            "[{}]",
            std::iter::repeat_n(one.as_str(), MAX_SYNCED_LEASES + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(apply_lease_sync(&pool, &body).is_err());
    }

    #[test]
    fn dhcp6_lease_lifetime_changes_edge_service_identity() {
        let mut cfg = Config {
            dhcp6_enable: true,
            dhcp6_range_start: Some("2001:db8::100".to_string()),
            dhcp6_range_end: Some("2001:db8::1ff".to_string()),
            ..Config::default()
        };
        let before = edge_service_keys(&cfg);

        cfg.dhcp_lease_secs = cfg.dhcp_lease_secs.saturating_add(1);

        assert_ne!(before, edge_service_keys(&cfg));
    }

    #[test]
    fn dhcp6_interface_changes_edge_service_identity() {
        let mut cfg = Config {
            dhcp6_enable: true,
            dhcp6_range_start: Some("2001:db8::100".to_string()),
            dhcp6_range_end: Some("2001:db8::1ff".to_string()),
            ..Config::default()
        };
        let before = edge_service_keys(&cfg);

        cfg.dhcp6_interface_index = 17;

        assert_ne!(before, edge_service_keys(&cfg));
    }
}
