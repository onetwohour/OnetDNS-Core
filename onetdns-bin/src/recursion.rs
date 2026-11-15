//! Sets up recursion: root servers, trust anchors with RFC 5011 updates, and detection of DNS
//! interception on the path.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;

use crate::error::{BoxResult, Context};
use crate::{
    read_text_limited, resolver_chain, sleep_or_shutdown, unix_now, LOCAL_STATE_MAX_BYTES,
};

pub(crate) fn recursor_roots(cfg: &Config) -> Vec<SocketAddr> {
    if cfg.root_hints.is_empty() {
        onetdns_recurse::default_roots()
    } else {
        cfg.root_hints
            .iter()
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect()
    }
}

/// One per process: UDP 53 interception is a property of the host network and does not change on
/// reload, and a per-recursor value would be lost by the recursor a reload builds.
fn authority_tcp_switch() -> Arc<std::sync::atomic::AtomicBool> {
    static SWITCH: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    SWITCH
        .get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .clone()
}

pub(crate) fn new_recursor(roots: Vec<SocketAddr>, timeout: Duration) -> onetdns_recurse::Recursor {
    onetdns_recurse::Recursor::new(roots, timeout).with_authority_tcp(authority_tcp_switch())
}

/// Roots answer non-recursive queries with referrals only, so an address answer means something on
/// the path answered instead. Some networks get no UDP answer from any root. Either way the same
/// root is asked over TCP, and a referral switches authority queries to TCP. If TCP is intercepted
/// too, recursion cannot work, and only a warning is logged.
pub(crate) fn detect_dns53_interception(
    roots: Vec<SocketAddr>,
    timeout: Duration,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static PROBED: AtomicBool = AtomicBool::new(false);
    if roots.is_empty() || PROBED.swap(true, Ordering::Relaxed) {
        return None;
    }
    let probe_timeout = timeout.min(Duration::from_secs(2));
    match std::thread::Builder::new()
        .name("dns53-hijack-probe".into())
        .spawn(move || {
            use onetdns_proto::{DnsClass, Header, Message, Question, RecordType};
            let Ok(name) = onetdns_proto::Name::from_str("example.com") else {
                return;
            };
            let probe = Message {
                header: Header {
                    id: 0x5454,
                    recursion_desired: false,
                    ..Default::default()
                },
                questions: vec![Question {
                    name,
                    qtype: RecordType::A,
                    qclass: DnsClass::IN,
                }],
                ..Default::default()
            };
            let Ok(wire) = probe.try_encode() else {
                return;
            };
            let tcp_gives_referral = |root: SocketAddr| {
                onetdns_forward::query_server_over(
                    root,
                    &probe,
                    probe_timeout,
                    onetdns_forward::AuthorityTransport::Tcp,
                    false,
                )
                .is_ok_and(|tcp| !is_forged_root_answer(&tcp))
            };
            let mut silent_root = None;
            'roots: for root in roots.iter().take(3) {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let bind = if root.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let Ok(sock) = std::net::UdpSocket::bind(bind) else {
                    continue;
                };
                let wait = onetdns_core::udp::RecvWait::new(
                    probe_timeout.min(Duration::from_millis(250)),
                );
                if wait.install(&sock).is_err() || sock.send_to(&wire, root).is_err() {
                    continue;
                }
                let mut buf = [0u8; 1500];
                let deadline = std::time::Instant::now() + probe_timeout;
                let (n, from) = loop {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    match wait.recv_from(&sock, &mut buf) {
                        Ok(received) => break received,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) && std::time::Instant::now() < deadline => {}
                        Err(_) => {
                            silent_root.get_or_insert(*root);
                            continue 'roots;
                        }
                    }
                };
                if from != *root {
                    continue;
                }
                let Ok(resp) = Message::parse(&buf[..n]) else {
                    continue;
                };

                if !is_forged_root_answer(&resp) {
                    return;
                }
                if tcp_gives_referral(*root) {
                    authority_tcp_switch().store(true, Ordering::Relaxed);
                    onetdns_core::warn!(event = "net.port53_udp_intercepted",
                        root = %root,
                        "Outgoing UDP port 53 is intercepted; sending recursive queries to authoritative servers over TCP"
                    );
                } else {
                    onetdns_core::warn!(event = "net.port53_intercepted",
                        root = %root,
                        "Outgoing port 53 is intercepted, so direct recursion is unavailable; use an encrypted upstream DNS server instead"
                    );
                }
                return;
            }
            if let Some(root) = silent_root {
                if !shutdown.load(Ordering::Relaxed) && tcp_gives_referral(root) {
                    authority_tcp_switch().store(true, Ordering::Relaxed);
                    onetdns_core::warn!(event = "net.port53_udp_blocked",
                        root = %root,
                        "Root servers do not answer on UDP port 53; sending recursive queries to authoritative servers over TCP"
                    );
                }
            }
        })
    {
        Ok(thread) => Some(thread),
        Err(error) => {
            PROBED.store(false, Ordering::Relaxed);
            onetdns_core::warn!(event = "net.intercept_probe_thread_failed", %error, "Could not start the port 53 interception check thread");
            None
        }
    }
}

fn is_forged_root_answer(resp: &onetdns_proto::Message) -> bool {
    resp.answers
        .iter()
        .any(|r| matches!(r.rdata, onetdns_proto::RData::A(_)))
}

/// The first label of the RFC 8145 signal query name. `anchors` are the root anchors validation
/// actually uses; None when there are none.
fn ta_signal_label(anchors: &[onetdns_dnssec::Ds]) -> Option<String> {
    let mut tags: Vec<u16> = anchors.iter().map(|anchor| anchor.key_tag).collect();
    tags.sort_unstable();
    tags.dedup();
    if tags.is_empty() {
        return None;
    }
    Some(format!(
        "_ta-{}",
        tags.iter()
            .map(|tag| format!("{tag:04x}"))
            .collect::<Vec<_>>()
            .join("-")
    ))
}

/// `anchors` is the resolver's anchor store, holding anchors from the config file or updated by RFC
/// 5011; signaling these, not the built-in ones, reports the real state.
pub(crate) fn spawn_ta_signaling(
    anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
    timeout: Duration,
    roots: Vec<SocketAddr>,
    deny: Vec<onetdns_core::IpNet>,
    allow: Vec<onetdns_core::IpNet>,
    max_ttl: u32,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("ta-signaling".into())
        .spawn(move || loop {
            let current = anchors.load();
            if let Some(label) = ta_signal_label(&current) {
                let r = new_recursor(roots.clone(), timeout)
                    .with_server_acl(deny.clone(), allow.clone())
                    .with_recursive_cache_ttl_max(max_ttl)
                    .with_trust_anchors(current.to_vec());
                match onetdns_proto::Name::from_str(&label) {
                    Ok(name) => match r.resolve(&name, onetdns_proto::RecordType(10)) {
                        Ok(_) => {
                            onetdns_core::info!(event = "dnssec.ta_signal_sent", signal = %label, "Sent RFC 8145 trust anchor signal");
                        }
                        Err(error) => {
                            onetdns_core::warn!(event = "dnssec.ta_signal_failed", signal = %label, error = ?error, "Could not send RFC 8145 trust anchor signal");
                        }
                    },
                    Err(error) => {
                        onetdns_core::warn!(event = "dnssec.ta_signal_name_invalid", signal = %label, error = ?error, "Could not build the trust anchor signal name");
                    }
                }
            }
            if sleep_or_shutdown(24 * 3600, &shutdown) {
                break;
            }
        })
}

/// The anchor file when configured, the built-in anchors otherwise. Reread on every chain build; a
/// value kept from the first build would keep validating with old keys after the anchor file
/// changes.
pub(crate) fn forward_trust_anchors(
    anchor_file: Option<&std::path::Path>,
) -> BoxResult<Vec<onetdns_dnssec::Ds>> {
    match anchor_file {
        Some(path) => load_configured_trust_anchors(path),
        None => Ok(onetdns_dnssec::root_trust_anchors()),
    }
}

/// Startup fails when they cannot be read.
pub(crate) fn load_configured_trust_anchors(
    path: &std::path::Path,
) -> BoxResult<Vec<onetdns_dnssec::Ds>> {
    let text = read_text_limited(path, LOCAL_STATE_MAX_BYTES).with_context(|| {
        format!(
            "Could not read the DNSSEC trust anchor state file '{}'",
            path.display()
        )
    })?;
    let manager = onetdns_dnssec::anchor::AnchorManager::deserialize(&text).ok_or_else(|| {
        crate::anyhow!(
            "DNSSEC trust anchor state file '{}' is malformed",
            path.display()
        )
    })?;
    if !manager.zone.is_root() {
        return Err(crate::anyhow!(
            "DNSSEC trust anchor state file '{}' supports only the root zone anchor",
            path.display()
        ));
    }
    let anchors = manager.active_ds();
    if anchors.is_empty() {
        return Err(crate::anyhow!(
            "DNSSEC trust anchor state file '{}' has no active key",
            path.display()
        ));
    }
    Ok(anchors)
}

pub(crate) fn spawn_rfc5011(
    plan: &resolver_chain::RecursivePlan,
    anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use onetdns_dnssec::anchor::{extract_dnskey_rrset, AnchorManager};
    let anchor_file = plan.anchor_state_file();
    let (deny, allow) = plan.server_acl();
    let roots = plan.roots();
    let max_ttl = plan.max_ttl();
    let timeout = plan.timeout();
    std::thread::Builder::new()
        .name("rfc5011".into())
        .spawn(move || {
        let root = onetdns_proto::Name::root();

        let mut mgr = read_text_limited(&anchor_file, LOCAL_STATE_MAX_BYTES)
            .ok()
            .and_then(|t| AnchorManager::deserialize(&t))
            .unwrap_or_else(|| AnchorManager {
                zone: root.clone(),
                keys: Vec::new(),
                hold_down_secs: onetdns_dnssec::anchor::DEFAULT_HOLD_DOWN_SECS,
            });

        let fetcher = new_recursor(roots, timeout)
            .with_server_acl(deny, allow)
            .with_recursive_cache_ttl_max(max_ttl)
            .with_dnssec();
        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            match fetcher.fetch_zone_dnskey(&root) {
                Ok(records) => {
                    let previous_mgr = mgr.clone();
                    let (keys, sigs) = extract_dnskey_rrset(&records, &root);
                    if mgr.keys.is_empty() {

                        let anchors_ds = onetdns_dnssec::root_trust_anchors();
                        let bootstrap: Vec<onetdns_dnssec::Dnskey> = keys
                            .iter()
                            .filter_map(onetdns_dnssec::Dnskey::from_record)
                            .filter(|k| {
                                anchors_ds.iter().any(|ds| {
                                    onetdns_dnssec::verify_ds(ds, k, &root).is_ok()
                                })
                            })
                            .collect();
                        if !bootstrap.is_empty() {
                            mgr = AnchorManager::bootstrap(root.clone(), bootstrap, unix_now());
                            onetdns_core::info!(event = "dnssec.rfc5011_initialized", keys = mgr.active_ds().len(), "Finished RFC 5011 root KSK initialization");
                        }
                    } else {
                        let changed = mgr.update(&keys, &sigs, unix_now());
                        if changed {
                            onetdns_core::info!(event = "dnssec.rfc5011_state_changed", active = mgr.active_ds().len(), "RFC 5011 trust anchor state changed");
                        }
                    }

                    if let Err(e) = crate::atomic_write(&anchor_file, mgr.serialize().as_bytes()) {

                        mgr = previous_mgr;
                        onetdns_core::warn!(event = "dnssec.rfc5011_save_failed", error = %e, "Could not save RFC 5011 trust anchor state; reverted the in-memory change too");
                    } else {
                        let active = mgr.active_ds();
                        if !active.is_empty() {
                            anchors.store(Arc::new(active));
                        }
                    }
                }
                Err(e) => onetdns_core::warn!(event = "dnssec.rfc5011_query_failed", error = %e, "Could not fetch the root DNSKEY for RFC 5011; retrying next cycle"),
            }

            if sleep_or_shutdown(12 * 3600, &shutdown) {
                break;
            }
        }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_trust_anchor_loads_synchronously_and_fails_closed() {
        let root = onetdns_proto::Name::root();
        let signer = onetdns_dnssec::sign::ZoneSigner::generate(root.clone(), [73; 32]);
        let manager =
            onetdns_dnssec::anchor::AnchorManager::bootstrap(root, vec![signer.dnskey()], 0);
        let path = std::env::temp_dir().join(format!(
            "onetdns-static-anchor-test-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, manager.serialize()).expect("write anchor state");

        assert_eq!(
            load_configured_trust_anchors(&path).expect("load anchor state"),
            manager.active_ds()
        );

        let child = onetdns_proto::Name::from_str("child.example").unwrap();
        let child_signer = onetdns_dnssec::sign::ZoneSigner::generate(child.clone(), [74; 32]);
        let child_manager =
            onetdns_dnssec::anchor::AnchorManager::bootstrap(child, vec![child_signer.dnskey()], 0);
        std::fs::write(&path, child_manager.serialize()).expect("write child anchor state");
        assert!(load_configured_trust_anchors(&path).is_err());

        std::fs::write(&path, "damaged anchor state").expect("damage anchor state");
        assert!(load_configured_trust_anchors(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ta_signal_label_uses_the_configured_anchors() {
        let anchor = |key_tag| onetdns_dnssec::Ds {
            key_tag,
            algorithm: 13,
            digest_type: 2,
            digest: vec![0; 32],
        };
        assert_eq!(ta_signal_label(&[]), None);
        assert_eq!(
            ta_signal_label(&[anchor(0x1234), anchor(0x00ab), anchor(0x1234)]).as_deref(),
            Some("_ta-00ab-1234")
        );
        let builtin = onetdns_dnssec::root_trust_anchors();
        assert_ne!(
            ta_signal_label(&[anchor(0x1234)]),
            ta_signal_label(&builtin),
            "사용자 앵커를 쓰면 내장 앵커와 다른 신호가 나가야 한다"
        );
    }
}
