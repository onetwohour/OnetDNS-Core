/*!
 * @brief 재귀 해석기를 준비한다. 루트 서버, 신뢰 앵커와 RFC 5011 갱신, 경로상의 DNS 가로채기 탐지를 맡는다.
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;

use crate::error::{BoxResult, Context};
use crate::{
    read_text_limited, resolver_chain, sleep_or_shutdown, unix_now, LOCAL_STATE_MAX_BYTES,
};

/** @brief 재귀를 시작할 루트 서버들. */
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

/**
 * @brief 권한 서버에 TCP로만 물을지의 판정. 프로세스에 하나만 둔다.
 *
 * @details UDP 53번 가로채기는 호스트 망의 성질이라 설정을 다시 읽어도 바뀌지 않는다.
 *          재귀기마다 따로 두면 다시 읽을 때 새로 만든 재귀기가 판정을 잃는다.
 */
fn authority_tcp_switch() -> Arc<std::sync::atomic::AtomicBool> {
    /** @brief 판정 값. */
    static SWITCH: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    SWITCH
        .get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .clone()
}

/** @brief 가로채기 판정을 공유하는 재귀기를 만든다. */
pub(crate) fn new_recursor(roots: Vec<SocketAddr>, timeout: Duration) -> onetdns_recurse::Recursor {
    onetdns_recurse::Recursor::new(roots, timeout).with_authority_tcp(authority_tcp_switch())
}

/**
 * @brief 일반 DNS가 중간에서 가로채이는지 확인한다.
 *
 * @details 루트 서버는 비재귀 질의에 위임만 돌려주므로, 주소 답이 오면 중간에서 다른 것이
 *          대신 답한 것이다. UDP로 물은 루트가 하나도 답하지 않는 망도 있다. 두 경우 모두
 *          같은 루트에 TCP로 다시 물어 위임이 오면 권한 서버 질의를 TCP로 돌린다. TCP까지
 *          가로채이면 재귀를 쓸 수 없으므로 경고만 남긴다.
 */
pub(crate) fn detect_dns53_interception(
    roots: Vec<SocketAddr>,
    timeout: Duration,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    /** @brief 한 번만 확인한다. */
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
                        "외부 UDP 53번이 가로채져 있어 재귀 해석의 권한 서버 질의를 TCP로 보냅니다"
                    );
                } else {
                    onetdns_core::warn!(event = "net.port53_intercepted",
                        root = %root,
                        "외부 53번 포트가 가로채져 직접 재귀 해석을 사용할 수 없습니다. 암호화 업스트림 DNS 서버 사용을 권장합니다"
                    );
                }
                return;
            }
            if let Some(root) = silent_root {
                if !shutdown.load(Ordering::Relaxed) && tcp_gives_referral(root) {
                    authority_tcp_switch().store(true, Ordering::Relaxed);
                    onetdns_core::warn!(event = "net.port53_udp_blocked",
                        root = %root,
                        "루트 서버가 UDP 53번으로 답하지 않아 재귀 해석의 권한 서버 질의를 TCP로 보냅니다"
                    );
                }
            }
        })
    {
        Ok(thread) => Some(thread),
        Err(error) => {
            PROBED.store(false, Ordering::Relaxed);
            onetdns_core::warn!(event = "net.intercept_probe_thread_failed", %error, "53번 포트 가로채기 진단 스레드를 시작하지 못했습니다");
            None
        }
    }
}

/** @brief 루트 서버가 비재귀 질의에 줄 수 없는 주소 답이 들어 있는지. */
fn is_forged_root_answer(resp: &onetdns_proto::Message) -> bool {
    resp.answers
        .iter()
        .any(|r| matches!(r.rdata, onetdns_proto::RData::A(_)))
}

/**
 * @brief RFC 8145 신호 질의에 쓸 이름의 첫 레이블.
 * @param anchors 검증에 실제로 쓰는 루트 신뢰 앵커.
 * @return 앵커가 없으면 알릴 것이 없으므로 없다.
 */
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

/**
 * @brief 이 서버가 쓰는 신뢰 루트를 주기적으로 알린다.
 * @param anchors 리졸버가 검증에 쓰는 앵커 저장소. 설정 파일의 앵커나 RFC 5011로 바뀐
 *                앵커가 여기 담기므로, 내장 앵커 대신 이것을 알려야 실제 상태가 나간다.
 */
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
                            onetdns_core::info!(event = "dnssec.ta_signal_sent", signal = %label, "RFC 8145 신뢰 앵커 신호를 전송했습니다");
                        }
                        Err(error) => {
                            onetdns_core::warn!(event = "dnssec.ta_signal_failed", signal = %label, error = ?error, "RFC 8145 신뢰 앵커 신호를 보내지 못했습니다");
                        }
                    },
                    Err(error) => {
                        onetdns_core::warn!(event = "dnssec.ta_signal_name_invalid", signal = %label, error = ?error, "신뢰 앵커 신호 이름을 만들지 못했습니다");
                    }
                }
            }
            if sleep_or_shutdown(24 * 3600, &shutdown) {
                break;
            }
        })
}

/**
 * @brief 전달 검증기가 쓸 루트 신뢰 기준.
 * @details 설정 파일로 앵커를 준 사람은 그것을, 아니면 내장 앵커를 쓴다. 체인을 새로 구성할
 *          때마다 이 설정에서 다시 읽는다. 처음 구성할 때 읽은 값을 계속 가지고 있으면 앵커 파일을
 *          바꿔도 이전 키로 검증한다.
 */
pub(crate) fn forward_trust_anchors(
    anchor_file: Option<&std::path::Path>,
) -> BoxResult<Vec<onetdns_dnssec::Ds>> {
    match anchor_file {
        Some(path) => load_configured_trust_anchors(path),
        None => Ok(onetdns_dnssec::root_trust_anchors()),
    }
}

/** @brief 설정한 신뢰 루트를 읽는다. 못 읽으면 시작하지 않는다. */
pub(crate) fn load_configured_trust_anchors(
    path: &std::path::Path,
) -> BoxResult<Vec<onetdns_dnssec::Ds>> {
    let text = read_text_limited(path, LOCAL_STATE_MAX_BYTES).with_context(|| {
        format!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'을 읽지 못했습니다",
            path.display()
        )
    })?;
    let manager = onetdns_dnssec::anchor::AnchorManager::deserialize(&text).ok_or_else(|| {
        crate::anyhow!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'의 형식이 올바르지 않습니다",
            path.display()
        )
    })?;
    if !manager.zone.is_root() {
        return Err(crate::anyhow!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'은 현재 루트 영역 앵커만 지원합니다",
            path.display()
        ));
    }
    let anchors = manager.active_ds();
    if anchors.is_empty() {
        return Err(crate::anyhow!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'에 활성 키가 없습니다",
            path.display()
        ));
    }
    Ok(anchors)
}

/** @brief 신뢰 루트가 바뀌는 것을 따라가는 스레드를 시작한다. */
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
                            onetdns_core::info!(event = "dnssec.rfc5011_initialized", keys = mgr.active_ds().len(), "RFC 5011 루트 KSK 초기화를 마쳤습니다");
                        }
                    } else {
                        let changed = mgr.update(&keys, &sigs, unix_now());
                        if changed {
                            onetdns_core::info!(event = "dnssec.rfc5011_state_changed", active = mgr.active_ds().len(), "RFC 5011 신뢰 앵커 상태가 바뀌었습니다");
                        }
                    }

                    if let Err(e) = crate::atomic_write(&anchor_file, mgr.serialize().as_bytes()) {

                        mgr = previous_mgr;
                        onetdns_core::warn!(event = "dnssec.rfc5011_save_failed", error = %e, "RFC 5011 신뢰 앵커 상태를 저장하지 못해 메모리의 변경도 되돌렸습니다");
                    } else {
                        let active = mgr.active_ds();
                        if !active.is_empty() {
                            anchors.store(Arc::new(active));
                        }
                    }
                }
                Err(e) => onetdns_core::warn!(event = "dnssec.rfc5011_query_failed", error = %e, "RFC 5011 루트 DNSKEY를 조회하지 못했습니다. 다음 주기에 다시 시도합니다"),
            }

            if sleep_or_shutdown(12 * 3600, &shutdown) {
                break;
            }
        }
        })
}

#[cfg(test)]
/** @brief 루트 서버와 신뢰 앵커 준비, 가로채기 탐지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 신뢰 루트를 시작 중에 읽고, 못 읽으면 시작하지 않는지. */
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
    /** @brief 신뢰 앵커 신호가 내장 앵커가 아니라 실제로 쓰는 앵커의 키 태그를 담는지. */
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
