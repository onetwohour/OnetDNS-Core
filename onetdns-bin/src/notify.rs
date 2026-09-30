/*!
 * @brief 영역이 바뀌면 세컨더리에 NOTIFY를 보내고, 응답이 없으면 다시 보낸다.
 */

use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_core::MutexExt;

use crate::{tsig_for_secondary, unix_now};

#[derive(Clone)]
/** @brief 알림을 보낼 곳 하나. */
struct NotifyRuntimeTarget {
    /** @brief 알림을 보낼 주소. */
    address: std::net::SocketAddr,
    /** @brief 알림에 쓸 공유 키. */
    tsig_key: Option<onetdns_dnssec::tsig::TsigKey>,
}

#[derive(Clone, Copy)]
/** @brief 답이 없을 때 다시 보내는 규칙. */
struct NotifyRetryPolicy {
    /** @brief 처음 다시 보내기까지 기다릴 시간. */
    initial: Duration,
    /** @brief 다시 보낼 횟수. */
    retransmissions: u8,
}

impl Default for NotifyRetryPolicy {
    /** @brief 기본 규칙. */
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            retransmissions: 5,
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
/** @brief 알림 하나를 가리키는 키. */
struct NotifyJobKey {
    /** @brief 알릴 영역. */
    origin: Vec<u8>,
    /** @brief 알릴 대상. */
    target: usize,
}

/** @brief 보낼 알림 하나. */
struct NotifyJob {
    /** @brief 알릴 영역 이름. */
    origin: onetdns_proto::Name,
    /** @brief 알릴 시리얼. */
    serial: u32,
}

#[derive(Default)]
/** @brief 보낼 알림들. */
struct NotifyQueue {
    /** @brief 아직 보내지 못한 알림들. */
    pending: Mutex<std::collections::HashMap<NotifyJobKey, NotifyJob>>,
    /** @brief 보내는 쪽을 깨우는 곳. */
    wake: std::sync::Condvar,
}

#[derive(Clone)]
/** @brief 알림을 맡기는 곳. */
pub(crate) struct NotifySender {
    /** @brief 보낼 알림을 넣을 곳. 없으면 알리지 않는다. */
    queue: Option<Arc<NotifyQueue>>,
    /** @brief 알림을 보낼 곳들. 설정이 바뀌면 교체한다. */
    targets: Arc<onetdns_core::ArcSwap<Vec<NotifyRuntimeTarget>>>,
}

impl NotifySender {
    #[cfg(test)]
    /** @brief 알리지 않는 곳. 테스트에서만 쓴다. */
    pub(crate) fn disabled() -> Self {
        Self {
            queue: None,
            targets: Arc::new(onetdns_core::ArcSwap::new(Arc::new(Vec::new()))),
        }
    }

    /** @brief 알림을 보낼 곳 목록을 교체한다. */
    pub(crate) fn replace_targets(&self, targets: NotifyTargets) {
        self.targets.store(Arc::new(targets.0));
    }

    /** @brief 이 영역이 바뀌었다고 알릴 것을 맡긴다. 같은 영역의 알림은 하나로 합친다. */
    pub(crate) fn enqueue(&self, origin: &onetdns_proto::Name, serial: u32) {
        let Some(queue) = &self.queue else {
            return;
        };
        let origin_key = origin.canonical_key();
        let mut pending = queue.pending.lock_recover();
        for target in 0..self.targets.load().len() {
            pending.insert(
                NotifyJobKey {
                    origin: origin_key.clone(),
                    target,
                },
                NotifyJob {
                    origin: origin.clone(),
                    serial,
                },
            );
        }
        drop(pending);
        queue.wake.notify_one();
    }

    /** @brief 이 영역의 지금 판으로 알린다. */
    pub(crate) fn enqueue_zone(&self, zone: &onetdns_authority::Zone) {
        self.enqueue(zone.origin(), zone.soa().serial);
    }

    #[cfg(test)]
    /** @brief 보내는 쪽을 깨운다. */
    fn wake(&self) {
        if let Some(queue) = &self.queue {
            queue.wake.notify_one();
        }
    }
}

/** @brief 답을 기다리는 알림 하나. */
struct OutstandingNotify {
    /** @brief 알린 영역. */
    origin: onetdns_proto::Name,
    /** @brief 알린 시리얼. */
    serial: u32,
    /** @brief 이 서버가 보낸 질의 번호. */
    id: u16,
    /** @brief 보낸 바이트. 다시 보낼 때 그대로 쓴다. */
    wire: Vec<u8>,
    /** @brief 요청에 붙인 서명. */
    request_mac: Option<Vec<u8>>,
    /** @brief 지금까지 보낸 횟수. */
    transmissions: u8,
    /** @brief 다음에 보낼 시각. */
    next_send: std::time::Instant,
}

/** @brief 알림을 모으는 시간. 변경이 잇달아 오면 한 번만 보내려는 것이다. */
const NOTIFY_COALESCE_DELAY: Duration = Duration::from_millis(20);

/** @brief 알림 패킷 바이트. */
fn notify_wire(
    origin: &onetdns_proto::Name,
    id: u16,
    target: &NotifyRuntimeTarget,
) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    use onetdns_proto::{DnsClass, Message, Question, RecordType};
    let mut message = Message::default();
    message.header.id = id;
    message.header.opcode = 4;
    message.header.authoritative = true;
    message.questions.push(Question {
        name: origin.clone(),
        qtype: RecordType::SOA,
        qclass: DnsClass::IN,
    });
    let request_mac = target
        .tsig_key
        .as_ref()
        .map(|key| {
            onetdns_dnssec::tsig::sign_message(&mut message, key, unix_now(), None)
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    message
        .try_encode()
        .map(|wire| (wire, request_mac))
        .map_err(|error| error.to_string())
}

/** @brief 답을 기다리는 알림을 만든다. */
fn outstanding_notify(
    origin: onetdns_proto::Name,
    serial: u32,
    target: &NotifyRuntimeTarget,
    delay: Duration,
) -> Result<OutstandingNotify, String> {
    let id = u16::from_ne_bytes(onetdns_core::random_array());
    let (wire, request_mac) = notify_wire(&origin, id, target)?;
    Ok(OutstandingNotify {
        origin,
        serial,
        id,
        wire,
        request_mac,
        transmissions: 0,
        next_send: std::time::Instant::now() + delay,
    })
}

/** @brief 이 답이 이 서버가 보낸 알림에 대한 것인지. 확인하지 않으면 아무 패킷이나 답으로 세어 다시 보내기를 멈춘다. */
fn valid_notify_ack(
    wire: &[u8],
    source: std::net::SocketAddr,
    key: &NotifyJobKey,
    outstanding: &OutstandingNotify,
    targets: &[NotifyRuntimeTarget],
) -> bool {
    use onetdns_proto::{DnsClass, Message, RecordType};
    let Some(target) = targets.get(key.target) else {
        return false;
    };
    if source != target.address {
        return false;
    }
    let message = if let Some(tsig_key) = &target.tsig_key {
        let Some(request_mac) = outstanding.request_mac.as_deref() else {
            return false;
        };
        let Ok((stripped, _)) =
            onetdns_dnssec::tsig::verify_wire(wire, tsig_key, unix_now(), Some(request_mac))
        else {
            return false;
        };
        let Ok(message) = Message::parse(&stripped) else {
            return false;
        };
        message
    } else {
        let Ok(message) = Message::parse(wire) else {
            return false;
        };
        message
    };
    message.header.response
        && message.header.authoritative
        && message.header.id == outstanding.id
        && message.header.opcode == 4
        && message.questions.len() == 1
        && message.questions[0]
            .name
            .eq_ignore_case(&outstanding.origin)
        && message.questions[0].qtype == RecordType::SOA
        && message.questions[0].qclass == DnsClass::IN
}

/** @brief 온 답들을 거둔다. */
fn receive_notify_acks(
    socket: &std::net::UdpSocket,
    active: &mut std::collections::HashMap<NotifyJobKey, OutstandingNotify>,
    targets: &[NotifyRuntimeTarget],
) {
    let mut wire = [0u8; 65_535];
    loop {
        let (length, source) = match socket.recv_from(&mut wire) {
            Ok(received) => received,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => {
                onetdns_core::warn!(event = "authority.notify_receive_failed", %error, "No ACK received for DNS NOTIFY");
                break;
            }
        };
        let matched = active.iter().find_map(|(job_key, outstanding)| {
            valid_notify_ack(&wire[..length], source, job_key, outstanding, targets)
                .then(|| job_key.clone())
        });
        if let Some(job_key) = matched {
            if let Some(done) = active.remove(&job_key) {
                let target = targets[job_key.target].address;
                onetdns_core::info!(event = "authority.notify_acknowledged", zone = %done.origin.to_ascii_lower(), serial = done.serial, %target, transmissions = done.transmissions, "DNS NOTIFY acknowledged");
            }
        }
    }
}

/** @brief 다시 보내기까지 기다릴 시간. */
fn retry_delay(policy: NotifyRetryPolicy, transmissions: u8) -> Duration {
    let shift = u32::from(transmissions.saturating_sub(1).min(20));
    policy
        .initial
        .checked_mul(1u32 << shift)
        .unwrap_or(Duration::MAX)
}

/** @brief 알림을 보내고 답을 기다리는 스레드를 시작한다. */
fn spawn_notify_worker(
    targets: Vec<NotifyRuntimeTarget>,
    policy: NotifyRetryPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(NotifySender, std::thread::JoinHandle<()>)> {
    // 두 계열 소켓을 모두 연다. 대상 목록을 교체할 수 있으므로 지금 목록에 없는 계열도
    // 나중에 들어올 수 있다.
    let socket4 = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        Some(socket)
    };
    let socket6 = match std::net::UdpSocket::bind("[::]:0") {
        Ok(socket) => {
            socket.set_nonblocking(true)?;
            Some(socket)
        }
        Err(error) => {
            onetdns_core::warn!(event = "authority.notify_ipv6_unavailable", %error, "Could not open the IPv6 NOTIFY socket; IPv6 targets will not be notified");
            None
        }
    };
    let queue = Arc::new(NotifyQueue::default());
    let targets = Arc::new(onetdns_core::ArcSwap::new(Arc::new(targets)));
    let sender = NotifySender {
        queue: Some(queue.clone()),
        targets: targets.clone(),
    };
    let thread = std::thread::Builder::new()
        .name("dns-notify".into())
        .spawn(move || {
            use std::sync::atomic::Ordering;
            let mut active = std::collections::HashMap::<
                NotifyJobKey,
                OutstandingNotify,
            >::new();
            while !shutdown.load(Ordering::Relaxed) {
                // 한 바퀴 동안은 같은 목록을 본다. 도중에 갈리면 인덱스가 어긋난다.
                let targets = targets.load();
                let pending = std::mem::take(&mut *queue.pending.lock_recover());
                for (job_key, job) in pending {
                    let Some(target) = targets.get(job_key.target) else {
                        continue;
                    };
                    if let Some(outstanding) = active.get_mut(&job_key) {
                        if outstanding.transmissions == 0 {
                            outstanding.serial = job.serial;
                            continue;
                        }
                    }
                    match outstanding_notify(
                        job.origin,
                        job.serial,
                        target,
                        NOTIFY_COALESCE_DELAY,
                    ) {
                        Ok(outstanding) => {
                            active.insert(job_key, outstanding);
                        }
                        Err(error) => onetdns_core::error!(event = "authority.notify_encode_failed", serial = job.serial, %error, "Could not encode DNS NOTIFY"),
                    }
                }

                let now = std::time::Instant::now();
                let mut timed_out = Vec::new();
                for (job_key, outstanding) in &mut active {
                    if now < outstanding.next_send {
                        continue;
                    }
                    if outstanding.transmissions > policy.retransmissions {
                        timed_out.push(job_key.clone());
                        continue;
                    }
                    let target = &targets[job_key.target];
                    let socket = if target.address.is_ipv4() {
                        socket4.as_ref()
                    } else {
                        socket6.as_ref()
                    };
                    let Some(socket) = socket else {
                        timed_out.push(job_key.clone());
                        continue;
                    };
                    match socket.send_to(&outstanding.wire, target.address) {
                        Ok(length) if length == outstanding.wire.len() => {
                            outstanding.transmissions += 1;
                            outstanding.next_send =
                                now + retry_delay(policy, outstanding.transmissions);
                            onetdns_core::info!(event = "authority.notify_sent", zone = %outstanding.origin.to_ascii_lower(), serial = outstanding.serial, target = %target.address, transmission = outstanding.transmissions, "Sent DNS NOTIFY");
                        }
                        Ok(_) => {
                            outstanding.next_send = now + Duration::from_millis(10);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            outstanding.next_send = now + Duration::from_millis(10);
                        }
                        Err(error) => {
                            outstanding.transmissions += 1;
                            outstanding.next_send =
                                now + retry_delay(policy, outstanding.transmissions);
                            onetdns_core::warn!(event = "authority.notify_send_failed", zone = %outstanding.origin.to_ascii_lower(), target = %target.address, transmission = outstanding.transmissions, %error, "Failed to send DNS NOTIFY");
                        }
                    }
                }
                for job_key in timed_out {
                    if let Some(expired) = active.remove(&job_key) {
                        onetdns_core::warn!(event = "authority.notify_timeout", zone = %expired.origin.to_ascii_lower(), serial = expired.serial, target = %targets[job_key.target].address, transmissions = expired.transmissions, "DNS NOTIFY expired without an ACK");
                    }
                }
                if let Some(socket) = &socket4 {
                    receive_notify_acks(socket, &mut active, &targets);
                }
                if let Some(socket) = &socket6 {
                    receive_notify_acks(socket, &mut active, &targets);
                }

                let wait = if active.is_empty() {
                    Duration::from_millis(100)
                } else {
                    let until_retry = active
                        .values()
                        .map(|job| job.next_send.saturating_duration_since(std::time::Instant::now()))
                        .min()
                        .unwrap_or(Duration::from_millis(10));
                    until_retry.min(Duration::from_millis(10))
                };
                let pending = queue.pending.lock_recover();
                if pending.is_empty() && !shutdown.load(Ordering::Relaxed) {
                    drop(match queue.wake.wait_timeout(pending, wait) {
                        Ok((pending, _)) => pending,
                        Err(error) => error.into_inner().0,
                    });
                }
            }
        })?;
    Ok((sender, thread))
}

/** @brief 알림 보내기를 시작한다. */
pub(crate) fn start_notify_dispatcher(
    configured: &[onetdns_config::NotifyTarget],
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(NotifySender, Option<std::thread::JoinHandle<()>>)> {
    let targets = notify_runtime_targets(configured, tsig_keys)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let (sender, thread) = spawn_notify_worker(targets, NotifyRetryPolicy::default(), shutdown)?;
    Ok((sender, Some(thread)))
}

/** @brief 설정에서 푼 알림 대상 목록. 대상마다 TSIG 키를 찾아 둔 상태다. */
pub(crate) struct NotifyTargets(Vec<NotifyRuntimeTarget>);

impl NotifyTargets {
    /**
     * @brief 설정에 적힌 대상과 그 TSIG 키를 푼다.
     * @return 대상의 TSIG 키가 설정에 없으면 실패. 그 대상만 빼고 교체하면 서명 없이 알리게 된다.
     */
    pub(crate) fn from_config(
        configured: &[onetdns_config::NotifyTarget],
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    ) -> Result<Self, String> {
        notify_runtime_targets(configured, tsig_keys).map(Self)
    }
}

/** @brief 설정에 적힌 알림 대상을 실행에 쓸 모양으로 푼다. */
fn notify_runtime_targets(
    configured: &[onetdns_config::NotifyTarget],
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
) -> Result<Vec<NotifyRuntimeTarget>, String> {
    configured
        .iter()
        .map(|target| {
            let tsig_key = match &target.tsig_key {
                Some(name) => Some(
                    tsig_for_secondary(tsig_keys, &Some(name.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "Could not find TSIG key '{}' for NOTIFY target '{}'",
                                target.address, name
                            )
                        })?,
                ),
                None => None,
            };
            Ok(NotifyRuntimeTarget {
                address: target.address,
                tsig_key,
            })
        })
        .collect()
}

#[cfg(test)]
/** @brief NOTIFY 전송, 응답 확인, 재전송. */
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use onetdns_core::MutexExt;

    use crate::unix_now;

    #[test]
    /** @brief 맞는 답이 올 때까지 다시 보내는지. */
    fn notify_dispatcher_retries_until_a_matching_ack_arrives() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        /*
         * 알림과 재전송을 기다리는 읽기 제한 시간이다. 재전송 간격보다 짧으면 재전송이
         * 오기 전에 읽기가 먼저 끝난다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let target = NotifyRuntimeTarget {
            address: receiver.local_addr().unwrap(),
            tsig_key: None,
        };
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, worker) = spawn_notify_worker(
            vec![target],
            NotifyRetryPolicy {
                initial: Duration::from_millis(300),
                retransmissions: 3,
            },
            shutdown.clone(),
        )
        .unwrap();
        let origin = onetdns_proto::Name::from_str("notify.test").unwrap();
        sender.enqueue(&origin, 7);

        let mut wire = [0u8; 2048];
        let (first_len, source) = receiver.recv_from(&mut wire).unwrap();
        let first = onetdns_proto::Message::parse(&wire[..first_len]).unwrap();
        assert_eq!(first.header.opcode, 4);
        assert!(!first.header.response);

        let mut wrong = onetdns_proto::Message::default();
        wrong.header.id = first.header.id.wrapping_add(1);
        wrong.header.response = true;
        wrong.header.opcode = 4;
        wrong.header.authoritative = true;
        wrong.questions = first.questions.clone();
        receiver
            .send_to(&wrong.try_encode().unwrap(), source)
            .unwrap();

        let (retry_len, retry_source) = receiver.recv_from(&mut wire).unwrap();
        let retry = onetdns_proto::Message::parse(&wire[..retry_len]).unwrap();
        assert_eq!(retry.header.id, first.header.id, "동일 transaction 재전송");
        let mut ack = onetdns_proto::Message::default();
        ack.header.id = retry.header.id;
        ack.header.response = true;
        ack.header.opcode = 4;
        ack.header.authoritative = true;
        ack.questions = retry.questions;
        receiver
            .send_to(&ack.try_encode().unwrap(), retry_source)
            .unwrap();

        /*
         * 재전송 간격은 두 배씩 늘어나므로 다음 재전송은 첫 재전송의 600밀리초 뒤다.
         * 침묵을 기다리는 구간은 그보다 길어야 재전송이 멈췄는지 실제로 확인할 수 있고,
         * 동시에 보내는 쪽이 ACK 를 처리할 시간도 그만큼 확보된다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_millis(900)))
            .unwrap();
        assert!(
            receiver.recv_from(&mut wire).is_err(),
            "일치하는 ACK 뒤에는 재전송을 중단해야 함"
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.wake();
        worker.join().unwrap();
    }

    #[test]
    /** @brief 키를 걸었으면 서명된 답만 답으로 세는지. */
    fn notify_dispatcher_requires_a_valid_tsig_ack_when_configured() {
        use onetdns_dnssec::tsig::{self, WireVerification};

        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        /*
         * 알림과 재전송을 기다리는 읽기 제한 시간이다. 재전송 간격보다 짧으면 재전송이
         * 오기 전에 읽기가 먼저 끝난다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let key = tsig::TsigKey::new(
            onetdns_proto::Name::from_str("notify-key.test").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, worker) = spawn_notify_worker(
            vec![NotifyRuntimeTarget {
                address: receiver.local_addr().unwrap(),
                tsig_key: Some(key.clone()),
            }],
            NotifyRetryPolicy {
                initial: Duration::from_millis(300),
                retransmissions: 2,
            },
            shutdown.clone(),
        )
        .unwrap();
        let origin = onetdns_proto::Name::from_str("signed-notify.test").unwrap();
        sender.enqueue(&origin, 9);

        let mut wire = [0u8; 2048];
        let (first_len, source) = receiver.recv_from(&mut wire).unwrap();
        let (stripped, verified) =
            match tsig::verify_wire_detailed(&wire[..first_len], &key, unix_now(), None).unwrap() {
                WireVerification::Valid { stripped, tsig } => (stripped, tsig),
                WireVerification::BadTime { .. } => panic!("fresh NOTIFY TSIG"),
            };
        let request = onetdns_proto::Message::parse(&stripped).unwrap();

        let mut unsigned_ack = onetdns_proto::Message::default();
        unsigned_ack.header.id = request.header.id;
        unsigned_ack.header.response = true;
        unsigned_ack.header.opcode = 4;
        unsigned_ack.header.authoritative = true;
        unsigned_ack.questions = request.questions.clone();
        receiver
            .send_to(&unsigned_ack.try_encode().unwrap(), source)
            .unwrap();

        let (retry_len, retry_source) = receiver.recv_from(&mut wire).unwrap();
        let retry_verified =
            match tsig::verify_wire_detailed(&wire[..retry_len], &key, unix_now(), None).unwrap() {
                WireVerification::Valid { tsig, .. } => tsig,
                WireVerification::BadTime { .. } => panic!("fresh retry TSIG"),
            };
        let mut signed_ack = unsigned_ack;
        tsig::sign_response_message(&mut signed_ack, &key, unix_now(), &retry_verified).unwrap();
        receiver
            .send_to(&signed_ack.try_encode().unwrap(), retry_source)
            .unwrap();

        /* 위 시험과 같은 이유로 다음 재전송 시점보다 길게 기다린다. */
        receiver
            .set_read_timeout(Some(Duration::from_millis(900)))
            .unwrap();
        assert!(receiver.recv_from(&mut wire).is_err());
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.wake();
        worker.join().unwrap();
        assert_eq!(verified.mac().len(), 32);
    }

    #[test]
    /** @brief 같은 영역과 대상의 알림이 하나로 합쳐지는지. */
    fn notify_pending_work_is_coalesced_per_zone_and_target() {
        let queue = Arc::new(NotifyQueue::default());
        let sender = NotifySender {
            queue: Some(queue.clone()),
            targets: Arc::new(onetdns_core::ArcSwap::new(Arc::new(vec![
                NotifyRuntimeTarget {
                    address: "127.0.0.1:5353".parse().unwrap(),
                    tsig_key: None,
                },
            ]))),
        };
        let origin = onetdns_proto::Name::from_str("coalesce.test").unwrap();
        for serial in 1..=10_000 {
            sender.enqueue(&origin, serial);
        }
        let pending = queue.pending.lock_recover();
        assert_eq!(
            pending.len(),
            1,
            "중복 변경 폭주가 큐 메모리를 늘리면 안 됨"
        );
        assert_eq!(pending.values().next().unwrap().serial, 10_000);
    }

    #[test]
    /** @brief IPv6 대상에 IPv6 소켓을 쓰는지. */
    fn notify_dispatcher_uses_an_ipv6_socket_for_ipv6_targets() {
        let Ok(receiver) = std::net::UdpSocket::bind("[::1]:0") else {
            return;
        };
        /*
         * 재전송 횟수를 0으로 두어 첫 알림을 놓치면 다시 오지 않는다. 느린 기계에서도
         * 받을 수 있도록 읽기 제한 시간을 넉넉히 둔다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, worker) = spawn_notify_worker(
            vec![NotifyRuntimeTarget {
                address: receiver.local_addr().unwrap(),
                tsig_key: None,
            }],
            NotifyRetryPolicy {
                initial: Duration::from_millis(100),
                retransmissions: 0,
            },
            shutdown.clone(),
        )
        .unwrap();
        sender.enqueue(&onetdns_proto::Name::from_str("notify-v6.test").unwrap(), 1);
        let mut wire = [0u8; 2048];
        let (length, _) = receiver.recv_from(&mut wire).unwrap();
        let request = onetdns_proto::Message::parse(&wire[..length]).unwrap();
        assert_eq!(request.questions[0].name.to_ascii_lower(), "notify-v6.test");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.wake();
        worker.join().unwrap();
    }
}
