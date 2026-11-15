//! Sends NOTIFY to secondaries when a zone changes, and resends until answered.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_core::MutexExt;

use crate::{tsig_for_secondary, unix_now};

#[derive(Clone)]
struct NotifyRuntimeTarget {
    address: std::net::SocketAddr,
    tsig_key: Option<onetdns_dnssec::tsig::TsigKey>,
}

#[derive(Clone, Copy)]
struct NotifyRetryPolicy {
    initial: Duration,
    retransmissions: u8,
}

impl Default for NotifyRetryPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            retransmissions: 5,
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct NotifyJobKey {
    origin: Vec<u8>,
    target: usize,
}

struct NotifyJob {
    origin: onetdns_proto::Name,
    serial: u32,
}

#[derive(Default)]
struct NotifyQueue {
    pending: Mutex<std::collections::HashMap<NotifyJobKey, NotifyJob>>,
    wake: std::sync::Condvar,
}

#[derive(Clone)]
pub(crate) struct NotifySender {
    /// None disables notifications.
    queue: Option<Arc<NotifyQueue>>,
    /// Swapped on config change.
    targets: Arc<onetdns_core::ArcSwap<Vec<NotifyRuntimeTarget>>>,
}

impl NotifySender {
    #[cfg(test)]
    /// Sends nothing; for tests.
    pub(crate) fn disabled() -> Self {
        Self {
            queue: None,
            targets: Arc::new(onetdns_core::ArcSwap::new(Arc::new(Vec::new()))),
        }
    }

    pub(crate) fn replace_targets(&self, targets: NotifyTargets) {
        self.targets.store(Arc::new(targets.0));
    }

    /// Notifications for one zone and target are merged.
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

    /// With the zone's current serial.
    pub(crate) fn enqueue_zone(&self, zone: &onetdns_authority::Zone) {
        self.enqueue(zone.origin(), zone.soa().serial);
    }

    #[cfg(test)]
    fn wake(&self) {
        if let Some(queue) = &self.queue {
            queue.wake.notify_one();
        }
    }
}

struct OutstandingNotify {
    origin: onetdns_proto::Name,
    serial: u32,
    id: u16,
    /// Resent as is.
    wire: Vec<u8>,
    /// The request's TSIG MAC, for checking the ack.
    request_mac: Option<Vec<u8>>,
    transmissions: u8,
    next_send: std::time::Instant,
}

/// Changes in quick succession go out as one notification.
const NOTIFY_COALESCE_DELAY: Duration = Duration::from_millis(20);

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

/// Unchecked, any packet would count as an ack and stop the resends.
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

/// Doubles with each transmission.
fn retry_delay(policy: NotifyRetryPolicy, transmissions: u8) -> Duration {
    let shift = u32::from(transmissions.saturating_sub(1).min(20));
    policy
        .initial
        .checked_mul(1u32 << shift)
        .unwrap_or(Duration::MAX)
}

/// Collects acks that already arrived before choosing what to resend, so a worker that wakes late,
/// past a resend time, does not resend a notification already answered. `sockets` holds the IPv4
/// and IPv6 sockets; None for a family that could not be opened.
fn notify_round(
    active: &mut std::collections::HashMap<NotifyJobKey, OutstandingNotify>,
    pending: std::collections::HashMap<NotifyJobKey, NotifyJob>,
    targets: &[NotifyRuntimeTarget],
    sockets: [Option<&std::net::UdpSocket>; 2],
    policy: NotifyRetryPolicy,
) {
    for socket in sockets.into_iter().flatten() {
        receive_notify_acks(socket, active, targets);
    }
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
        match outstanding_notify(job.origin, job.serial, target, NOTIFY_COALESCE_DELAY) {
            Ok(outstanding) => {
                active.insert(job_key, outstanding);
            }
            Err(error) => {
                onetdns_core::error!(event = "authority.notify_encode_failed", serial = job.serial, %error, "Could not encode DNS NOTIFY")
            }
        }
    }

    let now = std::time::Instant::now();
    let mut timed_out = Vec::new();
    for (job_key, outstanding) in active.iter_mut() {
        if now < outstanding.next_send {
            continue;
        }
        if outstanding.transmissions > policy.retransmissions {
            timed_out.push(job_key.clone());
            continue;
        }
        let target = &targets[job_key.target];
        let socket = if target.address.is_ipv4() {
            sockets[0]
        } else {
            sockets[1]
        };
        let Some(socket) = socket else {
            timed_out.push(job_key.clone());
            continue;
        };
        match socket.send_to(&outstanding.wire, target.address) {
            Ok(length) if length == outstanding.wire.len() => {
                outstanding.transmissions += 1;
                outstanding.next_send = now + retry_delay(policy, outstanding.transmissions);
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
                outstanding.next_send = now + retry_delay(policy, outstanding.transmissions);
                onetdns_core::warn!(event = "authority.notify_send_failed", zone = %outstanding.origin.to_ascii_lower(), target = %target.address, transmission = outstanding.transmissions, %error, "Failed to send DNS NOTIFY");
            }
        }
    }
    for job_key in timed_out {
        if let Some(expired) = active.remove(&job_key) {
            onetdns_core::warn!(event = "authority.notify_timeout", zone = %expired.origin.to_ascii_lower(), serial = expired.serial, target = %targets[job_key.target].address, transmissions = expired.transmissions, "DNS NOTIFY expired without an ACK");
        }
    }
}

fn spawn_notify_worker(
    targets: Vec<NotifyRuntimeTarget>,
    policy: NotifyRetryPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(NotifySender, std::thread::JoinHandle<()>)> {
    // Both families are opened: the targets can be swapped, so a family missing from the current
    // list can arrive later. One socket talks to several targets, so it is opened with
    // onetdns_core::udp::bind, which keeps an ICMP error from one closed target from blocking the
    // others' answers.
    let socket4 = {
        let socket = onetdns_core::udp::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_nonblocking(true)?;
        Some(socket)
    };
    let socket6 = match onetdns_core::udp::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)) {
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
            let mut active = std::collections::HashMap::<NotifyJobKey, OutstandingNotify>::new();
            while !shutdown.load(Ordering::Relaxed) {
                // One list for the whole round; a swap midway would misalign the indexes.
                let targets = targets.load();
                let pending = std::mem::take(&mut *queue.pending.lock_recover());
                notify_round(
                    &mut active,
                    pending,
                    &targets,
                    [socket4.as_ref(), socket6.as_ref()],
                    policy,
                );

                let wait = if active.is_empty() {
                    Duration::from_millis(100)
                } else {
                    let until_retry = active
                        .values()
                        .map(|job| {
                            job.next_send
                                .saturating_duration_since(std::time::Instant::now())
                        })
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

/// Targets from the config, with each TSIG key already resolved.
pub(crate) struct NotifyTargets(Vec<NotifyRuntimeTarget>);

impl NotifyTargets {
    /// Fails when a target's TSIG key is not in the config; going ahead without it would send that
    /// target unsigned notifications.
    pub(crate) fn from_config(
        configured: &[onetdns_config::NotifyTarget],
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    ) -> Result<Self, String> {
        notify_runtime_targets(configured, tsig_keys).map(Self)
    }
}

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
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use onetdns_core::MutexExt;

    use crate::unix_now;

    #[test]
    fn notify_dispatcher_retries_until_a_matching_ack_arrives() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // Read timeout for the notification and its resends; shorter than the resend interval, the
        // read would end before a resend arrives.
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

        // The interval doubles, so the next resend comes 600 ms after the first. The silence window
        // must be longer to show the resends really stopped, which also gives the sender that much
        // time to handle the ACK.
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
    fn notify_dispatcher_requires_a_valid_tsig_ack_when_configured() {
        use onetdns_dnssec::tsig::{self, WireVerification};

        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // Read timeout for the notification and its resends; shorter than the resend interval, the
        // read would end before a resend arrives.
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

        // Longer than the next resend, as in the test above.
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
    /// A worker that wakes late sees the resend time and the ack in the same round; choosing
    /// resends before collecting acks would send the same notification to a target that already
    /// answered.
    fn notify_round_collects_arrived_acks_before_retransmitting() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = onetdns_core::udp::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        let targets = vec![NotifyRuntimeTarget {
            address: receiver.local_addr().unwrap(),
            tsig_key: None,
        }];
        let origin = onetdns_proto::Name::from_str("late-ack.test").unwrap();
        let mut outstanding =
            outstanding_notify(origin.clone(), 3, &targets[0], Duration::ZERO).unwrap();
        outstanding.transmissions = 1;

        let mut ack = onetdns_proto::Message::parse(&outstanding.wire).unwrap();
        ack.header.response = true;
        receiver
            .send_to(&ack.try_encode().unwrap(), socket.local_addr().unwrap())
            .unwrap();
        let mut wire = [0u8; 2048];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while socket.peek_from(&mut wire).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "답이 알림 소켓에 닿지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let key = NotifyJobKey {
            origin: origin.canonical_key(),
            target: 0,
        };
        let mut active = std::collections::HashMap::from([(key, outstanding)]);
        notify_round(
            &mut active,
            std::collections::HashMap::new(),
            &targets,
            [Some(&socket), None],
            NotifyRetryPolicy::default(),
        );
        assert!(active.is_empty(), "도착한 답을 거두지 않았습니다");
        receiver
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        assert!(
            receiver.recv_from(&mut wire).is_err(),
            "답을 받은 알림을 다시 보냈습니다"
        );
    }

    #[test]
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
    fn notify_dispatcher_uses_an_ipv6_socket_for_ipv6_targets() {
        let Ok(receiver) = std::net::UdpSocket::bind("[::1]:0") else {
            return;
        };
        // With zero retransmissions, a missed first notification never comes again, so the timeout
        // is generous for slow machines.
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
