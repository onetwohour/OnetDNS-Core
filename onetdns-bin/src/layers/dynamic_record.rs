//! Records that choose their answer by mode and health, and the executor for their health probes.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, RData, Record, RecordType};

use super::{answer_message, configured_name_key, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

#[derive(Clone, Copy, PartialEq, Eq)]
enum DynMode {
    Random,
    Weighted,
    RoundRobin,
    /// Answers only addresses known to be up.
    Failover,
}

struct DynRec {
    qtype: RecordType,
    mode: DynMode,
    values: Vec<(IpAddr, u32)>,
    ttl: u32,
    /// 0 disables probing.
    probe_port: u16,
    rr: std::sync::atomic::AtomicUsize,
    /// Last probe result and time, per address.
    health: Arc<Mutex<HashMap<IpAddr, (bool, Instant)>>>,
    /// Keeps one address from being probed twice at once.
    probing: Arc<Mutex<HashSet<IpAddr>>>,
}

impl DynRec {
    /// Failover probes on the bounded workers, so queries never wait for a probe; the answer uses
    /// what is known now. When no address is known to be up, the first one is answered: answering
    /// nothing would take the name down on a single failed probe.
    fn select(&self) -> Vec<IpAddr> {
        if self.values.is_empty() {
            return Vec::new();
        }
        match self.mode {
            DynMode::Random => {
                let i = rand_usize() % self.values.len();
                vec![self.values[i].0]
            }
            DynMode::Weighted => {
                let total: u64 = self.values.iter().map(|(_, w)| u64::from(*w)).sum();
                if total == 0 {
                    return vec![self.values[0].0];
                }
                let mut random = [0u8; 8];
                onetdns_core::fill_random(&mut random);
                let mut r = u64::from_le_bytes(random) % total;
                for (ip, w) in &self.values {
                    let weight = u64::from(*w);
                    if r < weight {
                        return vec![*ip];
                    }
                    r -= weight;
                }
                vec![self.values[0].0]
            }
            DynMode::RoundRobin => {
                let i =
                    self.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.values.len();
                vec![self.values[i].0]
            }
            DynMode::Failover => {
                let port = self.probe_port;
                if port == 0 {
                    return self.values.iter().map(|(ip, _)| *ip).collect();
                }
                let now = Instant::now();
                let mut known_up = Vec::new();
                let should_probe = {
                    let health = self.health.lock_recover();
                    let mut stale = Vec::new();
                    for (ip, _) in &self.values {
                        match health.get(ip) {
                            Some((up, checked)) => {
                                let age = now.saturating_duration_since(*checked);
                                if *up && age <= Duration::from_secs(10) {
                                    known_up.push(*ip);
                                }
                                if age > Duration::from_secs(5) {
                                    stale.push(*ip);
                                }
                            }
                            None => {
                                stale.push(*ip);
                            }
                        }
                    }
                    stale
                };
                let should_probe = {
                    let mut probing = self.probing.lock_recover();
                    should_probe
                        .into_iter()
                        .filter(|ip| probing.insert(*ip))
                        .collect::<Vec<_>>()
                };
                for ip in should_probe {
                    let health = self.health.clone();
                    let probing = self.probing.clone();
                    if !submit_health_probe(move || {
                        let up = tcp_reachable(ip, port);
                        let previous = health
                            .lock_recover()
                            .insert(ip, (up, Instant::now()))
                            .map(|state| state.0);
                        match (previous, up) {
                            (Some(false), true) => onetdns_core::info!(
                                event = "upstream.health_recovered",
                                address = %ip,
                                port,
                                "Upstream DNS server is answering again"
                            ),
                            (None | Some(true), false) => onetdns_core::warn!(
                                event = "upstream.health_failed",
                                address = %ip,
                                port,
                                "Upstream DNS server health check failed"
                            ),
                            _ => {}
                        }
                        probing.lock_recover().remove(&ip);
                    }) {
                        self.probing.lock_recover().remove(&ip);
                        onetdns_core::debug!(
                            event = "upstream.health_probe_queue_full",
                            address = %ip,
                            port,
                            "Upstream health check queue is full; skipping this check"
                        );
                    }
                }
                if known_up.is_empty() {
                    vec![self.values[0].0]
                } else {
                    known_up
                }
            }
        }
    }
}

fn rand_usize() -> usize {
    let mut b = [0u8; std::mem::size_of::<usize>()];
    onetdns_core::fill_random(&mut b);
    usize::from_le_bytes(b)
}

fn tcp_reachable(ip: IpAddr, port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::new(ip, port),
        Duration::from_millis(400),
    )
    .is_ok()
}

type HealthProbeJob = Box<dyn FnOnce() + Send + 'static>;

const HEALTH_PROBE_WORKERS: usize = 8;
/// Without a cap, backed-up probes would pile up without bound.
const HEALTH_PROBE_QUEUE: usize = 256;
static HEALTH_PROBE_EXECUTOR: OnceLock<mpsc::SyncSender<HealthProbeJob>> = OnceLock::new();
#[cfg(test)]
static HEALTH_PROBE_ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static HEALTH_PROBE_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
struct HealthProbeActivity;

#[cfg(test)]
impl HealthProbeActivity {
    fn enter() -> Self {
        use std::sync::atomic::Ordering;
        let active = HEALTH_PROBE_ACTIVE.fetch_add(1, Ordering::SeqCst) + 1;
        HEALTH_PROBE_PEAK.fetch_max(active, Ordering::SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for HealthProbeActivity {
    fn drop(&mut self) {
        HEALTH_PROBE_ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Started on first use.
fn health_probe_executor() -> &'static mpsc::SyncSender<HealthProbeJob> {
    HEALTH_PROBE_EXECUTOR.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<HealthProbeJob>(HEALTH_PROBE_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..HEALTH_PROBE_WORKERS {
            let rx = rx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("onetdns-health-probe-{index}"))
                .spawn(move || loop {
                    let job = rx.lock_recover().recv();
                    match job {
                        Ok(job) => {
                            #[cfg(test)]
                            let _activity = HealthProbeActivity::enter();
                            job();
                        }
                        Err(_) => break,
                    }
                })
            {
                onetdns_core::warn!(event = "upstream.health_worker_start_failed", %error, index, "Could not start the upstream health check thread; part of this feature is disabled");
                break;
            }
        }
        tx
    })
}

/// A full queue skips this probe.
fn submit_health_probe(job: impl FnOnce() + Send + 'static) -> bool {
    health_probe_executor().try_send(Box::new(job)).is_ok()
}

pub struct DynamicRecordLayer {
    inner: Arc<dyn Resolver>,
    records: HashMap<Vec<u8>, Vec<DynRec>>,
}

impl DynamicRecordLayer {
    pub fn new(
        inner: Arc<dyn Resolver>,
        cfg: &[onetdns_config::DynamicRecord],
    ) -> Result<Self, String> {
        let mut records: HashMap<Vec<u8>, Vec<DynRec>> = HashMap::new();
        for (index, r) in cfg.iter().enumerate() {
            let qtype = match r.qtype.as_str() {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                other => {
                    return Err(format!(
                        "dynamic_records[{index}].qtype has a value that is not allowed: '{other}'"
                    ));
                }
            };
            let mode = match r.mode.as_str() {
                "random" => DynMode::Random,
                "weighted" => DynMode::Weighted,
                "round_robin" => DynMode::RoundRobin,
                "failover" => DynMode::Failover,
                other => {
                    return Err(format!(
                        "dynamic_records[{index}].mode has a value that is not allowed: '{other}'"
                    ));
                }
            };
            let mut values = Vec::new();
            for (item, v) in r.values.iter().enumerate() {
                let (ip_s, weight) = match v.split_once('|') {
                    Some((a, w)) => (
                        a.trim(),
                        w.trim().parse::<u32>().map_err(|_| {
                            format!("dynamic_records[{index}].values[{item}] has an invalid weight")
                        })?,
                    ),
                    None => (v.trim(), 1),
                };
                let ip = ip_s.parse::<IpAddr>().map_err(|_| {
                    format!("dynamic_records[{index}].values[{item}] has an invalid IP address")
                })?;
                let family_ok = (qtype == RecordType::A && ip.is_ipv4())
                    || (qtype == RecordType::AAAA && ip.is_ipv6());
                if !family_ok {
                    return Err(format!(
                        "dynamic_records[{index}].values[{item}] has an IP address family that does not match qtype"
                    ));
                }
                values.push((ip, weight));
            }
            if values.is_empty() {
                return Err(format!(
                    "dynamic_records[{index}].values needs at least one IP address"
                ));
            }
            let name_key = configured_name_key(&r.name)
                .ok_or_else(|| format!("dynamic_records[{index}].name is not a valid DNS name"))?;
            let record = DynRec {
                qtype,
                mode,
                values,
                ttl: r.ttl,
                probe_port: r.probe_port,
                rr: std::sync::atomic::AtomicUsize::new(0),
                health: Arc::new(Mutex::new(HashMap::new())),
                probing: Arc::new(Mutex::new(HashSet::new())),
            };
            let records_for_name = records.entry(name_key).or_default();
            if records_for_name
                .iter_mut()
                .any(|existing| existing.qtype == qtype)
            {
                return Err(format!(
                    "dynamic_records[{index}] defines the same name and qtype twice"
                ));
            }
            records_for_name.push(record);
        }
        Ok(DynamicRecordLayer { inner, records })
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Resolver for DynamicRecordLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            let mut key = [0u8; 255];
            let rec = q
                .name
                .canonical_key_into(&mut key)
                .and_then(|key| self.records.get(key))
                .and_then(|records| records.iter().find(|record| record.qtype == q.qtype));
            if let Some(rec) = rec {
                let ips = rec.select();
                if !ips.is_empty() {
                    let answers: Vec<Record> = ips
                        .iter()
                        .map(|ip| {
                            let rd = match ip {
                                IpAddr::V4(a) => RData::A(*a),
                                IpAddr::V6(a) => RData::Aaaa(*a),
                            };
                            Record::new(q.name.clone(), rec.ttl, rd)
                        })
                        .collect();
                    return ResolveOutcome::Response(answer_message(
                        req.header.id,
                        q.name.clone(),
                        rec.qtype,
                        answers,
                    ));
                }

                if rec.mode == DynMode::Failover {
                    return ResolveOutcome::Response(answer_message(
                        req.header.id,
                        q.name.clone(),
                        rec.qtype,
                        vec![],
                    ));
                }
            }
        }
        self.inner.resolve_outcome(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use onetdns_proto::{Message, Name, RecordType};

    fn dynrec(mode: &str, values: &[&str]) -> onetdns_config::DynamicRecord {
        onetdns_config::DynamicRecord {
            name: "dyn.test".into(),
            qtype: "A".into(),
            mode: mode.into(),
            values: values.iter().map(|s| s.to_string()).collect(),
            ttl: 30,
            probe_port: 0,
        }
    }

    #[test]
    fn dynamic_random_picks_configured_value() {
        let mock = Mock::new(9, 0);
        let layer =
            DynamicRecordLayer::new(mock.clone(), &[dynrec("random", &["10.0.0.1", "10.0.0.2"])])
                .unwrap();
        let resp = layer.resolve(&query("dyn.test", RecordType::A)).unwrap();
        let ip = first_a(&resp);
        assert!(
            ip == Ipv4Addr::new(10, 0, 0, 1) || ip == Ipv4Addr::new(10, 0, 0, 2),
            "구성된 값 중 하나"
        );
        assert_eq!(
            mock.calls.load(Ordering::SeqCst),
            0,
            "동적 레코드가 가로채 inner 미호출"
        );
    }

    #[test]
    fn dynamic_weighted_respects_weight_zero() {
        let mock = Mock::new(9, 0);

        let layer =
            DynamicRecordLayer::new(mock, &[dynrec("weighted", &["10.0.0.1|0", "10.0.0.2|10"])])
                .unwrap();
        for _ in 0..20 {
            let resp = layer.resolve(&query("dyn.test", RecordType::A)).unwrap();
            assert_eq!(first_a(&resp), Ipv4Addr::new(10, 0, 0, 2));
        }
    }

    #[test]
    fn dynamic_round_robin_rotates() {
        let mock = Mock::new(9, 0);
        let layer =
            DynamicRecordLayer::new(mock, &[dynrec("round_robin", &["10.0.0.1", "10.0.0.2"])])
                .unwrap();
        let a = first_a(&layer.resolve(&query("dyn.test", RecordType::A)).unwrap());
        let b = first_a(&layer.resolve(&query("dyn.test", RecordType::A)).unwrap());
        let c = first_a(&layer.resolve(&query("dyn.test", RecordType::A)).unwrap());
        assert_ne!(a, b, "연속 호출은 회전");
        assert_eq!(a, c, "2개 값 → 한 바퀴 후 복귀");
    }

    #[test]
    /// Otherwise probe threads would grow without bound.
    fn dynamic_failover_health_checks_use_bounded_executor() {
        let values = (1..=64)
            .map(|last| format!("192.0.2.{last}"))
            .collect::<Vec<_>>();
        let record = onetdns_config::DynamicRecord {
            name: "dyn.test".into(),
            qtype: "A".into(),
            mode: "failover".into(),
            values,
            ttl: 30,
            probe_port: 9,
        };
        let layer = DynamicRecordLayer::new(Mock::new(9, 0), &[record]).unwrap();
        let started = Instant::now();
        let response = layer.resolve(&query("dyn.test", RecordType::A)).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(first_a(&response), Ipv4Addr::new(192, 0, 2, 1));

        std::thread::sleep(Duration::from_millis(20));
        let peak = HEALTH_PROBE_PEAK.load(std::sync::atomic::Ordering::SeqCst);
        assert!(peak > 0 && peak <= HEALTH_PROBE_WORKERS, "peak={peak}");
    }

    #[test]
    fn dynamic_passthrough_for_other_names() {
        let mock = Mock::new(7, 0);
        let layer =
            DynamicRecordLayer::new(mock.clone(), &[dynrec("random", &["10.0.0.1"])]).unwrap();
        let resp = layer.resolve(&query("other.test", RecordType::A)).unwrap();
        assert_eq!(first_a(&resp), Ipv4Addr::new(7, 7, 7, 7), "inner로 통과");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /// Otherwise different names could share a key and get the same answer.
    fn dynamic_record_key_preserves_raw_name_octets() {
        let mock = Mock::new(7, 0);
        let mut record = dynrec("random", &["10.0.0.1"]);
        record.name = "�".into();
        let layer = DynamicRecordLayer::new(mock.clone(), &[record]).unwrap();

        let configured = Message::query(1, Name::from_str("�").unwrap(), RecordType::A);
        assert_eq!(
            first_a(&layer.resolve(&configured).unwrap()),
            Ipv4Addr::new(10, 0, 0, 1)
        );

        let raw = Message::query(
            2,
            Name::from_labels(vec![vec![0xff]]).unwrap(),
            RecordType::A,
        );
        assert_eq!(
            first_a(&layer.resolve(&raw).unwrap()),
            Ipv4Addr::new(7, 7, 7, 7),
            "invalid UTF-8 wire label must not collide with configured U+FFFD"
        );
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /// Ignored, the operator would believe it applies.
    fn invalid_dynamic_record_cannot_disappear_silently() {
        let mut record = dynrec("random", &["10.0.0.1"]);
        record.name = "bad..name".to_string();
        assert!(DynamicRecordLayer::new(Mock::new(7, 0), &[record]).is_err());
    }
}
