/*!
 * @brief 상태를 확인해 값을 고르는 동적 레코드 계층과 그 상태 확인 실행기.
 */

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, RData, Record, RecordType};

use super::{answer_message, configured_name_key, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

#[derive(Clone, Copy, PartialEq, Eq)]
/** @brief 여러 주소 중 무엇을 답할지 고르는 방식. */
enum DynMode {
    /** @brief 무작위로 하나 고른다. */
    Random,
    /** @brief 몫에 비례해 고른다. */
    Weighted,
    /** @brief 돌아가며 고른다. */
    RoundRobin,
    /** @brief 살아 있는 것만 답한다. */
    Failover,
}

/** @brief 상태를 보고 답을 고르는 기록 하나. */
struct DynRec {
    /** @brief 이 기록의 종류. */
    qtype: RecordType,
    /** @brief 고르는 방식. */
    mode: DynMode,
    /** @brief 후보 주소와 그 몫. */
    values: Vec<(IpAddr, u32)>,
    /** @brief 답에 담을 수명. */
    ttl: u32,
    /** @brief 살아 있는지 확인할 포트. 0이면 확인하지 않는다. */
    probe_port: u16,
    /** @brief 돌아가며 고를 때의 지금 위치. */
    rr: std::sync::atomic::AtomicUsize,
    /** @brief 주소별로 마지막에 확인한 결과와 시각. */
    health: Arc<Mutex<HashMap<IpAddr, (bool, Instant)>>>,
    /** @brief 지금 확인 중인 주소들. 같은 주소를 겹쳐 확인하지 않으려는 것이다. */
    probing: Arc<Mutex<HashSet<IpAddr>>>,
}

impl DynRec {
    /**
     * @brief 이번에 답할 주소를 고른다.
     * @details 살아 있는 것만 답하려면 확인해야 한다. 확인은 질의 처리를 붙잡지 않도록
     *          제한된 워커에게 맡기고, 지금 아는 상태로 답한다.
     * @warning 아는 것이 하나도 없으면 첫 주소를 답한다. 아무것도 답하지 않으면 확인이
     *          한 번 실패한 것만으로 그 이름이 전부 죽는다.
     */
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
                                "업스트림 DNS 서버가 다시 응답합니다"
                            ),
                            (None | Some(true), false) => onetdns_core::warn!(
                                event = "upstream.health_failed",
                                address = %ip,
                                port,
                                "업스트림 DNS 서버의 연결 확인에 실패했습니다"
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
                            "업스트림 DNS 서버 상태 확인 대기열이 가득 차 이번 확인을 건너뜁니다"
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

/** @brief 무작위 수 하나. */
fn rand_usize() -> usize {
    let mut b = [0u8; std::mem::size_of::<usize>()];
    onetdns_core::fill_random(&mut b);
    usize::from_le_bytes(b)
}

/** @brief 이 주소의 이 포트에 닿는지. */
fn tcp_reachable(ip: IpAddr, port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::new(ip, port),
        Duration::from_millis(400),
    )
    .is_ok()
}

/** @brief 상태 확인 일 하나. */
type HealthProbeJob = Box<dyn FnOnce() + Send + 'static>;

/** @brief 상태 확인 워커 수. */
const HEALTH_PROBE_WORKERS: usize = 8;
/** @brief 상태 확인 대기열 크기. 상한이 없으면 확인이 밀릴 때 스레드가 끝없이 늘어난다. */
const HEALTH_PROBE_QUEUE: usize = 256;
/** @brief 상태 확인 워커 풀. */
static HEALTH_PROBE_EXECUTOR: OnceLock<mpsc::SyncSender<HealthProbeJob>> = OnceLock::new();
#[cfg(test)]
/** @brief 지금 실행 중인 확인 수. 테스트용. */
static HEALTH_PROBE_ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
/** @brief 동시에 돈 확인의 최대치. 테스트용. */
static HEALTH_PROBE_PEAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
/** @brief 동시 확인 수를 세는 것. 테스트용. */
struct HealthProbeActivity;

#[cfg(test)]
impl HealthProbeActivity {
    /** @brief 확인 하나를 세기 시작한다. */
    fn enter() -> Self {
        use std::sync::atomic::Ordering;
        let active = HEALTH_PROBE_ACTIVE.fetch_add(1, Ordering::SeqCst) + 1;
        HEALTH_PROBE_PEAK.fetch_max(active, Ordering::SeqCst);
        Self
    }
}

#[cfg(test)]
impl Drop for HealthProbeActivity {
    /** @brief 확인 하나를 뺀다. */
    fn drop(&mut self) {
        HEALTH_PROBE_ACTIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/** @brief 상태 확인 워커 풀. 처음 쓸 때 시작한다. */
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
                onetdns_core::warn!(event = "upstream.health_worker_start_failed", %error, index, "업스트림 DNS 서버 상태 확인 스레드를 시작하지 못해 해당 기능을 일부 비활성화합니다");
                break;
            }
        }
        tx
    })
}

/** @brief 확인을 맡긴다. 대기열이 꽉 차면 이번 확인을 건너뛴다. */
fn submit_health_probe(job: impl FnOnce() + Send + 'static) -> bool {
    health_probe_executor().try_send(Box::new(job)).is_ok()
}

/** @brief 상태를 보고 답을 고르는 기록들을 답하는 계층. */
pub struct DynamicRecordLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 이름별로 걸린 기록들. */
    records: HashMap<Vec<u8>, Vec<DynRec>>,
}

impl DynamicRecordLayer {
    /** @brief 설정한 기록들로 만든다. */
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
                        "dynamic_records[{index}].qtype에 허용되지 않은 값이 있습니다: '{other}'"
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
                        "dynamic_records[{index}].mode에 허용되지 않은 값이 있습니다: '{other}'"
                    ));
                }
            };
            let mut values = Vec::new();
            for (item, v) in r.values.iter().enumerate() {
                let (ip_s, weight) = match v.split_once('|') {
                    Some((a, w)) => (
                        a.trim(),
                        w.trim().parse::<u32>().map_err(|_| {
                            format!(
                                "dynamic_records[{index}].values[{item}]의 weight가 올바르지 않습니다"
                            )
                        })?,
                    ),
                    None => (v.trim(), 1),
                };
                let ip = ip_s.parse::<IpAddr>().map_err(|_| {
                    format!("dynamic_records[{index}].values[{item}]의 IP 주소가 올바르지 않습니다")
                })?;
                let family_ok = (qtype == RecordType::A && ip.is_ipv4())
                    || (qtype == RecordType::AAAA && ip.is_ipv6());
                if !family_ok {
                    return Err(format!(
                        "dynamic_records[{index}].values[{item}]의 IP 주소 계열이 qtype과 다릅니다"
                    ));
                }
                values.push((ip, weight));
            }
            if values.is_empty() {
                return Err(format!(
                    "dynamic_records[{index}].values에 한 개 이상의 IP 주소가 필요합니다"
                ));
            }
            let name_key = configured_name_key(&r.name).ok_or_else(|| {
                format!("dynamic_records[{index}].name의 DNS 이름이 올바르지 않습니다")
            })?;
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
                    "dynamic_records[{index}]가 같은 name과 qtype을 중복 정의합니다"
                ));
            }
            records_for_name.push(record);
        }
        Ok(DynamicRecordLayer { inner, records })
    }

    /** @brief 답할 기록이 하나도 없는지. */
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Resolver for DynamicRecordLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 설정한 이름이면 골라 답하고, 아니면 안으로 넘긴다. */
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
/** @brief 동적 레코드의 선택 방식과 상태 확인 실행기의 한도. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use onetdns_proto::{Message, Name, RecordType};

    /** @brief 테스트용 동적 기록 설정. */
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
    /** @brief 무작위 방식이 설정한 값 중에서만 고르는지. */
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
    /** @brief 몫이 0인 값을 고르지 않는지. */
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
    /** @brief 돌아가며 고르는지. */
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
    /** @brief 상태 확인이 제한된 워커 안에서만 도는지. 안 그러면 스레드가 끝없이 는다. */
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
    /** @brief 설정하지 않은 이름은 그냥 지나가는지. */
    fn dynamic_passthrough_for_other_names() {
        let mock = Mock::new(7, 0);
        let layer =
            DynamicRecordLayer::new(mock.clone(), &[dynrec("random", &["10.0.0.1"])]).unwrap();
        let resp = layer.resolve(&query("other.test", RecordType::A)).unwrap();
        assert_eq!(first_a(&resp), Ipv4Addr::new(7, 7, 7, 7), "inner로 통과");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 이름의 원래 바이트가 키에서 바뀌지 않는지. 바뀌면 다른 이름이 같은 답을 받는다. */
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
    /** @brief 잘못된 설정이 조용히 무시되지 않는지. 무시되면 운영자는 걸린 줄 안다. */
    fn invalid_dynamic_record_cannot_disappear_silently() {
        let mut record = dynrec("random", &["10.0.0.1"]);
        record.name = "bad..name".to_string();
        assert!(DynamicRecordLayer::new(Mock::new(7, 0), &[record]).is_err());
    }
}
