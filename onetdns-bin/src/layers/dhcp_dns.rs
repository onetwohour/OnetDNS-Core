/*!
 * @brief DHCP 임대 풀에서 정방향과 역방향 이름을 답하는 계층.
 */

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use onetdns_core::MutexExt;
use onetdns_proto::{Message, Name, RData, Record, RecordType};

use super::{answer_message, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

/** @brief 이 서버가 나눠 준 주소를 이름으로도 답하는 계층. */
pub struct DhcpDnsLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 임대 기록. */
    pool: Arc<Mutex<crate::dhcp::LeasePool>>,
    /** @brief 임대에 붙일 도메인 접미사. 없으면 이름으로 답하지 않는다. */
    domain: Option<Name>,
    /** @brief 답에 담을 수명 상한. */
    local_ttl: Arc<std::sync::atomic::AtomicU32>,
}

impl DhcpDnsLayer {
    /** @brief 임대 기록을 잡은 계층을 만든다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        pool: Arc<Mutex<crate::dhcp::LeasePool>>,
        domain: &str,
        local_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        DhcpDnsLayer {
            inner,
            pool,
            domain: Name::from_str(domain.trim().trim_end_matches('.'))
                .ok()
                .filter(|name| !name.is_root()),
            local_ttl,
        }
    }

    /** @brief 이 임대가 끝날 때까지 남은 수명. 임대보다 길게 답하면 안 된다. */
    fn lease_ttl(&self, expiry_unix: u64) -> Option<u32> {
        let remaining = expiry_unix
            .saturating_sub(crate::unix_now())
            .min(u64::from(u32::MAX)) as u32;
        (remaining > 0).then(|| {
            self.local_ttl
                .load(std::sync::atomic::Ordering::Acquire)
                .min(remaining)
        })
    }

    /** @brief 이 이름에 임대된 주소. */
    fn forward_lookup(&self, name: &Name) -> Option<(Ipv4Addr, u32)> {
        let domain = self.domain.as_ref()?;
        if name.num_labels() != domain.num_labels() + 1 || !name.ends_with_ignore_case(domain) {
            return None;
        }
        let host = name.labels().first()?;
        let pool = self.pool.lock_recover();
        pool.snapshot().into_iter().find_map(|l| {
            l.hostname
                .as_deref()
                .filter(|h| h.as_bytes().eq_ignore_ascii_case(host))
                .and_then(|_| self.lease_ttl(l.expiry_unix).map(|ttl| (l.ip, ttl)))
        })
    }

    /** @brief 이 주소를 잡은 클라이언트의 이름. */
    fn reverse_lookup(&self, name: &Name) -> Option<(Name, u32)> {
        let domain = self.domain.as_ref()?;
        let ip = ptr_to_ipv4(name)?;
        let pool = self.pool.lock_recover();
        let lease = pool
            .snapshot()
            .into_iter()
            .find(|l| l.ip == ip)
            .filter(|lease| lease.hostname.is_some())?;
        let ttl = self.lease_ttl(lease.expiry_unix)?;
        let mut labels = Vec::with_capacity(domain.labels().len() + 1);
        labels.push(lease.hostname?.into_bytes());
        labels.extend(domain.labels().map(<[u8]>::to_vec));
        Some((Name::from_labels(labels).ok()?, ttl))
    }
}

/** @brief 거꾸로 적힌 이름에서 주소를 읽는다. */
fn ptr_to_ipv4(name: &Name) -> Option<Ipv4Addr> {
    let mut labels = name.labels();
    if labels.len() != 6 {
        return None;
    }
    let labels = [
        labels.next()?,
        labels.next()?,
        labels.next()?,
        labels.next()?,
        labels.next()?,
        labels.next()?,
    ];
    let lab = |i: usize| std::str::from_utf8(labels[i]).ok();
    if !lab(4)?.eq_ignore_ascii_case("in-addr") || !lab(5)?.eq_ignore_ascii_case("arpa") {
        return None;
    }
    let oct = |i: usize| -> Option<u8> { lab(i)?.parse().ok() };
    Some(Ipv4Addr::new(oct(3)?, oct(2)?, oct(1)?, oct(0)?))
}

impl Resolver for DhcpDnsLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 임대 기록에 있으면 답하고, 아니면 안으로 넘긴다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            match q.qtype {
                RecordType::A => {
                    if let Some((ip, ttl)) = self.forward_lookup(&q.name) {
                        return ResolveOutcome::Response(answer_message(
                            req.header.id,
                            q.name.clone(),
                            q.qtype,
                            vec![Record::new(q.name.clone(), ttl, RData::A(ip))],
                        ));
                    }
                }
                RecordType::AAAA if self.forward_lookup(&q.name).is_some() => {
                    return ResolveOutcome::Response(answer_message(
                        req.header.id,
                        q.name.clone(),
                        q.qtype,
                        vec![],
                    ));
                }
                RecordType::PTR => {
                    if let Some((target, ttl)) = self.reverse_lookup(&q.name) {
                        return ResolveOutcome::Response(answer_message(
                            req.header.id,
                            q.name.clone(),
                            q.qtype,
                            vec![Record::new(q.name.clone(), ttl, RData::Ptr(target))],
                        ));
                    }
                }
                _ => {}
            }
        }
        self.inner.resolve_outcome(req)
    }
}

#[cfg(test)]
/** @brief 임대 이름의 정방향, 역방향 응답과 위임. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use onetdns_proto::{Message, Name, RData, RecordType};

    use crate::native::Resolver;

    #[test]
    /** @brief 임대 기록으로 이름과 주소를 서로 답하고, 없으면 넘기는지. */
    fn dhcp_dns_forward_reverse_and_delegate() {
        use crate::dhcp::{ClientIdentity, DhcpConfig, LeasePool};
        let dc = DhcpConfig {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
            lease_secs: 3600,
            tftp_server: None,
            boot_file: None,
            domain_name: None,
            lease_file: None,
            static_file: None,
        };
        let mut pool = LeasePool::new(&dc);
        let first_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        pool.commit(
            &ClientIdentity::Hardware(first_mac),
            first_mac,
            u32::from(Ipv4Addr::new(192, 168, 1, 123)),
            Some("myhost".to_string()),
        );
        let second_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xfe];
        pool.commit(
            &ClientIdentity::Hardware(second_mac),
            second_mac,
            u32::from(Ipv4Addr::new(192, 168, 1, 124)),
            Some("�".to_string()),
        );
        let pool = Arc::new(Mutex::new(pool));
        let inner = Mock::new(9, 0);
        let local_ttl = Arc::new(AtomicU32::new(17));
        let layer = DhcpDnsLayer::new(
            inner.clone() as Arc<dyn Resolver>,
            pool,
            "lan",
            local_ttl.clone(),
        );

        let r = layer.resolve(&query("MyHost.LAN", RecordType::A)).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].ttl, 17);
        match &r.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 123)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }

        let raw_name = Name::from_labels(vec![vec![0xff], b"lan".to_vec()]).unwrap();
        let raw_query = Message::query(2, raw_name, RecordType::A);
        let raw_response = layer.resolve(&raw_query).unwrap();
        assert_eq!(first_a(&raw_response), Ipv4Addr::new(9, 9, 9, 9));

        let before = inner.calls.load(Ordering::SeqCst);
        let r = layer
            .resolve(&query("myhost.lan", RecordType::AAAA))
            .unwrap();
        assert!(r.answers.is_empty());
        assert_eq!(inner.calls.load(Ordering::SeqCst), before, "AAAA 미위임");

        let r = layer
            .resolve(&query("123.1.168.192.in-addr.arpa", RecordType::PTR))
            .unwrap();
        assert_eq!(r.answers.len(), 1);
        match &r.answers[0].rdata {
            RData::Ptr(n) => assert_eq!(n.to_ascii_lower().trim_end_matches('.'), "myhost.lan"),
            other => panic!("PTR 기대, got {other:?}"),
        }
        assert_eq!(r.answers[0].ttl, 17);
        local_ttl.store(23, Ordering::Release);
        assert_eq!(
            layer
                .resolve(&query("myhost.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            23,
            "DHCP DNS도 로컬 TTL 핫 변경을 공유"
        );
        local_ttl.store(u32::MAX, Ordering::Release);
        let lease_bounded = layer
            .resolve(&query("myhost.lan", RecordType::A))
            .unwrap()
            .answers[0]
            .ttl;
        assert!(
            (1..=3_600).contains(&lease_bounded),
            "DNS TTL이 남은 DHCP 임대를 넘으면 안 됨: {lease_bounded}"
        );
        local_ttl.store(0, Ordering::Release);
        assert_eq!(
            layer
                .resolve(&query("myhost.lan", RecordType::A))
                .unwrap()
                .answers[0]
                .ttl,
            0,
            "명시한 TTL 0은 현재 응답 전용으로 보존"
        );

        let before = inner.calls.load(Ordering::SeqCst);
        let _ = layer.resolve(&query("other.lan", RecordType::A));
        let _ = layer.resolve(&query("example.com", RecordType::A));
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            before + 2,
            "미지 이름은 위임"
        );
    }
}
