//! Keeps domain_needed, bogus_priv, and empty_zones names from reaching upstreams.

use std::sync::Arc;

use onetdns_proto::{Message, Name, RecordType};

use super::outcome_to_option;
use crate::native::{ResolveOutcome, Resolver};

pub const LOCAL_ONLY_DOMAIN_NEEDED: u8 = 1;
pub const LOCAL_ONLY_BOGUS_PRIV: u8 = 2;
pub const LOCAL_ONLY_EMPTY_ZONES: u8 = 4;

/// The enabled categories. They change on reload, so layers read them here instead of copying; bits
/// let one load read all three.
pub struct LocalOnlyNames {
    bits: std::sync::atomic::AtomicU8,
}

impl LocalOnlyNames {
    pub fn new(domain_needed: bool, bogus_priv: bool, empty_zones: bool) -> Self {
        let value = Self {
            bits: std::sync::atomic::AtomicU8::new(0),
        };
        value.set(domain_needed, bogus_priv, empty_zones);
        value
    }

    pub fn set(&self, domain_needed: bool, bogus_priv: bool, empty_zones: bool) {
        let mut bits = 0u8;
        if domain_needed {
            bits |= LOCAL_ONLY_DOMAIN_NEEDED;
        }
        if bogus_priv {
            bits |= LOCAL_ONLY_BOGUS_PRIV;
        }
        if empty_zones {
            bits |= LOCAL_ONLY_EMPTY_ZONES;
        }
        self.bits.store(bits, std::sync::atomic::Ordering::Relaxed);
    }

    fn bits(&self) -> u8 {
        self.bits.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Answers NXDOMAIN for these names right before the upstream query. It sits inside local zones,
/// DHCP leases, stub delegations, and local addresses so they answer first; placed outside them, it
/// would hide a configured home.arpa or private reverse zone behind NXDOMAIN.
pub struct LocalOnlyLayer {
    inner: Arc<dyn Resolver>,
    names: Arc<LocalOnlyNames>,
    block_ttl: Arc<std::sync::atomic::AtomicU32>,
}

impl LocalOnlyLayer {
    pub fn new(
        inner: Arc<dyn Resolver>,
        names: Arc<LocalOnlyNames>,
        block_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        LocalOnlyLayer {
            inner,
            names,
            block_ttl,
        }
    }

    fn blocked(&self, name: &Name, qtype: RecordType) -> bool {
        let bits = self.names.bits();
        if bits == 0 {
            return false;
        }
        (bits & LOCAL_ONLY_DOMAIN_NEEDED != 0 && crate::native::is_single_label(name))
            || (bits & LOCAL_ONLY_BOGUS_PRIV != 0
                && qtype == RecordType::PTR
                && crate::native::is_private_reverse(name))
            || (bits & LOCAL_ONLY_EMPTY_ZONES != 0 && crate::native::is_empty_zone(name))
    }
}

impl Resolver for LocalOnlyLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if self.blocked(&q.name, q.qtype) {
                let ttl = self.block_ttl.load(std::sync::atomic::Ordering::Acquire);
                return ResolveOutcome::Response(crate::native::local_only_negative_response(
                    req, &q.name, ttl,
                ));
            }
        }
        self.inner.resolve_outcome(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::query;
    use onetdns_proto::{RData, Record, ResponseCode};
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{mpsc, Mutex};

    /// Holds the first query until released, and answers every query with an upstream PTR.
    struct HeldUpstream {
        entered: Mutex<Option<mpsc::Sender<()>>>,
        release: Mutex<mpsc::Receiver<()>>,
        calls: AtomicUsize,
    }

    impl Resolver for HeldUpstream {
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let entered = self.entered.lock().unwrap().take();
            if let Some(entered) = entered {
                entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
            let q = req.questions.first()?;
            let mut response =
                crate::layers::answer_message(req.header.id, q.name.clone(), q.qtype, vec![]);
            response.answers.push(Record::new(
                q.name.clone(),
                300,
                RData::Ptr(Name::from_str("printer.lan").unwrap()),
            ));
            Some(response)
        }
    }

    #[test]
    /// An answer from a query sent before bogus_priv was turned on must not re-enter the cache
    /// after the flush; private reverse lookups would get that upstream answer for its TTL.
    fn a_local_only_flush_is_not_undone_by_an_in_flight_answer() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let upstream = Arc::new(HeldUpstream {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
            calls: AtomicUsize::new(0),
        });
        let names = Arc::new(LocalOnlyNames::new(false, false, false));
        let cache = crate::cache::CacheLayer::new(
            Arc::new(LocalOnlyLayer::new(
                upstream.clone(),
                names.clone(),
                Arc::new(AtomicU32::new(10)),
            )),
            64,
            1,
            0,
            86_400,
            0,
            86_400,
        );
        let handle = cache.handle();
        let chain: Arc<dyn Resolver> = Arc::new(cache);
        let request = query("1.0.168.192.in-addr.arpa", RecordType::PTR);
        let in_flight = {
            let chain = chain.clone();
            let request = request.clone();
            std::thread::spawn(move || chain.resolve(&request))
        };

        entered_rx.recv().unwrap();
        names.set(false, true, false);
        handle.clear();
        release_tx.send(()).unwrap();
        in_flight
            .join()
            .unwrap()
            .expect("붙잡혔던 질의도 답은 받아야 합니다");

        let after = chain.resolve(&request).expect("답");
        assert_eq!(
            after.header.rcode,
            ResponseCode::NXDomain.0,
            "비운 뒤에 도착한 이전 설정의 답이 캐시에 남았습니다"
        );
        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            1,
            "켜진 범주의 이름이 업스트림으로 나갔습니다"
        );
    }
}
