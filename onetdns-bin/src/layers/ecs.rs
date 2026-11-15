//! Adds or strips EDNS Client Subnet.

use std::net::IpAddr;
use std::sync::Arc;

use onetdns_proto::{Edns, Message, RecordType};

use super::outcome_to_option;
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/// With a subnet attached, upstreams answer by client location, so this layer closes the UDP fast
/// path.
pub struct EcsLayer {
    inner: Arc<dyn Resolver>,
    /// None strips an incoming option.
    option: Option<(u16, Vec<u8>)>,
}

impl EcsLayer {
    pub fn new(inner: Arc<dyn Resolver>, custom_ip: IpAddr) -> Self {
        let (family, addr, prefix): (u16, Vec<u8>, u8) = match custom_ip {
            IpAddr::V4(v4) => (1, v4.octets().to_vec(), 24),
            IpAddr::V6(v6) => (2, v6.octets().to_vec(), 56),
        };
        let nbytes = (prefix as usize).div_ceil(8);
        let mut data = Vec::new();
        data.extend_from_slice(&family.to_be_bytes());
        data.push(prefix);
        data.push(0);
        data.extend_from_slice(&addr[..nbytes.min(addr.len())]);
        EcsLayer {
            inner,
            option: Some((8, data)),
        }
    }

    /// Keeps this server's client locations from reaching upstreams.
    pub fn strip(inner: Arc<dyn Resolver>) -> Self {
        EcsLayer {
            inner,
            option: None,
        }
    }
}

/// The query fails when the EDNS record cannot be rebuilt, and the client sees SERVFAIL; without a
/// log the cause is invisible. Called per query, so only powers of two are logged.
fn ecs_encode_failed(error: &impl std::fmt::Display) {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::error!(event = "ecs.edns_encode_failed", count = count, %error, "Could not build the EDNS record carrying the client subnet; failing the query");
    }
}

impl Resolver for EcsLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let mut r = req.clone();
        let opt_index = r
            .additionals
            .iter()
            .position(|record| record.rtype == RecordType::OPT);
        let mut edns = opt_index
            .and_then(|index| Edns::from_record(&r.additionals[index]))
            .unwrap_or_default();
        edns.options.retain(|(code, _)| *code != 8);
        if let Some(option) = &self.option {
            edns.options.push(option.clone());
        }
        match (opt_index, self.option.is_some()) {
            (Some(index), _) => match edns.try_to_record() {
                Ok(record) => r.additionals[index] = record,

                Err(error) => {
                    ecs_encode_failed(&error);
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                }
            },
            (None, true) => match edns.try_to_record() {
                Ok(record) => r.additionals.push(record),
                Err(error) => {
                    ecs_encode_failed(&error);
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                }
            },
            (None, false) => {}
        }
        self.inner.resolve_outcome(&r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use onetdns_proto::{RecordType, ResponseCode};

    #[test]
    fn ecs_option_attached() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let layer = EcsLayer::new(inner, "203.0.113.5".parse().unwrap());

        let option = layer.option.as_ref().expect("ECS 옵션이 부착되어야 함");
        assert_eq!(option.0, 8);
        assert_eq!(option.1, vec![0x00, 0x01, 24, 0, 203, 0, 113]);

        let resp = layer.resolve(&query("x.test", RecordType::A));
        assert!(resp.is_some());
    }
}
