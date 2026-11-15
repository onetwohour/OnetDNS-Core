//! Asks a fallback path again only when the primary path's transport failed.

use std::sync::Arc;

use onetdns_proto::{Message, RecordType, ResponseCode};

use super::outcome_to_option;
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/// Only transport failures fall back. A config or validation failure would repeat, and falling back
/// on it would bypass validation.
pub struct FallbackLayer {
    primary: Arc<dyn Resolver>,
    fallback: Arc<dyn Resolver>,
}

impl FallbackLayer {
    pub fn new(primary: Arc<dyn Resolver>, fallback: Arc<dyn Resolver>) -> Self {
        FallbackLayer { primary, fallback }
    }
}

impl Resolver for FallbackLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /// Retries with a clean query with RD set: response-only flags and records in the client's
    /// request would otherwise reach the fallback as if this server had sent them.
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        match self.primary.resolve_outcome(req) {
            ResolveOutcome::Response(response) => ResolveOutcome::Response(response),

            failure @ ResolveOutcome::Failure(ResolveFailure::Permanent(_)) => failure,
            ResolveOutcome::Failure(ResolveFailure::TransportExhausted) => {
                let mut fallback_req = req.clone();
                fallback_req.header.response = false;
                fallback_req.header.authoritative = false;
                fallback_req.header.truncated = false;
                fallback_req.header.recursion_desired = true;
                fallback_req.header.recursion_available = false;
                fallback_req.header.authentic_data = false;
                fallback_req.header.rcode = ResponseCode::NoError.0;
                fallback_req.answers.clear();
                fallback_req.authorities.clear();

                fallback_req
                    .additionals
                    .retain(|record| record.rtype == RecordType::OPT);

                match self.fallback.resolve(&fallback_req) {
                    Some(mut response) => {
                        response.header.id = req.header.id;
                        response.header.opcode = req.header.opcode;
                        response.header.recursion_desired = req.header.recursion_desired;
                        response.questions = req.questions.clone();
                        ResolveOutcome::Response(response)
                    }

                    None => ResolveOutcome::Failure(ResolveFailure::TransportExhausted),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use onetdns_proto::{Message, RData, Record, RecordType, ResponseCode};

    use crate::layers::answer_message;
    use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

    struct RecursionDesiredMock {
        seen: std::sync::atomic::AtomicBool,
    }

    impl RecursionDesiredMock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    impl Resolver for RecursionDesiredMock {
        fn resolve(&self, req: &Message) -> Option<Message> {
            self.seen
                .store(req.header.recursion_desired, Ordering::SeqCst);
            let q = req.questions.first()?;
            Some(answer_message(
                req.header.id,
                q.name.clone(),
                q.qtype,
                vec![Record::new(
                    q.name.clone(),
                    60,
                    RData::A(Ipv4Addr::new(2, 2, 2, 2)),
                )],
            ))
        }
    }

    struct TransportFailureMock {
        calls: AtomicU32,
    }

    impl TransportFailureMock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for TransportFailureMock {
        fn resolve(&self, _req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolveOutcome::Failure(ResolveFailure::TransportExhausted)
        }
    }

    struct PermanentFailureMock {
        calls: AtomicU32,
    }

    impl PermanentFailureMock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for PermanentFailureMock {
        fn resolve(&self, _req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolveOutcome::Failure(ResolveFailure::Permanent(None))
        }
    }

    #[test]
    fn fallback_on_transport_exhaustion() {
        let primary = TransportFailureMock::new();
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(
            response.answers[0].ttl, 2,
            "transport failure uses fallback"
        );
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fallback_forces_recursion_desired() {
        let primary = TransportFailureMock::new();
        let fallback = RecursionDesiredMock::new();
        let layer = FallbackLayer::new(primary, fallback.clone());
        let mut req = query("www.example.com", RecordType::A);
        req.header.recursion_desired = false;

        let response = layer.resolve(&req).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(
            fallback.seen.load(Ordering::SeqCst),
            "configured recursive fallback must receive RD=1"
        );
        let got = response.questions.first().expect("fallback question");
        let expected = req.questions.first().expect("original question");
        assert!(got.name.eq_ignore_case(&expected.name));
        assert_eq!(got.qtype, expected.qtype);
        assert_eq!(got.qclass, expected.qclass);
    }

    #[test]
    fn no_fallback_on_permanent_backend_failure() {
        let primary = PermanentFailureMock::new();
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());

        assert!(
            matches!(
                layer.resolve_outcome(&query("x.test", RecordType::A)),
                ResolveOutcome::Failure(ResolveFailure::Permanent(_))
            ),
            "영구 실패가 대체 경로에 가려지거나 다른 실패와 합쳐지면 안 된다"
        );
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_fallback_on_servfail_response() {
        let primary = Mock::new(1, ResponseCode::ServFail.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::ServFail.0);
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_fallback_on_refused_response() {
        let primary = Mock::new(1, ResponseCode::Refused.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary, fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::Refused.0);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_fallback_on_noerror() {
        let primary = Mock::new(1, ResponseCode::NoError.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.answers[0].ttl, 1, "primary response is final");
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_fallback_on_unproven_empty_noerror_packet() {
        let primary = EmptyMock::new(false);
        let fallback = Mock::new(8, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());

        let response = layer.resolve(&query("empty.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(response.answers.is_empty());
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_fallback_on_proven_nodata() {
        let primary = EmptyMock::new(true);
        let fallback = Mock::new(8, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());

        let response = layer.resolve(&query("nodata.test", RecordType::A)).unwrap();
        assert!(response.answers.is_empty());
        assert_eq!(response.authorities.len(), 1);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }
}
