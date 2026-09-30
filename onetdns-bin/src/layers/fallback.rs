/*!
 * @brief 주 경로의 전송이 끊겼을 때만 예비 경로로 다시 묻는 계층.
 */

use std::sync::Arc;

use onetdns_proto::{Message, RecordType, ResponseCode};

use super::outcome_to_option;
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/**
 * @brief 주 경로가 닿지 못했을 때 다른 경로로 다시 묻는 계층.
 * @warning 전송이 끊긴 실패만 넘긴다. 설정이 틀렸거나 검증에 실패한 것은 다시 물어도
 *          같고, 넘기면 검증 실패를 우회하는 길이 된다.
 */
pub struct FallbackLayer {
    /** @brief 먼저 물어볼 곳. */
    primary: Arc<dyn Resolver>,
    /** @brief 주 경로가 닿지 못했을 때 물어볼 곳. */
    fallback: Arc<dyn Resolver>,
}

impl FallbackLayer {
    /** @brief 주 경로와 보조 경로로 만든다. */
    pub fn new(primary: Arc<dyn Resolver>, fallback: Arc<dyn Resolver>) -> Self {
        FallbackLayer { primary, fallback }
    }
}

impl Resolver for FallbackLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /**
     * @brief 주 경로가 닿지 못했을 때만 보조 경로로 다시 묻는다.
     * @note 다시 물을 때 요청을 처음 상태로 되돌린다. 주 경로가 채워 넣은 표시를 그대로
     *       전달하면 보조 경로가 그것을 이 서버의 판단으로 오해한다.
     */
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
/** @brief 예비 경로로 넘어가는 실패와 넘어가지 않는 응답. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use onetdns_proto::{Message, RData, Record, RecordType, ResponseCode};

    use crate::layers::answer_message;
    use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

    /** @brief 재귀 요구 표시를 그대로 되비추는 테스트용 리졸버. */
    struct RecursionDesiredMock {
        /** @brief 재귀 요구 표시가 실려 왔는지. */
        seen: std::sync::atomic::AtomicBool,
    }

    impl RecursionDesiredMock {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    impl Resolver for RecursionDesiredMock {
        /** @brief 미리 정해 둔 응답을 돌려준다. */
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

    /** @brief 전송이 끊긴 실패를 내는 테스트용 리졸버. */
    struct TransportFailureMock {
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }

    impl TransportFailureMock {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for TransportFailureMock {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        /** @brief 전송이 끊겼다고 알린다. */
        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolveOutcome::Failure(ResolveFailure::TransportExhausted)
        }
    }

    /** @brief 다시 물어도 같은 실패를 내는 테스트용 리졸버. */
    struct PermanentFailureMock {
        /** @brief 불린 횟수. */
        calls: AtomicU32,
    }

    impl PermanentFailureMock {
        /** @brief 만든다. */
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
            })
        }
    }

    impl Resolver for PermanentFailureMock {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }

        /** @brief 되돌릴 수 없는 실패라고 알린다. */
        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ResolveOutcome::Failure(ResolveFailure::Permanent(None))
        }
    }

    #[test]
    /** @brief 전송이 끊겼을 때 보조 경로로 넘어가는지. */
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
    /** @brief 보조 경로에 재귀를 요구해 묻는지. */
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
    /** @brief 되돌릴 수 없는 실패는 넘기지 않는지. 넘기면 검증 실패를 우회하는 길이 된다. */
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
    /** @brief 오류 응답을 받은 것은 실패로 보지 않는지. */
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
    /** @brief 거절 응답을 받은 것은 실패로 보지 않는지. */
    fn no_fallback_on_refused_response() {
        let primary = Mock::new(1, ResponseCode::Refused.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary, fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::Refused.0);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 정상 응답에는 다시 묻지 않는지. */
    fn no_fallback_on_noerror() {
        let primary = Mock::new(1, ResponseCode::NoError.0);
        let fallback = Mock::new(2, ResponseCode::NoError.0);
        let layer = FallbackLayer::new(primary.clone(), fallback.clone());
        let response = layer.resolve(&query("x.test", RecordType::A)).unwrap();
        assert_eq!(response.answers[0].ttl, 1, "primary response is final");
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    /** @brief 근거 없이 비어 온 응답에도 다시 묻지 않는지. */
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
    /** @brief 근거가 담긴 빈 응답에 다시 묻지 않는지. */
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
