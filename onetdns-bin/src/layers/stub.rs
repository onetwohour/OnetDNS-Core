/*!
 * @brief 이름 접미사별로 지정한 업스트림에 전달하는 stub 계층.
 */

use std::sync::Arc;

use onetdns_proto::{Message, Name};

use super::{configured_name_key, outcome_to_option};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/** @brief 특정 접미사를 지정한 서버로 보내는 계층. */
pub struct StubLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
    /** @brief 접미사와 그 접미사를 보낼 곳. */
    stubs: Vec<(Vec<u8>, Arc<dyn Resolver>)>,
}

impl StubLayer {
    /** @brief 접미사 목록으로 만든다. 이름이 틀리거나 겹치면 실패다. */
    pub fn new(
        inner: Arc<dyn Resolver>,
        stubs: Vec<(String, Arc<dyn Resolver>)>,
    ) -> Result<Self, String> {
        let mut parsed = Vec::with_capacity(stubs.len());
        for (suffix, backend) in stubs {
            let key = configured_name_key(&suffix)
                .ok_or_else(|| format!("스텁 영역 이름이 올바르지 않습니다: {suffix}"))?;
            if parsed.iter().any(|(existing, _)| existing == &key) {
                return Err(format!("스텁 영역 이름이 중복되었습니다: {suffix}"));
            }
            parsed.push((key, backend));
        }
        Ok(StubLayer {
            inner,
            stubs: parsed,
        })
    }

    /** @brief 이 이름에 맞는 서버. 가장 긴 접미사가 이긴다. */
    fn match_stub(&self, name: &Name) -> Option<&Arc<dyn Resolver>> {
        let mut key = [0u8; 255];
        for labels in (0..=name.num_labels()).rev() {
            let key = name.canonical_suffix_key_into(labels, &mut key)?;
            if let Some((_, b)) = self
                .stubs
                .iter()
                .find(|(suffix, _)| suffix.as_slice() == key)
            {
                return Some(b);
            }
        }
        None
    }
}

impl Resolver for StubLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 맞는 접미사가 있으면 그리로, 없으면 안으로. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        match self.match_stub(&q.name) {
            Some(b) => b.resolve_outcome(req),
            None => self.inner.resolve_outcome(req),
        }
    }
}

#[cfg(test)]
/** @brief 접미사가 맞는 질의만 stub 업스트림으로 가는지. */
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::Arc;

    use onetdns_proto::{RecordType, ResponseCode};

    use crate::native::Resolver;

    #[test]
    /** @brief 접미사가 맞는 질의가 지정한 서버로 가는지. */
    fn stub_routes_matching_suffix() {
        let inner = Mock::new(1, ResponseCode::NoError.0);
        let stub = Mock::new(9, ResponseCode::NoError.0);
        let layer = StubLayer::new(
            inner.clone(),
            vec![(
                "corp.internal".to_string(),
                stub.clone() as Arc<dyn Resolver>,
            )],
        )
        .unwrap();

        let r1 = layer
            .resolve(&query("host.corp.internal", RecordType::A))
            .unwrap();
        assert_eq!(r1.answers[0].ttl, 9);

        let r2 = layer.resolve(&query("example.com", RecordType::A)).unwrap();
        assert_eq!(r2.answers[0].ttl, 1);
    }
}
