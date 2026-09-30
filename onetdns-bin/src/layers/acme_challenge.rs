/*!
 * @brief ACME DNS-01 검증용 _acme-challenge TXT를 답하는 계층.
 */

use std::sync::Arc;

use onetdns_proto::{Message, RData, Record, RecordType};

use super::{answer_message, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

/** @brief 인증서 발급 도전에 답하는 계층. */
pub struct AcmeChallengeLayer {
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
}

impl AcmeChallengeLayer {
    /** @brief 안쪽 리졸버를 잡은 계층을 만든다. */
    pub fn new(inner: Arc<dyn Resolver>) -> Self {
        AcmeChallengeLayer { inner }
    }
}

impl Resolver for AcmeChallengeLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /** @brief 도전이 걸린 이름이면 그 값을 답한다. 발급이 끝나면 걸린 것이 없어 그냥 지나간다. */
    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        if let Some(q) = req.questions.first() {
            if q.qtype == RecordType::TXT {
                let name = q.name.to_string();
                if name.to_ascii_lowercase().starts_with("_acme-challenge.") {
                    if let Some(txt) = crate::acme::dns01_txt(&name) {
                        let rec =
                            Record::new(q.name.clone(), 0, RData::Txt(vec![txt.into_bytes()]));
                        return ResolveOutcome::Response(answer_message(
                            req.header.id,
                            q.name.clone(),
                            RecordType::TXT,
                            vec![rec],
                        ));
                    }
                }
            }
        }
        self.inner.resolve_outcome(req)
    }
}
