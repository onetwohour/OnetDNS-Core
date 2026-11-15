//! Answers _acme-challenge TXT queries for ACME DNS-01 validation.

use std::sync::Arc;

use onetdns_proto::{Message, RData, Record, RecordType};

use super::{answer_message, outcome_to_option};
use crate::native::{ResolveOutcome, Resolver};

pub struct AcmeChallengeLayer {
    inner: Arc<dyn Resolver>,
}

impl AcmeChallengeLayer {
    pub fn new(inner: Arc<dyn Resolver>) -> Self {
        AcmeChallengeLayer { inner }
    }
}

impl Resolver for AcmeChallengeLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    /// Once issuance is done nothing is pending, and the query passes through.
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
