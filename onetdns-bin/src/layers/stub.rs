//! Sends names under configured suffixes to their own upstreams.

use std::sync::Arc;

use onetdns_proto::{Message, Name};

use super::{configured_name_key, outcome_to_option};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

pub struct StubLayer {
    inner: Arc<dyn Resolver>,
    stubs: Vec<(Vec<u8>, Arc<dyn Resolver>)>,
}

impl StubLayer {
    /// Fails on an invalid or duplicate suffix.
    pub fn new(
        inner: Arc<dyn Resolver>,
        stubs: Vec<(String, Arc<dyn Resolver>)>,
    ) -> Result<Self, String> {
        let mut parsed = Vec::with_capacity(stubs.len());
        for (suffix, backend) in stubs {
            let key = configured_name_key(&suffix)
                .ok_or_else(|| format!("Invalid stub zone name: {suffix}"))?;
            if parsed.iter().any(|(existing, _)| existing == &key) {
                return Err(format!("Duplicate stub zone name: {suffix}"));
            }
            parsed.push((key, backend));
        }
        Ok(StubLayer {
            inner,
            stubs: parsed,
        })
    }

    /// The longest suffix wins.
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
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

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
mod tests {
    use super::*;
    use crate::layers::test_support::*;
    use std::sync::Arc;

    use onetdns_proto::{RecordType, ResponseCode};

    use crate::native::Resolver;

    #[test]
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
