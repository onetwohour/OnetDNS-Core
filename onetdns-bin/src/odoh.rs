//! Oblivious DoH target on the DoH listener: opens queries a proxy relays, resolves them as DoH
//! queries from the proxy, and seals the answers.

use std::net::SocketAddr;

use onetdns_forward::odoh::{OdohError, TargetKey};
use onetdns_http2::{Oblivious, ObliviousReply};
use onetdns_tls::hpke::PrivateKey;

use crate::transport_observe;

pub(crate) struct OdohTarget {
    key: TargetKey,
    configs: Vec<u8>,
}

impl OdohTarget {
    pub(crate) fn new(secret: PrivateKey) -> Self {
        let key = TargetKey::new(secret);
        let configs = key.configs();
        Self { key, configs }
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }
}

/// Oblivious DoH on one DoH connection. `resolve` answers a DNS query as the listener answers DoH
/// from this peer, which is the proxy, not the client behind it.
pub(crate) struct ObliviousConn<'a, R> {
    pub(crate) target: &'a OdohTarget,
    pub(crate) peer: SocketAddr,
    pub(crate) resolve: R,
}

impl<R> Oblivious for ObliviousConn<'_, R>
where
    R: Fn(&[u8]) -> Result<Option<Vec<u8>>, &'static str>,
{
    fn configs(&self) -> Option<Vec<u8>> {
        Some(self.target.configs.clone())
    }

    fn target(&self, message: &[u8]) -> ObliviousReply {
        let opened = match self.target.key.open_query(message) {
            Ok(opened) => opened,
            Err(error) => {
                transport_observe::record_error("odoh", "open_query", Some(self.peer), error);
                // A client holding an old config learns from 401 to fetch the current one.
                return ObliviousReply::Status(if error == OdohError::UnknownKey {
                    "401"
                } else {
                    "400"
                });
            }
        };
        let response = match (self.resolve)(opened.dns()) {
            Ok(Some(response)) => response,
            Ok(None) => return ObliviousReply::Drop,
            Err(status) => return ObliviousReply::Status(status),
        };
        match opened.seal_response(&response) {
            Ok(sealed) => ObliviousReply::Message(sealed),
            Err(error) => {
                transport_observe::record_error("odoh", "seal_response", Some(self.peer), error);
                ObliviousReply::Status("502")
            }
        }
    }
}
