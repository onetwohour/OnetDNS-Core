//! Certificate and key helpers: PEM input and output, and self-signed certificates. Despite the
//! crate name it opens no listeners; the transports live in onetdns-bin and onetdns-tls.

pub mod tls;

pub use tls::{
    generate_self_signed_pem, load_pem, parse_pem, self_signed_material, verify_key_matches_cert,
    TlsError,
};
