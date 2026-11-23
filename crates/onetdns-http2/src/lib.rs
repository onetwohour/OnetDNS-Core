//! HTTP/2 for DoH and Oblivious DoH only, not a general HTTP/2 stack. Only what they use is
//! implemented: the client always sends POST with application/dns-message, and neither side handles
//! server push or priority.

pub mod client;
pub mod frame;
pub mod hpack;
pub mod huffman;
pub mod server;
#[cfg(test)]
mod testutil;
pub(crate) mod wire;

pub use client::H2Client;
pub use server::{
    serve_doh, serve_doh_h1, serve_doh_h1_with_deadline_reset, serve_doh_with_deadline_reset,
    DohAnswer, Oblivious, ObliviousReply, MAX_ODOH_MESSAGE, ODOH_CONFIGS_PATH, ODOH_MEDIA_TYPE,
};

/// Whether a header field follows the HTTP/2 rules: a lowercase name of token characters, and a
/// value without NUL, CR, LF, or leading or trailing whitespace. This is the header injection
/// defense: a CR or LF in a value could create headers or split the response. A pseudo-header may
/// start with `:`, but no other `:` may appear in the name.
pub fn valid_header_field(name: &[u8], value: &[u8]) -> bool {
    let token = name.strip_prefix(b":").unwrap_or(name);
    if token.is_empty()
        || !token.iter().all(|&byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return false;
    }
    if name != token && name[1..].contains(&b':') {
        return false;
    }
    !value.iter().any(|&byte| matches!(byte, 0 | b'\r' | b'\n'))
        && !value
            .first()
            .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
        && !value
            .last()
            .is_some_and(|&byte| matches!(byte, b' ' | b'\t'))
}

#[derive(Debug)]
pub enum H2Error {
    Io,
    /// The connection must be closed, not reused.
    Protocol,

    /// Reconnecting recovers.
    Closed,

    /// The upstream answered with a non-200 status. Only that stream ended, so the connection stays
    /// usable.
    BadStatus,
}
