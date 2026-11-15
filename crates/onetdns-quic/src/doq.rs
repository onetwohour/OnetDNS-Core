//! DoQ application error codes from RFC 9250, sent in an application CONNECTION_CLOSE.

pub const NO_ERROR: u64 = 0x0;
pub const INTERNAL_ERROR: u64 = 0x1;
pub const PROTOCOL_ERROR: u64 = 0x2;
pub const EXCESSIVE_LOAD: u64 = 0x4;
