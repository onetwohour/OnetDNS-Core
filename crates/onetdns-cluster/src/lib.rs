//! Raft replication of configuration and state between nodes. `raft` is a pure state machine
//! without I/O, so it is tested deterministically; `transport` runs it over authenticated
//! connections.

pub mod raft;
pub mod transport;

pub use raft::{Config, LogEntry, Msg, NodeId, Output, RaftNode, Role};
pub use transport::{decode_msg, encode_msg};
