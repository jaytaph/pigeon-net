//! The replication protocol, as a sans-io state machine.
//!
//! `step(input) -> outputs`, with no sockets and no clock. This is where the
//! interesting attacks live (D5, D6), so it is built to be driven by a scripted
//! hostile peer and by a fuzzer rather than by a network.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod limits;
pub mod memory;
pub mod message;
pub mod replica;
pub mod session;

pub use error::ProtocolError;
pub use limits::Limits;
pub use memory::MemoryReplica;
pub use message::{Features, JournalEntry, Message, PROTOCOL_VERSION, StreamId};
pub use replica::{AcceptError, Replica, ReplicaError};
pub use session::{Input, Output, Role, Session};
