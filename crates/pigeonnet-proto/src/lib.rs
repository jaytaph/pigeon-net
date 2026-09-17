//! The replication protocol, as a sans-io state machine.
//!
//! `step(input) -> outputs`, with no sockets and no clock. This is where the
//! interesting attacks live (D5, D6), so it is built to be driven by a scripted
//! hostile peer and by a fuzzer rather than by a network.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
