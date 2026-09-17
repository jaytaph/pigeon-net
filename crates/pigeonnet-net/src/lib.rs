//! Transports. The only crate in the workspace that depends on tokio.
//!
//! TCP first; QUIC, Tor and others later (§3.6). Transport choice must not reach
//! the protocol layer.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
