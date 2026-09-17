//! Node core: wires the store, the protocol and local policy together.
//!
//! Reaches transports through a trait, never through tokio types, so the policy
//! layer stays testable without a runtime.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
