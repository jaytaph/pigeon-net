//! Reading and writing `.pack` bundles for offline transport (§19).
//!
//! A bundle from untrusted removable media must be exactly as safe to import as
//! a sync with a peer, because neither is trusted. Everything here is a parser
//! of hostile input and is fuzzed accordingly.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
