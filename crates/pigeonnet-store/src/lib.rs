//! SQLite-backed object store, journals and derived indexes.
//!
//! The store preserves the original canonical bytes of every object (D2, §25).
//! Derived indexes are rebuilt from those bytes, never from a re-serialization.
//!
//! Synchronous by design — see §34.1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
