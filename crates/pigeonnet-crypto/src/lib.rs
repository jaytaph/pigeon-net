//! Keys, signatures, key agreement and authenticated encryption.
//!
//! Private key material is wrapped in zeroizing types and never logged. Signing
//! and key agreement use separate keys: Ed25519 keys are never converted to
//! X25519 keys via the birational map (D4).
//!
//! Pure: no I/O. Randomness is supplied by the caller.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
