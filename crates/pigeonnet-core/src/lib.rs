//! Core object model: canonical encoding, object identifiers, and object
//! validation.
//!
//! This crate is pure. It performs no I/O, opens no sockets, reads no clock and
//! draws no randomness — time and entropy are supplied by the caller. That is
//! what allows every validation decision to be reproduced exactly in a test, and
//! fuzzed without a network.
//!
//! It also holds no cryptography beyond BLAKE3 for content addressing. Key
//! material is opaque here; signatures are verified in `pigeonnet-crypto`.
//!
//! See `docs/pigeonnet-architecture.md` §3.2, §3.3, §22 and decisions D1–D3.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod base32;
pub mod bytes;
pub mod cbor;
pub mod error;
pub mod object;
pub mod payload;
pub mod time;

pub use bytes::{AgreementKeyBytes, IdentityId, NodeId, ObjectId, PublicKeyBytes, SignatureBytes};
pub use error::Error;
pub use object::{Object, ObjectType, Tbs};
pub use time::Timestamp;

/// Object format version carried by every object (§31).
///
/// Object versioning and transport versioning are deliberately separate numbers.
pub const OBJECT_VERSION: u16 = 1;

/// BLAKE3 derive-key context for object identifiers (D1).
///
/// Domain separation: a hash computed under this context cannot collide with one
/// computed for a file chunk or for a signature transcript, because those use
/// their own contexts.
pub const OBJECT_ID_CONTEXT: &str = "pigeonnet object-id v1";

/// BLAKE3 derive-key context for file content hashes (D1, §9).
pub const FILE_ROOT_CONTEXT: &str = "pigeonnet file-root v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_contexts_are_distinct() {
        // Domain separation is the point of these strings; if they ever collide,
        // a file root and an object id could be confused for one another.
        assert_ne!(OBJECT_ID_CONTEXT, FILE_ROOT_CONTEXT);
    }
}
