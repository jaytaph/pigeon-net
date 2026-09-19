//! Keys, signatures, key agreement and authenticated encryption.
//!
//! Private key material is wrapped in zeroizing types and never rendered by
//! `Debug`. Signing and key agreement use separate keys: Ed25519 keys are never
//! converted to X25519 keys via the birational map (D4).
//!
//! No I/O: the keystore seals and opens byte buffers, and leaves files to the
//! caller. Randomness comes from the operating system at key generation and
//! at sealing, and nowhere else.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod error;
pub mod identity;
pub mod keys;
pub mod keystore;
pub mod message;
pub mod prekey;
pub mod sign;
pub mod snapshot;

pub use error::CryptoError;
pub use identity::{IdentityError, IdentityState};
pub use keys::{AgreementKeypair, SigningKeypair, verify};
pub use keystore::{KdfParams, Keyring};
pub use message::{SUITE_V1, Target, open_message, seal_message};
pub use prekey::{ColdSeed, EPOCHS_PER_WINDOW, PrekeySeed, PrekeyWindows, window_of, window_start};
pub use sign::{sign_object, verify_object};
pub use snapshot::{ResolvedIdentity, Snapshot, SnapshotError};
