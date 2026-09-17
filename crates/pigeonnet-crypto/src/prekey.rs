//! Epoch prekey secrets, derived from a ratcheting seed (§8.1, §37.1).
//!
//! M5 published prekeys and threw their private halves away — a placeholder that
//! made the published keys structurally valid and cryptographically useless.
//! This is the replacement.
//!
//! # Why a ratchet rather than a pile of keys
//!
//! §37.1 leans toward deriving private halves from a seed instead of storing
//! them individually, and this implements that. Two reasons, and the second is
//! the real one:
//!
//! - There is one secret in the keystore rather than one per epoch, so
//!   destroying an epoch is an operation on a value rather than on a file the
//!   filesystem may have copied three times.
//! - The seed is **one-way**. `seed(n+1)` is derived from `seed(n)`, and the
//!   reverse is not computable, so advancing the ratchet past an epoch destroys
//!   that epoch's secret for good. Deletion becomes arithmetic instead of an
//!   erasure the storage layer may quietly decline to perform.
//!
//! ```text
//!   seed(n) ──ratchet──> seed(n+1) ──ratchet──> seed(n+2) ...
//!      │                    │                      │
//!    leaf                 leaf                   leaf
//!      ↓                    ↓                      ↓
//!   secret(n)            secret(n+1)            secret(n+2)
//! ```
//!
//! Leaf derivation is domain-separated from the ratchet step, so learning one
//! epoch's secret does not yield the seed it came from, and therefore does not
//! yield any other epoch.
//!
//! # What this does not fix
//!
//! Holding `seed(n)` yields every epoch from `n` **forward**. That is the
//! exposure §37.1 names and does not resolve: a leaked backup stops being a
//! window into the past and becomes a standing wiretap on the future, for as far
//! ahead as lookahead reaches. Nothing here shrinks that. The measures §37.1
//! proposes — excluding key material from node backups, or splitting the seed
//! cold and warm — sit above this layer, and this construction is what makes
//! them cheap to add later without a format break.

use blake3::Hasher;
use pigeonnet_core::AgreementKeyBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::{AgreementKeypair, CryptoError};

/// Domain separator for advancing the seed.
const RATCHET_CONTEXT: &str = "pigeonnet prekey-ratchet v1";

/// Domain separator for deriving an epoch's secret from a seed.
const SECRET_CONTEXT: &str = "pigeonnet prekey-secret v1";

/// Most epochs this will derive forward in one call.
///
/// A bound rather than a policy: deriving is a hash chain, so a caller asking
/// for an epoch a century away would otherwise spend the afternoon on it.
pub const MAX_DERIVATION_SPAN: u64 = 4096;

/// A ratcheting source of epoch prekey secrets.
///
/// Held in the keystore as `(seed, epoch)`: the seed, and the epoch it
/// corresponds to. Secrets for earlier epochs are not recoverable from it, by
/// construction.
pub struct PrekeySeed {
    seed: [u8; 32],
    epoch: u64,
}

impl PrekeySeed {
    /// A fresh seed, anchored at `epoch`.
    pub fn generate(epoch: u64) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Entropy)?;
        Ok(Self { seed, epoch })
    }

    /// Reconstruct from stored material.
    #[must_use]
    pub const fn from_parts(seed: [u8; 32], epoch: u64) -> Self {
        Self { seed, epoch }
    }

    /// The seed, for sealing into a keystore.
    #[must_use]
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.seed)
    }

    /// The earliest epoch this seed can still produce.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The keypair for an epoch.
    ///
    /// Fails for an epoch already ratcheted past: that is the point of the
    /// ratchet, and a caller asking for one is asking to undo a destruction.
    pub fn keypair(&self, epoch: u64) -> Result<AgreementKeypair, CryptoError> {
        let Some(steps) = epoch.checked_sub(self.epoch) else {
            return Err(CryptoError::EpochDestroyed {
                epoch,
                earliest: self.epoch,
            });
        };
        if steps > MAX_DERIVATION_SPAN {
            return Err(CryptoError::EpochTooFar {
                epoch,
                limit: MAX_DERIVATION_SPAN,
            });
        }

        let mut seed = Zeroizing::new(self.seed);
        for _ in 0..steps {
            *seed = advance(&seed);
        }
        let mut secret = Zeroizing::new(leaf(&seed));
        let keypair = AgreementKeypair::from_secret(&secret);
        secret.zeroize();
        Ok(keypair)
    }

    /// The public half for an epoch.
    pub fn public(&self, epoch: u64) -> Result<AgreementKeyBytes, CryptoError> {
        Ok(self.keypair(epoch)?.public())
    }

    /// Advance to `epoch`, destroying every secret before it.
    ///
    /// Idempotent, and never goes backwards: asking to rewind is asking to
    /// recover a destroyed key, which is exactly what must not be possible.
    /// Returns how many epochs were destroyed.
    pub fn ratchet_to(&mut self, epoch: u64) -> Result<u64, CryptoError> {
        let Some(steps) = epoch.checked_sub(self.epoch) else {
            return Ok(0);
        };
        if steps > MAX_DERIVATION_SPAN {
            return Err(CryptoError::EpochTooFar {
                epoch,
                limit: MAX_DERIVATION_SPAN,
            });
        }
        for _ in 0..steps {
            let next = advance(&self.seed);
            self.seed.zeroize();
            self.seed = next;
        }
        self.epoch = epoch;
        Ok(steps)
    }
}

impl Drop for PrekeySeed {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl core::fmt::Debug for PrekeySeed {
    /// Names the epoch it stands at, never the seed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrekeySeed")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// One ratchet step. One-way: the previous seed is not recoverable.
fn advance(seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RATCHET_CONTEXT);
    hasher.update(seed);
    *hasher.finalize().as_bytes()
}

/// An epoch's secret. Domain-separated from [`advance`], so a leaked secret
/// does not yield the seed and therefore does not yield any other epoch.
fn leaf(seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(SECRET_CONTEXT);
    hasher.update(seed);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_epochs_keypair_is_stable() {
        let seed = PrekeySeed::generate(100).unwrap();
        assert_eq!(seed.public(105).unwrap(), seed.public(105).unwrap());
    }

    #[test]
    fn different_epochs_give_different_keys() {
        let seed = PrekeySeed::generate(100).unwrap();
        assert_ne!(seed.public(100).unwrap(), seed.public(101).unwrap());
    }

    #[test]
    fn ratcheting_preserves_later_epochs() {
        let mut seed = PrekeySeed::generate(100).unwrap();
        let later = seed.public(110).unwrap();
        assert_eq!(seed.ratchet_to(105).unwrap(), 5);
        assert_eq!(seed.public(110).unwrap(), later, "epoch 110 survives");
    }

    #[test]
    fn ratcheting_destroys_earlier_epochs() {
        // The whole point: deletion is arithmetic, not an erasure the storage
        // layer may quietly decline to perform.
        let mut seed = PrekeySeed::generate(100).unwrap();
        seed.ratchet_to(105).unwrap();
        assert!(matches!(
            seed.keypair(104),
            Err(CryptoError::EpochDestroyed {
                epoch: 104,
                earliest: 105
            })
        ));
    }

    #[test]
    fn ratcheting_never_rewinds() {
        let mut seed = PrekeySeed::generate(100).unwrap();
        seed.ratchet_to(105).unwrap();
        assert_eq!(seed.ratchet_to(100).unwrap(), 0, "a rewind is a no-op");
        assert_eq!(seed.epoch(), 105);
        assert!(seed.keypair(104).is_err(), "and does not restore anything");
    }

    #[test]
    fn a_destroyed_seed_cannot_be_reconstructed_from_a_leaked_secret() {
        // Leaf derivation is domain-separated from the ratchet step, so an
        // epoch's secret must not equal the seed that produced it.
        let seed = PrekeySeed::generate(100).unwrap();
        let raw = seed.seed();
        let secret = leaf(&raw);
        assert_ne!(secret, *raw);
        assert_ne!(secret, advance(&raw));
    }

    #[test]
    fn derivation_is_bounded() {
        let seed = PrekeySeed::generate(0).unwrap();
        assert!(matches!(
            seed.public(MAX_DERIVATION_SPAN + 1),
            Err(CryptoError::EpochTooFar { .. })
        ));
    }

    #[test]
    fn a_restored_seed_agrees_with_the_original() {
        let original = PrekeySeed::generate(42).unwrap();
        let restored = PrekeySeed::from_parts(*original.seed(), original.epoch());
        assert_eq!(original.public(50).unwrap(), restored.public(50).unwrap());
    }

    #[test]
    fn debug_does_not_leak_the_seed() {
        let seed = PrekeySeed::generate(7).unwrap();
        let hex: String = seed.seed().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!format!("{seed:?}").contains(&hex));
    }
}
