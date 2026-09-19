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
//! # Why the ratchet is not enough, and what bounds it (D16)
//!
//! A ratchet runs one way, which settles the past and says nothing about the
//! future: holding `seed(n)` yields every epoch from `n` **forward**. The first
//! version of this file bounded that with `MAX_DERIVATION_SPAN`, a constant
//! introduced to stop a caller spending an afternoon on a hash chain. At daily
//! epochs it also, silently, set the security parameter to about eleven years — a
//! stolen keystore was a standing wiretap rather than a historical leak.
//!
//! D16 splits the seed. A **cold half** lives off the machine; the **warm seed**
//! on the node covers one window and refuses anything at or past its end:
//!
//! ```text
//!   cold ──derive(window w)──> warm seed ──ratchet──> ... ──> window_end
//!    │                                                            │
//!    └──derive(window w+1)──> next warm seed                    refused
//! ```
//!
//! So a leaked node backup opens the remainder of one window rather than every
//! epoch anyone will ever seal to. Crossing into the next window is a deliberate
//! act with the cold half, and a node that has not done it degrades to
//! `fs: none` (§8.1) rather than breaking.

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

/// Epochs one derivation window covers.
///
/// Thirteen weekly epochs — a quarter. This is the exposure of a stolen keystore,
/// so it is policy and not a tuning knob: shrinking it means crossing windows
/// more often, and every crossing needs material that is deliberately awkward to
/// reach.
pub const EPOCHS_PER_WINDOW: u64 = 13;

/// Domain separator for deriving a window's warm seed from the cold half.
const WINDOW_CONTEXT: &str = "pigeonnet prekey-window v1";

/// Which window an epoch falls in.
#[must_use]
pub const fn window_of(epoch: u64) -> u64 {
    epoch / EPOCHS_PER_WINDOW
}

/// The first epoch of a window.
#[must_use]
pub const fn window_start(window: u64) -> u64 {
    window * EPOCHS_PER_WINDOW
}

/// The cold half of the prekey seed (D16).
///
/// Generated once, displayed once, and **never written to the keystore** — a cold
/// half stored beside the warm seed it bounds would bound nothing, which is the
/// same reasoning that keeps the recovery key out of the keystore (D11).
pub struct ColdSeed([u8; 32]);

impl ColdSeed {
    /// A fresh cold half.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Entropy)?;
        Ok(Self(seed))
    }

    /// Reconstruct from transcribed material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes, for display once at genesis.
    #[must_use]
    pub fn as_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }

    /// Open the window containing `epoch`.
    ///
    /// Deterministic: the same cold half always yields the same warm seed for the
    /// same window, so a window can be reopened after a restore without
    /// invalidating prekeys already published from it.
    #[must_use]
    pub fn open_window(&self, window: u64) -> PrekeySeed {
        let mut hasher = Hasher::new_derive_key(WINDOW_CONTEXT);
        hasher.update(&self.0);
        hasher.update(&window.to_le_bytes());
        let seed = *hasher.finalize().as_bytes();
        let start = window_start(window);
        PrekeySeed {
            seed,
            epoch: start,
            window_end: start.saturating_add(EPOCHS_PER_WINDOW),
        }
    }
}

impl Drop for ColdSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for ColdSeed {
    /// Never its contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ColdSeed(..)")
    }
}

/// A ratcheting source of epoch prekey secrets, bounded to one window (D16).
///
/// Held in the keystore as `(seed, epoch, window_end)`. Secrets before `epoch`
/// are unrecoverable because the ratchet runs one way; secrets at or after
/// `window_end` are unreachable because deriving them needs the cold half.
pub struct PrekeySeed {
    seed: [u8; 32],
    epoch: u64,
    window_end: u64,
}

impl PrekeySeed {
    /// A fresh seed covering the window that contains `epoch`.
    ///
    /// Used only where no cold half exists — a legacy keystore being carried
    /// forward. A new identity derives its warm seed from a [`ColdSeed`] instead,
    /// so that it can open the next window when the time comes.
    pub fn generate(epoch: u64) -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| CryptoError::Entropy)?;
        let start = window_start(window_of(epoch));
        Ok(Self {
            seed,
            epoch,
            window_end: start.saturating_add(EPOCHS_PER_WINDOW),
        })
    }

    /// Reconstruct from stored material.
    #[must_use]
    pub const fn from_parts(seed: [u8; 32], epoch: u64, window_end: u64) -> Self {
        Self {
            seed,
            epoch,
            window_end,
        }
    }

    /// The first epoch this seed cannot reach.
    #[must_use]
    pub const fn window_end(&self) -> u64 {
        self.window_end
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
        // The window bound, and the reason this type exists in this shape (D16).
        if epoch >= self.window_end {
            return Err(CryptoError::EpochBeyondWindow {
                epoch,
                window_end: self.window_end,
            });
        }
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

/// The windows a node must hold at once (D16).
///
/// **Two, and provably never more.** An epoch's secret is needed until its epoch
/// ends plus the retention window `W` (thirty days by default, D4). A window is a
/// quarter. So when window `w+1` opens, window `w` is still needed for another
/// thirty days — but never into `w+2`, because thirty days is shorter than a
/// quarter.
///
/// Getting this wrong is not a theoretical matter. An earlier version of this
/// code held one window and *replaced* it on rotation, which meant an operator
/// rotating at the sensible moment — before the current window ran out —
/// instantly lost the ability to read mail sealed to epochs that were still live
/// and whose public halves were already published. The mail was undecryptable and
/// nothing said so.
pub struct PrekeyWindows {
    current: PrekeySeed,
    previous: Option<PrekeySeed>,
}

impl PrekeyWindows {
    /// Hold a single window. What a fresh identity starts with.
    #[must_use]
    pub const fn new(current: PrekeySeed) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// Reconstruct from stored material.
    #[must_use]
    pub const fn from_parts(current: PrekeySeed, previous: Option<PrekeySeed>) -> Self {
        Self { current, previous }
    }

    /// The window prekeys are published from.
    #[must_use]
    pub const fn current(&self) -> &PrekeySeed {
        &self.current
    }

    /// The window being kept alive only for retention, if there is one.
    #[must_use]
    pub const fn previous(&self) -> Option<&PrekeySeed> {
        self.previous.as_ref()
    }

    /// Take a newly opened window into use, keeping the outgoing one for retention.
    ///
    /// Opening the window already current is idempotent. Opening one *behind* the
    /// current is refused: that is a request to resurrect destroyed epochs.
    pub fn install(&mut self, window: PrekeySeed) -> Result<(), CryptoError> {
        if window.window_end() == self.current.window_end() {
            return Ok(());
        }
        if window.window_end() < self.current.window_end() {
            return Err(CryptoError::EpochDestroyed {
                epoch: window.epoch(),
                earliest: self.current.epoch(),
            });
        }
        let outgoing = core::mem::replace(&mut self.current, window);
        self.previous = Some(outgoing);
        Ok(())
    }

    /// The keypair for an epoch, from whichever held window covers it.
    pub fn keypair(&self, epoch: u64) -> Result<AgreementKeypair, CryptoError> {
        // Current first: it is the common case, and the one publishing uses.
        match self.current.keypair(epoch) {
            Ok(pair) => Ok(pair),
            Err(current_error) => match self.previous.as_ref() {
                Some(previous) => previous.keypair(epoch).map_err(|_| current_error),
                None => Err(current_error),
            },
        }
    }

    /// The public half for an epoch.
    pub fn public(&self, epoch: u64) -> Result<AgreementKeyBytes, CryptoError> {
        Ok(self.keypair(epoch)?.public())
    }

    /// Destroy every secret before `epoch`, dropping a window once it is spent.
    ///
    /// Returns how many epoch secrets were destroyed.
    pub fn ratchet_to(&mut self, epoch: u64) -> Result<u64, CryptoError> {
        let mut destroyed = 0;
        if let Some(previous) = self.previous.as_mut() {
            // A window whose epochs are all gone is dropped rather than carried
            // as a seed that can no longer produce anything.
            let target = epoch.min(previous.window_end());
            destroyed += previous.ratchet_to(target)?;
            if target >= previous.window_end() {
                self.previous = None;
            }
        }
        let target = epoch.min(self.current.window_end());
        destroyed += self.current.ratchet_to(target)?;
        Ok(destroyed)
    }

    /// The earliest epoch any held window can still produce.
    #[must_use]
    pub fn earliest(&self) -> u64 {
        match self.previous.as_ref() {
            Some(previous) => previous.epoch().min(self.current.epoch()),
            None => self.current.epoch(),
        }
    }
}

impl core::fmt::Debug for PrekeyWindows {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrekeyWindows")
            .field("current", &self.current)
            .field("previous", &self.previous)
            .finish()
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn a_window_covers_exactly_its_own_epochs() {
        let cold = ColdSeed::generate().unwrap();
        let seed = cold.open_window(4);
        let start = window_start(4);

        assert_eq!(seed.epoch(), start);
        assert_eq!(seed.window_end(), start + EPOCHS_PER_WINDOW);

        // Every epoch inside the window derives.
        for epoch in start..start + EPOCHS_PER_WINDOW {
            assert!(seed.public(epoch).is_ok(), "epoch {epoch} inside refused");
        }
        // The first epoch of the next window does not, and says why.
        assert!(matches!(
            seed.public(start + EPOCHS_PER_WINDOW),
            Err(CryptoError::EpochBeyondWindow { .. })
        ));
    }

    #[test]
    fn the_bound_is_the_point_and_is_not_the_compute_guard() {
        // Before D16 the only forward limit was MAX_DERIVATION_SPAN, which is
        // thousands of epochs. The window must bite long before it does.
        let cold = ColdSeed::generate().unwrap();
        let seed = cold.open_window(0);
        const { assert!(EPOCHS_PER_WINDOW < MAX_DERIVATION_SPAN) };
        assert!(matches!(
            seed.public(MAX_DERIVATION_SPAN - 1),
            Err(CryptoError::EpochBeyondWindow { .. })
        ));
    }

    #[test]
    fn opening_the_same_window_twice_gives_the_same_keys() {
        // Required for restore: reopening a window must not invalidate prekeys
        // already published from it.
        let cold = ColdSeed::generate().unwrap();
        let first = cold.open_window(7);
        let again = cold.open_window(7);
        let epoch = window_start(7) + 3;
        assert_eq!(first.public(epoch).unwrap(), again.public(epoch).unwrap());
    }

    #[test]
    fn different_windows_are_unrelated() {
        let cold = ColdSeed::generate().unwrap();
        let a = cold.open_window(1);
        let b = cold.open_window(2);
        // No shared epoch to compare, so compare the seeds themselves.
        assert_ne!(*a.seed(), *b.seed());
    }

    #[test]
    fn a_warm_seed_cannot_reach_the_next_window() {
        // The whole guarantee: holding the warm seed for window 3 tells you
        // nothing about window 4, so a stolen keystore stops at the boundary.
        let cold = ColdSeed::generate().unwrap();
        let warm = cold.open_window(3);
        let next = cold.open_window(4);

        let mut ratcheted = PrekeySeed::from_parts(*warm.seed(), warm.epoch(), u64::MAX);
        ratcheted.ratchet_to(window_start(4)).unwrap();
        assert_ne!(
            ratcheted.public(window_start(4)).unwrap(),
            next.public(window_start(4)).unwrap(),
            "ratcheting past the boundary reproduced the next window"
        );
    }

    #[test]
    fn different_cold_halves_share_nothing() {
        let a = ColdSeed::generate().unwrap();
        let b = ColdSeed::generate().unwrap();
        assert_ne!(*a.open_window(0).seed(), *b.open_window(0).seed());
    }

    #[test]
    fn the_cold_half_is_not_in_its_own_debug_output() {
        let cold = ColdSeed::generate().unwrap();
        let hex: String = cold.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!format!("{cold:?}").contains(&hex));
    }

    #[test]
    fn window_arithmetic_is_consistent() {
        for epoch in 0u64..60 {
            let w = window_of(epoch);
            assert!(window_start(w) <= epoch);
            assert!(epoch < window_start(w) + EPOCHS_PER_WINDOW);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_epochs_keypair_is_stable() {
        let seed = PrekeySeed::generate(100).unwrap();
        // 103 rather than 105: epoch 100 sits in the window ending at 104 (D16).
        assert_eq!(seed.public(103).unwrap(), seed.public(103).unwrap());
    }

    #[test]
    fn different_epochs_give_different_keys() {
        let seed = PrekeySeed::generate(100).unwrap();
        assert_ne!(seed.public(100).unwrap(), seed.public(101).unwrap());
    }

    #[test]
    fn ratcheting_preserves_later_epochs() {
        let mut seed = PrekeySeed::generate(100).unwrap();
        // Within the window containing 100, which ends at 104.
        let later = seed.public(103).unwrap();
        assert_eq!(seed.ratchet_to(102).unwrap(), 2);
        assert_eq!(seed.public(103).unwrap(), later, "epoch 103 survives");
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
        // Two different bounds, and which one fires matters.
        //
        // The window is the security bound and must fire first (D16). The compute
        // guard is now only a backstop, reachable only by a seed with an absurd
        // window, and it is kept because `keypair` walks a hash chain and a caller
        // asking for an epoch a century away should not be obliged.
        let windowed = PrekeySeed::generate(0).unwrap();
        assert!(matches!(
            windowed.public(MAX_DERIVATION_SPAN + 1),
            Err(CryptoError::EpochBeyondWindow { .. })
        ));

        let unbounded = PrekeySeed::from_parts([3u8; 32], 0, u64::MAX);
        assert!(matches!(
            unbounded.public(MAX_DERIVATION_SPAN + 1),
            Err(CryptoError::EpochTooFar { .. })
        ));
    }

    #[test]
    fn a_restored_seed_agrees_with_the_original() {
        let original = PrekeySeed::generate(42).unwrap();
        let restored =
            PrekeySeed::from_parts(*original.seed(), original.epoch(), original.window_end());
        assert_eq!(original.public(50).unwrap(), restored.public(50).unwrap());
    }

    #[test]
    fn debug_does_not_leak_the_seed() {
        let seed = PrekeySeed::generate(7).unwrap();
        let hex: String = seed.seed().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!format!("{seed:?}").contains(&hex));
    }
}
