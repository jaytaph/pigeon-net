//! The keystore: private key material, sealed at rest (D9).
//!
//! Key material is encrypted under a passphrase-derived key, always, with no
//! opt-out. The root key especially: recovery is a mechanism, not a rescue
//! service (§5.5), so losing this file ends the identity and leaking it ends
//! everything.
//!
//! File layout, all little-endian:
//!
//! ```text
//! magic        8 bytes   "PGNKEY\0\0"
//! version      1 byte
//! memory_kib   4 bytes   Argon2id cost parameters
//! iterations   4 bytes
//! parallelism  4 bytes
//! salt        16 bytes   Argon2id salt
//! nonce       12 bytes   ChaCha20-Poly1305 nonce
//! ciphertext + 16-byte tag
//! ```
//!
//! The header is authenticated as associated data, so nothing in it can be
//! swapped for another file's without the tag failing.
//!
//! # Why the cost parameters are in the file
//!
//! They used to be compile-time constants, which quietly made every keystore
//! readable only by a build that agreed with it. Two consequences, both bad: the
//! production parameters could never be raised without orphaning every existing
//! file, and tests had no way to use cheap ones without producing keystores the
//! real binary could not open.
//!
//! Recording them costs twelve bytes and removes both problems. A file says how
//! it was sealed and anyone can open it. There is no downgrade to worry about:
//! the parameters are authenticated, and editing them yields a different key and
//! a failed tag.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload as AeadPayload},
};
use minicbor::{Decode, Encode};
use pigeonnet_core::cbor;
use zeroize::Zeroizing;

use crate::{AgreementKeypair, CryptoError, SigningKeypair};

const MAGIC: &[u8; 8] = b"PGNKEY\0\0";
const VERSION: u8 = 3;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const COST_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 1 + COST_LEN + SALT_LEN + NONCE_LEN;

/// The format before the cost parameters were recorded.
///
/// Version 2 keystores exist on real machines, including a node serving on a
/// public address, so they are still opened. They are read with the cost that
/// was compiled in at the time — which is what they were sealed with, because
/// there was no other option — and re-sealed as version 3 the next time anything
/// writes them.
const VERSION_V2: u8 = 2;
const HEADER_LEN_V2: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;

/// Argon2id cost parameters, as recorded in a keystore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost, in kibibytes.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Lanes. One, unless there is a reason.
    pub parallelism: u32,
}

impl KdfParams {
    /// What a real keystore is sealed with.
    ///
    /// 64 MiB and three passes: enough that guessing a passphrase against a
    /// stolen file is expensive, while a legitimate unlock stays under a second
    /// on the Raspberry Pi-class hardware this system claims to run on (§1).
    pub const PRODUCTION: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    /// Cost parameters that provide **no meaningful resistance**, for tests.
    ///
    /// At production cost a single derive takes about 1.7 seconds in a debug
    /// build, and the suite opens keystores hundreds of times; this turns that
    /// into well under a millisecond. The name is deliberately unpleasant, and it
    /// is a function rather than a constant, so that every use is visible in a
    /// diff and none of them can be reached by accident or by a feature flag
    /// somebody else enabled.
    ///
    /// A keystore sealed with these is readable by anyone who has the file. Never
    /// use it for an identity that matters.
    #[must_use]
    pub const fn insecure_for_tests() -> Self {
        Self {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Whether these are the parameters a real keystore should have.
    #[must_use]
    pub const fn is_production(self) -> bool {
        self.memory_kib >= Self::PRODUCTION.memory_kib
            && self.iterations >= Self::PRODUCTION.iterations
    }
}

/// The private half of an identity, as held on one node.
///
/// The **recovery key is deliberately absent**. It is generated at genesis,
/// shown once, and never written here — a recovery key stored beside the root
/// key it is meant to outrank would protect against nothing (D11).
#[derive(Encode, Decode)]
#[cbor(map)]
pub struct Keyring {
    /// Seed of the root key, which signs key management only (§5.4).
    #[cbor(n(0), with = "minicbor::bytes")]
    root_seed: [u8; 32],

    /// Seed of this device's key, which signs everything else.
    #[cbor(n(1), with = "minicbor::bytes")]
    device_seed: [u8; 32],

    /// The long-term X25519 secret, used only for the `fs: none` fallback
    /// (§8.1).
    #[cbor(n(2), with = "minicbor::bytes")]
    agreement_secret: [u8; 32],

    /// The ratcheting seed every epoch prekey secret derives from (§8.1).
    ///
    /// One value rather than one secret per epoch, so that destroying an epoch
    /// is a ratchet step rather than a file deletion the storage layer may
    /// quietly decline to perform.
    #[cbor(n(3), with = "minicbor::bytes")]
    prekey_seed: [u8; 32],

    /// The earliest epoch `prekey_seed` can still produce. Everything before it
    /// has been ratcheted away.
    #[n(4)]
    prekey_epoch: u64,

    /// The first epoch `prekey_seed` cannot reach (D16).
    ///
    /// Optional because keyrings written before D16 do not have it. Absent means
    /// "bound this seed to the window its epoch falls in" — which gives a legacy
    /// identity the bound immediately, at the cost that it has no cold half and so
    /// cannot open the next window.
    #[n(5)]
    prekey_window_end: Option<u64>,

    /// The outgoing window, kept only for retention (D16).
    ///
    /// Fields 3–5 are the *current* window; these three are the one before it.
    /// Two is provably enough — see [`PrekeyWindows`](crate::PrekeyWindows) — and
    /// absent simply means there is no outgoing window, which is the case for a
    /// new identity and after the old one has been fully ratcheted away.
    #[cbor(n(6), with = "minicbor::bytes")]
    previous_prekey_seed: Option<[u8; 32]>,

    /// The earliest epoch `previous_prekey_seed` can still produce.
    #[n(7)]
    previous_prekey_epoch: Option<u64>,

    /// The first epoch `previous_prekey_seed` cannot reach.
    #[n(8)]
    previous_prekey_window_end: Option<u64>,
}

impl Keyring {
    /// Assemble from generated keys.
    #[must_use]
    pub fn new(
        root: &SigningKeypair,
        device: &SigningKeypair,
        agreement: &AgreementKeypair,
        prekeys: &crate::PrekeyWindows,
    ) -> Self {
        Self {
            root_seed: *root.seed(),
            device_seed: *device.seed(),
            agreement_secret: *agreement.secret(),
            prekey_seed: *prekeys.current().seed(),
            prekey_epoch: prekeys.current().epoch(),
            prekey_window_end: Some(prekeys.current().window_end()),
            previous_prekey_seed: prekeys.previous().map(|p| *p.seed()),
            previous_prekey_epoch: prekeys.previous().map(crate::PrekeySeed::epoch),
            previous_prekey_window_end: prekeys.previous().map(crate::PrekeySeed::window_end),
        }
    }

    /// The root key.
    #[must_use]
    pub fn root(&self) -> SigningKeypair {
        SigningKeypair::from_seed(&self.root_seed)
    }

    /// This device's key.
    #[must_use]
    pub fn device(&self) -> SigningKeypair {
        SigningKeypair::from_seed(&self.device_seed)
    }

    /// The long-term agreement key.
    #[must_use]
    pub fn agreement(&self) -> AgreementKeypair {
        AgreementKeypair::from_secret(&self.agreement_secret)
    }

    /// The epoch prekey windows this node holds.
    #[must_use]
    pub fn prekeys(&self) -> crate::PrekeyWindows {
        // A keyring from before D16 is bounded to the window its epoch falls in,
        // rather than left unbounded: an old file must not keep the old exposure
        // simply because it predates the rule.
        let window_end = self.prekey_window_end.unwrap_or_else(|| {
            crate::prekey::window_start(crate::prekey::window_of(self.prekey_epoch))
                .saturating_add(crate::prekey::EPOCHS_PER_WINDOW)
        });
        let current =
            crate::PrekeySeed::from_parts(self.prekey_seed, self.prekey_epoch, window_end);
        let previous = match (
            self.previous_prekey_seed,
            self.previous_prekey_epoch,
            self.previous_prekey_window_end,
        ) {
            (Some(seed), Some(epoch), Some(end)) => {
                Some(crate::PrekeySeed::from_parts(seed, epoch, end))
            }
            // Anything less than all three is no outgoing window. A partially
            // written one would be a seed that cannot say what it covers.
            _ => None,
        };
        crate::PrekeyWindows::from_parts(current, previous)
    }

    /// Replace the prekey seed, after ratcheting it forward.
    ///
    /// The caller re-seals the keystore; until it does, the destroyed epochs are
    /// only destroyed in memory.
    pub fn set_prekeys(&mut self, prekeys: &crate::PrekeyWindows) {
        self.prekey_seed = *prekeys.current().seed();
        self.prekey_epoch = prekeys.current().epoch();
        self.prekey_window_end = Some(prekeys.current().window_end());
        self.previous_prekey_seed = prekeys.previous().map(|p| *p.seed());
        self.previous_prekey_epoch = prekeys.previous().map(crate::PrekeySeed::epoch);
        self.previous_prekey_window_end = prekeys.previous().map(crate::PrekeySeed::window_end);
    }

    /// Seal under a passphrase, at production cost.
    pub fn seal(&self, passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seal_with(passphrase, KdfParams::PRODUCTION)
    }

    /// Seal under a passphrase at a chosen cost.
    ///
    /// The cost is recorded in the file, so whatever is chosen here does not
    /// limit who can open the result.
    pub fn seal_with(&self, passphrase: &[u8], params: KdfParams) -> Result<Vec<u8>, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::Entropy)?;
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Entropy)?;

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&params.memory_kib.to_le_bytes());
        header.extend_from_slice(&params.iterations.to_le_bytes());
        header.extend_from_slice(&params.parallelism.to_le_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let plaintext = Zeroizing::new(cbor::to_canonical_vec(self)?);
        let key = derive_key(passphrase, &salt, params)?;
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                AeadPayload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| CryptoError::KeystoreUnreadable)?;

        let mut out = header;
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a sealed keystore, and report the cost it was sealed at.
    pub fn open_with_params(
        sealed: &[u8],
        passphrase: &[u8],
    ) -> Result<(Self, KdfParams), CryptoError> {
        let params = Self::params_of(sealed)?;
        Ok((Self::open(sealed, passphrase)?, params))
    }

    /// The header length and cost of a sealed keystore, by version.
    fn layout(sealed: &[u8]) -> Result<(usize, KdfParams), CryptoError> {
        if sealed.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(CryptoError::KeystoreFormat);
        }
        match sealed.get(MAGIC.len()) {
            Some(&VERSION) => Ok((HEADER_LEN, Self::params_of(sealed)?)),
            // Version 2 predates recorded costs; it was always production.
            Some(&VERSION_V2) => Ok((HEADER_LEN_V2, KdfParams::PRODUCTION)),
            _ => Err(CryptoError::KeystoreFormat),
        }
    }

    /// The cost parameters a sealed keystore records, without opening it.
    pub fn params_of(sealed: &[u8]) -> Result<KdfParams, CryptoError> {
        if sealed.get(MAGIC.len()) == Some(&VERSION_V2) {
            return Ok(KdfParams::PRODUCTION);
        }
        let header = sealed
            .get(..HEADER_LEN)
            .ok_or(CryptoError::KeystoreFormat)?;
        if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(CryptoError::KeystoreFormat);
        }
        if header.get(MAGIC.len()) != Some(&VERSION) {
            return Err(CryptoError::KeystoreFormat);
        }
        let at = |offset: usize| -> Result<u32, CryptoError> {
            header
                .get(offset..offset + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(CryptoError::KeystoreFormat)
        };
        let base = MAGIC.len() + 1;
        Ok(KdfParams {
            memory_kib: at(base)?,
            iterations: at(base + 4)?,
            parallelism: at(base + 8)?,
        })
    }

    /// Open a sealed keystore, of any supported version.
    pub fn open(sealed: &[u8], passphrase: &[u8]) -> Result<Self, CryptoError> {
        // The cost is taken from the file, not from a constant here: that is what
        // lets a keystore outlive a change to the default, and what lets a test
        // seal cheaply without producing something the real binary cannot open.
        let (header_len, params) = Self::layout(sealed)?;
        let header = sealed
            .get(..header_len)
            .ok_or(CryptoError::KeystoreFormat)?;
        let body = sealed
            .get(header_len..)
            .ok_or(CryptoError::KeystoreFormat)?;

        let salt_at = header_len - SALT_LEN - NONCE_LEN;
        let salt = header
            .get(salt_at..salt_at + SALT_LEN)
            .ok_or(CryptoError::KeystoreFormat)?;
        let nonce: [u8; NONCE_LEN] = header
            .get(salt_at + SALT_LEN..)
            .and_then(|n| n.try_into().ok())
            .ok_or(CryptoError::KeystoreFormat)?;

        let key = derive_key(passphrase, salt, params)?;
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    (&nonce).into(),
                    AeadPayload {
                        msg: body,
                        aad: header,
                    },
                )
                .map_err(|_| CryptoError::KeystoreUnreadable)?,
        );

        cbor::from_canonical_slice(&plaintext).map_err(|_| CryptoError::KeystoreUnreadable)
    }
}

impl core::fmt::Debug for Keyring {
    /// Names the keys it holds, never their contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("root", &self.root().public())
            .field("device", &self.device().public())
            .field("agreement", &self.agreement().public())
            .field("prekey_epoch", &self.prekey_epoch)
            .finish()
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.root_seed.zeroize();
        self.device_seed.zeroize();
        self.agreement_secret.zeroize();
        self.prekey_seed.zeroize();
        if let Some(seed) = self.previous_prekey_seed.as_mut() {
            seed.zeroize();
        }
    }
}

/// Derive the storage key from a passphrase.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    cost: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = argon2::Params::new(cost.memory_kib, cost.iterations, cost.parallelism, Some(32))
        .map_err(|_| CryptoError::KeystoreFormat)?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| CryptoError::KeystoreUnreadable)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Keyring {
        /// Seal at a cost that keeps the suite usable. See the tests below for
        /// what guarantees this does and does not preserve.
        fn seal_with_test(&self, passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.seal_with(passphrase, KdfParams::insecure_for_tests())
        }
    }

    fn keyring() -> Keyring {
        Keyring::new(
            &SigningKeypair::generate().unwrap(),
            &SigningKeypair::generate().unwrap(),
            &AgreementKeypair::generate().unwrap(),
            &crate::PrekeyWindows::new(crate::PrekeySeed::generate(100).unwrap()),
        )
    }

    /// Seal in the version 2 layout: no recorded cost, always production.
    ///
    /// Reproduces the old writer exactly, so the compatibility test below is
    /// checking the real thing rather than a reimplementation that drifted.
    fn seal_v2(keyring: &Keyring, passphrase: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).unwrap();
        getrandom::fill(&mut nonce).unwrap();

        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.push(VERSION_V2);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let plaintext = cbor::to_canonical_vec(keyring).unwrap();
        let key = derive_key(passphrase, &salt, KdfParams::PRODUCTION).unwrap();
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                AeadPayload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        let mut out = header;
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn a_version_2_keystore_still_opens() {
        // Version 2 files exist on real machines, one of them serving on a public
        // address. Bumping the format must not lock anybody out of their identity,
        // which cannot be recreated -- recovery is not built yet (D11, M8).
        let ring = keyring();
        let root = ring.root().public();
        let sealed = seal_v2(&ring, b"correct horse");

        assert_eq!(sealed[MAGIC.len()], VERSION_V2);
        assert_eq!(sealed.len(), HEADER_LEN_V2 + (sealed.len() - HEADER_LEN_V2));
        assert_eq!(Keyring::params_of(&sealed).unwrap(), KdfParams::PRODUCTION);

        let opened = Keyring::open(&sealed, b"correct horse").unwrap();
        assert_eq!(opened.root().public(), root);

        // And a wrong passphrase is still a wrong passphrase, not a format error.
        assert!(matches!(
            Keyring::open(&sealed, b"wrong"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn re_sealing_moves_a_version_2_keystore_forward() {
        let ring = keyring();
        let v2 = seal_v2(&ring, b"p");
        let opened = Keyring::open(&v2, b"p").unwrap();
        let v3 = opened.seal_with(b"p", KdfParams::PRODUCTION).unwrap();
        assert_eq!(v3[MAGIC.len()], VERSION);
        assert_eq!(
            Keyring::open(&v3, b"p").unwrap().root().public(),
            ring.root().public()
        );
    }

    #[test]
    fn the_default_cost_is_the_production_cost() {
        // Asserted rather than derived: the point is that nothing in the test
        // configuration can quietly lower what a real keystore is sealed with.
        assert_eq!(KdfParams::PRODUCTION.memory_kib, 65_536);
        assert_eq!(KdfParams::PRODUCTION.iterations, 3);
        assert!(KdfParams::PRODUCTION.is_production());
        assert!(!KdfParams::insecure_for_tests().is_production());
    }

    #[test]
    fn the_cost_is_recorded_and_survives_a_round_trip() {
        let cheap = KdfParams::insecure_for_tests();
        let sealed = keyring().seal_with(b"p", cheap).unwrap();
        assert_eq!(Keyring::params_of(&sealed).unwrap(), cheap);

        // The whole point: a file sealed cheaply is still openable by a caller
        // that knows nothing about the cost, because the file carries it. Without
        // this, a test-built keystore would be unreadable by the real binary.
        assert!(Keyring::open(&sealed, b"p").is_ok());
        let (_, params) = Keyring::open_with_params(&sealed, b"p").unwrap();
        assert_eq!(params, cheap);
    }

    #[test]
    fn the_recorded_cost_cannot_be_edited() {
        // Lowering the cost on a stolen file, to make guessing cheaper, must not
        // yield a file that opens. The edited value is a *valid* Argon2 cost, so
        // this exercises the authentication rather than a parameter range check:
        // the header is associated data, and the key derives from it, so either
        // way the tag fails.
        let cheap = KdfParams::insecure_for_tests();
        let mut sealed = keyring().seal_with(b"p", cheap).unwrap();
        let at = MAGIC.len() + 1;
        let raised = cheap.memory_kib * 2;
        sealed[at..at + 4].copy_from_slice(&raised.to_le_bytes());
        assert!(matches!(
            Keyring::open(&sealed, b"p"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn a_cost_argon2_will_not_accept_is_a_format_error() {
        // Distinct from the case above: nonsense in the header is rejected before
        // any derivation is attempted, rather than being reported as a bad
        // passphrase.
        let mut sealed = keyring()
            .seal_with(b"p", KdfParams::insecure_for_tests())
            .unwrap();
        let at = MAGIC.len() + 1;
        sealed[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            Keyring::open(&sealed, b"p"),
            Err(CryptoError::KeystoreFormat)
        ));
    }

    #[test]
    fn seals_and_opens() {
        let original = keyring();
        let root = original.root().public();
        let sealed = original.seal_with_test(b"correct horse").unwrap();
        let opened = Keyring::open(&sealed, b"correct horse").unwrap();
        assert_eq!(opened.root().public(), root);
    }

    #[test]
    fn the_prekey_seed_survives_a_round_trip() {
        let original = keyring();
        // 103, not 105: epoch 100's window ends at 104 (D16).
        let public = original.prekeys().public(103).unwrap();
        let sealed = original.seal_with_test(b"p").unwrap();
        let opened = Keyring::open(&sealed, b"p").unwrap();
        assert_eq!(opened.prekeys().public(103).unwrap(), public);
        assert_eq!(opened.prekeys().current().epoch(), 100);
        // And the window bound survives the round trip, or it would be lost the
        // first time the keystore was rewritten.
        assert_eq!(
            opened.prekeys().current().window_end(),
            original.prekeys().current().window_end()
        );
    }

    #[test]
    fn both_windows_survive_a_round_trip() {
        // Three new CBOR fields carry the outgoing window. If any of them is lost
        // in a round trip, rotating destroys live mail -- which is the whole
        // failure the two-window design exists to prevent.
        let mut windows = crate::PrekeyWindows::new(crate::PrekeySeed::generate(100).unwrap());
        let old_public = windows.public(103).unwrap();

        let cold = crate::ColdSeed::generate().unwrap();
        windows
            .install(cold.open_window(crate::window_of(104)))
            .unwrap();
        let new_public = windows.public(104).unwrap();

        let mut ring = keyring();
        ring.set_prekeys(&windows);
        let sealed = ring.seal_with_test(b"p").unwrap();
        let opened = Keyring::open(&sealed, b"p").unwrap();
        let restored = opened.prekeys();

        assert_eq!(
            restored.public(104).unwrap(),
            new_public,
            "current window lost"
        );
        assert_eq!(
            restored.public(103).unwrap(),
            old_public,
            "outgoing window lost"
        );
        assert!(restored.previous().is_some());
    }

    #[test]
    fn a_keyring_with_no_outgoing_window_round_trips_too() {
        let windows = crate::PrekeyWindows::new(crate::PrekeySeed::generate(100).unwrap());
        let mut ring = keyring();
        ring.set_prekeys(&windows);
        let sealed = ring.seal_with_test(b"p").unwrap();
        let opened = Keyring::open(&sealed, b"p").unwrap();
        assert!(opened.prekeys().previous().is_none());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let sealed = keyring().seal_with_test(b"correct horse").unwrap();
        assert!(matches!(
            Keyring::open(&sealed, b"correct horst"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn tampering_with_the_header_fails() {
        // The salt is authenticated, so editing it must not merely produce a
        // different key -- it must fail the tag.
        let mut sealed = keyring().seal_with_test(b"passphrase").unwrap();
        sealed[10] ^= 0x01;
        assert!(matches!(
            Keyring::open(&sealed, b"passphrase"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_fails() {
        let mut sealed = keyring().seal_with_test(b"passphrase").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            Keyring::open(&sealed, b"passphrase"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn rejects_foreign_format() {
        assert!(matches!(
            Keyring::open(b"not a keystore", b"x"),
            Err(CryptoError::KeystoreFormat)
        ));
        assert!(matches!(
            Keyring::open(&[], b"x"),
            Err(CryptoError::KeystoreFormat)
        ));
    }

    #[test]
    fn sealed_bytes_do_not_contain_the_key() {
        let original = keyring();
        let seed = original.root().seed();
        let sealed = original.seal_with_test(b"passphrase").unwrap();
        assert!(
            !sealed.windows(32).any(|w| w == seed.as_slice()),
            "root seed appears in the sealed file"
        );
    }

    #[test]
    fn two_seals_differ() {
        // Fresh salt and nonce each time, so identical input must not give
        // identical output.
        let ring = keyring();
        assert_ne!(
            ring.seal_with_test(b"p").unwrap(),
            ring.seal_with_test(b"p").unwrap()
        );
    }

    #[test]
    fn debug_does_not_leak() {
        let ring = keyring();
        let seed_hex: String = ring
            .root()
            .seed()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!format!("{ring:?}").contains(&seed_hex));
    }
}
