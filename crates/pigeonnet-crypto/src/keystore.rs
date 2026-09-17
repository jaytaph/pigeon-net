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
//! magic    8 bytes   "PGNKEY\0\0"
//! version  1 byte
//! salt    16 bytes   Argon2id salt
//! nonce   12 bytes   ChaCha20-Poly1305 nonce
//! ciphertext + 16-byte tag
//! ```
//!
//! The header is authenticated as associated data, so salt and nonce cannot be
//! swapped for another file's without the tag failing.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload as AeadPayload},
};
use minicbor::{Decode, Encode};
use pigeonnet_core::cbor;
use zeroize::Zeroizing;

use crate::{AgreementKeypair, CryptoError, SigningKeypair};

const MAGIC: &[u8; 8] = b"PGNKEY\0\0";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;

/// Argon2id cost parameters.
///
/// 64 MiB and three passes: enough that guessing a passphrase against a stolen
/// file is expensive, while a legitimate unlock stays under a second on the
/// Raspberry Pi-class hardware this system claims to run on (§1).
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;

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

    /// The long-term X25519 secret (§8.1).
    #[cbor(n(2), with = "minicbor::bytes")]
    agreement_secret: [u8; 32],
}

impl Keyring {
    /// Assemble from generated keys.
    #[must_use]
    pub fn new(
        root: &SigningKeypair,
        device: &SigningKeypair,
        agreement: &AgreementKeypair,
    ) -> Self {
        Self {
            root_seed: *root.seed(),
            device_seed: *device.seed(),
            agreement_secret: *agreement.secret(),
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

    /// The agreement key.
    #[must_use]
    pub fn agreement(&self) -> AgreementKeypair {
        AgreementKeypair::from_secret(&self.agreement_secret)
    }

    /// Seal under a passphrase.
    pub fn seal(&self, passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::Entropy)?;
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Entropy)?;

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let plaintext = Zeroizing::new(cbor::to_canonical_vec(self)?);
        let key = derive_key(passphrase, &salt)?;
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

    /// Open a sealed keystore.
    pub fn open(sealed: &[u8], passphrase: &[u8]) -> Result<Self, CryptoError> {
        let header = sealed
            .get(..HEADER_LEN)
            .ok_or(CryptoError::KeystoreFormat)?;
        let body = sealed
            .get(HEADER_LEN..)
            .ok_or(CryptoError::KeystoreFormat)?;

        if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(CryptoError::KeystoreFormat);
        }
        if header.get(MAGIC.len()) != Some(&VERSION) {
            return Err(CryptoError::KeystoreFormat);
        }
        let salt = header
            .get(MAGIC.len() + 1..MAGIC.len() + 1 + SALT_LEN)
            .ok_or(CryptoError::KeystoreFormat)?;
        let nonce: [u8; NONCE_LEN] = header
            .get(MAGIC.len() + 1 + SALT_LEN..)
            .and_then(|n| n.try_into().ok())
            .ok_or(CryptoError::KeystoreFormat)?;

        let key = derive_key(passphrase, salt)?;
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
            .finish()
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.root_seed.zeroize();
        self.device_seed.zeroize();
        self.agreement_secret.zeroize();
    }
}

/// Derive the storage key from a passphrase.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params = argon2::Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(32))
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

    fn keyring() -> Keyring {
        Keyring::new(
            &SigningKeypair::generate().unwrap(),
            &SigningKeypair::generate().unwrap(),
            &AgreementKeypair::generate().unwrap(),
        )
    }

    #[test]
    fn seals_and_opens() {
        let original = keyring();
        let root = original.root().public();
        let sealed = original.seal(b"correct horse").unwrap();
        let opened = Keyring::open(&sealed, b"correct horse").unwrap();
        assert_eq!(opened.root().public(), root);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let sealed = keyring().seal(b"correct horse").unwrap();
        assert!(matches!(
            Keyring::open(&sealed, b"correct horst"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn tampering_with_the_header_fails() {
        // The salt is authenticated, so editing it must not merely produce a
        // different key -- it must fail the tag.
        let mut sealed = keyring().seal(b"passphrase").unwrap();
        sealed[10] ^= 0x01;
        assert!(matches!(
            Keyring::open(&sealed, b"passphrase"),
            Err(CryptoError::KeystoreUnreadable)
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_fails() {
        let mut sealed = keyring().seal(b"passphrase").unwrap();
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
        let sealed = original.seal(b"passphrase").unwrap();
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
        assert_ne!(ring.seal(b"p").unwrap(), ring.seal(b"p").unwrap());
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
