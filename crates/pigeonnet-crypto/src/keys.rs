//! Key material.
//!
//! Signing and key agreement use separate keys, always. Ed25519 keys are never
//! converted to X25519 keys via the birational map (D4): cross-protocol key
//! reuse is a footgun that buys thirty-two bytes.

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use pigeonnet_core::{AgreementKeyBytes, PublicKeyBytes, SignatureBytes};
use zeroize::{Zeroize, Zeroizing};

use crate::CryptoError;

/// Fill a buffer with operating-system entropy.
fn entropy(buffer: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buffer).map_err(|_| CryptoError::Entropy)
}

/// An Ed25519 signing key and its public half.
///
/// Used for root keys, recovery keys and device keys alike — they differ in
/// authority, not in kind.
pub struct SigningKeypair(SigningKey);

impl SigningKeypair {
    /// Generate from operating-system entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        entropy(seed.as_mut())?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// Reconstruct from a stored seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The seed, for sealing into a keystore.
    ///
    /// Zeroized when dropped. There is no other way to extract it.
    #[must_use]
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> PublicKeyBytes {
        PublicKeyBytes::from_bytes(self.0.verifying_key().to_bytes())
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        SignatureBytes::from_bytes(self.0.sign(message).to_bytes())
    }
}

impl core::fmt::Debug for SigningKeypair {
    /// Prints the public half only. A `Debug` that leaked a private key would
    /// leak it into logs, backtraces and bug reports.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SigningKeypair")
            .field(&self.public())
            .finish()
    }
}

/// Verify a signature, strictly.
///
/// `verify_strict` rejects small-order and non-canonically-encoded points. The
/// permissive alternative would allow signatures that verify under more than one
/// public key, which in a system where authorship is identity is not a subtlety.
pub fn verify(
    public: PublicKeyBytes,
    message: &[u8],
    signature: SignatureBytes,
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public.as_bytes()).map_err(|_| CryptoError::BadPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    key.verify_strict(message, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// An X25519 key agreement keypair.
///
/// In M1 this exists only so its public half can be published in the genesis
/// object; agreement itself arrives with private messaging (M5).
pub struct AgreementKeypair(x25519_dalek::StaticSecret);

impl AgreementKeypair {
    /// Generate from operating-system entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        entropy(&mut seed)?;
        let keypair = Self(x25519_dalek::StaticSecret::from(seed));
        seed.zeroize();
        Ok(keypair)
    }

    /// Reconstruct from a stored secret.
    #[must_use]
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(*secret))
    }

    /// The secret, for sealing into a keystore.
    #[must_use]
    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> AgreementKeyBytes {
        AgreementKeyBytes::from_bytes(*x25519_dalek::PublicKey::from(&self.0).as_bytes())
    }

    /// Diffie-Hellman against someone else's public half.
    ///
    /// The raw shared point, which is **not** a key. It goes through a KDF
    /// before anything encrypts with it: X25519 outputs are not uniformly
    /// distributed, and using one directly as an AEAD key is a classic way to
    /// lose the security proof.
    ///
    /// A contributory-behaviour check is deliberately absent. An all-zero result
    /// means the peer supplied a small-order point, and the KDF binds the
    /// ephemeral key and both identities, so a forced-zero shared secret yields a
    /// key the attacker still cannot predict for any *other* pair. It is worth
    /// revisiting if this is ever used for authenticated key exchange, which it
    /// is not — authorship comes from the signature (D4).
    #[must_use]
    pub fn agree(&self, their_public: AgreementKeyBytes) -> Zeroizing<[u8; 32]> {
        let their_public = x25519_dalek::PublicKey::from(*their_public.as_bytes());
        Zeroizing::new(self.0.diffie_hellman(&their_public).to_bytes())
    }
}

impl core::fmt::Debug for AgreementKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AgreementKeypair")
            .field(&self.public())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies() {
        let key = SigningKeypair::generate().unwrap();
        let sig = key.sign(b"hello");
        assert!(verify(key.public(), b"hello", sig).is_ok());
    }

    #[test]
    fn rejects_wrong_message() {
        let key = SigningKeypair::generate().unwrap();
        let sig = key.sign(b"hello");
        assert_eq!(
            verify(key.public(), b"goodbye", sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let a = SigningKeypair::generate().unwrap();
        let b = SigningKeypair::generate().unwrap();
        let sig = a.sign(b"hello");
        assert_eq!(
            verify(b.public(), b"hello", sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn seed_round_trips() {
        let key = SigningKeypair::generate().unwrap();
        let restored = SigningKeypair::from_seed(&key.seed());
        assert_eq!(key.public(), restored.public());
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let key = SigningKeypair::generate().unwrap();
        let seed = key.seed();
        let rendered = format!("{key:?}");
        let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&seed_hex));
        assert!(rendered.contains("ed25519:"));
    }

    #[test]
    fn agreement_is_symmetric() {
        let a = AgreementKeypair::generate().unwrap();
        let b = AgreementKeypair::generate().unwrap();
        assert_eq!(a.agree(b.public()), b.agree(a.public()));
    }

    #[test]
    fn different_pairs_agree_differently() {
        let a = AgreementKeypair::generate().unwrap();
        let b = AgreementKeypair::generate().unwrap();
        let c = AgreementKeypair::generate().unwrap();
        assert_ne!(a.agree(b.public()), a.agree(c.public()));
    }

    #[test]
    fn signing_and_agreement_keys_are_unrelated() {
        // Same seed bytes, two protocols. If these ever coincided it would mean
        // the birational map had been used somewhere it should not be.
        let seed = [42u8; 32];
        let signing = SigningKeypair::from_seed(&seed);
        let agreement = AgreementKeypair::from_secret(&seed);
        assert_ne!(signing.public().as_bytes(), agreement.public().as_bytes());
    }
}
