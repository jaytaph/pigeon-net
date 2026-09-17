//! Cryptographic errors.

use core::fmt;

/// A cryptographic operation failed.
///
/// Deliberately coarse. A verification failure reports *that* it failed and not
/// *why*, because the difference between "wrong key" and "wrong message" is
/// information an attacker can use and a caller cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A signature did not verify against the key and message given.
    BadSignature,

    /// A public key was not a valid point.
    BadPublicKey,

    /// The operating system would not supply entropy.
    Entropy,

    /// The keystore could not be opened: wrong passphrase, or tampering.
    ///
    /// These are one variant on purpose. Distinguishing them would tell an
    /// attacker holding a stolen keystore file whether a guessed passphrase was
    /// close, and would tell them nothing useful otherwise.
    KeystoreUnreadable,

    /// The keystore file is not in a format this build understands.
    KeystoreFormat,

    /// The object's envelope could not be read.
    Object(pigeonnet_core::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => f.write_str("signature did not verify"),
            Self::BadPublicKey => f.write_str("invalid public key"),
            Self::Entropy => f.write_str("could not obtain entropy from the operating system"),
            Self::KeystoreUnreadable => f.write_str("keystore could not be opened"),
            Self::KeystoreFormat => f.write_str("unrecognised keystore format"),
            Self::Object(e) => write!(f, "object envelope: {e}"),
        }
    }
}

impl core::error::Error for CryptoError {}

impl From<pigeonnet_core::Error> for CryptoError {
    fn from(e: pigeonnet_core::Error) -> Self {
        Self::Object(e)
    }
}
