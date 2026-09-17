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

    /// An epoch's secret has been destroyed by the ratchet (§8.1).
    ///
    /// Not a failure: it is the mechanism working. A message sealed to that
    /// epoch is unreadable, by anyone, for good.
    EpochDestroyed {
        /// What was asked for.
        epoch: u64,
        /// The earliest epoch still derivable.
        earliest: u64,
    },

    /// An epoch is too far ahead to derive in one go.
    EpochTooFar {
        /// What was asked for.
        epoch: u64,
        /// How many steps forward are permitted.
        limit: u64,
    },

    /// A message was sealed to nobody.
    NoRecipients,

    /// A message could not be sealed.
    Seal,

    /// A message could not be opened: wrong key, wrong device, or tampering.
    ///
    /// One variant on purpose. Distinguishing them would tell an attacker
    /// holding a captured message which of its guesses was closest.
    Open,

    /// This message names no entry for the device that tried to open it.
    NotAddressedToUs,

    /// The message was sealed with primitives this build does not implement.
    UnknownSuite(u16),

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
            Self::EpochDestroyed { epoch, earliest } => {
                write!(
                    f,
                    "epoch {epoch} was destroyed; earliest derivable is {earliest}"
                )
            }
            Self::EpochTooFar { epoch, limit } => {
                write!(f, "epoch {epoch} is more than {limit} steps ahead")
            }
            Self::NoRecipients => f.write_str("no usable keys for that recipient"),
            Self::Seal => f.write_str("could not seal message"),
            Self::Open => f.write_str("could not open message"),
            Self::NotAddressedToUs => f.write_str("message carries no entry for this device"),
            Self::UnknownSuite(s) => write!(f, "unsupported cipher suite {s}"),
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
