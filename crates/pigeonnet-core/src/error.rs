//! Errors produced while decoding or validating objects.

use core::fmt;

/// Something was wrong with an object arriving from outside this process.
///
/// Every variant means "reject this object". None of them mean "retry".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes did not re-encode to themselves (§22.1).
    ///
    /// This is checked before the signature, because a non-canonical encoding
    /// means the object could carry more than one identifier.
    NonCanonical,

    /// The object declared a format version this build does not implement (§31).
    UnsupportedVersion(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonical => f.write_str("object is not canonically encoded"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported object version {v}"),
        }
    }
}

impl core::error::Error for Error {}
