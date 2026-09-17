//! Errors produced while decoding or validating objects.

use core::fmt;

/// Something was wrong with data arriving from outside this process.
///
/// Every variant means "reject this". None of them mean "retry".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes decoded, but did not re-encode to themselves (§22.1).
    ///
    /// Checked before the signature, because a non-canonical encoding means the
    /// object could carry more than one identifier, and an identifier that is
    /// not unique breaks deduplication, threading, retraction and moderation at
    /// once.
    NonCanonical,

    /// The bytes are not well-formed CBOR, or not the expected shape.
    Malformed,

    /// A value could not be encoded.
    Encode,

    /// The object declared a format version this build does not implement (§31).
    UnsupportedVersion(u16),

    /// The object declared a type code this build does not know.
    ///
    /// Not fatal to a relay: an unknown payload can still be verified and
    /// forwarded, because the signature covers bytes rather than meaning.
    UnknownObjectType(u16),

    /// A fixed-width field was the wrong length.
    BadLength {
        /// What was being read.
        field: &'static str,
        /// How many bytes were expected.
        expected: usize,
        /// How many bytes were present.
        actual: usize,
    },

    /// Text was not valid for the identifier format it claimed to be in.
    BadIdentifier,

    /// An echo area name was malformed (§6).
    BadAreaName,

    /// A post's threading fields were inconsistent (§7).
    ///
    /// A reply names both a parent and a thread root; a root post names neither.
    /// One without the other is unreconstructable, and a node cannot repair it.
    BadThreading,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonical => f.write_str("not canonically encoded"),
            Self::Malformed => f.write_str("malformed encoding"),
            Self::Encode => f.write_str("could not encode value"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported object version {v}"),
            Self::UnknownObjectType(t) => write!(f, "unknown object type {t}"),
            Self::BadLength {
                field,
                expected,
                actual,
            } => {
                write!(f, "{field}: expected {expected} bytes, found {actual}")
            }
            Self::BadIdentifier => f.write_str("malformed identifier"),
            Self::BadAreaName => f.write_str("malformed echo area name"),
            Self::BadThreading => f.write_str("a reply must name both a parent and a thread root"),
        }
    }
}

impl core::error::Error for Error {}
