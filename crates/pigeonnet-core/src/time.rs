//! Timestamps.

use core::fmt;

use minicbor::{Decode, Encode};

/// Milliseconds since the Unix epoch.
///
/// An integer on the wire rather than RFC 3339 text: one value must have exactly
/// one encoding (D2), and date strings have many. The human-readable form in the
/// architecture document's examples is a rendering, not the encoding.
///
/// Signed, so that timestamps before 1970 are representable rather than wrapping
/// into the far future.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
#[cbor(transparent)]
pub struct Timestamp(#[n(0)] i64);

impl Timestamp {
    /// The Unix epoch.
    pub const EPOCH: Self = Self(0);

    /// From milliseconds since the Unix epoch.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({}ms)", self.0)
    }
}
