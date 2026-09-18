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

/// A timestamp split into UTC calendar fields.
///
/// For display only. Nothing on the wire is ever a calendar date (see
/// [`Timestamp`]), so this exists purely so that every tool renders an instant
/// the same way rather than each rolling its own arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    /// Proleptic Gregorian year. Negative before 1 BCE.
    pub year: i64,
    /// 1..=12.
    pub month: u32,
    /// 1..=31.
    pub day: u32,
    /// 0..=23.
    pub hour: u32,
    /// 0..=59.
    pub minute: u32,
    /// 0..=59. There are no leap seconds here; Unix time has none.
    pub second: u32,
    /// 0..=999.
    pub millisecond: u32,
}

impl Timestamp {
    /// Split into UTC calendar fields.
    ///
    /// Exact for every representable value, including dates before the epoch:
    /// the division is euclidean, so a negative millisecond count floors into the
    /// previous day rather than truncating towards zero.
    #[must_use]
    pub const fn civil(self) -> Civil {
        let days = self.0.div_euclid(86_400_000);
        let time_of_day = self.0.rem_euclid(86_400_000);
        let (year, month, day) = civil_from_days(days);
        let seconds = time_of_day / 1000;
        Civil {
            year,
            month,
            day,
            hour: (seconds / 3600) as u32,
            minute: ((seconds / 60) % 60) as u32,
            second: (seconds % 60) as u32,
            millisecond: (time_of_day % 1000) as u32,
        }
    }
}

/// Days since 1970-01-01 to a civil date. Howard Hinnant's algorithm.
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({}ms)", self.0)
    }
}
