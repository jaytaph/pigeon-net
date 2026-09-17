//! Echo area names (§6).
//!
//! `TECH.RUST`, `GOSUB.DEV`, `RETRO.C64`. Dotted, uppercase, and deliberately
//! narrow: an area name reaches a filesystem path, a journal key, a CLI argument
//! and a peer's subscription list, so the set of legal characters is kept small
//! enough that none of those have to think about it.

use core::fmt;

use minicbor::{Decode, Decoder, Encode, Encoder, decode, encode};

use crate::Error;

/// Longest legal area name.
pub const MAX_AREA_NAME: usize = 64;

/// A validated echo area name.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AreaName(String);

impl AreaName {
    /// Validate and normalise a name.
    ///
    /// Accepts `A-Z`, `0-9` and `.` as a separator, case-insensitively, and
    /// stores the uppercase form. Rejects an empty name, an empty segment, a
    /// leading or trailing dot, and anything over [`MAX_AREA_NAME`].
    ///
    /// Case folding happens here rather than at comparison time so that two
    /// spellings of one area cannot become two journals, two subscriptions and
    /// two threads.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.is_empty() || text.len() > MAX_AREA_NAME {
            return Err(Error::BadAreaName);
        }
        let upper = text.to_ascii_uppercase();
        if upper.starts_with('.') || upper.ends_with('.') || upper.contains("..") {
            return Err(Error::BadAreaName);
        }
        if !upper
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'.')
        {
            return Err(Error::BadAreaName);
        }
        Ok(Self(upper))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AreaName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for AreaName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "echo://{}", self.0)
    }
}

impl<C> Encode<C> for AreaName {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        e.str(&self.0)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for AreaName {
    /// Re-validates on the way in.
    ///
    /// An area name arriving from a peer is untrusted input like any other, and
    /// an unvalidated one would become a journal key.
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, decode::Error> {
        let text = d.str()?;
        // Must already be canonical: accepting lowercase here and normalising
        // would mean two byte encodings of one logical value (D2).
        if text != text.to_ascii_uppercase() {
            return Err(decode::Error::message("area name must be uppercase"));
        }
        Self::parse(text).map_err(|_| decode::Error::message("malformed area name"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;

    #[test]
    fn accepts_reasonable_names() {
        for name in ["TECH.RUST", "GOSUB.DEV", "RETRO.C64", "A", "X9.Y8.Z7"] {
            assert_eq!(AreaName::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn folds_case_on_the_way_in() {
        // Two spellings must not become two journals.
        assert_eq!(
            AreaName::parse("tech.rust").unwrap(),
            AreaName::parse("TECH.RUST").unwrap()
        );
    }

    #[test]
    fn rejects_malformed_names() {
        for name in [
            "", ".", "A.", ".A", "A..B", "A B", "A/B", "A-B", "A_B", "\u{e9}",
        ] {
            assert!(AreaName::parse(name).is_err(), "accepted {name:?}");
        }
        assert!(AreaName::parse(&"A".repeat(MAX_AREA_NAME + 1)).is_err());
    }

    #[test]
    fn wire_form_must_already_be_canonical() {
        // Normalising at decode time would give one value two encodings (D2).
        let lowercase = cbor::to_canonical_vec(&"tech.rust").unwrap();
        assert!(cbor::from_canonical_slice::<AreaName>(&lowercase).is_err());
    }

    #[test]
    fn round_trips() {
        let area = AreaName::parse("GOSUB.DEV").unwrap();
        let bytes = cbor::to_canonical_vec(&area).unwrap();
        assert_eq!(
            cbor::from_canonical_slice::<AreaName>(&bytes).unwrap(),
            area
        );
    }
}
