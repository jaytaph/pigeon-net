//! Canonical CBOR, and the ingest check that makes canonicality binding.
//!
//! Decision D2. The wire format is deterministic CBOR (RFC 8949 §4.2.1) with
//! integer-keyed maps.
//!
//! Nothing here assumes the CBOR library is canonical. Determinism is *verified*
//! on the way in rather than trusted: see [`from_canonical_slice`].

use minicbor::{Decode, Encode};

use crate::Error;

/// Encode a value to its canonical CBOR representation.
pub fn to_canonical_vec<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: Encode<()>,
{
    minicbor::to_vec(value).map_err(|_| Error::Encode)
}

/// Decode bytes that arrived from outside this process.
///
/// Decodes, re-encodes canonically, and requires the result to be
/// byte-identical to the input. Anything else is rejected as
/// [`Error::NonCanonical`].
///
/// This runs *before* any signature check, and it is the only place the
/// canonical rule is enforced. Without it, every decode path in the codebase
/// would carry a standing obligation to reject non-canonical input, and a single
/// oversight anywhere would reintroduce malleability everywhere.
///
/// It also rejects trailing bytes for free: unconsumed input cannot survive a
/// re-encode comparison.
pub fn from_canonical_slice<'b, T>(bytes: &'b [u8]) -> Result<T, Error>
where
    T: Decode<'b, ()> + Encode<()>,
{
    let value: T = minicbor::decode(bytes).map_err(|_| Error::Malformed)?;
    let reencoded = to_canonical_vec(&value)?;
    if reencoded.as_slice() != bytes {
        return Err(Error::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cbor(map)]
    struct Sample {
        #[n(0)]
        a: u64,
        #[n(1)]
        b: bool,
    }

    fn sample() -> Sample {
        Sample { a: 7, b: true }
    }

    #[test]
    fn round_trip() {
        let bytes = to_canonical_vec(&sample()).unwrap();
        assert_eq!(from_canonical_slice::<Sample>(&bytes).unwrap(), sample());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = to_canonical_vec(&sample()).unwrap();
        bytes.push(0xff);
        assert_eq!(
            from_canonical_slice::<Sample>(&bytes),
            Err(Error::NonCanonical)
        );
    }

    #[test]
    fn rejects_indefinite_length_map() {
        // 0xbf = indefinite-length map, 0xff = break. Same logical value as the
        // canonical encoding, different bytes, so it must not be accepted.
        let indefinite = [0xbf, 0x00, 0x07, 0x01, 0xf5, 0xff];
        assert_eq!(
            from_canonical_slice::<Sample>(&indefinite),
            Err(Error::NonCanonical)
        );
    }

    #[test]
    fn rejects_non_minimal_integer() {
        // Key 0 written as 0x18 0x00 (one-byte uint) instead of 0x00.
        let non_minimal = [0xa2, 0x18, 0x00, 0x07, 0x01, 0xf5];
        assert_eq!(
            from_canonical_slice::<Sample>(&non_minimal),
            Err(Error::NonCanonical)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(
            from_canonical_slice::<Sample>(&[0xff, 0xff]),
            Err(Error::Malformed)
        );
    }
}
