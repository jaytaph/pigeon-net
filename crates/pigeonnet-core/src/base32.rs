//! Lowercase unpadded base32 (RFC 4648), used for every identifier.
//!
//! Chosen over hex because it is a third shorter, and over base64 because it is
//! case-insensitive and survives being read aloud, double-clicked, or written on
//! paper — all of which identifiers in this system are expected to do.

/// Map a 5-bit value to its symbol.
const fn symbol(value: u32) -> u8 {
    match value {
        0..=25 => b'a' + value as u8,
        _ => b'2' + (value - 26) as u8,
    }
}

/// Map a symbol back to its 5-bit value.
const fn value(symbol: u8) -> Option<u32> {
    match symbol {
        b'a'..=b'z' => Some((symbol - b'a') as u32),
        b'2'..=b'7' => Some((symbol - b'2') as u32 + 26),
        _ => None,
    }
}

/// Encode bytes as lowercase unpadded base32.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(symbol((acc >> bits) & 0x1f)));
        }
    }
    if bits > 0 {
        out.push(char::from(symbol((acc << (5 - bits)) & 0x1f)));
    }
    out
}

/// Decode lowercase unpadded base32.
///
/// Returns `None` on an unknown symbol, or when the trailing bits are non-zero —
/// the latter would mean two different strings decoding to the same bytes, which
/// is exactly the kind of ambiguity identifiers must not have.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for symbol in input.bytes() {
        acc = (acc << 5) | value(symbol)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Leftover bits must be zero padding, not discarded data.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // RFC 4648 test vectors, lowercased and unpadded.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "my");
        assert_eq!(encode(b"fo"), "mzxq");
        assert_eq!(encode(b"foo"), "mzxw6");
        assert_eq!(encode(b"foob"), "mzxw6yq");
        assert_eq!(encode(b"fooba"), "mzxw6ytb");
        assert_eq!(encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn thirty_two_bytes_is_fifty_two_symbols() {
        assert_eq!(encode(&[0u8; 32]).len(), 52);
    }

    #[test]
    fn rejects_unknown_symbol() {
        assert_eq!(decode("mzxw6ytbo!"), None);
        assert_eq!(decode("MZXW6YTBOI"), None, "uppercase is not our alphabet");
        assert_eq!(decode("mzxw6ytboi="), None, "padding is not accepted");
    }

    #[test]
    fn rejects_non_zero_trailing_bits() {
        // "mz" decodes one byte and leaves 2 bits set; two strings would then
        // decode to the same bytes.
        assert!(decode("my").is_some());
        assert_eq!(decode("mz"), None);
    }

    #[test]
    fn round_trip_all_lengths() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode(&bytes);
            assert_eq!(
                decode(&text).as_deref(),
                Some(bytes.as_slice()),
                "len {len}"
            );
        }
    }
}
