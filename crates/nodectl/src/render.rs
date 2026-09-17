//! Human-facing rendering. Nothing here is part of the wire format.

use pigeonnet_core::base32;

/// Group bytes into a spoken-aloud fingerprint (§13).
pub(crate) fn fingerprint(bytes: &[u8]) -> Vec<String> {
    let hex: Vec<String> = bytes.iter().take(16).map(|b| format!("{b:02X}")).collect();
    hex.chunks(8)
        .map(|row| {
            row.chunks(2)
                .map(|pair| pair.concat())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// Render the recovery secret for transcription onto paper.
///
/// Base32 for now. The twelve-word mnemonic the quickstart shows needs a
/// wordlist and a checksum, and needs deciding whether the seed is 128 or 256
/// bits — a 256-bit Ed25519 seed is twenty-four BIP39 words, not twelve. That is
/// a real decision, not a rendering detail, so it is deferred rather than
/// guessed at.
pub(crate) fn recovery_phrase(secret: &[u8; 32]) -> String {
    let text = base32::encode(secret);
    text.as_bytes()
        .chunks(13)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format milliseconds since the epoch as an ISO 8601 instant in UTC.
///
/// Hand-rolled rather than pulling in a date library for one call site. Uses the
/// civil-from-days algorithm, which is exact for all representable dates.
pub(crate) fn iso8601(millis: i64) -> String {
    let (days, time_of_day) = (millis.div_euclid(86_400_000), millis.rem_euclid(86_400_000));
    let (year, month, day) = civil_from_days(days);
    let (seconds, milliseconds) = (time_of_day / 1000, time_of_day % 1000);
    let (hour, minute, second) = (seconds / 3600, (seconds / 60) % 60, seconds % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

/// Days since 1970-01-01 to a civil date. Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_758_000_000_000), "2025-09-16T05:20:00.000Z");
    }

    #[test]
    fn handles_leap_days() {
        // 2024-02-29, a date a naive implementation gets wrong.
        assert_eq!(iso8601(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn handles_pre_epoch() {
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn fingerprint_is_two_rows_of_four_groups() {
        let rows = fingerprint(&[
            0xB2, 0xA7, 0xF9, 0x12, 0x02, 0xDE, 0x8B, 0x41, 0x91, 0xCD, 0x77, 0x2A, 0xD1, 0x5F,
            0xF8, 0x21,
        ]);
        assert_eq!(rows, vec!["B2A7 F912 02DE 8B41", "91CD 772A D15F F821"]);
    }
}
