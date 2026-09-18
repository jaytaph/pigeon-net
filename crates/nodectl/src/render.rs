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
/// The calendar arithmetic lives in `pigeonnet_core::Timestamp::civil`, so that
/// every tool renders the same instant identically.
pub(crate) fn iso8601(millis: i64) -> String {
    let c = pigeonnet_core::Timestamp::from_millis(millis).civil();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.millisecond
    )
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

/// Parse a `--at` value into milliseconds since the epoch.
///
/// Accepts a relative offset — `-3d`, `-90m`, `-2h`, `+45s`, `-1w` — or raw
/// milliseconds for scripts. Relative is what a human wants; absolute is what a
/// generator wants.
///
/// # On backdating
///
/// This lets a node claim its own posts were written earlier than they were.
/// That is not a hole this flag opens: §3.3 defines `timestamp` as *when the
/// author says* the object was created, and it has always been author-asserted.
/// A signature proves who wrote something and that it has not changed since — it
/// has never proved when. Anything that needs real ordering must derive it from
/// something other than a claimed clock.
pub(crate) fn parse_when(text: &str, now: i64) -> Result<i64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("empty timestamp".to_owned());
    }

    // Raw milliseconds, for generated input.
    if text.bytes().all(|b| b.is_ascii_digit()) {
        return text
            .parse::<i64>()
            .map_err(|_| format!("{text} is not a timestamp"));
    }

    let (body, unit) = text.split_at(text.len() - 1);
    let millis_per = match unit {
        "s" => 1_000_i64,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "w" => 604_800_000,
        other => {
            return Err(format!(
                "unknown unit {other:?}; use s, m, h, d or w, e.g. -3d, or raw milliseconds"
            ));
        }
    };

    let count: i64 = body
        .parse()
        .map_err(|_| format!("{body:?} is not a number of {unit}"))?;
    count
        .checked_mul(millis_per)
        .and_then(|offset| now.checked_add(offset))
        .ok_or_else(|| format!("{text} is too far from now to represent"))
}

#[cfg(test)]
mod when_tests {
    use super::parse_when;

    const NOW: i64 = 1_789_552_800_000;

    #[test]
    fn relative_offsets_go_both_ways() {
        assert_eq!(parse_when("-1d", NOW).unwrap(), NOW - 86_400_000);
        assert_eq!(parse_when("+2h", NOW).unwrap(), NOW + 7_200_000);
        assert_eq!(parse_when("-90m", NOW).unwrap(), NOW - 5_400_000);
        assert_eq!(parse_when("-1w", NOW).unwrap(), NOW - 604_800_000);
        assert_eq!(parse_when("-45s", NOW).unwrap(), NOW - 45_000);
    }

    #[test]
    fn a_bare_number_is_milliseconds() {
        assert_eq!(parse_when("1789552800000", NOW).unwrap(), NOW);
    }

    #[test]
    fn whitespace_is_forgiven() {
        assert_eq!(parse_when("  -1d  ", NOW).unwrap(), NOW - 86_400_000);
    }

    #[test]
    fn nonsense_is_refused_with_a_hint() {
        assert!(parse_when("", NOW).is_err());
        assert!(parse_when("-3", NOW).is_err(), "no unit");
        assert!(parse_when("yesterday", NOW).is_err());
        let error = parse_when("-3y", NOW).unwrap_err();
        assert!(error.contains("use s, m, h, d or w"), "{error}");
    }

    #[test]
    fn absurd_offsets_do_not_wrap() {
        // A silent wrap would put a post in the far past or future with no
        // indication anything went wrong.
        assert!(parse_when(&format!("{}w", i64::MAX), NOW).is_err());
        assert!(parse_when(&format!("-{}w", i64::MAX), NOW).is_err());
    }
}
