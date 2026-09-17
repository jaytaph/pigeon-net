//! The ingest rule of D2, fuzzed.
//!
//! Anything accepted must re-encode to exactly the bytes it came from. A failure
//! here means two wire encodings of one object, and therefore two identifiers
//! for one object — which silently breaks deduplication, threading, retraction
//! and moderation together.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pigeonnet_core::Object;

fuzz_target!(|data: &[u8]| {
    if let Ok(object) = Object::from_canonical_bytes(data) {
        let reencoded = object.to_canonical_bytes().expect("an accepted object must re-encode");
        assert_eq!(reencoded, data, "accepted a non-canonical encoding");
    }
});
