//! Bundle reading, against arbitrary bytes.
//!
//! §19 requires that a bundle be safely importable from untrusted media. That is
//! a promise about files nobody vouched for, which is exactly what a fuzzer
//! produces. Anything that decodes must also re-encode to itself: two byte forms
//! of one bundle would mean the same stick applying differently twice.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pigeonnet_bundle::Bundle;
use pigeonnet_proto::{Limits, MemoryReplica};

fuzz_target!(|data: &[u8]| {
    let Ok(bundle) = Bundle::decode(data, &Limits::MINIMAL) else { return };

    let reencoded = bundle.encode().expect("an accepted bundle must re-encode");
    assert_eq!(reencoded, data, "accepted a bundle that does not re-encode");

    // Importing must terminate, and must never panic, whatever it contains.
    let mut replica = MemoryReplica::new();
    let _ = bundle.import(&mut replica);
});
