//! The object decoder, against arbitrary bytes.
//!
//! Every object on this network arrives from somewhere untrusted — a peer, a
//! bundle, a USB stick (§29). This target asserts the weakest useful property:
//! whatever the input, decoding terminates without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pigeonnet_core::Object;

fuzz_target!(|data: &[u8]| {
    let _ = Object::from_canonical_bytes(data);
});
