//! Frame decoding, against arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pigeonnet_proto::{Limits, Message};

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data, &Limits::DEFAULT);
});
