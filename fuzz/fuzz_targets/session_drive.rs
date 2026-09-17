//! The replication state machine, driven by a hostile peer.
//!
//! Arbitrary bytes are chopped into frames and fed to an initiator session.
//! Anything that decodes is a frame some peer could genuinely send, in any
//! order, at any point in the conversation. The session must reject it, not
//! panic on it — and having rejected once, must stay rejected.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pigeonnet_core::NodeId;
use pigeonnet_proto::{Input, Limits, MemoryReplica, Message, Session, StreamId};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::MINIMAL;
    let mut session =
        Session::initiator(NodeId::from_bytes([1; 32]), vec![StreamId::All], limits);
    let mut replica = MemoryReplica::new();

    if session.step(&mut replica, Input::Start).is_err() {
        return;
    }

    // Length-prefixed chunks, so the fuzzer can steer frame boundaries.
    let mut rest = data;
    while let Some((&length, tail)) = rest.split_first() {
        let length = usize::from(length).min(tail.len());
        let (frame, remainder) = tail.split_at(length);
        rest = remainder;

        let Ok(message) = Message::decode(frame, &limits) else { continue };
        if session.step(&mut replica, Input::Received(message)).is_err() {
            // A failed session must refuse everything afterwards.
            assert!(session.is_failed());
            assert!(session.step(&mut replica, Input::Start).is_err());
            return;
        }
    }
});
