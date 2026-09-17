//! The adversarial peer harness (M2's exit criterion).
//!
//! Two sessions are driven against each other entirely in-process — no sockets,
//! no runtime, no clock. That is the point of sans-io: the hostile peer below is
//! a `match` arm, not a network fixture, so every case here is deterministic and
//! runs in microseconds.
//!
//! What must hold under all of it: no panic, no unbounded growth, and no invalid
//! object accepted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pigeonnet_core::{
    IdentityId, NodeId, Object, ObjectType, PublicKeyBytes, SignatureBytes, Tbs, Timestamp,
};
use pigeonnet_proto::{
    Features, Input, JournalEntry, Limits, MemoryReplica, Message, Output, ProtocolError, Session,
    StreamId,
};

const ALICE: NodeId = NodeId::from_bytes([0xa1; 32]);
const BOB: NodeId = NodeId::from_bytes([0xb0; 32]);

/// A distinct, structurally valid object. The signature is not checked here:
/// `MemoryReplica` validates structure only, exactly as a relay does.
fn object(n: u64) -> Vec<u8> {
    let tbs = Tbs {
        version: pigeonnet_core::OBJECT_VERSION,
        type_code: ObjectType::IdentityCreated.code(),
        author: IdentityId::ZERO,
        signing_key: PublicKeyBytes::from_bytes([7; 32]),
        timestamp: Timestamp::from_millis(1_789_552_800_000),
        sequence: n,
        payload: format!("object {n}").into_bytes(),
    };
    Object::from_parts(tbs.to_canonical_bytes().unwrap(), SignatureBytes::ZERO)
        .to_canonical_bytes()
        .unwrap()
}

/// Run two honest sessions to completion. Returns how many objects moved.
fn sync(
    initiator: &mut Session,
    local: &mut MemoryReplica,
    responder: &mut Session,
    remote: &mut MemoryReplica,
) -> Result<usize, ProtocolError> {
    let mut accepted = 0;
    let mut to_responder: Vec<Message> = Vec::new();
    let mut to_initiator: Vec<Message> = Vec::new();

    for output in initiator.step(local, Input::Start)? {
        if let Output::Send(m) = output {
            to_responder.push(m);
        }
    }

    // Bounded: a session that cannot finish in this many exchanges is looping,
    // and a test that hangs is worse than a test that fails.
    for _ in 0..10_000 {
        if initiator.is_complete() && to_responder.is_empty() && to_initiator.is_empty() {
            return Ok(accepted);
        }
        if let Some(message) = to_responder.pop() {
            for output in responder.step(remote, Input::Received(message))? {
                if let Output::Send(m) = output {
                    to_initiator.push(m);
                }
            }
        } else if let Some(message) = to_initiator.pop() {
            for output in initiator.step(local, Input::Received(message))? {
                match output {
                    Output::Send(m) => to_responder.push(m),
                    Output::Accepted(_) => accepted += 1,
                    Output::Complete => {}
                }
            }
        } else {
            return Ok(accepted);
        }
    }
    panic!("session did not terminate");
}

fn pair(limits: Limits) -> (Session, Session) {
    (
        Session::initiator(ALICE, vec![StreamId::All], limits),
        Session::responder(BOB, limits),
    )
}

/// Drive an initiator against a scripted hostile responder.
fn against_hostile(
    mut reply: impl FnMut(&Message) -> Option<Message>,
    limits: Limits,
) -> Result<(), ProtocolError> {
    let mut alice = Session::initiator(ALICE, vec![StreamId::All], limits);
    let mut store = MemoryReplica::new();
    let mut queue: Vec<Message> = Vec::new();

    for output in alice.step(&mut store, Input::Start)? {
        if let Output::Send(m) = output {
            queue.push(m);
        }
    }
    for _ in 0..1000 {
        let Some(sent) = queue.pop() else {
            return Ok(());
        };
        let Some(response) = reply(&sent) else {
            return Ok(());
        };
        for output in alice.step(&mut store, Input::Received(response))? {
            if let Output::Send(m) = output {
                queue.push(m);
            }
        }
        if alice.is_complete() {
            return Ok(());
        }
    }
    Ok(())
}

// -- convergence -----------------------------------------------------------

#[test]
fn two_nodes_converge() {
    let (mut alice, mut bob) = pair(Limits::DEFAULT);
    let (mut a, mut b) = (MemoryReplica::new(), MemoryReplica::new());
    for n in 0..10 {
        b.insert(StreamId::All, object(n)).unwrap();
    }

    assert_eq!(sync(&mut alice, &mut a, &mut bob, &mut b).unwrap(), 10);
    assert_eq!(a.ids(), b.ids(), "same object set on both sides");
}

#[test]
fn only_missing_objects_move() {
    let (mut alice, mut bob) = pair(Limits::DEFAULT);
    let (mut a, mut b) = (MemoryReplica::new(), MemoryReplica::new());
    for n in 0..10 {
        b.insert(StreamId::All, object(n)).unwrap();
    }
    for n in 0..6 {
        a.insert(StreamId::All, object(n)).unwrap();
    }

    assert_eq!(sync(&mut alice, &mut a, &mut bob, &mut b).unwrap(), 4);
    assert_eq!(a.len(), 10);
}

#[test]
fn a_second_sync_transfers_nothing() {
    // The cursor is the whole point of D5: cost proportional to what is new.
    let (mut alice, mut bob) = pair(Limits::DEFAULT);
    let (mut a, mut b) = (MemoryReplica::new(), MemoryReplica::new());
    for n in 0..10 {
        b.insert(StreamId::All, object(n)).unwrap();
    }
    sync(&mut alice, &mut a, &mut bob, &mut b).unwrap();

    let (mut alice2, mut bob2) = pair(Limits::DEFAULT);
    assert_eq!(sync(&mut alice2, &mut a, &mut bob2, &mut b).unwrap(), 0);
}

#[test]
fn batching_walks_a_long_journal() {
    // 200 objects through a 16-entry window: the `more` flag must carry the
    // cursor forward rather than restarting. Session budgets are raised, since
    // this test is about batching and not about budgets.
    let limits = Limits {
        max_objects_per_session: 1000,
        max_bytes_per_session: 1 << 20,
        ..Limits::MINIMAL
    };
    let (mut alice, mut bob) = pair(limits);
    let (mut a, mut b) = (MemoryReplica::new(), MemoryReplica::new());
    for n in 0..200 {
        b.insert(StreamId::All, object(n)).unwrap();
    }

    let moved = sync(&mut alice, &mut a, &mut bob, &mut b).unwrap();
    assert_eq!(moved, 200);
    assert_eq!(a.len(), 200);
}

#[test]
fn a_session_budget_stops_an_endless_peer() {
    // Storage exhaustion is an expected attack (§29). A peer with more to give
    // than we agreed to take must be cut off mid-sync, not indulged.
    let (mut alice, mut bob) = pair(Limits::MINIMAL);
    let (mut a, mut b) = (MemoryReplica::new(), MemoryReplica::new());
    for n in 0..(Limits::MINIMAL.max_objects_per_session as u64 + 50) {
        b.insert(StreamId::All, object(n)).unwrap();
    }

    let error = sync(&mut alice, &mut a, &mut bob, &mut b).unwrap_err();
    assert!(
        matches!(error, ProtocolError::SessionBudgetExhausted),
        "{error}"
    );
    assert!(
        a.len() <= Limits::MINIMAL.max_objects_per_session,
        "stopped at the budget"
    );
}

#[test]
fn features_are_negotiated() {
    let (mut alice, mut bob) = pair(Limits::DEFAULT);
    let (mut a, mut b) = (MemoryReplica::new(), MemoryReplica::new());
    sync(&mut alice, &mut a, &mut bob, &mut b).unwrap();

    assert!(alice.features().contains(Features::INVENTORY_REPAIR));
    assert!(!alice.features().contains(Features::RANGE_RECONCILIATION));
    assert_eq!(alice.peer(), Some(BOB));
    assert_eq!(bob.peer(), Some(ALICE));
}

// -- hostile peers ---------------------------------------------------------

#[test]
fn rejects_a_journal_that_goes_backwards() {
    // Rewinding our cursor would make us re-fetch history for as long as we
    // listen.
    let error = against_hostile(
        |sent| match sent {
            Message::Hello { .. } => Some(Message::HelloAck {
                version: pigeonnet_proto::PROTOCOL_VERSION,
                node: BOB,
                features: Features::SUPPORTED,
            }),
            Message::Want { stream, .. } => Some(Message::Have {
                stream: *stream,
                entries: vec![
                    JournalEntry {
                        position: 5,
                        object: pigeonnet_core::ObjectId::from_bytes([1; 32]),
                    },
                    JournalEntry {
                        position: 3,
                        object: pigeonnet_core::ObjectId::from_bytes([2; 32]),
                    },
                ],
                more: false,
            }),
            _ => None,
        },
        Limits::DEFAULT,
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::NonMonotonicJournal { .. }),
        "{error}"
    );
}

#[test]
fn rejects_entries_at_or_below_our_cursor() {
    let error = against_hostile(
        |sent| match sent {
            Message::Hello { .. } => Some(Message::HelloAck {
                version: pigeonnet_proto::PROTOCOL_VERSION,
                node: BOB,
                features: Features::SUPPORTED,
            }),
            // We asked for `after: 0`, so position 0 is not after it.
            Message::Want { stream, .. } => Some(Message::Have {
                stream: *stream,
                entries: vec![JournalEntry {
                    position: 0,
                    object: pigeonnet_core::ObjectId::from_bytes([1; 32]),
                }],
                more: false,
            }),
            _ => None,
        },
        Limits::DEFAULT,
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::NonMonotonicJournal { .. }),
        "{error}"
    );
}

#[test]
fn rejects_unsolicited_objects() {
    // Every limit here is expressed in terms of what we asked for, so pushing
    // unrequested content would bypass all of them at once.
    let error = against_hostile(
        |sent| match sent {
            Message::Hello { .. } => Some(Message::HelloAck {
                version: pigeonnet_proto::PROTOCOL_VERSION,
                node: BOB,
                features: Features::SUPPORTED,
            }),
            Message::Want { stream, .. } => Some(Message::Have {
                stream: *stream,
                entries: vec![JournalEntry {
                    position: 1,
                    object: Object::from_canonical_bytes(&object(1)).unwrap().id(),
                }],
                more: false,
            }),
            // Asked for object 1; delivering object 2.
            Message::Fetch { .. } => Some(Message::Deliver {
                objects: vec![object(2).into()],
            }),
            _ => None,
        },
        Limits::DEFAULT,
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::UnsolicitedObject(_)),
        "{error}"
    );
}

#[test]
fn rejects_garbage_in_place_of_an_object() {
    let error = against_hostile(
        |sent| match sent {
            Message::Hello { .. } => Some(Message::HelloAck {
                version: pigeonnet_proto::PROTOCOL_VERSION,
                node: BOB,
                features: Features::SUPPORTED,
            }),
            Message::Want { stream, .. } => Some(Message::Have {
                stream: *stream,
                entries: vec![JournalEntry {
                    position: 1,
                    object: Object::from_canonical_bytes(&object(1)).unwrap().id(),
                }],
                more: false,
            }),
            Message::Fetch { .. } => Some(Message::Deliver {
                objects: vec![vec![0xff, 0xfe, 0xfd].into()],
            }),
            _ => None,
        },
        Limits::DEFAULT,
    )
    .unwrap_err();
    assert!(matches!(error, ProtocolError::InvalidObject), "{error}");
}

#[test]
fn rejects_a_version_mismatch() {
    let error = against_hostile(
        |sent| match sent {
            Message::Hello { .. } => Some(Message::HelloAck {
                version: 999,
                node: BOB,
                features: Features::SUPPORTED,
            }),
            _ => None,
        },
        Limits::DEFAULT,
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::VersionMismatch { .. }),
        "{error}"
    );
}

#[test]
fn rejects_messages_out_of_order() {
    // A peer answering a question it was never asked.
    let error = against_hostile(
        |sent| match sent {
            Message::Hello { .. } => Some(Message::Deliver {
                objects: vec![object(1).into()],
            }),
            _ => None,
        },
        Limits::DEFAULT,
    )
    .unwrap_err();
    assert!(matches!(error, ProtocolError::Unexpected { .. }), "{error}");
}

#[test]
fn a_failed_session_refuses_further_input() {
    let mut alice = Session::initiator(ALICE, vec![StreamId::All], Limits::DEFAULT);
    let mut store = MemoryReplica::new();
    alice.step(&mut store, Input::Start).unwrap();

    let error = alice
        .step(
            &mut store,
            Input::Received(Message::HelloAck {
                version: 999,
                node: BOB,
                features: Features::NONE,
            }),
        )
        .unwrap_err();
    assert!(
        matches!(error, ProtocolError::VersionMismatch { .. }),
        "{error}"
    );
    assert!(alice.is_failed());

    // Continuing to talk to a peer that already broke the protocol is how a
    // resource attack gets its second try.
    assert!(alice.step(&mut store, Input::Start).is_err());
}

// -- frame limits ----------------------------------------------------------

#[test]
fn oversized_frames_are_refused_before_decoding() {
    let huge = vec![0u8; Limits::MINIMAL.max_frame_bytes + 1];
    assert!(matches!(
        Message::decode(&huge, &Limits::MINIMAL),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
}

#[test]
fn oversized_objects_are_refused() {
    let message = Message::Deliver {
        objects: vec![vec![0u8; Limits::MINIMAL.max_object_bytes + 1].into()],
    };
    let encoded = message.encode().unwrap();
    assert!(matches!(
        Message::decode(&encoded, &Limits::MINIMAL),
        Err(ProtocolError::ObjectTooLarge { .. })
    ));
}

#[test]
fn overlong_collections_are_refused() {
    let entries: Vec<JournalEntry> = (1..=(Limits::MINIMAL.max_have_entries as u64 + 1))
        .map(|position| JournalEntry {
            position,
            object: pigeonnet_core::ObjectId::from_bytes([0; 32]),
        })
        .collect();
    let encoded = Message::Have {
        stream: StreamId::All,
        entries,
        more: false,
    }
    .encode()
    .unwrap();
    assert!(matches!(
        Message::decode(&encoded, &Limits::MINIMAL),
        Err(ProtocolError::TooMany { .. })
    ));
}

#[test]
fn wide_inventory_requests_are_refused() {
    let encoded = Message::InventoryRequest {
        stream: StreamId::All,
        from: 0,
        to: Limits::MINIMAL.max_inventory_span + 10,
    }
    .encode()
    .unwrap();
    assert!(matches!(
        Message::decode(&encoded, &Limits::MINIMAL),
        Err(ProtocolError::InventorySpanTooWide { .. })
    ));
}

#[test]
fn malformed_frames_are_refused() {
    assert!(matches!(
        Message::decode(&[0xff, 0xff, 0xff], &Limits::DEFAULT),
        Err(ProtocolError::Malformed)
    ));
    assert!(matches!(
        Message::decode(&[], &Limits::DEFAULT),
        Err(ProtocolError::Malformed)
    ));
}

#[test]
fn frames_round_trip() {
    let messages = vec![
        Message::Hello {
            version: 1,
            node: ALICE,
            features: Features::SUPPORTED,
        },
        Message::Want {
            stream: StreamId::All,
            after: 42,
            limit: 16,
        },
        Message::Have {
            stream: StreamId::Identity(IdentityId::from_bytes([3; 32])),
            entries: vec![JournalEntry {
                position: 1,
                object: pigeonnet_core::ObjectId::from_bytes([9; 32]),
            }],
            more: true,
        },
        Message::Bye,
    ];
    for message in messages {
        let encoded = message.encode().unwrap();
        assert_eq!(
            Message::decode(&encoded, &Limits::DEFAULT).unwrap(),
            message
        );
    }
}
