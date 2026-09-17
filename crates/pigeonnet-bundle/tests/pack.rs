//! Bundles, including from media nobody should trust (§19, §29).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pigeonnet_bundle::{Bundle, BundleError, Section, StreamCursor};
use pigeonnet_core::{
    IdentityId, NodeId, Object, ObjectType, PublicKeyBytes, SignatureBytes, Tbs, Timestamp,
};
use pigeonnet_proto::{JournalEntry, Limits, MemoryReplica, Replica, StreamId};

const ORIGIN: NodeId = NodeId::from_bytes([0xa1; 32]);
const NOW: i64 = 1_789_552_800_000;

fn object(n: u64) -> Vec<u8> {
    let tbs = Tbs {
        version: pigeonnet_core::OBJECT_VERSION,
        type_code: ObjectType::IdentityCreated.code(),
        author: IdentityId::ZERO,
        signing_key: PublicKeyBytes::from_bytes([7; 32]),
        timestamp: Timestamp::from_millis(NOW),
        sequence: n,
        payload: format!("object {n}").into_bytes(),
    };
    Object::from_parts(tbs.to_canonical_bytes().unwrap(), SignatureBytes::ZERO)
        .to_canonical_bytes()
        .unwrap()
}

fn id_of(bytes: &[u8]) -> pigeonnet_core::ObjectId {
    Object::from_canonical_bytes(bytes).unwrap().id()
}

fn replica_with(count: u64) -> MemoryReplica {
    let mut replica = MemoryReplica::new();
    for n in 0..count {
        replica.insert(StreamId::All, object(n)).unwrap();
    }
    replica
}

fn everything() -> Vec<StreamCursor> {
    vec![StreamCursor {
        stream: StreamId::All,
        after: 0,
    }]
}

fn export(replica: &MemoryReplica, limits: &Limits) -> Bundle {
    Bundle::export(replica, ORIGIN, NOW, &everything(), Vec::new(), limits).unwrap()
}

// -- the point of the milestone --------------------------------------------

#[test]
fn a_bundle_carries_a_node_across_an_air_gap() {
    let sender = replica_with(10);
    let bytes = export(&sender, &Limits::DEFAULT).encode().unwrap();

    // Nothing but a file crosses between these two.
    let mut receiver = MemoryReplica::new();
    let report = Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver)
        .unwrap();

    assert_eq!(report.accepted, 10);
    assert_eq!(report.cursors_advanced, 1);
    assert_eq!(receiver.ids(), sender.ids());
}

#[test]
fn importing_twice_changes_nothing() {
    let sender = replica_with(5);
    let bytes = export(&sender, &Limits::DEFAULT).encode().unwrap();
    let mut receiver = MemoryReplica::new();

    let bundle = Bundle::decode(&bytes, &Limits::DEFAULT).unwrap();
    assert_eq!(bundle.import(&mut receiver).unwrap().accepted, 5);

    let again = bundle.import(&mut receiver).unwrap();
    assert_eq!(again.accepted, 0);
    assert_eq!(again.already_held, 5);
    assert_eq!(receiver.len(), 5);
}

#[test]
fn the_cursor_lands_where_the_sender_stood() {
    let sender = replica_with(7);
    let bytes = export(&sender, &Limits::DEFAULT).encode().unwrap();
    let mut receiver = MemoryReplica::new();
    Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver)
        .unwrap();

    // Positions start at 1, so seven objects means the cursor is at seven.
    assert_eq!(receiver.cursor(ORIGIN, &StreamId::All).unwrap(), 7);
}

#[test]
fn an_incremental_bundle_carries_only_what_is_new() {
    let sender = replica_with(10);
    let partial = Bundle::export(
        &sender,
        ORIGIN,
        NOW,
        &[StreamCursor {
            stream: StreamId::All,
            after: 6,
        }],
        Vec::new(),
        &Limits::DEFAULT,
    )
    .unwrap();
    assert_eq!(partial.objects.len(), 4);
}

#[test]
fn a_bundle_walks_past_one_journal_window() {
    // There is no `more` flag to come back for, so export must drain the journal
    // rather than stopping at the first batch.
    let sender = replica_with(200);
    let bundle = Bundle::export(
        &sender,
        ORIGIN,
        NOW,
        &everything(),
        Vec::new(),
        &Limits {
            max_bundle_objects: 1000,
            ..Limits::MINIMAL
        },
    )
    .unwrap();
    assert_eq!(bundle.objects.len(), 200);
    assert_eq!(bundle.sections[0].entries.len(), 200);
}

#[test]
fn requests_survive_the_round_trip() {
    // FidoNet's trick: say where you stand so the reply can be targeted.
    let sender = replica_with(3);
    let requests = vec![StreamCursor {
        stream: StreamId::All,
        after: 42,
    }];
    let bundle = Bundle::export(
        &sender,
        ORIGIN,
        NOW,
        &everything(),
        requests.clone(),
        &Limits::DEFAULT,
    )
    .unwrap();
    let bytes = bundle.encode().unwrap();
    assert_eq!(
        Bundle::decode(&bytes, &Limits::DEFAULT).unwrap().requests,
        requests
    );
}

// -- hostile media ---------------------------------------------------------

#[test]
fn rejects_anything_that_is_not_a_bundle() {
    for bytes in [b"".as_slice(), b"hello", b"PGNPACK\x01", b"PGNPACX\0\x01"] {
        assert!(matches!(
            Bundle::decode(bytes, &Limits::DEFAULT),
            Err(BundleError::Format | BundleError::Malformed)
        ));
    }
}

#[test]
fn rejects_a_future_version() {
    let mut bytes = export(&replica_with(1), &Limits::DEFAULT).encode().unwrap();
    bytes[8] = 99;
    assert_eq!(
        Bundle::decode(&bytes, &Limits::DEFAULT),
        Err(BundleError::Format)
    );
}

#[test]
fn rejects_a_file_larger_than_we_agreed_to_read() {
    // Removable media has no handshake and no back pressure. This number is the
    // only thing between a hostile stick and our memory.
    let huge = vec![0u8; Limits::MINIMAL.max_bundle_bytes + 1];
    assert!(matches!(
        Bundle::decode(&huge, &Limits::MINIMAL),
        Err(BundleError::TooLarge { .. })
    ));
}

#[test]
fn rejects_more_objects_than_the_limit() {
    let sender = replica_with(Limits::MINIMAL.max_bundle_objects as u64 + 10);
    let bytes = export(&sender, &Limits::DEFAULT).encode().unwrap();
    assert!(matches!(
        Bundle::decode(&bytes, &Limits::MINIMAL),
        Err(BundleError::TooManyObjects { .. })
    ));
}

#[test]
fn rejects_oversized_objects_before_storing_any() {
    let sender = replica_with(3);
    let mut bundle = export(&sender, &Limits::DEFAULT);
    bundle
        .objects
        .push(vec![0u8; Limits::MINIMAL.max_object_bytes + 1].into());
    let bytes = bundle.encode().unwrap();

    assert!(matches!(
        Bundle::decode(&bytes, &Limits::MINIMAL),
        Err(BundleError::ObjectTooLarge { .. })
    ));
}

#[test]
fn rejects_a_journal_that_goes_backwards() {
    let sender = replica_with(3);
    let mut bundle = export(&sender, &Limits::DEFAULT);
    bundle.sections[0].entries.reverse();
    let bytes = bundle.encode().unwrap();

    let mut receiver = MemoryReplica::new();
    let error = Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver)
        .unwrap_err();
    assert!(
        matches!(error, BundleError::NonMonotonicJournal { .. }),
        "{error}"
    );
}

#[test]
fn rejects_an_entry_whose_object_is_absent() {
    // A bundle that advertises more than it carries would otherwise advance the
    // cursor past objects that never arrived, losing them permanently.
    let sender = replica_with(3);
    let mut bundle = export(&sender, &Limits::DEFAULT);
    bundle.sections[0].entries.push(JournalEntry {
        position: 99,
        object: id_of(&object(1000)),
    });
    let bytes = bundle.encode().unwrap();

    let mut receiver = MemoryReplica::new();
    let error = Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver)
        .unwrap_err();
    assert!(matches!(error, BundleError::DanglingEntry(_)), "{error}");
}

#[test]
fn rejects_garbage_in_place_of_an_object() {
    let sender = replica_with(2);
    let mut bundle = export(&sender, &Limits::DEFAULT);
    bundle.objects.push(vec![0xff, 0xfe, 0xfd].into());
    let bytes = bundle.encode().unwrap();

    let mut receiver = MemoryReplica::new();
    let error = Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver)
        .unwrap_err();
    assert!(matches!(error, BundleError::InvalidObject(_)), "{error}");
}

#[test]
fn a_rejected_bundle_advances_no_cursor() {
    let sender = replica_with(3);
    let mut bundle = export(&sender, &Limits::DEFAULT);
    bundle.sections[0].entries.push(JournalEntry {
        position: 99,
        object: id_of(&object(1000)),
    });
    let bytes = bundle.encode().unwrap();

    let mut receiver = MemoryReplica::new();
    let _ = Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver);
    assert_eq!(
        receiver.cursor(ORIGIN, &StreamId::All).unwrap(),
        0,
        "a cursor must never move on a bundle we refused"
    );
}

#[test]
fn every_single_byte_flip_is_rejected_or_harmless() {
    // Not a fuzzer, but exhaustive over one mutation: no single-byte change to a
    // bundle may be silently mis-accepted.
    let sender = replica_with(2);
    let original = export(&sender, &Limits::DEFAULT).encode().unwrap();

    for index in 0..original.len() {
        let mut bytes = original.clone();
        bytes[index] ^= 0x40;
        if bytes == original {
            continue;
        }
        if let Ok(bundle) = Bundle::decode(&bytes, &Limits::DEFAULT) {
            let mut receiver = MemoryReplica::new();
            if bundle.import(&mut receiver).is_ok() {
                // Accepted: then it must re-encode to exactly what we fed it.
                assert_eq!(
                    bundle.encode().unwrap(),
                    bytes,
                    "accepted a bundle that does not re-encode (byte {index})"
                );
            }
        }
    }
}

#[test]
fn an_empty_bundle_is_valid_and_does_nothing() {
    let bundle = Bundle {
        origin: ORIGIN,
        created_at: NOW,
        sections: vec![Section {
            stream: StreamId::All,
            entries: Vec::new(),
        }],
        objects: Vec::new(),
        requests: Vec::new(),
    };
    let bytes = bundle.encode().unwrap();
    let mut receiver = MemoryReplica::new();
    let report = Bundle::decode(&bytes, &Limits::DEFAULT)
        .unwrap()
        .import(&mut receiver)
        .unwrap();
    assert_eq!(report.accepted, 0);
    assert_eq!(report.cursors_advanced, 0);
}
