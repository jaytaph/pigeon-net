//! Snapshot verification (D12, §5.6).
//!
//! A snapshot may be served by anyone and cached by anyone, so every test here
//! is really the same question: what can a hostile *holder* do? The answer must
//! always be "withhold", never "forge".

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use minicbor::bytes::ByteVec;
use pigeonnet_core::{
    AgreementKeyBytes, IdentityId, NodeId, ObjectType, Tbs, Timestamp,
    payload::{
        Capabilities, CarriageAccepted, Carrier, DeviceKeyGranted, EpochPrekey, IdentityCreated,
        IdentityProfile, Payload, ReachabilityClaim,
    },
};
use pigeonnet_crypto::{AgreementKeypair, SigningKeypair, Snapshot, SnapshotError, sign_object};

const T0: i64 = 1_789_552_800_000;
const DAY: i64 = 86_400_000;

fn now() -> Timestamp {
    Timestamp::from_millis(T0)
}

/// An identity with one prekey-publishing device, plus the pieces to build a
/// snapshot of it.
struct Fixture {
    identity: IdentityId,
    #[allow(dead_code)]
    root: SigningKeypair,
    device: SigningKeypair,
    chain: Vec<ByteVec>,
    device_sequence: u64,
}

impl Fixture {
    fn new() -> Self {
        Self::with_capabilities(Capabilities::POST | Capabilities::PUBLISH_PREKEYS)
    }

    fn with_capabilities(capabilities: Capabilities) -> Self {
        let root = SigningKeypair::generate().unwrap();
        let device = SigningKeypair::generate().unwrap();
        let recovery = SigningKeypair::generate().unwrap();
        let agreement = AgreementKeypair::generate().unwrap();

        let genesis = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: ObjectType::IdentityCreated.code(),
                author: IdentityId::ZERO,
                signing_key: root.public(),
                timestamp: Timestamp::from_millis(T0 - DAY),
                sequence: 0,
                payload: IdentityCreated {
                    root_key: root.public(),
                    recovery_key: recovery.public(),
                    agreement_key: agreement.public(),
                }
                .encode_payload()
                .unwrap(),
            },
            &root,
        )
        .unwrap();
        let identity = IdentityId::from_genesis(genesis.id());

        let grant = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: ObjectType::DeviceKeyGranted.code(),
                author: identity,
                signing_key: root.public(),
                timestamp: Timestamp::from_millis(T0 - DAY),
                sequence: 1,
                payload: DeviceKeyGranted {
                    device_key: device.public(),
                    capabilities,
                    not_before: Timestamp::from_millis(T0 - DAY),
                    not_after: None,
                }
                .encode_payload()
                .unwrap(),
            },
            &root,
        )
        .unwrap();

        let chain = vec![
            genesis.to_canonical_bytes().unwrap().into(),
            grant.to_canonical_bytes().unwrap().into(),
        ];
        Self {
            identity,
            root,
            device,
            chain,
            device_sequence: 0,
        }
    }

    /// Sign an object as this identity's device.
    fn signed(&mut self, object_type: ObjectType, payload: Vec<u8>) -> ByteVec {
        let object = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: object_type.code(),
                author: self.identity,
                signing_key: self.device.public(),
                timestamp: now(),
                sequence: self.device_sequence,
                payload,
            },
            &self.device,
        )
        .unwrap();
        self.device_sequence += 1;
        object.to_canonical_bytes().unwrap().into()
    }

    fn prekey(&mut self, epoch: u64, valid_for_days: i64) -> ByteVec {
        let payload = EpochPrekey {
            epoch,
            public_key: AgreementKeyBytes::from_bytes([u8::try_from(epoch % 251).unwrap(); 32]),
            valid_until: Timestamp::from_millis(T0 + valid_for_days * DAY),
        }
        .encode_payload()
        .unwrap();
        self.signed(ObjectType::EpochPrekey, payload)
    }

    fn reachability(&mut self, carriers: &[(NodeId, u32)], days: i64) -> ByteVec {
        let payload = ReachabilityClaim {
            via: carriers
                .iter()
                .map(|(node, cost)| Carrier {
                    node: *node,
                    cost: *cost,
                })
                .collect(),
            expires_at: Timestamp::from_millis(T0 + days * DAY),
        }
        .encode_payload()
        .unwrap();
        self.signed(ObjectType::ReachabilityClaim, payload)
    }

    fn snapshot(&self, valid_days: i64) -> Snapshot {
        Snapshot {
            identity: self.identity,
            chain: self.chain.clone(),
            prekeys: Vec::new(),
            reachability: None,
            carriage: Vec::new(),
            profile: None,
            valid_until: Timestamp::from_millis(T0 + valid_days * DAY),
        }
    }
}

/// A carrier node, signing its own acceptance.
struct CarrierNode {
    key: SigningKeypair,
    node: NodeId,
}

impl CarrierNode {
    fn new() -> Self {
        let key = SigningKeypair::generate().unwrap();
        let node = NodeId::from_bytes(*key.public().as_bytes());
        Self { key, node }
    }

    /// Accept carriage for an identity. `claimed_as` lets a test forge the
    /// carrier field independently of the signature.
    fn accept(&self, identity: IdentityId, claimed_as: NodeId, days: i64) -> ByteVec {
        let object = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: ObjectType::CarriageAccepted.code(),
                author: IdentityId::ZERO,
                signing_key: self.key.public(),
                timestamp: now(),
                sequence: 0,
                payload: CarriageAccepted {
                    carrier: claimed_as,
                    identity,
                    expires_at: Timestamp::from_millis(T0 + days * DAY),
                }
                .encode_payload()
                .unwrap(),
            },
            &self.key,
        )
        .unwrap();
        object.to_canonical_bytes().unwrap().into()
    }
}

// -- the happy path --------------------------------------------------------

#[test]
fn a_complete_snapshot_resolves() {
    let mut f = Fixture::new();
    let carrier = CarrierNode::new();

    let mut snapshot = f.snapshot(30);
    snapshot.prekeys = vec![f.prekey(1, 10), f.prekey(2, 20)];
    snapshot.reachability = Some(f.reachability(&[(carrier.node, 1)], 25));
    snapshot.carriage = vec![carrier.accept(f.identity, carrier.node, 25)];

    let resolved = snapshot.verify(now()).unwrap();
    assert_eq!(resolved.state.id(), f.identity);
    assert_eq!(resolved.prekeys.len(), 2);
    assert_eq!(resolved.carriers.len(), 1);
    assert_eq!(resolved.carriers[0].node, carrier.node);
    assert!(resolved.unconfirmed.is_empty());
}

#[test]
fn a_cached_copy_from_a_stranger_verifies_identically() {
    // The property the whole design rests on: everything inside is self-signed,
    // so who handed it over is irrelevant.
    let mut f = Fixture::new();
    let mut snapshot = f.snapshot(30);
    snapshot.prekeys = vec![f.prekey(1, 10)];

    let from_origin = snapshot.verify(now()).unwrap();

    // Round-trip through the wire, as a third party's cache would.
    let bytes = pigeonnet_core::cbor::to_canonical_vec(&snapshot).unwrap();
    let relayed: Snapshot = pigeonnet_core::cbor::from_canonical_slice(&bytes).unwrap();
    let from_stranger = relayed.verify(now()).unwrap();

    assert_eq!(from_origin.state.id(), from_stranger.state.id());
    assert_eq!(from_origin.prekeys.len(), from_stranger.prekeys.len());
    assert_eq!(from_origin.valid_until, from_stranger.valid_until);
}

// -- what a holder cannot do -----------------------------------------------

#[test]
fn a_server_cannot_extend_expiry_past_its_contents() {
    // The snapshot is an aggregate and is not itself signed, so a far-future
    // `valid_until` stapled onto stale contents must not be believed. Each
    // object carries its own signed expiry; the effective answer is the
    // earliest.
    let mut f = Fixture::new();
    let mut snapshot = f.snapshot(365);
    snapshot.prekeys = vec![f.prekey(1, 3)];

    let resolved = snapshot.verify(now()).unwrap();
    assert_eq!(
        resolved.valid_until,
        Timestamp::from_millis(T0 + 3 * DAY),
        "server's 365 days should clamp to the prekey's 3"
    );
}

#[test]
fn a_tampered_object_is_refused() {
    let mut f = Fixture::new();
    let mut snapshot = f.snapshot(30);
    let mut prekey = f.prekey(1, 10).to_vec();
    let last = prekey.len() - 1;
    prekey[last] ^= 0x40;
    snapshot.prekeys = vec![prekey.into()];

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::Malformed)
    ));
}

#[test]
fn another_identitys_object_is_refused() {
    let mine = Fixture::new();
    let mut theirs = Fixture::new();
    let mut snapshot = mine.snapshot(30);
    snapshot.prekeys = vec![theirs.prekey(1, 10)];

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::ForeignObject)
    ));
}

#[test]
fn a_chain_for_the_wrong_identity_is_refused() {
    let mine = Fixture::new();
    let theirs = Fixture::new();
    let mut snapshot = mine.snapshot(30);
    snapshot.chain = theirs.chain.clone();

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::Chain(_))
    ));
}

#[test]
fn a_prekey_from_a_device_without_the_capability_is_refused() {
    // `publish-prekeys` is what lets the root key stay cold (§8.1). A device
    // without it publishing prekeys would be a quiet downgrade.
    let mut f = Fixture::with_capabilities(Capabilities::POST);
    let mut snapshot = f.snapshot(30);
    snapshot.prekeys = vec![f.prekey(1, 10)];

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::Chain(_))
    ));
}

#[test]
fn an_object_of_the_wrong_type_is_refused() {
    let mut f = Fixture::new();
    let mut snapshot = f.snapshot(30);
    let profile = IdentityProfile {
        display_name: Some("joshua".into()),
    }
    .encode_payload()
    .unwrap();
    snapshot.prekeys = vec![f.signed(ObjectType::IdentityProfile, profile)];

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::UnexpectedType(_))
    ));
}

// -- carriage --------------------------------------------------------------

#[test]
fn a_carrier_that_has_not_consented_is_unconfirmed_not_usable() {
    // Either half alone is not actionable: the claim alone would let any
    // identity aim traffic at any node.
    let mut f = Fixture::new();
    let carrier = CarrierNode::new();
    let mut snapshot = f.snapshot(30);
    snapshot.reachability = Some(f.reachability(&[(carrier.node, 1)], 25));

    let resolved = snapshot.verify(now()).unwrap();
    assert!(resolved.carriers.is_empty());
    assert_eq!(
        resolved.unconfirmed.len(),
        1,
        "surfaced, not silently dropped"
    );
}

#[test]
fn consent_signed_by_the_wrong_node_is_refused() {
    let mut f = Fixture::new();
    let real = CarrierNode::new();
    let impostor = CarrierNode::new();

    let mut snapshot = f.snapshot(30);
    snapshot.reachability = Some(f.reachability(&[(real.node, 1)], 25));
    // The impostor signs, but names the real carrier.
    snapshot.carriage = vec![impostor.accept(f.identity, real.node, 25)];

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::CarrierMismatch)
    ));
}

#[test]
fn consent_for_a_different_identity_is_refused() {
    let mut f = Fixture::new();
    let other = Fixture::new();
    let carrier = CarrierNode::new();

    let mut snapshot = f.snapshot(30);
    snapshot.reachability = Some(f.reachability(&[(carrier.node, 1)], 25));
    snapshot.carriage = vec![carrier.accept(other.identity, carrier.node, 25)];

    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::ForeignObject)
    ));
}

#[test]
fn two_carriers_both_resolve() {
    // §5.7: always list two, and list the second before the outage.
    let mut f = Fixture::new();
    let (a, b) = (CarrierNode::new(), CarrierNode::new());
    let mut snapshot = f.snapshot(30);
    snapshot.reachability = Some(f.reachability(&[(a.node, 1), (b.node, 3)], 25));
    snapshot.carriage = vec![
        a.accept(f.identity, a.node, 25),
        b.accept(f.identity, b.node, 25),
    ];

    let resolved = snapshot.verify(now()).unwrap();
    assert_eq!(resolved.carriers.len(), 2);
    assert_eq!(
        resolved.carriers[0].cost, 1,
        "order of preference is the author's"
    );
}

// -- expiry ----------------------------------------------------------------

#[test]
fn expired_prekeys_are_dropped_not_rejected() {
    // An expired prekey is garbage, not misbehaviour.
    let mut f = Fixture::new();
    let mut snapshot = f.snapshot(30);
    snapshot.prekeys = vec![f.prekey(1, -5), f.prekey(2, 10)];

    let resolved = snapshot.verify(now()).unwrap();
    assert_eq!(resolved.prekeys.len(), 1);
    assert_eq!(resolved.prekeys[0].1.epoch, 2);
}

#[test]
fn a_wholly_expired_snapshot_is_refused() {
    let f = Fixture::new();
    let snapshot = f.snapshot(-1);
    assert!(matches!(
        snapshot.verify(now()),
        Err(SnapshotError::Expired { .. })
    ));
}

#[test]
fn usability_is_a_property_of_the_snapshot() {
    // Not of prekey exhaustion: that signal vanishes if lookahead increases
    // (§37.1), so nothing may depend on it.
    let mut f = Fixture::new();
    let mut snapshot = f.snapshot(30);
    snapshot.prekeys = vec![f.prekey(1, 10)];
    let resolved = snapshot.verify(now()).unwrap();

    assert!(resolved.is_usable_at(Timestamp::from_millis(T0 + 9 * DAY)));
    assert!(!resolved.is_usable_at(Timestamp::from_millis(T0 + 11 * DAY)));
    assert_eq!(
        resolved.age_millis(now(), Timestamp::from_millis(T0 + 41 * DAY)),
        41 * DAY
    );
}
