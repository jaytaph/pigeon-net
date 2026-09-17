//! Key-chain replay, exercised adversarially (D3, §5.4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use pigeonnet_core::{
    IdentityId, Object, ObjectType, Tbs, Timestamp,
    payload::{Capabilities, DeviceKeyGranted, DeviceKeyRevoked, IdentityCreated, Payload},
};
use pigeonnet_crypto::{
    AgreementKeypair, IdentityError, IdentityState, SigningKeypair, sign_object,
};

const T0: i64 = 1_758_000_000_000;

fn object(
    object_type: ObjectType,
    author: IdentityId,
    key: &SigningKeypair,
    sequence: u64,
    at: i64,
    payload: Vec<u8>,
) -> Object {
    let tbs = Tbs {
        version: pigeonnet_core::OBJECT_VERSION,
        type_code: object_type.code(),
        author,
        signing_key: key.public(),
        timestamp: Timestamp::from_millis(at),
        sequence,
        payload,
    };
    sign_object(&tbs, key).expect("sign")
}

struct Fixture {
    root: SigningKeypair,
    device: SigningKeypair,
    state: IdentityState,
    root_sequence: u64,
}

impl Fixture {
    fn new() -> Self {
        let root = SigningKeypair::generate().unwrap();
        let recovery = SigningKeypair::generate().unwrap();
        let agreement = AgreementKeypair::generate().unwrap();
        let payload = IdentityCreated {
            root_key: root.public(),
            recovery_key: recovery.public(),
            agreement_key: agreement.public(),
        }
        .encode_payload()
        .unwrap();

        let genesis = object(
            ObjectType::IdentityCreated,
            IdentityId::ZERO,
            &root,
            0,
            T0,
            payload,
        );
        let state = IdentityState::from_genesis(&genesis).expect("genesis is valid");

        Self {
            root,
            device: SigningKeypair::generate().unwrap(),
            state,
            root_sequence: 1,
        }
    }

    /// Grant the fixture's device key, valid from `T0` with no expiry.
    fn grant(&mut self, capabilities: Capabilities) -> Result<(), IdentityError> {
        self.grant_window(capabilities, T0, None)
    }

    fn grant_window(
        &mut self,
        capabilities: Capabilities,
        not_before: i64,
        not_after: Option<i64>,
    ) -> Result<(), IdentityError> {
        let payload = DeviceKeyGranted {
            device_key: self.device.public(),
            capabilities,
            not_before: Timestamp::from_millis(not_before),
            not_after: not_after.map(Timestamp::from_millis),
        }
        .encode_payload()
        .unwrap();
        let obj = object(
            ObjectType::DeviceKeyGranted,
            self.state.id(),
            &self.root,
            self.root_sequence,
            T0,
            payload,
        );
        let result = self.state.admit(&obj);
        if result.is_ok() {
            self.root_sequence += 1;
        }
        result
    }

    fn revoke(
        &mut self,
        revoked_at: i64,
        invalidate_from: Option<i64>,
    ) -> Result<(), IdentityError> {
        let payload = DeviceKeyRevoked {
            device_key: self.device.public(),
            revoked_at: Timestamp::from_millis(revoked_at),
            invalidate_from: invalidate_from.map(Timestamp::from_millis),
        }
        .encode_payload()
        .unwrap();
        let obj = object(
            ObjectType::DeviceKeyRevoked,
            self.state.id(),
            &self.root,
            self.root_sequence,
            T0,
            payload,
        );
        let result = self.state.admit(&obj);
        if result.is_ok() {
            self.root_sequence += 1;
        }
        result
    }

    fn authority(&self, at: i64, required: Capabilities) -> Result<(), IdentityError> {
        self.state.check_device_authority(
            self.device.public(),
            Timestamp::from_millis(at),
            required,
        )
    }
}

// -- genesis ---------------------------------------------------------------

#[test]
fn identity_is_the_genesis_object_identifier() {
    let root = SigningKeypair::generate().unwrap();
    let recovery = SigningKeypair::generate().unwrap();
    let agreement = AgreementKeypair::generate().unwrap();
    let payload = IdentityCreated {
        root_key: root.public(),
        recovery_key: recovery.public(),
        agreement_key: agreement.public(),
    }
    .encode_payload()
    .unwrap();
    let genesis = object(
        ObjectType::IdentityCreated,
        IdentityId::ZERO,
        &root,
        0,
        T0,
        payload,
    );

    let state = IdentityState::from_genesis(&genesis).unwrap();
    assert_eq!(state.id(), IdentityId::from_genesis(genesis.id()));
    assert_eq!(state.id().genesis_object(), genesis.id());
    assert_eq!(state.recovery_key(), recovery.public());
}

#[test]
fn genesis_must_be_signed_by_the_root_key_it_declares() {
    let root = SigningKeypair::generate().unwrap();
    let impostor = SigningKeypair::generate().unwrap();
    let payload = IdentityCreated {
        root_key: root.public(),
        recovery_key: SigningKeypair::generate().unwrap().public(),
        agreement_key: AgreementKeypair::generate().unwrap().public(),
    }
    .encode_payload()
    .unwrap();
    // Declares root's key, signed by someone else's.
    let genesis = object(
        ObjectType::IdentityCreated,
        IdentityId::ZERO,
        &impostor,
        0,
        T0,
        payload,
    );

    assert!(matches!(
        IdentityState::from_genesis(&genesis),
        Err(IdentityError::GenesisNotSelfSigned)
    ));
}

#[test]
fn genesis_must_be_sequence_zero() {
    let root = SigningKeypair::generate().unwrap();
    let payload = IdentityCreated {
        root_key: root.public(),
        recovery_key: SigningKeypair::generate().unwrap().public(),
        agreement_key: AgreementKeypair::generate().unwrap().public(),
    }
    .encode_payload()
    .unwrap();
    let genesis = object(
        ObjectType::IdentityCreated,
        IdentityId::ZERO,
        &root,
        4,
        T0,
        payload,
    );

    assert!(matches!(
        IdentityState::from_genesis(&genesis),
        Err(IdentityError::SequenceOutOfOrder {
            expected: 0,
            found: 4
        })
    ));
}

// -- delegation ------------------------------------------------------------

#[test]
fn root_may_grant_a_device_key() {
    let mut f = Fixture::new();
    assert_eq!(f.grant(Capabilities::POST | Capabilities::MESSAGE), Ok(()));
    assert_eq!(
        f.state.capabilities_of(f.device.public()),
        Some(Capabilities::POST | Capabilities::MESSAGE)
    );
    assert_eq!(f.authority(T0 + 1, Capabilities::POST), Ok(()));
}

#[test]
fn a_device_key_may_not_grant_device_keys() {
    // If a device key could delegate, revoking it would not contain the damage:
    // a thief would simply mint another before the revocation propagated.
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();

    let accomplice = SigningKeypair::generate().unwrap();
    let payload = DeviceKeyGranted {
        device_key: accomplice.public(),
        capabilities: Capabilities::POST,
        not_before: Timestamp::from_millis(T0),
        not_after: None,
    }
    .encode_payload()
    .unwrap();
    let obj = object(
        ObjectType::DeviceKeyGranted,
        f.state.id(),
        &f.device,
        0,
        T0,
        payload,
    );

    assert_eq!(f.state.admit(&obj), Err(IdentityError::NotSignedByRoot));
}

#[test]
fn objects_for_another_identity_are_refused() {
    let mut f = Fixture::new();
    let other = Fixture::new();
    let payload = DeviceKeyGranted {
        device_key: f.device.public(),
        capabilities: Capabilities::POST,
        not_before: Timestamp::from_millis(T0),
        not_after: None,
    }
    .encode_payload()
    .unwrap();
    let obj = object(
        ObjectType::DeviceKeyGranted,
        other.state.id(),
        &f.root,
        1,
        T0,
        payload,
    );

    assert!(matches!(
        f.state.admit(&obj),
        Err(IdentityError::WrongIdentity { .. })
    ));
}

#[test]
fn revoking_an_unknown_device_is_refused() {
    let mut f = Fixture::new();
    assert!(matches!(
        f.revoke(T0, None),
        Err(IdentityError::UnknownSigningKey(_))
    ));
}

// -- sequences -------------------------------------------------------------

#[test]
fn sequence_gaps_are_refused() {
    let mut f = Fixture::new();
    f.root_sequence = 5; // genesis used 0, so 1 is expected
    assert!(matches!(
        f.grant(Capabilities::POST),
        Err(IdentityError::SequenceOutOfOrder {
            expected: 1,
            found: 5
        })
    ));
}

#[test]
fn reusing_a_sequence_is_equivocation() {
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();
    f.root_sequence -= 1; // sign a second, different object at the same position

    assert!(matches!(
        f.grant(Capabilities::MESSAGE),
        Err(IdentityError::Equivocation { sequence: 1, .. })
    ));
}

#[test]
fn each_key_has_its_own_sequence_space() {
    // Two devices of one person must never have to coordinate a counter (D3).
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();

    let second = SigningKeypair::generate().unwrap();
    let payload = DeviceKeyGranted {
        device_key: second.public(),
        capabilities: Capabilities::POST,
        not_before: Timestamp::from_millis(T0),
        not_after: None,
    }
    .encode_payload()
    .unwrap();
    let obj = object(
        ObjectType::DeviceKeyGranted,
        f.state.id(),
        &f.root,
        f.root_sequence,
        T0,
        payload,
    );
    f.state.admit(&obj).unwrap();

    // Both devices start their own sequence at 0, independently.
    assert_eq!(
        f.state.capabilities_of(f.device.public()),
        Some(Capabilities::POST)
    );
    assert_eq!(
        f.state.capabilities_of(second.public()),
        Some(Capabilities::POST)
    );
}

// -- validity windows and revocation ---------------------------------------

#[test]
fn authority_respects_the_validity_window() {
    let mut f = Fixture::new();
    f.grant_window(Capabilities::POST, T0 + 100, Some(T0 + 200))
        .unwrap();

    assert_eq!(
        f.authority(T0 + 50, Capabilities::POST),
        Err(IdentityError::OutsideValidityWindow)
    );
    assert_eq!(f.authority(T0 + 150, Capabilities::POST), Ok(()));
    assert_eq!(
        f.authority(T0 + 250, Capabilities::POST),
        Err(IdentityError::OutsideValidityWindow)
    );
}

#[test]
fn revocation_is_not_retroactive_by_default() {
    // The victim's own history must survive their device being stolen (§5.4).
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();
    f.revoke(T0 + 500, None).unwrap();

    assert_eq!(
        f.authority(T0 + 100, Capabilities::POST),
        Ok(()),
        "earlier objects stay valid"
    );
    assert_eq!(
        f.authority(T0 + 500, Capabilities::POST),
        Err(IdentityError::Revoked)
    );
    assert_eq!(
        f.authority(T0 + 900, Capabilities::POST),
        Err(IdentityError::Revoked)
    );
}

#[test]
fn invalidate_from_reaches_backwards() {
    // For when the owner learns the compromise predates the discovery.
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();
    f.revoke(T0 + 500, Some(T0 + 200)).unwrap();

    assert_eq!(f.authority(T0 + 100, Capabilities::POST), Ok(()));
    assert_eq!(
        f.authority(T0 + 300, Capabilities::POST),
        Err(IdentityError::Invalidated)
    );
}

// -- capabilities ----------------------------------------------------------

#[test]
fn missing_capabilities_are_refused() {
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();

    assert_eq!(f.authority(T0 + 1, Capabilities::POST), Ok(()));
    assert!(matches!(
        f.authority(T0 + 1, Capabilities::PUBLISH_PREKEYS),
        Err(IdentityError::MissingCapability { .. })
    ));
}

#[test]
fn an_undelegated_key_has_no_authority() {
    let f = Fixture::new();
    assert!(matches!(
        f.authority(T0 + 1, Capabilities::POST),
        Err(IdentityError::UnknownSigningKey(_))
    ));
}

#[test]
fn a_tampered_object_never_reaches_authorisation() {
    let mut f = Fixture::new();
    f.grant(Capabilities::POST).unwrap();

    let payload = DeviceKeyRevoked {
        device_key: f.device.public(),
        revoked_at: Timestamp::from_millis(T0),
        invalidate_from: None,
    }
    .encode_payload()
    .unwrap();
    let genuine = object(
        ObjectType::DeviceKeyRevoked,
        f.state.id(),
        &f.root,
        f.root_sequence,
        T0,
        payload,
    );

    // Same signature, different bytes.
    let mut tbs = genuine.tbs().unwrap();
    tbs.sequence += 1;
    let forged = Object::from_parts(tbs.to_canonical_bytes().unwrap(), genuine.signature());

    assert!(matches!(
        f.state.admit(&forged),
        Err(IdentityError::Crypto(_))
    ));
}
