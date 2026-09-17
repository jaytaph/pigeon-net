//! The ingest rule of D2, expressed as a property rather than a comment.
//!
//! `encode(decode(bytes)) == bytes` for *every* accepted input is what makes
//! object identifiers unique. These tests exist to find the inputs where that
//! stops being true.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use pigeonnet_core::{
    IdentityId, Object, ObjectType, PublicKeyBytes, SignatureBytes, Tbs, Timestamp,
    cbor::{from_canonical_slice, to_canonical_vec},
};
use proptest::prelude::*;

fn arbitrary_tbs() -> impl Strategy<Value = Tbs> {
    (
        any::<u16>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<i64>(),
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(
            |(type_code, author, signing_key, millis, sequence, payload)| Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code,
                author: IdentityId::from_bytes(author),
                signing_key: PublicKeyBytes::from_bytes(signing_key),
                timestamp: Timestamp::from_millis(millis),
                sequence,
                payload,
            },
        )
}

fn arbitrary_object() -> impl Strategy<Value = Object> {
    (arbitrary_tbs(), any::<[u8; 64]>()).prop_map(|(tbs, sig)| {
        Object::from_parts(
            tbs.to_canonical_bytes().expect("tbs encodes"),
            SignatureBytes::from_bytes(sig),
        )
    })
}

proptest! {
    /// Encoding then decoding must return the same value.
    #[test]
    fn tbs_value_round_trips(tbs in arbitrary_tbs()) {
        let bytes = to_canonical_vec(&tbs)?;
        let back: Tbs = from_canonical_slice(&bytes)?;
        prop_assert_eq!(back, tbs);
    }

    /// The ingest rule: anything accepted must re-encode to exactly its input.
    #[test]
    fn accepted_objects_reencode_identically(object in arbitrary_object()) {
        let bytes = object.to_canonical_bytes()?;
        let decoded = Object::from_canonical_bytes(&bytes)?;
        prop_assert_eq!(decoded.to_canonical_bytes()?, bytes);
    }

    /// Identifiers are a function of the to-be-signed bytes alone. Changing the
    /// signature must not change the identifier (D1) -- otherwise signature
    /// malleability would mint two identifiers for one object.
    #[test]
    fn identifier_ignores_signature(
        tbs in arbitrary_tbs(),
        sig_a in any::<[u8; 64]>(),
        sig_b in any::<[u8; 64]>(),
    ) {
        let bytes = tbs.to_canonical_bytes()?;
        let a = Object::from_parts(bytes.clone(), SignatureBytes::from_bytes(sig_a));
        let b = Object::from_parts(bytes, SignatureBytes::from_bytes(sig_b));
        prop_assert_eq!(a.id(), b.id());
    }

    /// Distinct to-be-signed bytes must give distinct identifiers.
    #[test]
    fn identifier_follows_content(a in arbitrary_tbs(), b in arbitrary_tbs()) {
        prop_assume!(a != b);
        let id_a = Object::from_parts(a.to_canonical_bytes()?, SignatureBytes::ZERO).id();
        let id_b = Object::from_parts(b.to_canonical_bytes()?, SignatureBytes::ZERO).id();
        prop_assert_ne!(id_a, id_b);
    }

    /// Mutating a single byte must either be rejected, or re-encode to itself.
    /// What must never happen is acceptance of bytes that encode differently:
    /// that is two wire forms for one object, and two identifiers with it.
    #[test]
    fn mutations_are_rejected_or_canonical(
        object in arbitrary_object(),
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let mut bytes = object.to_canonical_bytes()?;
        prop_assume!(!bytes.is_empty());
        let i = index.index(bytes.len());
        bytes[i] = bytes[i].wrapping_add(delta);

        if let Ok(decoded) = Object::from_canonical_bytes(&bytes) {
            prop_assert_eq!(
                decoded.to_canonical_bytes()?,
                bytes,
                "accepted a non-canonical encoding"
            );
        }
    }
}

/// Unknown type codes are *unknown*, not invalid (§31): a relay must be able to
/// store, verify and forward an object from a newer vocabulary.
#[test]
fn unknown_type_codes_still_decode() {
    let tbs = Tbs {
        version: pigeonnet_core::OBJECT_VERSION,
        type_code: 61_000,
        author: IdentityId::ZERO,
        signing_key: PublicKeyBytes::ZERO,
        timestamp: Timestamp::EPOCH,
        sequence: 0,
        payload: b"payload from the future".to_vec(),
    };
    let object = Object::from_parts(tbs.to_canonical_bytes().unwrap(), SignatureBytes::ZERO);
    let bytes = object.to_canonical_bytes().unwrap();

    let decoded = Object::from_canonical_bytes(&bytes).expect("relayable");
    let decoded_tbs = decoded.tbs().expect("envelope is readable");
    assert_eq!(decoded_tbs.payload, tbs.payload);
    assert!(matches!(
        decoded_tbs.object_type(),
        Err(pigeonnet_core::Error::UnknownObjectType(61_000))
    ));
}

/// A future *version*, by contrast, is not processable at all (§31).
#[test]
fn unknown_versions_are_rejected() {
    let tbs = Tbs {
        version: pigeonnet_core::OBJECT_VERSION + 1,
        type_code: ObjectType::IdentityCreated.code(),
        author: IdentityId::ZERO,
        signing_key: PublicKeyBytes::ZERO,
        timestamp: Timestamp::EPOCH,
        sequence: 0,
        payload: Vec::new(),
    };
    let object = Object::from_parts(tbs.to_canonical_bytes().unwrap(), SignatureBytes::ZERO);
    let bytes = object.to_canonical_bytes().unwrap();
    assert!(matches!(
        Object::from_canonical_bytes(&bytes),
        Err(pigeonnet_core::Error::UnsupportedVersion(_))
    ));
}
