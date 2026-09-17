//! Signing and verifying objects.

use pigeonnet_core::{Object, Tbs};

use crate::{CryptoError, SigningKeypair, keys};

/// Sign a to-be-signed structure, producing a complete object.
///
/// The signature covers the canonical encoding of `tbs`, which is also what the
/// object's identifier is taken over — so signing and addressing agree on
/// exactly which bytes matter (D1).
pub fn sign_object(tbs: &Tbs, key: &SigningKeypair) -> Result<Object, CryptoError> {
    let bytes = tbs.to_canonical_bytes()?;
    let signature = key.sign(&bytes);
    Ok(Object::from_parts(bytes, signature))
}

/// Verify that the key named in an object's envelope signed its bytes.
///
/// This is **not** authorisation. It establishes that `signing_key` produced
/// this signature, and nothing about whether that key was ever entitled to speak
/// for the author, or was still valid when it did. That question is answered by
/// replaying the author's key chain (D3), which needs history this function does
/// not have.
///
/// Calling only this and treating the result as "the object is genuine" would
/// accept any object from any key that invented an `author` field.
pub fn verify_object(object: &Object) -> Result<(), CryptoError> {
    let tbs = object.tbs()?;
    keys::verify(tbs.signing_key, object.tbs_bytes(), object.signature())
}

#[cfg(test)]
mod tests {
    use pigeonnet_core::{IdentityId, ObjectType, SignatureBytes, Timestamp};

    use super::*;

    fn tbs(key: &SigningKeypair) -> Tbs {
        Tbs {
            version: pigeonnet_core::OBJECT_VERSION,
            type_code: ObjectType::IdentityCreated.code(),
            author: IdentityId::ZERO,
            signing_key: key.public(),
            timestamp: Timestamp::from_millis(1_758_000_000_000),
            sequence: 0,
            payload: b"payload".to_vec(),
        }
    }

    #[test]
    fn signs_and_verifies() {
        let key = SigningKeypair::generate().unwrap();
        let object = sign_object(&tbs(&key), &key).unwrap();
        assert!(verify_object(&object).is_ok());
    }

    #[test]
    fn rejects_tampered_payload() {
        let key = SigningKeypair::generate().unwrap();
        let mut altered = tbs(&key);
        altered.payload = b"payload!".to_vec();
        let signed = sign_object(&tbs(&key), &key).unwrap();

        // Same signature, different bytes.
        let forged = Object::from_parts(altered.to_canonical_bytes().unwrap(), signed.signature());
        assert_eq!(verify_object(&forged), Err(CryptoError::BadSignature));
    }

    #[test]
    fn rejects_swapped_signing_key() {
        let key = SigningKeypair::generate().unwrap();
        let other = SigningKeypair::generate().unwrap();
        let mut claimed = tbs(&key);
        claimed.signing_key = other.public();
        let object = Object::from_parts(
            claimed.to_canonical_bytes().unwrap(),
            key.sign(b"unrelated"),
        );
        assert_eq!(verify_object(&object), Err(CryptoError::BadSignature));
    }

    #[test]
    fn identifier_is_unchanged_by_resigning() {
        // Two signatures over identical bytes must give one identifier (D1).
        let key = SigningKeypair::generate().unwrap();
        let object = sign_object(&tbs(&key), &key).unwrap();
        let resigned = Object::from_parts(object.tbs_bytes().to_vec(), SignatureBytes::ZERO);
        assert_eq!(object.id(), resigned.id());
    }
}
