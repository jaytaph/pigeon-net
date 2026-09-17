//! The signed object envelope.
//!
//! Objects are three nested layers, each one opaque to the layer above:
//!
//! ```text
//! Object { tbs: bytes, signature: bytes }
//!            └─ Tbs { version, type, author, signing_key, timestamp,
//!                     sequence, payload: bytes }
//!                                           └─ type-specific payload
//! ```
//!
//! Nesting by byte string rather than by structure is deliberate. It makes
//! "the identifier covers everything except the signature" (D1) structural
//! rather than a rule someone has to remember, and it means a relay can verify
//! and forward an object whose payload type it has never heard of — the
//! signature covers bytes, not meaning.

use minicbor::{Decode, Encode};

use crate::{
    Error, OBJECT_ID_CONTEXT, OBJECT_VERSION,
    bytes::{IdentityId, ObjectId, PublicKeyBytes, SignatureBytes},
    cbor,
    time::Timestamp,
};

/// Known object type codes.
///
/// Codes are assigned once and never reused. An unknown code is *unknown*, not
/// invalid (§31) — see [`Tbs::object_type`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u16)]
pub enum ObjectType {
    /// Genesis. Its object identifier becomes the identity (D3).
    IdentityCreated = 1,
    /// The root key delegates signing authority to a device key.
    DeviceKeyGranted = 2,
    /// The root key withdraws a device key's authority.
    DeviceKeyRevoked = 3,
}

impl ObjectType {
    /// The wire code for this type.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Interpret a wire code.
    pub const fn from_code(code: u16) -> Result<Self, Error> {
        match code {
            1 => Ok(Self::IdentityCreated),
            2 => Ok(Self::DeviceKeyGranted),
            3 => Ok(Self::DeviceKeyRevoked),
            other => Err(Error::UnknownObjectType(other)),
        }
    }
}

/// Everything a signature covers.
///
/// Field indices are assigned once and never reused, so renaming a field here
/// cannot change the wire format.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Tbs {
    /// Object format version (§31).
    #[n(0)]
    pub version: u16,

    /// Object type code. Deliberately not an enum: see [`Tbs::object_type`].
    #[n(1)]
    pub type_code: u16,

    /// The identity that authored this object.
    ///
    /// [`IdentityId::ZERO`] on a genesis object, which has no prior identity to
    /// name — the identity is what that object *creates*.
    #[n(2)]
    pub author: IdentityId,

    /// The key that produced the signature.
    ///
    /// A device key for ordinary objects; the root key for key management
    /// (§5.4); the recovery key for recovery (§5.5).
    #[n(3)]
    pub signing_key: PublicKeyBytes,

    /// When the author says this was created.
    #[n(4)]
    pub timestamp: Timestamp,

    /// Position in this *signing key's* sequence — not the identity's (D3).
    ///
    /// Per-key sequences are what let two devices of one person sign
    /// concurrently without coordinating, and what make two objects sharing a
    /// `(signing_key, sequence)` pair a self-contained proof of equivocation.
    #[n(5)]
    pub sequence: u64,

    /// Canonical encoding of the type-specific payload.
    #[cbor(n(6), with = "minicbor::bytes")]
    pub payload: Vec<u8>,
}

impl Tbs {
    /// The object type, if this build knows it.
    ///
    /// Returns [`Error::UnknownObjectType`] for a code from a newer vocabulary.
    /// That is not a validation failure: the object can still be stored,
    /// verified and relayed.
    pub const fn object_type(&self) -> Result<ObjectType, Error> {
        ObjectType::from_code(self.type_code)
    }

    /// True for a genesis object, which names no prior author.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.author == IdentityId::ZERO
    }

    /// Canonical bytes: what gets signed, and what the identifier is taken over.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::to_canonical_vec(self)
    }
}

/// A signed object, holding its to-be-signed bytes verbatim.
///
/// The original bytes are preserved rather than re-derived (§25): an identifier
/// and a signature both refer to exact bytes, so keeping them is the only way to
/// re-verify later without trusting our own encoder to be stable forever.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Object {
    #[cbor(n(0), with = "minicbor::bytes")]
    tbs: Vec<u8>,

    #[n(1)]
    signature: SignatureBytes,
}

impl Object {
    /// Assemble from canonical to-be-signed bytes and a signature over them.
    #[must_use]
    pub const fn from_parts(tbs: Vec<u8>, signature: SignatureBytes) -> Self {
        Self { tbs, signature }
    }

    /// The to-be-signed bytes, exactly as received or produced.
    #[must_use]
    pub fn tbs_bytes(&self) -> &[u8] {
        &self.tbs
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> SignatureBytes {
        self.signature
    }

    /// This object's content address (D1).
    ///
    /// Taken over the to-be-signed bytes, which excludes the signature.
    #[must_use]
    pub fn id(&self) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key(OBJECT_ID_CONTEXT);
        hasher.update(&self.tbs);
        ObjectId::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode the to-be-signed layer, enforcing canonical encoding.
    pub fn tbs(&self) -> Result<Tbs, Error> {
        let tbs: Tbs = cbor::from_canonical_slice(&self.tbs)?;
        if tbs.version != OBJECT_VERSION {
            return Err(Error::UnsupportedVersion(tbs.version));
        }
        Ok(tbs)
    }

    /// Canonical wire bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::to_canonical_vec(self)
    }

    /// Decode from bytes that arrived from outside this process.
    ///
    /// Enforces canonical encoding at both layers, and the version check, before
    /// any caller sees the contents. It does **not** check the signature: that
    /// needs cryptography, and lives in `pigeonnet-crypto`.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let object: Self = cbor::from_canonical_slice(bytes)?;
        // Force the inner layer through the same gate. An object whose envelope
        // is canonical but whose payload envelope is not would otherwise pass.
        let _ = object.tbs()?;
        Ok(object)
    }
}

impl core::fmt::Debug for Object {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Object")
            .field("id", &self.id())
            .field("tbs_len", &self.tbs.len())
            .field("signature", &self.signature)
            .finish()
    }
}
