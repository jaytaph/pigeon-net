//! Type-specific object payloads.
//!
//! Each payload is encoded canonically and carried as an opaque byte string
//! inside [`Tbs`](crate::Tbs), so an object can be verified and relayed without
//! its payload type being known.

use minicbor::{Decode, Encode};

use crate::{
    Error, ObjectType,
    area::AreaName,
    bytes::{AgreementKeyBytes, ObjectId, PublicKeyBytes},
    cbor,
    time::Timestamp,
};

/// A type-specific payload that knows which object type carries it.
pub trait Payload: Sized + Encode<()> + for<'b> Decode<'b, ()> {
    /// The object type this payload belongs to.
    const OBJECT_TYPE: ObjectType;

    /// Decode from an object's payload bytes, enforcing canonical encoding.
    fn decode_payload(bytes: &[u8]) -> Result<Self, Error> {
        cbor::from_canonical_slice(bytes)
    }

    /// Encode canonically, for embedding in an object.
    fn encode_payload(&self) -> Result<Vec<u8>, Error> {
        cbor::to_canonical_vec(self)
    }
}

/// What a device key is permitted to sign.
///
/// A bit set rather than a list: a set has no inherent order, and a list of it
/// would have many encodings of the same value. Unknown bits from a newer
/// vocabulary survive a round trip without being understood.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Encode, Decode)]
#[cbor(transparent)]
pub struct Capabilities(#[n(0)] u32);

impl Capabilities {
    /// Public posts in echo areas.
    pub const POST: Self = Self(1 << 0);
    /// Private messages.
    pub const MESSAGE: Self = Self(1 << 1);
    /// File manifests.
    pub const PUBLISH_FILE: Self = Self(1 << 2);
    /// Epoch prekeys (§8.1) — the capability that keeps the root key cold.
    pub const PUBLISH_PREKEYS: Self = Self(1 << 3);

    /// No capabilities.
    pub const NONE: Self = Self(0);

    /// Raw bits, including any this build does not recognise.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// From raw bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every capability in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for Capabilities {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::fmt::Debug for Capabilities {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut names = Vec::new();
        for (bit, name) in [
            (Self::POST, "post"),
            (Self::MESSAGE, "message"),
            (Self::PUBLISH_FILE, "publish-file"),
            (Self::PUBLISH_PREKEYS, "publish-prekeys"),
        ] {
            if self.contains(bit) {
                names.push(name);
            }
        }
        let known = Self::POST | Self::MESSAGE | Self::PUBLISH_FILE | Self::PUBLISH_PREKEYS;
        let unknown = self.0 & !known.0;
        if unknown != 0 {
            write!(f, "[{} +unknown:{unknown:#x}]", names.join(","))
        } else {
            write!(f, "[{}]", names.join(","))
        }
    }
}

/// Genesis. This object's identifier becomes the identity (D3).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct IdentityCreated {
    /// The first root key. Signs key management only, and is expected to live
    /// offline (§5.4).
    #[n(0)]
    pub root_key: PublicKeyBytes,

    /// The recovery key (D11, §5.5).
    ///
    /// Present from genesis and mandatory, because an identity cannot acquire
    /// one safely later: designating a recovery key after the fact leaves a
    /// window in which a thief designates theirs instead. It outranks the root
    /// key, and the root key cannot revoke it.
    #[n(1)]
    pub recovery_key: PublicKeyBytes,

    /// The long-term X25519 key, used only as the `fs: none` fallback when every
    /// epoch prekey a sender holds has expired (§8.1).
    #[n(2)]
    pub agreement_key: AgreementKeyBytes,
}

impl Payload for IdentityCreated {
    const OBJECT_TYPE: ObjectType = ObjectType::IdentityCreated;
}

/// The root key delegates signing authority to a device key (§5.4).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct DeviceKeyGranted {
    /// The delegated key.
    #[n(0)]
    pub device_key: PublicKeyBytes,

    /// What it may sign.
    #[n(1)]
    pub capabilities: Capabilities,

    /// Not valid before this instant.
    #[n(2)]
    pub not_before: Timestamp,

    /// Not valid after this instant; absent means no expiry.
    #[n(3)]
    pub not_after: Option<Timestamp>,
}

impl Payload for DeviceKeyGranted {
    const OBJECT_TYPE: ObjectType = ObjectType::DeviceKeyGranted;
}

/// The root key withdraws a device key's authority (§5.4).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct DeviceKeyRevoked {
    /// The key losing authority.
    #[n(0)]
    pub device_key: PublicKeyBytes,

    /// From when the key is no longer valid for *new* objects.
    #[n(1)]
    pub revoked_at: Timestamp,

    /// Optionally invalidate objects signed from this instant onward.
    ///
    /// Revocation is not retroactive by default: invalidating history would
    /// erase the victim's own past objects, which a thief did not forge. This
    /// field is for when the owner believes the key was compromised before the
    /// compromise was noticed.
    #[n(2)]
    pub invalidate_from: Option<Timestamp>,
}

impl Payload for DeviceKeyRevoked {
    const OBJECT_TYPE: ObjectType = ObjectType::DeviceKeyRevoked;
}

/// A public post in an echo area (§6, §7).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct EchoPost {
    /// Which area this belongs to.
    #[n(0)]
    pub area: AreaName,

    /// The thread root, or absent on a root post.
    ///
    /// A root post cannot name itself: its identifier is a hash of the bytes
    /// being written, so the value would have to exist before it does. Absent
    /// therefore means "I am the root", and readers substitute the object's own
    /// identifier — the same trick genesis objects use for `author` (D3).
    #[n(1)]
    pub thread: Option<ObjectId>,

    /// The immediate parent, or absent on a root post.
    #[n(2)]
    pub parent: Option<ObjectId>,

    /// How to interpret `content`.
    #[n(3)]
    pub content_type: String,

    /// The post itself.
    #[n(4)]
    pub content: String,
}

impl EchoPost {
    /// A new thread.
    #[must_use]
    pub fn root(area: AreaName, content_type: String, content: String) -> Self {
        Self {
            area,
            thread: None,
            parent: None,
            content_type,
            content,
        }
    }

    /// A reply.
    #[must_use]
    pub fn reply(
        area: AreaName,
        thread: ObjectId,
        parent: ObjectId,
        content_type: String,
        content: String,
    ) -> Self {
        Self {
            area,
            thread: Some(thread),
            parent: Some(parent),
            content_type,
            content,
        }
    }

    /// Whether this starts a thread.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.thread.is_none()
    }

    /// The thread this post belongs to, given the post's own identifier.
    #[must_use]
    pub fn thread_root(&self, own_id: ObjectId) -> ObjectId {
        self.thread.unwrap_or(own_id)
    }

    /// Reject inconsistent threading.
    ///
    /// A reply names both a parent and a thread root; a root post names neither.
    /// One without the other cannot be placed in a tree, and no node downstream
    /// can repair it — so it is refused at the boundary rather than stored and
    /// rendered wrongly forever (§7).
    fn validate(&self) -> Result<(), Error> {
        if self.thread.is_some() == self.parent.is_some() {
            Ok(())
        } else {
            Err(Error::BadThreading)
        }
    }
}

impl Payload for EchoPost {
    const OBJECT_TYPE: ObjectType = ObjectType::EchoPost;

    fn decode_payload(bytes: &[u8]) -> Result<Self, Error> {
        let post: Self = cbor::from_canonical_slice(bytes)?;
        post.validate()?;
        Ok(post)
    }

    fn encode_payload(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        cbor::to_canonical_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_order_free() {
        let a = Capabilities::POST | Capabilities::MESSAGE;
        let b = Capabilities::MESSAGE | Capabilities::POST;
        assert_eq!(a, b);
        // The point: one logical set, one encoding. A list would give two.
        assert_eq!(
            cbor::to_canonical_vec(&a).unwrap(),
            cbor::to_canonical_vec(&b).unwrap()
        );
    }

    #[test]
    fn capabilities_preserve_unknown_bits() {
        let future = Capabilities::from_bits(Capabilities::POST.bits() | 1 << 30);
        let bytes = cbor::to_canonical_vec(&future).unwrap();
        let back: Capabilities = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(back, future);
        assert!(back.contains(Capabilities::POST));
        assert!(!back.contains(Capabilities::MESSAGE));
    }

    #[test]
    fn absent_option_is_omitted_not_null() {
        let granted = DeviceKeyGranted {
            device_key: PublicKeyBytes::ZERO,
            capabilities: Capabilities::POST,
            not_before: Timestamp::EPOCH,
            not_after: None,
        };
        let bytes = granted.encode_payload().unwrap();
        assert!(
            !bytes.contains(&0xf6),
            "CBOR null must not appear: {bytes:02x?}"
        );
        assert_eq!(DeviceKeyGranted::decode_payload(&bytes).unwrap(), granted);
    }

    fn area() -> AreaName {
        AreaName::parse("GOSUB.DEV").unwrap()
    }

    #[test]
    fn a_root_post_is_its_own_thread() {
        let post = EchoPost::root(area(), "text/markdown".into(), "hello".into());
        assert!(post.is_root());
        let own = ObjectId::from_bytes([5; 32]);
        assert_eq!(post.thread_root(own), own);
    }

    #[test]
    fn a_reply_names_its_thread() {
        let root = ObjectId::from_bytes([1; 32]);
        let parent = ObjectId::from_bytes([2; 32]);
        let post = EchoPost::reply(area(), root, parent, "text/plain".into(), "ack".into());
        assert!(!post.is_root());
        assert_eq!(post.thread_root(ObjectId::from_bytes([9; 32])), root);
    }

    #[test]
    fn half_threaded_posts_are_refused() {
        // A parent without a thread root, or the reverse, cannot be placed in a
        // tree and cannot be repaired downstream.
        let mut orphan = EchoPost::root(area(), "text/plain".into(), "x".into());
        orphan.parent = Some(ObjectId::from_bytes([2; 32]));
        assert_eq!(orphan.encode_payload(), Err(Error::BadThreading));

        let mut rootless = EchoPost::root(area(), "text/plain".into(), "x".into());
        rootless.thread = Some(ObjectId::from_bytes([1; 32]));
        assert_eq!(rootless.encode_payload(), Err(Error::BadThreading));
    }

    #[test]
    fn half_threaded_posts_are_refused_on_the_way_in_too() {
        // Encoded by something that did not check, or edited in transit.
        let mut orphan = EchoPost::root(area(), "text/plain".into(), "x".into());
        orphan.parent = Some(ObjectId::from_bytes([2; 32]));
        let bytes = cbor::to_canonical_vec(&orphan).unwrap();
        assert_eq!(EchoPost::decode_payload(&bytes), Err(Error::BadThreading));
    }

    #[test]
    fn echo_posts_round_trip() {
        let post = EchoPost::reply(
            area(),
            ObjectId::from_bytes([1; 32]),
            ObjectId::from_bytes([2; 32]),
            "text/markdown".into(),
            "Works here too, Debian 13.".into(),
        );
        let bytes = post.encode_payload().unwrap();
        assert_eq!(EchoPost::decode_payload(&bytes).unwrap(), post);
    }

    #[test]
    fn payload_round_trips() {
        let created = IdentityCreated {
            root_key: PublicKeyBytes::from_bytes([1; 32]),
            recovery_key: PublicKeyBytes::from_bytes([2; 32]),
            agreement_key: AgreementKeyBytes::from_bytes([3; 32]),
        };
        let bytes = created.encode_payload().unwrap();
        assert_eq!(IdentityCreated::decode_payload(&bytes).unwrap(), created);
    }
}
