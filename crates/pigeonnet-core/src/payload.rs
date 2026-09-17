//! Type-specific object payloads.
//!
//! Each payload is encoded canonically and carried as an opaque byte string
//! inside [`Tbs`](crate::Tbs), so an object can be verified and relayed without
//! its payload type being known.

use minicbor::{Decode, Encode};

use crate::{
    Error, ObjectType,
    area::AreaName,
    bytes::{AgreementKeyBytes, IdentityId, NodeId, ObjectId, PublicKeyBytes},
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

// ---------------------------------------------------------------------------
// Current state (§5.6). Latest-wins, aggressively pruned, never journalled.
// ---------------------------------------------------------------------------

/// Optional human-facing detail about an identity (§5.6).
///
/// Carries no authority. A display name here is what its owner chose to call
/// itself, not a name anyone else has agreed to (§5.2 is where names bind).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct IdentityProfile {
    /// What the identity calls itself.
    #[n(0)]
    pub display_name: Option<String>,
}

impl Payload for IdentityProfile {
    const OBJECT_TYPE: ObjectType = ObjectType::IdentityProfile;
}

/// One device's key-agreement key for one epoch (§8.1, D4).
///
/// The identity and the device are **not** repeated here: they are the
/// envelope's `author` and `signing_key`. Carrying them twice would create two
/// places that can disagree, and a validation rule to reconcile them, for no
/// gain.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct EpochPrekey {
    /// Which epoch this covers.
    #[n(0)]
    pub epoch: u64,

    /// The public half.
    #[n(1)]
    pub public_key: AgreementKeyBytes,

    /// When the private half is destroyed (`epoch_end + W`).
    ///
    /// Published so a sender can see how much of the delivery budget is left
    /// before committing to this key, rather than guessing at the recipient's
    /// retention window.
    #[n(2)]
    pub valid_until: Timestamp,
}

impl Payload for EpochPrekey {
    const OBJECT_TYPE: ObjectType = ObjectType::EpochPrekey;
}

/// One carrier, and what it costs to reach the identity through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Carrier {
    /// The carrying node.
    #[n(0)]
    pub node: NodeId,
    /// Lower is preferred. Ranking only; carries no units.
    #[n(1)]
    pub cost: u32,
}

/// An identity naming the carriers it can be reached through (§5.7).
///
/// This is **not** a `RouteAdvertisement` and must not be treated as one. A
/// route advertisement is a peer's claim about a third party, which is
/// forgeable and therefore restricted to one hop (D6). This is an identity's
/// claim about itself: the worst it can do is direct its own mail at a node that
/// drops it, so it replicates freely.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ReachabilityClaim {
    /// Carriers, in the author's order of preference.
    #[n(0)]
    pub via: Vec<Carrier>,

    /// When this claim stops being actionable.
    #[n(1)]
    pub expires_at: Timestamp,
}

impl Payload for ReachabilityClaim {
    const OBJECT_TYPE: ObjectType = ObjectType::ReachabilityClaim;
}

/// A carrier consenting to spool for an identity (§5.7).
///
/// Required alongside a [`ReachabilityClaim`] before any sender routes toward
/// the named carrier. Without it, any identity could name any node and aim the
/// network at it — reflection with an attacker-chosen target — and declining the
/// traffic at the victim is no defence, because it already arrived.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct CarriageAccepted {
    /// The consenting node. Must match the signing device key.
    #[n(0)]
    pub carrier: NodeId,

    /// Who is being carried.
    #[n(1)]
    pub identity: IdentityId,

    /// When consent lapses. Carriage is revoked by expiry, not by an object.
    #[n(2)]
    pub expires_at: Timestamp,
}

impl Payload for CarriageAccepted {
    const OBJECT_TYPE: ObjectType = ObjectType::CarriageAccepted;
}

// ---------------------------------------------------------------------------
// Private messaging (§8, D4).
// ---------------------------------------------------------------------------

/// What kind of forward secrecy a message has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
pub enum ForwardSecrecy {
    /// Sealed to epoch prekeys. Unrecoverable once they are destroyed.
    #[n(0)]
    Epoch,
    /// Sealed to a long-term identity key because no current prekey was held.
    ///
    /// **Displayed to both parties.** The fallback keeps offline-first working
    /// when a sender's view of the recipient is months stale, and the cost is
    /// that the message never becomes unreadable. Silent degradation here would
    /// be worse than the degradation.
    #[n(1)]
    None,
}

/// The content key, wrapped for one of the recipient's devices.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct WrappedKey {
    /// Which device can open this entry.
    #[n(0)]
    pub device: PublicKeyBytes,

    /// Which epoch prekey it is sealed to, or absent for the identity-key
    /// fallback.
    #[n(1)]
    pub epoch: Option<u64>,

    /// The content key under a key derived for this device.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub wrapped: Vec<u8>,
}

/// Everything a direct message binds but does not hide.
///
/// Separated from the ciphertext so it can be canonically encoded and used as
/// associated data: the content is then cryptographically bound to the recipient
/// it names, the keys it was wrapped for, and the secrecy level it claims. A
/// relay that edits any of it invalidates the message rather than redirecting it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct MessageHeader {
    /// Who it is for. Cleartext by necessity — relays route on it (§8.2).
    #[n(0)]
    pub recipient: IdentityId,

    /// Which set of primitives sealed it.
    #[n(1)]
    pub suite: u16,

    /// The sender's one-shot public key, destroyed after sealing.
    #[n(2)]
    pub ephemeral_key: AgreementKeyBytes,

    /// The weakest entry below, so a client can label the message without
    /// inspecting every wrap.
    #[n(3)]
    pub fs: ForwardSecrecy,

    /// One entry per device the sender sealed to (§8.1 fan-out).
    #[n(4)]
    pub recipients: Vec<WrappedKey>,
}

/// An encrypted message to one identity (§8).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct DirectMessage {
    /// Bound, but not hidden.
    #[n(0)]
    pub header: MessageHeader,

    /// The content, sealed under a key wrapped in `header.recipients`.
    #[cbor(n(1), with = "minicbor::bytes")]
    pub ciphertext: Vec<u8>,
}

impl Payload for DirectMessage {
    const OBJECT_TYPE: ObjectType = ObjectType::DirectMessage;
}

impl MessageHeader {
    /// Canonical bytes, for use as associated data.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::to_canonical_vec(self)
    }
}
