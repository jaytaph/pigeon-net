//! Protocol frames.
//!
//! Frames are not signed objects and carry no authority. They are decoded with
//! the same canonical rule as objects (D2) anyway — not because a frame's
//! identity matters, but because "exactly one encoding per value" is a cheap
//! property to keep and an expensive one to reintroduce.

use minicbor::{Decode, Encode, bytes::ByteVec};
use pigeonnet_core::{
    AreaName, IdentityId, NodeId, ObjectId, PublicKeyBytes, SignatureBytes, cbor,
};

use crate::{ProtocolError, limits::Limits};

/// The protocol version this build speaks.
///
/// Deliberately separate from the object format version (§31): a transport
/// change and a wire-format change are different events and must not be forced
/// to happen together.
pub const PROTOCOL_VERSION: u16 = 1;

/// Optional protocol features, negotiated at handshake.
///
/// Present from the first release so that D5's deferred reconciliation
/// strategies can arrive later without a flag day. A node offers what it can do;
/// the session uses the intersection.
#[derive(Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
#[cbor(transparent)]
pub struct Features(#[n(0)] u32);

impl Features {
    /// No optional features: journal cursors and inventory repair only.
    pub const NONE: Self = Self(0);
    /// Bounded inventory exchange for cursor repair (D5).
    pub const INVENTORY_REPAIR: Self = Self(1 << 0);
    /// Reserved: Merkle range reconciliation (D5, deferred).
    pub const RANGE_RECONCILIATION: Self = Self(1 << 1);

    /// What this build actually implements.
    pub const SUPPORTED: Self = Self(Self::INVENTORY_REPAIR.0);

    /// Whether every feature in `other` is present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Features common to both sides.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl core::fmt::Debug for Features {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Features({:#06x})", self.0)
    }
}

/// What is being replicated.
///
/// M2 implements whole-store replication and identity chains. Echo areas, file
/// areas and inboxes are further variants, added by the milestones that
/// introduce them.
/// Not `Copy`: an area name owns its text, and interning it to win back a
/// `Copy` impl would trade a real cost for a cosmetic one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum StreamId {
    /// Everything this node holds and is willing to share.
    #[n(0)]
    All,
    /// One identity's key chain.
    ///
    /// Worth its own stream because a node usually wants an identity's
    /// delegation history before it can make sense of anything that identity
    /// signed.
    #[n(1)]
    Identity(#[n(0)] IdentityId),
    /// One echo area (§6).
    ///
    /// A node subscribing to `TECH.RUST` and nothing else syncs exactly that,
    /// which is what makes a subscription mean something rather than being a
    /// display filter over everything.
    #[n(2)]
    Echo(#[n(0)] AreaName),

    /// One identity's incoming private messages (§15.4).
    ///
    /// Restricted, and the only restricted stream in v1. An inbox open to every
    /// peer would make any identity's complete correspondence graph — senders,
    /// sizes, timing — globally fetchable from any carrier in the world, which
    /// is a far larger disclosure than §8.2's concession that relays on the path
    /// see metadata.
    #[n(3)]
    Inbox(#[n(0)] IdentityId),
}

/// Who may read a stream (§15.4, D15).
///
/// Access is a property of the **stream class**, never of the asker's identity.
/// There is no account, no registration, and no acceptance step: a brand-new
/// identity nobody has heard of may pull an area, read years of history and
/// leave. The network has to be readable before anyone has a reason to join it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Anyone who connects, subject to the serving node's quotas.
    Open,
    /// Only the named identity, proving it.
    Owner(IdentityId),
}

impl StreamId {
    /// Who may read this stream.
    #[must_use]
    pub const fn access(&self) -> Access {
        match self {
            Self::All | Self::Identity(_) | Self::Echo(_) => Access::Open,
            Self::Inbox(identity) => Access::Owner(*identity),
        }
    }
}

/// Domain separator for the inbox authentication transcript.
const INBOX_AUTH_CONTEXT: &[u8] = b"pigeonnet inbox-auth v1\x00";

/// What a client signs to prove it may read an inbox.
///
/// Binds the stream, the serving node's nonce, and the serving node itself, so a
/// proof captured by one node cannot be replayed at another or against a
/// different stream.
///
/// The leading ASCII context string is what keeps this out of reach of object
/// signatures: an object's signed bytes are canonical CBOR, which never begins
/// with this prefix, so a signature collected here can never be presented as an
/// object the key authored — or the reverse.
pub fn inbox_auth_transcript(stream: &StreamId, nonce: &[u8; 32], serving: NodeId) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(128);
    transcript.extend_from_slice(INBOX_AUTH_CONTEXT);
    transcript.extend_from_slice(serving.as_bytes());
    transcript.extend_from_slice(nonce);
    if let Ok(encoded) = cbor::to_canonical_vec(stream) {
        transcript.extend_from_slice(&encoded);
    }
    transcript
}

/// One journal position and the object at it.
///
/// `position` is the *sending* node's local sequence. It means nothing anywhere
/// else, and is never interpreted as an ordering claim about the world (D5) —
/// it is a cursor anchor and nothing more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct JournalEntry {
    /// The sender's local position.
    #[n(0)]
    pub position: u64,
    /// The object there.
    #[n(1)]
    pub object: ObjectId,
}

/// A protocol frame.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Message {
    /// Opening frame from the initiator.
    #[n(0)]
    Hello {
        /// Protocol version offered.
        #[n(0)]
        version: u16,
        /// Who is calling.
        #[n(1)]
        node: NodeId,
        /// What the caller can do.
        #[n(2)]
        features: Features,
    },

    /// The responder's answer.
    #[n(1)]
    HelloAck {
        /// Protocol version agreed.
        #[n(0)]
        version: u16,
        /// Who answered.
        #[n(1)]
        node: NodeId,
        /// What the responder can do.
        #[n(2)]
        features: Features,
    },

    /// "Send me what you have in this stream after this position."
    #[n(2)]
    Want {
        /// The stream.
        #[n(0)]
        stream: StreamId,
        /// Exclusive lower bound: the requester's cursor.
        #[n(1)]
        after: u64,
        /// Most entries wanted in the answer.
        #[n(2)]
        limit: u32,
    },

    /// Journal entries, in ascending position order.
    #[n(3)]
    Have {
        /// The stream.
        #[n(0)]
        stream: StreamId,
        /// Entries, ascending.
        #[n(1)]
        entries: Vec<JournalEntry>,
        /// Whether more remain beyond the last entry.
        #[n(2)]
        more: bool,
    },

    /// "Send me the bytes of these objects."
    #[n(4)]
    Fetch {
        /// What is wanted.
        #[n(0)]
        objects: Vec<ObjectId>,
    },

    /// Object bytes, canonically encoded.
    #[n(5)]
    Deliver {
        /// Each element is one object's canonical encoding.
        #[n(0)]
        objects: Vec<ByteVec>,
    },

    /// Repair path: list identifiers across a bounded range (D5).
    #[n(6)]
    InventoryRequest {
        /// The stream.
        #[n(0)]
        stream: StreamId,
        /// Inclusive lower bound.
        #[n(1)]
        from: u64,
        /// Inclusive upper bound.
        #[n(2)]
        to: u64,
    },

    /// The answer to an inventory request.
    #[n(7)]
    InventoryResponse {
        /// The stream.
        #[n(0)]
        stream: StreamId,
        /// Identifiers in the requested range.
        #[n(1)]
        objects: Vec<ObjectId>,
    },

    /// "Do you hold this identity's current state?" (D12, §5.6)
    ///
    /// **One hop. A node answers from what it holds and never forwards this.**
    /// Forwarding would build a DHT: every node would learn who is asking about
    /// whom, and the query would be floodable. One hop keeps it a cache lookup
    /// against peers already chosen.
    #[n(9)]
    Resolve {
        /// The exact identity. There is no search and no enumeration.
        #[n(0)]
        identity: IdentityId,
    },

    /// The answer, or its absence.
    ///
    /// The snapshot is opaque here: this crate never parses it. Everything
    /// inside is self-signed, so verification belongs to the receiver and a
    /// relay has no business pre-digesting it.
    #[n(10)]
    Resolved {
        /// Who was asked about.
        #[n(0)]
        identity: IdentityId,
        /// The encoded snapshot, or absent if this node does not hold it.
        #[n(1)]
        snapshot: Option<ByteVec>,
    },

    /// "Prove you may read that stream first." (§15.4)
    #[n(11)]
    AuthRequired {
        /// The stream in question.
        #[n(0)]
        stream: StreamId,
        /// A challenge chosen by the serving node.
        #[cbor(n(1), with = "minicbor::bytes")]
        nonce: [u8; 32],
    },

    /// A device-key signature over the challenge.
    #[n(12)]
    AuthProof {
        /// The stream being claimed.
        #[n(0)]
        stream: StreamId,
        /// Who is claiming it.
        #[n(1)]
        identity: IdentityId,
        /// Which of that identity's device keys signed.
        #[n(2)]
        signing_key: PublicKeyBytes,
        /// The signature over [`inbox_auth_transcript`].
        #[n(3)]
        signature: SignatureBytes,
    },

    /// Orderly end of session.
    #[n(8)]
    Bye,
}

impl Message {
    /// A short name, for error messages.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::HelloAck { .. } => "HelloAck",
            Self::Want { .. } => "Want",
            Self::Have { .. } => "Have",
            Self::Fetch { .. } => "Fetch",
            Self::Deliver { .. } => "Deliver",
            Self::InventoryRequest { .. } => "InventoryRequest",
            Self::InventoryResponse { .. } => "InventoryResponse",
            Self::AuthRequired { .. } => "AuthRequired",
            Self::AuthProof { .. } => "AuthProof",
            Self::Resolve { .. } => "Resolve",
            Self::Resolved { .. } => "Resolved",
            Self::Bye => "Bye",
        }
    }

    /// Encode canonically.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        cbor::to_canonical_vec(self).map_err(|_| ProtocolError::Malformed)
    }

    /// Decode a frame from a peer, enforcing size and collection limits.
    ///
    /// Limits are checked here rather than by the caller, because a frame that
    /// has already been decoded has already cost the memory the limit exists to
    /// bound.
    pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Self, ProtocolError> {
        if bytes.len() > limits.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size: bytes.len(),
                limit: limits.max_frame_bytes,
            });
        }
        let message: Self =
            cbor::from_canonical_slice(bytes).map_err(|_| ProtocolError::Malformed)?;
        message.check_limits(limits)?;
        Ok(message)
    }

    fn check_limits(&self, limits: &Limits) -> Result<(), ProtocolError> {
        let too_many = |what, count, limit| {
            if count > limit {
                Err(ProtocolError::TooMany { what, count, limit })
            } else {
                Ok(())
            }
        };
        match self {
            Self::Have { entries, .. } => {
                too_many("journal entries", entries.len(), limits.max_have_entries)
            }
            Self::Fetch { objects } => {
                too_many("fetch identifiers", objects.len(), limits.max_fetch_ids)
            }
            Self::Deliver { objects } => {
                too_many(
                    "delivered objects",
                    objects.len(),
                    limits.max_deliver_objects,
                )?;
                for object in objects {
                    if object.len() > limits.max_object_bytes {
                        return Err(ProtocolError::ObjectTooLarge {
                            size: object.len(),
                            limit: limits.max_object_bytes,
                        });
                    }
                }
                Ok(())
            }
            Self::InventoryResponse { objects, .. } => too_many(
                "inventory identifiers",
                objects.len(),
                limits.max_have_entries,
            ),
            Self::InventoryRequest { from, to, .. } => {
                let span = to.saturating_sub(*from).saturating_add(1);
                if span > limits.max_inventory_span {
                    return Err(ProtocolError::InventorySpanTooWide {
                        span,
                        limit: limits.max_inventory_span,
                    });
                }
                Ok(())
            }
            Self::Resolved { snapshot, .. } => {
                // A snapshot is roughly 14 KB for a three-device identity
                // (§5.6). The frame limit is the real bound; this guards against
                // a peer padding one to exhaust memory before it is parsed.
                match snapshot {
                    Some(bytes) if bytes.len() > limits.max_snapshot_bytes => {
                        Err(ProtocolError::TooMany {
                            what: "snapshot bytes",
                            count: bytes.len(),
                            limit: limits.max_snapshot_bytes,
                        })
                    }
                    _ => Ok(()),
                }
            }
            Self::Hello { .. }
            | Self::HelloAck { .. }
            | Self::Want { .. }
            | Self::Resolve { .. }
            | Self::AuthRequired { .. }
            | Self::AuthProof { .. }
            | Self::Bye => Ok(()),
        }
    }
}
