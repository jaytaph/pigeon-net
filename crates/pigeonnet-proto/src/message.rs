//! Protocol frames.
//!
//! Frames are not signed objects and carry no authority. They are decoded with
//! the same canonical rule as objects (D2) anyway — not because a frame's
//! identity matters, but because "exactly one encoding per value" is a cheap
//! property to keep and an expensive one to reintroduce.

use minicbor::{Decode, Encode, bytes::ByteVec};
use pigeonnet_core::{AreaName, IdentityId, NodeId, ObjectId, cbor};

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
            Self::Hello { .. } | Self::HelloAck { .. } | Self::Want { .. } | Self::Bye => Ok(()),
        }
    }
}
