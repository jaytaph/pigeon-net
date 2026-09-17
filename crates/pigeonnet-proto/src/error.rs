//! Protocol errors.
//!
//! Every variant here means "this peer is not behaving; end the session". None
//! of them are recoverable in-session, because continuing to talk to a peer that
//! has already broken the protocol is how a resource-exhaustion attack gets its
//! second chance.

use core::fmt;

use pigeonnet_core::{NodeId, ObjectId};

/// A peer broke the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A frame did not decode, or was not canonically encoded.
    Malformed,

    /// A frame exceeded [`Limits::max_frame_bytes`](crate::Limits).
    FrameTooLarge {
        /// How large it was.
        size: usize,
        /// The configured ceiling.
        limit: usize,
    },

    /// A message arrived that does not belong in the current state.
    ///
    /// Covers a peer replying before the handshake, answering a question it was
    /// not asked, or sending two `Hello`s.
    Unexpected {
        /// What arrived.
        message: &'static str,
        /// What the session was doing.
        state: &'static str,
    },

    /// No protocol version in common (§31).
    VersionMismatch {
        /// What this node offered.
        ours: u16,
        /// What the peer offered.
        theirs: u16,
    },

    /// A collection exceeded its configured limit.
    TooMany {
        /// What was being counted.
        what: &'static str,
        /// How many arrived.
        count: usize,
        /// The configured ceiling.
        limit: usize,
    },

    /// An object exceeded the per-object size limit.
    ObjectTooLarge {
        /// How large it was.
        size: usize,
        /// The configured ceiling.
        limit: usize,
    },

    /// The session's cumulative budget ran out.
    SessionBudgetExhausted,

    /// A peer's journal positions did not increase.
    ///
    /// A journal is append-only by definition, so this is either corruption or a
    /// peer trying to make us rewind a cursor and re-fetch history indefinitely.
    NonMonotonicJournal {
        /// The position last seen.
        previous: u64,
        /// The position offered.
        offered: u64,
    },

    /// A peer delivered an object that was never requested.
    ///
    /// Accepting these would let any peer push arbitrary content at any time,
    /// bypassing every limit expressed in terms of what we asked for.
    UnsolicitedObject(ObjectId),

    /// A peer delivered bytes whose content address is not what was requested.
    WrongObject {
        /// What had been asked for.
        expected: ObjectId,
        /// What arrived.
        received: ObjectId,
    },

    /// A delivered object failed structural validation.
    InvalidObject,

    /// An inventory request covered too wide a range.
    InventorySpanTooWide {
        /// The span asked for.
        span: u64,
        /// The configured ceiling.
        limit: u64,
    },

    /// The peer proved a different identity than the one pinned to its address.
    ///
    /// Either the address now points somewhere else, or something is answering
    /// in its place. Both are worth stopping for.
    WrongPeer {
        /// What was pinned.
        expected: NodeId,
        /// What answered.
        found: NodeId,
    },

    /// A restricted stream was requested without an acceptable proof (§15.4).
    ///
    /// Carries no detail. Which of "no credential", "wrong identity" or "bad
    /// signature" applied is information an asker can use and a legitimate one
    /// does not need.
    ///
    /// Note where this is raised. A client raises it *locally*, before sending
    /// anything, when it can see it cannot answer a challenge. A server raises
    /// it when a proof fails, and then simply stops talking — so the client sees
    /// a disconnect, not a reason. That asymmetry is deliberate: a server that
    /// distinguished "denied" from "gone" would confirm to a prober that an
    /// inbox exists and is guarded, and the legitimate owner never needs the
    /// distinction, because it knows what credential it offered.
    AccessDenied,

    /// The local store failed. Not the peer's fault, but the session ends.
    Local(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("frame was malformed or non-canonical"),
            Self::FrameTooLarge { size, limit } => {
                write!(f, "frame of {size} bytes exceeds limit of {limit}")
            }
            Self::Unexpected { message, state } => {
                write!(f, "unexpected {message} while {state}")
            }
            Self::VersionMismatch { ours, theirs } => {
                write!(
                    f,
                    "no common protocol version (ours {ours}, theirs {theirs})"
                )
            }
            Self::TooMany { what, count, limit } => {
                write!(f, "{count} {what} exceeds limit of {limit}")
            }
            Self::ObjectTooLarge { size, limit } => {
                write!(f, "object of {size} bytes exceeds limit of {limit}")
            }
            Self::SessionBudgetExhausted => f.write_str("session budget exhausted"),
            Self::NonMonotonicJournal { previous, offered } => {
                write!(f, "journal went backwards: {previous} then {offered}")
            }
            Self::UnsolicitedObject(id) => write!(f, "unsolicited object {id}"),
            Self::WrongObject { expected, received } => {
                write!(f, "asked for {expected}, received {received}")
            }
            Self::InvalidObject => f.write_str("object failed validation"),
            Self::InventorySpanTooWide { span, limit } => {
                write!(f, "inventory span {span} exceeds limit of {limit}")
            }
            Self::WrongPeer { expected, found } => {
                write!(f, "expected peer {expected}, but {found} answered")
            }
            Self::AccessDenied => f.write_str("not permitted to read that stream"),
            Self::Local(message) => write!(f, "local failure: {message}"),
        }
    }
}

impl core::error::Error for ProtocolError {}
