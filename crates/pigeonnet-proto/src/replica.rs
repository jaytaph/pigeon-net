//! What the protocol needs from local storage.
//!
//! Expressed as a trait so that `pigeonnet-proto` depends on no database, no
//! filesystem and no runtime. The session logic is then drivable by an in-memory
//! fake in tests and by a fuzzer, which is where the attacks in D5 and D6 are
//! actually going to be found.

use pigeonnet_core::{IdentityId, NodeId, ObjectId, PublicKeyBytes, SignatureBytes};

use crate::message::{JournalEntry, StreamId};

/// Proves an identity may read its own inbox (§15.4).
///
/// A trait rather than a key, so that `pigeonnet-proto` holds no cryptography
/// and no private material: the session asks for a signature and never learns
/// what produced it.
pub trait InboxSigner {
    /// Whose inbox this credential is for.
    fn identity(&self) -> IdentityId;
    /// The device key that will sign.
    fn signing_key(&self) -> PublicKeyBytes;
    /// Sign a challenge transcript.
    fn sign(&self, transcript: &[u8]) -> SignatureBytes;
}

/// A local storage failure. Not the peer's fault; the session ends anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaError(pub String);

impl core::fmt::Display for ReplicaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for ReplicaError {}

/// Why an object was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    /// The object failed structural validation.
    Invalid,
    /// Local storage failed.
    Local(ReplicaError),
}

/// The local view a replication session operates on.
///
/// Note what is *not* here: authorisation. [`Replica::accept`] checks that an
/// object is canonically encoded, within limits, and signed by the key its own
/// envelope names — nothing more. Whether that key was entitled to speak for the
/// author needs the author's key chain, which a relay frequently does not have
/// and has no business requiring. A node that refused to carry objects for
/// identities it knows nothing about would not be a relay.
///
/// Authority is evaluated on read, by whoever cares.
pub trait Replica {
    /// Journal entries after `after`, ascending, at most `limit` of them.
    ///
    /// Returns the entries and whether more remain beyond them.
    fn journal_after(
        &self,
        stream: &StreamId,
        after: u64,
        limit: usize,
    ) -> Result<(Vec<JournalEntry>, bool), ReplicaError>;

    /// Identifiers in a bounded journal range, for repair (D5).
    fn inventory(
        &self,
        stream: &StreamId,
        from: u64,
        to: u64,
    ) -> Result<Vec<ObjectId>, ReplicaError>;

    /// Whether this node already holds an object.
    fn contains(&self, id: ObjectId) -> Result<bool, ReplicaError>;

    /// An object's canonical bytes, if held.
    fn object_bytes(&self, id: ObjectId) -> Result<Option<Vec<u8>>, ReplicaError>;

    /// Validate and store an object, returning its identifier.
    ///
    /// Must be idempotent: objects are immutable and content-addressed, so
    /// storing one twice is storing the same one.
    fn accept(&mut self, bytes: &[u8]) -> Result<ObjectId, AcceptError>;

    /// This node's current-state snapshot for an identity, encoded (D12).
    ///
    /// Answered from what this node already holds. **Never by asking anyone
    /// else** — see [`Message::Resolve`](crate::Message::Resolve).
    fn snapshot(&self, identity: IdentityId) -> Result<Option<Vec<u8>>, ReplicaError>;

    /// Whether a device key may read an identity's inbox (§15.4, D15).
    ///
    /// The implementor checks the signature over `transcript` and then whether
    /// that key was entitled to act for `identity` — which needs the identity's
    /// key chain, and is why this is not decided here.
    ///
    /// Returning `false` is a refusal, not an error: an unauthenticated asker
    /// has done nothing wrong, it simply may not read this.
    fn verify_inbox_access(
        &self,
        identity: IdentityId,
        signing_key: PublicKeyBytes,
        transcript: &[u8],
        signature: SignatureBytes,
    ) -> Result<bool, ReplicaError>;

    /// This node's cursor into a peer's journal for a stream.
    fn cursor(&self, peer: NodeId, stream: &StreamId) -> Result<u64, ReplicaError>;

    /// Record a new cursor position.
    fn set_cursor(
        &mut self,
        peer: NodeId,
        stream: &StreamId,
        position: u64,
    ) -> Result<(), ReplicaError>;
}
