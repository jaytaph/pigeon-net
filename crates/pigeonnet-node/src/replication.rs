//! This node, seen as something a replication session can drive.
//!
//! The clock is injected rather than read, so a session's behaviour is
//! reproducible in a test.

use pigeonnet_core::{
    IdentityId, NodeId, Object, ObjectId, ObjectType, PublicKeyBytes, SignatureBytes, cbor,
    payload::Payload as _,
};
use pigeonnet_proto::{AcceptError, JournalEntry, Replica, ReplicaError, StreamId};

use crate::Node;

/// A replication view of a node.
#[derive(Debug)]
pub struct Replication<'a> {
    node: &'a Node,
    now: i64,
}

impl<'a> Replication<'a> {
    pub(crate) const fn new(node: &'a Node, now: i64) -> Self {
        Self { node, now }
    }
}

/// Streams are opaque keys to the store; this is where they get their meaning.
fn stream_key(stream: &StreamId) -> Result<Vec<u8>, ReplicaError> {
    cbor::to_canonical_vec(stream).map_err(|e| ReplicaError(e.to_string()))
}

fn local(e: impl core::fmt::Display) -> ReplicaError {
    ReplicaError(e.to_string())
}

impl Replica for Replication<'_> {
    fn journal_after(
        &self,
        stream: &StreamId,
        after: u64,
        limit: usize,
    ) -> Result<(Vec<JournalEntry>, bool), ReplicaError> {
        let key = stream_key(stream)?;
        let (entries, more) = self
            .node
            .store()
            .journal_after(&key, after, limit)
            .map_err(local)?;
        Ok((
            entries
                .into_iter()
                .map(|(position, object)| JournalEntry { position, object })
                .collect(),
            more,
        ))
    }

    fn inventory(
        &self,
        stream: &StreamId,
        from: u64,
        to: u64,
    ) -> Result<Vec<ObjectId>, ReplicaError> {
        let key = stream_key(stream)?;
        self.node
            .store()
            .journal_range(&key, from, to)
            .map_err(local)
    }

    fn contains(&self, id: ObjectId) -> Result<bool, ReplicaError> {
        self.node.store().contains(id).map_err(local)
    }

    fn object_bytes(&self, id: ObjectId) -> Result<Option<Vec<u8>>, ReplicaError> {
        let object = self.node.store().get(id).map_err(local)?;
        object
            .map(|o| o.to_canonical_bytes().map_err(local))
            .transpose()
    }

    /// Validate structurally and store.
    ///
    /// Three checks, and deliberately not a fourth. Canonical encoding, size,
    /// and a signature that verifies against the key the envelope itself names.
    /// What is *not* checked is whether that key was entitled to speak for the
    /// author — that needs the author's key chain, which a relay usually does
    /// not have and has no business demanding before it will carry traffic.
    ///
    /// Authority is evaluated on read, by whoever cares.
    fn accept(&mut self, bytes: &[u8]) -> Result<ObjectId, AcceptError> {
        if bytes.len() > self.node.limits().max_object_bytes {
            return Err(AcceptError::Invalid);
        }
        let object = Object::from_canonical_bytes(bytes).map_err(|_| AcceptError::Invalid)?;
        pigeonnet_crypto::verify_object(&object).map_err(|_| AcceptError::Invalid)?;

        let id = self
            .node
            .store()
            .put(&object, self.now)
            .map_err(|e| AcceptError::Local(local(e)))?;
        self.journal(&object, id).map_err(AcceptError::Local)?;
        Ok(id)
    }

    fn snapshot(&self, identity: IdentityId) -> Result<Option<Vec<u8>>, ReplicaError> {
        let snapshot = self.node.snapshot(identity, self.now).map_err(local)?;
        snapshot
            .map(|s| cbor::to_canonical_vec(&s).map_err(local))
            .transpose()
    }

    /// Check an inbox proof: the signature, then the authority behind it.
    ///
    /// Both halves matter. A valid signature from a key the identity never
    /// delegated is not authorisation, and a delegated key that has since been
    /// revoked is not either.
    fn verify_inbox_access(
        &self,
        identity: IdentityId,
        signing_key: PublicKeyBytes,
        transcript: &[u8],
        signature: SignatureBytes,
    ) -> Result<bool, ReplicaError> {
        if pigeonnet_crypto::verify(signing_key, transcript, signature).is_err() {
            return Ok(false);
        }
        // Needs the identity's key chain. A carrier holds it as an obligation of
        // carriage (§5.7); anyone else may simply not know this identity, which
        // is a refusal rather than a failure.
        let Ok(state) = self.node.identity_state(identity) else {
            return Ok(false);
        };
        Ok(state
            .check_device_authority(
                signing_key,
                pigeonnet_core::Timestamp::from_millis(self.now),
                pigeonnet_core::payload::Capabilities::NONE,
            )
            .is_ok())
    }

    fn cursor(&self, peer: NodeId, stream: &StreamId) -> Result<u64, ReplicaError> {
        let key = stream_key(stream)?;
        self.node
            .store()
            .cursor(peer.as_bytes(), &key)
            .map_err(local)
    }

    fn set_cursor(
        &mut self,
        peer: NodeId,
        stream: &StreamId,
        position: u64,
    ) -> Result<(), ReplicaError> {
        let key = stream_key(stream)?;
        self.node
            .store()
            .set_cursor(peer.as_bytes(), &key, position)
            .map_err(local)
    }
}

impl Replication<'_> {
    /// Journal an object into every stream it belongs to.
    ///
    /// Key-management objects land in their identity's stream as well as the
    /// general one, so a peer can pull an identity's delegation history without
    /// pulling everything else first.
    fn journal(&self, object: &Object, id: ObjectId) -> Result<(), ReplicaError> {
        let store = self.node.store();
        store
            .journal_append(&stream_key(&StreamId::All)?, id)
            .map_err(local)?;

        let tbs = object.tbs().map_err(local)?;
        let is_key_management = matches!(
            tbs.object_type(),
            Ok(ObjectType::IdentityCreated
                | ObjectType::DeviceKeyGranted
                | ObjectType::DeviceKeyRevoked)
        );
        if tbs.object_type() == Ok(ObjectType::DirectMessage) {
            // Spooled under the recipient, whoever is holding it. A carrier does
            // this as an obligation of carriage (§5.7); any other node does it
            // because a message it happens to hold is one it can serve to the
            // person it is for. Reading that stream needs a proof (§15.4).
            let message = pigeonnet_core::payload::DirectMessage::decode_payload(&tbs.payload)
                .map_err(local)?;
            let key = stream_key(&StreamId::Inbox(message.header.recipient))?;
            store.journal_append(&key, id).map_err(local)?;
        }

        if tbs.object_type() == Ok(ObjectType::EchoPost) {
            // Journalled into its area whether or not this node subscribes:
            // holding an object and wanting its area are separate questions, and
            // a subscription governs what we *ask* for (see `Node::sync_plan`).
            let post =
                pigeonnet_core::payload::EchoPost::decode_payload(&tbs.payload).map_err(local)?;
            let key = stream_key(&StreamId::Echo(post.area))?;
            store.journal_append(&key, id).map_err(local)?;
        }

        if is_key_management {
            // A genesis object names no author: the identity it belongs to is
            // the one it creates.
            let identity = if tbs.is_genesis() {
                pigeonnet_core::IdentityId::from_genesis(id)
            } else {
                tbs.author
            };
            let key = stream_key(&StreamId::Identity(identity))?;
            store.journal_append(&key, id).map_err(local)?;
        }
        Ok(())
    }
}
