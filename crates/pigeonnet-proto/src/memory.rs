//! An in-memory [`Replica`], for tests, fuzzing and examples.
//!
//! Shipped rather than confined to `#[cfg(test)]` so the fuzz targets and the
//! adversarial harness can share one implementation. It validates structure only
//! — no signatures — which is exactly what the trait asks of a relay (see
//! [`Replica`]).

use std::collections::BTreeMap;

use pigeonnet_core::{NodeId, Object, ObjectId};

use crate::{
    AcceptError, Replica, ReplicaError,
    message::{JournalEntry, StreamId},
};

/// An in-memory object store and journal.
#[derive(Debug, Default)]
pub struct MemoryReplica {
    objects: BTreeMap<ObjectId, Vec<u8>>,
    journals: BTreeMap<StreamId, Vec<JournalEntry>>,
    cursors: BTreeMap<(NodeId, StreamId), u64>,
}

impl MemoryReplica {
    /// An empty replica.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an object locally and journal it, as if it had been authored here.
    ///
    /// Positions start at 1, so that a cursor of 0 means "nothing yet" without
    /// needing a sentinel.
    pub fn insert(&mut self, stream: StreamId, bytes: Vec<u8>) -> Result<ObjectId, AcceptError> {
        let object = Object::from_canonical_bytes(&bytes).map_err(|_| AcceptError::Invalid)?;
        let id = object.id();
        self.objects.insert(id, bytes);

        let journal = self.journals.entry(stream).or_default();
        if !journal.iter().any(|e| e.object == id) {
            let position = journal.last().map_or(1, |e| e.position + 1);
            journal.push(JournalEntry {
                position,
                object: id,
            });
        }
        Ok(id)
    }

    /// How many objects are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Every identifier held, for assertions.
    #[must_use]
    pub fn ids(&self) -> Vec<ObjectId> {
        self.objects.keys().copied().collect()
    }
}

impl Replica for MemoryReplica {
    fn journal_after(
        &self,
        stream: &StreamId,
        after: u64,
        limit: usize,
    ) -> Result<(Vec<JournalEntry>, bool), ReplicaError> {
        let Some(journal) = self.journals.get(stream) else {
            return Ok((Vec::new(), false));
        };
        let matching: Vec<JournalEntry> = journal
            .iter()
            .filter(|e| e.position > after)
            .copied()
            .collect();
        let more = matching.len() > limit;
        Ok((matching.into_iter().take(limit).collect(), more))
    }

    fn inventory(
        &self,
        stream: &StreamId,
        from: u64,
        to: u64,
    ) -> Result<Vec<ObjectId>, ReplicaError> {
        let Some(journal) = self.journals.get(stream) else {
            return Ok(Vec::new());
        };
        Ok(journal
            .iter()
            .filter(|e| e.position >= from && e.position <= to)
            .map(|e| e.object)
            .collect())
    }

    fn contains(&self, id: ObjectId) -> Result<bool, ReplicaError> {
        Ok(self.objects.contains_key(&id))
    }

    fn object_bytes(&self, id: ObjectId) -> Result<Option<Vec<u8>>, ReplicaError> {
        Ok(self.objects.get(&id).cloned())
    }

    fn accept(&mut self, bytes: &[u8]) -> Result<ObjectId, AcceptError> {
        self.insert(StreamId::All, bytes.to_vec())
    }

    fn cursor(&self, peer: NodeId, stream: &StreamId) -> Result<u64, ReplicaError> {
        Ok(self.cursors.get(&(peer, *stream)).copied().unwrap_or(0))
    }

    fn set_cursor(
        &mut self,
        peer: NodeId,
        stream: &StreamId,
        position: u64,
    ) -> Result<(), ReplicaError> {
        self.cursors.insert((peer, *stream), position);
        Ok(())
    }
}
