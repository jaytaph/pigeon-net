//! SQLite-backed object store.
//!
//! The store preserves the original canonical bytes of every object (D2, §25).
//! Everything else in the schema is a derived index: it exists to make lookups
//! fast, and can be dropped and rebuilt from the stored bytes without loss.
//!
//! Synchronous by design (§34.1). No async reaches this crate.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::path::Path;

use pigeonnet_core::{IdentityId, NodeId, Object, ObjectId, PublicKeyBytes, SignatureBytes};
use rusqlite::{Connection, OptionalExtension, params};

/// Schema version, bumped whenever the derived tables change shape.
///
/// A mismatch is not a migration problem: the derived tables can always be
/// rebuilt from the `objects` table's canonical bytes.
const SCHEMA_VERSION: i64 = 1;

/// Storage errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The database rejected an operation.
    Database(rusqlite::Error),
    /// Stored bytes did not decode — corruption, or a downgrade.
    Corrupt(pigeonnet_core::Error),
    /// The database was written by a newer build.
    SchemaTooNew(i64),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database: {e}"),
            Self::Corrupt(e) => write!(f, "stored object did not decode: {e}"),
            Self::SchemaTooNew(v) => {
                write!(f, "database schema version {v} is newer than this build")
            }
        }
    }
}

impl core::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}

impl From<pigeonnet_core::Error> for StoreError {
    fn from(e: pigeonnet_core::Error) -> Self {
        Self::Corrupt(e)
    }
}

/// A configured peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// Where to reach it.
    pub address: String,
    /// The identity it proved, once it has proved one.
    pub node_id: Option<NodeId>,
    /// When it was added.
    pub added_at: i64,
    /// When it was last synced with.
    pub last_sync_at: Option<i64>,
    /// Why the last attempt failed, if it did.
    pub last_error: Option<String>,
}

/// An object store.
#[derive(Debug)]
pub struct ObjectStore {
    conn: Connection,
}

impl ObjectStore {
    /// Open or create a store on disk.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open a transient store, for tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        // WAL: readers do not block the writer, which matters when a sync is
        // running while the CLI is reading.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew(version));
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS objects (
                 id          BLOB PRIMARY KEY NOT NULL,
                 tbs         BLOB NOT NULL,
                 signature   BLOB NOT NULL,
                 type_code   INTEGER NOT NULL,
                 author      BLOB NOT NULL,
                 signing_key BLOB NOT NULL,
                 timestamp   INTEGER NOT NULL,
                 sequence    INTEGER NOT NULL,
                 received_at INTEGER NOT NULL
             ) STRICT;
             CREATE INDEX IF NOT EXISTS objects_by_author
                 ON objects (author, signing_key, sequence);
             CREATE INDEX IF NOT EXISTS objects_by_type
                 ON objects (type_code, timestamp);

             -- Append-only journal, one per replication stream (D5).
             -- `stream` is an opaque key: the store has no business knowing
             -- what a stream means, only that entries under one never move.
             CREATE TABLE IF NOT EXISTS journal (
                 stream    BLOB NOT NULL,
                 position  INTEGER NOT NULL,
                 object_id BLOB NOT NULL,
                 PRIMARY KEY (stream, position)
             ) STRICT;
             CREATE UNIQUE INDEX IF NOT EXISTS journal_stream_object
                 ON journal (stream, object_id);

             -- How far we have read each peer's journal, per stream.
             -- Facts about *this* node, as opposed to objects it happens to hold.
             -- A node cannot infer which identity is its own by inspecting its
             -- object store: after one sync it holds other people's genesis
             -- objects too, and they are indistinguishable from its own.
             CREATE TABLE IF NOT EXISTS node_state (
                 key   TEXT PRIMARY KEY NOT NULL,
                 value BLOB NOT NULL
             ) STRICT;

             -- Peers this operator chose to talk to (§17.1). Static
             -- configuration: there is no discovery, and nothing adds a row
             -- here but `peer add`.
             CREATE TABLE IF NOT EXISTS peers (
                 address      TEXT PRIMARY KEY NOT NULL,
                 node_id      BLOB,
                 added_at     INTEGER NOT NULL,
                 last_sync_at INTEGER,
                 last_error   TEXT
             ) STRICT;

             -- Which echo areas this node carries (§6).
             CREATE TABLE IF NOT EXISTS subscriptions (
                 area TEXT PRIMARY KEY NOT NULL
             ) STRICT;

             CREATE TABLE IF NOT EXISTS cursors (
                 peer     BLOB NOT NULL,
                 stream   BLOB NOT NULL,
                 position INTEGER NOT NULL,
                 PRIMARY KEY (peer, stream)
             ) STRICT;",
        )?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;

        Ok(Self { conn })
    }

    /// Store an object. Storing one twice is not an error: objects are immutable
    /// and content-addressed, so a second copy is the same copy.
    pub fn put(&self, object: &Object, received_at: i64) -> Result<ObjectId, StoreError> {
        let id = object.id();
        let tbs = object.tbs()?;
        self.conn.execute(
            "INSERT INTO objects
                 (id, tbs, signature, type_code, author, signing_key, timestamp, sequence, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (id) DO NOTHING",
            params![
                id.as_bytes().as_slice(),
                object.tbs_bytes(),
                object.signature().as_bytes().as_slice(),
                i64::from(tbs.type_code),
                tbs.author.as_bytes().as_slice(),
                tbs.signing_key.as_bytes().as_slice(),
                tbs.timestamp.as_millis(),
                // SQLite integers are signed; sequences beyond i64::MAX are not
                // reachable in any real history, but reinterpret rather than
                // truncate so the round trip stays exact.
                tbs.sequence.cast_signed(),
                received_at,
            ],
        )?;
        Ok(id)
    }

    /// Retrieve an object by identifier.
    pub fn get(&self, id: ObjectId) -> Result<Option<Object>, StoreError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT tbs, signature FROM objects WHERE id = ?1",
                params![id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let Some((tbs, signature)) = row else {
            return Ok(None);
        };
        let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
            StoreError::Corrupt(pigeonnet_core::Error::BadLength {
                field: "signature",
                expected: 64,
                actual: signature.len(),
            })
        })?;
        Ok(Some(Object::from_parts(
            tbs,
            SignatureBytes::from_bytes(signature),
        )))
    }

    /// Whether an object is held.
    pub fn contains(&self, id: ObjectId) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM objects WHERE id = ?1",
                params![id.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// How many objects are held.
    pub fn len(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?;
        Ok(n.cast_unsigned())
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// The highest sequence number seen from a signing key, if any.
    pub fn highest_sequence(
        &self,
        author: IdentityId,
        signing_key: PublicKeyBytes,
    ) -> Result<Option<u64>, StoreError> {
        let value: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM objects WHERE author = ?1 AND signing_key = ?2",
            params![
                author.as_bytes().as_slice(),
                signing_key.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?;
        Ok(value.map(i64::cast_unsigned))
    }

    /// Append an object to a stream's journal, returning its position.
    ///
    /// Positions start at 1, so a cursor of 0 means "nothing yet" without
    /// needing a sentinel. Appending the same object twice returns the position
    /// it already has: journals are append-only, and moving an entry would
    /// rewind every peer's cursor that had passed it.
    pub fn journal_append(&self, stream: &[u8], id: ObjectId) -> Result<u64, StoreError> {
        if let Some(existing) = self.journal_position(stream, id)? {
            return Ok(existing);
        }
        let next: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM journal WHERE stream = ?1",
            params![stream],
            |row| row.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO journal (stream, position, object_id) VALUES (?1, ?2, ?3)",
            params![stream, next, id.as_bytes().as_slice()],
        )?;
        Ok(next.cast_unsigned())
    }

    /// Where an object sits in a stream's journal, if at all.
    pub fn journal_position(&self, stream: &[u8], id: ObjectId) -> Result<Option<u64>, StoreError> {
        let position: Option<i64> = self
            .conn
            .query_row(
                "SELECT position FROM journal WHERE stream = ?1 AND object_id = ?2",
                params![stream, id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(position.map(i64::cast_unsigned))
    }

    /// Journal entries after a position, ascending, and whether more remain.
    ///
    /// Asks for one more than `limit` so that "is there more" is answered by the
    /// same query rather than a second count.
    pub fn journal_after(
        &self,
        stream: &[u8],
        after: u64,
        limit: usize,
    ) -> Result<(Vec<(u64, ObjectId)>, bool), StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT position, object_id FROM journal
             WHERE stream = ?1 AND position > ?2
             ORDER BY position
             LIMIT ?3",
        )?;
        let probe = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let rows = statement.query_map(params![stream, after.cast_signed(), probe], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (position, id) = row?;
            let id: [u8; 32] = id.as_slice().try_into().map_err(|_| {
                StoreError::Corrupt(pigeonnet_core::Error::BadLength {
                    field: "object_id",
                    expected: 32,
                    actual: id.len(),
                })
            })?;
            entries.push((position.cast_unsigned(), ObjectId::from_bytes(id)));
        }
        let more = entries.len() > limit;
        entries.truncate(limit);
        Ok((entries, more))
    }

    /// Identifiers within a bounded journal range, for repair (D5).
    pub fn journal_range(
        &self,
        stream: &[u8],
        from: u64,
        to: u64,
    ) -> Result<Vec<ObjectId>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT object_id FROM journal
             WHERE stream = ?1 AND position >= ?2 AND position <= ?3
             ORDER BY position",
        )?;
        let rows = statement.query_map(
            params![stream, from.cast_signed(), to.cast_signed()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;

        let mut ids = Vec::new();
        for row in rows {
            let bytes = row?;
            let id: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                StoreError::Corrupt(pigeonnet_core::Error::BadLength {
                    field: "object_id",
                    expected: 32,
                    actual: bytes.len(),
                })
            })?;
            ids.push(ObjectId::from_bytes(id));
        }
        Ok(ids)
    }

    /// How far we have read a peer's journal for a stream.
    pub fn cursor(&self, peer: &[u8], stream: &[u8]) -> Result<u64, StoreError> {
        let position: Option<i64> = self
            .conn
            .query_row(
                "SELECT position FROM cursors WHERE peer = ?1 AND stream = ?2",
                params![peer, stream],
                |row| row.get(0),
            )
            .optional()?;
        Ok(position.map_or(0, i64::cast_unsigned))
    }

    /// Record a cursor position.
    ///
    /// Never moves backwards: a peer that offered us a lower position than we
    /// already hold is either corrupt or trying to make us re-fetch history, and
    /// the store refuses to help either way.
    pub fn set_cursor(&self, peer: &[u8], stream: &[u8], position: u64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO cursors (peer, stream, position) VALUES (?1, ?2, ?3)
             ON CONFLICT (peer, stream) DO UPDATE SET position = MAX(position, excluded.position)",
            params![peer, stream, position.cast_signed()],
        )?;
        Ok(())
    }

    /// Record a fact about this node.
    pub fn set_state(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO node_state (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Read a fact about this node.
    pub fn state(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM node_state WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Remember a peer. Adding the same address twice keeps the first row,
    /// including whatever identity was pinned to it.
    pub fn peer_add(
        &self,
        address: &str,
        node_id: Option<NodeId>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO peers (address, node_id, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (address) DO NOTHING",
            params![address, node_id.map(|n| n.as_bytes().to_vec()), now],
        )?;
        Ok(())
    }

    /// Forget a peer. Objects learned from it are kept: they were valid when
    /// they arrived and remain so.
    pub fn peer_remove(&self, address: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM peers WHERE address = ?1", params![address])?
            > 0)
    }

    /// Every configured peer.
    pub fn peers(&self) -> Result<Vec<PeerRecord>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT address, node_id, added_at, last_sync_at, last_error
             FROM peers ORDER BY address",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut peers = Vec::new();
        for row in rows {
            let (address, node_id, added_at, last_sync_at, last_error) = row?;
            let node_id = node_id
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                .map(NodeId::from_bytes);
            peers.push(PeerRecord {
                address,
                node_id,
                added_at,
                last_sync_at,
                last_error,
            });
        }
        Ok(peers)
    }

    /// Pin the identity a peer proved on first contact.
    ///
    /// Trust on first use, like an SSH host key: the pin is what makes a later
    /// substitution visible. Never silently overwritten.
    pub fn peer_pin(&self, address: &str, node_id: NodeId) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE peers SET node_id = ?2 WHERE address = ?1 AND node_id IS NULL",
            params![address, node_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Record how a sync went.
    pub fn peer_record_sync(
        &self,
        address: &str,
        now: i64,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE peers SET last_sync_at = ?2, last_error = ?3 WHERE address = ?1",
            params![address, now, error],
        )?;
        Ok(())
    }

    /// Subscribe to an echo area. Subscribing twice is not an error.
    pub fn subscribe(&self, area: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO subscriptions (area) VALUES (?1) ON CONFLICT DO NOTHING",
            params![area],
        )?;
        Ok(())
    }

    /// Unsubscribe. Objects already held are kept: they are valid whether or not
    /// this node still wants the area, and pruning is a separate decision (D8).
    pub fn unsubscribe(&self, area: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM subscriptions WHERE area = ?1", params![area])?;
        Ok(())
    }

    /// Whether this node carries an area.
    pub fn is_subscribed(&self, area: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM subscriptions WHERE area = ?1",
                params![area],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Every subscribed area, sorted.
    pub fn subscriptions(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT area FROM subscriptions ORDER BY area")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut areas = Vec::new();
        for row in rows {
            areas.push(row?);
        }
        Ok(areas)
    }

    /// An identity's key-management objects, in causal order.
    ///
    /// Key management is the root key's alone (§5.4), so ordering by sequence is
    /// ordering by cause: a grant always precedes anything the granted key
    /// signed.
    ///
    /// This is deliberately *not* every object the identity authored. Ordering
    /// those by `(signing_key, sequence)` is lexicographic rather than causal —
    /// when a device key happens to sort below the root key, a post replays
    /// before the grant that authorised it, and the chain appears to contain a
    /// key it never delegated. Authority for ordinary objects is evaluated on
    /// read instead, against the state this chain produces.
    ///
    /// Root rotation (D11) will introduce a second root key and with it a real
    /// ordering question; until then there is exactly one signer here.
    pub fn key_chain(&self, author: IdentityId) -> Result<Vec<Object>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT tbs, signature FROM objects
             WHERE author = ?1 AND type_code IN (1, 2, 3)
             ORDER BY signing_key, sequence",
        )?;
        let rows = statement.query_map(params![author.as_bytes().as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        Self::collect_objects(rows)
    }

    /// Every object authored by an identity, in chain order.
    ///
    /// Ordered by signing key then sequence, which is the order a key chain must
    /// be replayed in (D3).
    pub fn objects_by_author(&self, author: IdentityId) -> Result<Vec<Object>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT tbs, signature FROM objects
             WHERE author = ?1
             ORDER BY signing_key, sequence",
        )?;
        let rows = statement.query_map(params![author.as_bytes().as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;

        Self::collect_objects(rows)
    }

    /// Every object an identity authored of one type, newest last.
    pub fn objects_by_author_and_type(
        &self,
        author: IdentityId,
        type_code: u16,
    ) -> Result<Vec<Object>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT tbs, signature FROM objects
             WHERE author = ?1 AND type_code = ?2
             ORDER BY timestamp, id",
        )?;
        let rows = statement.query_map(
            params![author.as_bytes().as_slice(), i64::from(type_code)],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        Self::collect_objects(rows)
    }

    /// Every object of one type, whoever wrote it, newest last.
    ///
    /// Used to find carriage acceptances, which are authored by the *carrier*
    /// and so cannot be found by the carried identity. A dedicated index belongs
    /// here once carriage is common; a scan is honest while it is not.
    pub fn objects_of_type(&self, type_code: u16) -> Result<Vec<Object>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT tbs, signature FROM objects WHERE type_code = ?1 ORDER BY timestamp, id",
        )?;
        let rows = statement.query_map(params![i64::from(type_code)], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        Self::collect_objects(rows)
    }

    fn collect_objects<I>(rows: I) -> Result<Vec<Object>, StoreError>
    where
        I: Iterator<Item = rusqlite::Result<(Vec<u8>, Vec<u8>)>>,
    {
        let mut objects = Vec::new();
        for row in rows {
            let (tbs, signature) = row?;
            let signature: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                StoreError::Corrupt(pigeonnet_core::Error::BadLength {
                    field: "signature",
                    expected: 64,
                    actual: signature.len(),
                })
            })?;
            objects.push(Object::from_parts(
                tbs,
                SignatureBytes::from_bytes(signature),
            ));
        }
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use pigeonnet_core::{ObjectType, Tbs, Timestamp};

    use super::*;

    fn object(sequence: u64, payload: &[u8]) -> Object {
        let tbs = Tbs {
            version: pigeonnet_core::OBJECT_VERSION,
            type_code: ObjectType::IdentityCreated.code(),
            author: IdentityId::from_bytes([9; 32]),
            signing_key: PublicKeyBytes::from_bytes([4; 32]),
            timestamp: Timestamp::from_millis(1_758_000_000_000),
            sequence,
            payload: payload.to_vec(),
        };
        Object::from_parts(tbs.to_canonical_bytes().unwrap(), SignatureBytes::ZERO)
    }

    #[test]
    fn stores_and_retrieves_exact_bytes() {
        let store = ObjectStore::open_in_memory().unwrap();
        let original = object(0, b"hello");
        let id = store.put(&original, 1).unwrap();

        let fetched = store.get(id).unwrap().expect("present");
        // Byte-exact, not merely equivalent: an identifier refers to bytes.
        assert_eq!(fetched.tbs_bytes(), original.tbs_bytes());
        assert_eq!(fetched.id(), id);
    }

    #[test]
    fn storing_twice_is_idempotent() {
        let store = ObjectStore::open_in_memory().unwrap();
        let o = object(0, b"hello");
        store.put(&o, 1).unwrap();
        store.put(&o, 2).unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn missing_objects_are_absent_not_errors() {
        let store = ObjectStore::open_in_memory().unwrap();
        assert!(store.get(ObjectId::from_bytes([1; 32])).unwrap().is_none());
        assert!(!store.contains(ObjectId::from_bytes([1; 32])).unwrap());
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn tracks_highest_sequence_per_key() {
        let store = ObjectStore::open_in_memory().unwrap();
        let author = IdentityId::from_bytes([9; 32]);
        let key = PublicKeyBytes::from_bytes([4; 32]);
        assert_eq!(store.highest_sequence(author, key).unwrap(), None);

        for seq in [0, 1, 2] {
            store.put(&object(seq, b"x"), 1).unwrap();
        }
        assert_eq!(store.highest_sequence(author, key).unwrap(), Some(2));
    }

    #[test]
    fn large_sequences_round_trip() {
        // SQLite integers are signed; a sequence above i64::MAX must survive.
        let store = ObjectStore::open_in_memory().unwrap();
        let o = object(u64::MAX, b"x");
        store.put(&o, 1).unwrap();
        let author = IdentityId::from_bytes([9; 32]);
        let key = PublicKeyBytes::from_bytes([4; 32]);
        assert_eq!(store.highest_sequence(author, key).unwrap(), Some(u64::MAX));
    }

    #[test]
    fn journal_positions_start_at_one_and_increase() {
        let store = ObjectStore::open_in_memory().unwrap();
        let a = store.put(&object(0, b"a"), 1).unwrap();
        let b = store.put(&object(1, b"b"), 1).unwrap();
        assert_eq!(store.journal_append(b"all", a).unwrap(), 1);
        assert_eq!(store.journal_append(b"all", b).unwrap(), 2);
    }

    #[test]
    fn journal_append_is_idempotent() {
        // Re-appending must not move an entry: every peer past it would rewind.
        let store = ObjectStore::open_in_memory().unwrap();
        let a = store.put(&object(0, b"a"), 1).unwrap();
        assert_eq!(store.journal_append(b"all", a).unwrap(), 1);
        assert_eq!(store.journal_append(b"all", a).unwrap(), 1);
        let (entries, _) = store.journal_after(b"all", 0, 10).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn journals_are_independent_per_stream() {
        let store = ObjectStore::open_in_memory().unwrap();
        let a = store.put(&object(0, b"a"), 1).unwrap();
        assert_eq!(store.journal_append(b"one", a).unwrap(), 1);
        assert_eq!(store.journal_append(b"two", a).unwrap(), 1);
        assert_eq!(store.journal_after(b"one", 0, 10).unwrap().0.len(), 1);
    }

    #[test]
    fn journal_after_reports_whether_more_remain() {
        let store = ObjectStore::open_in_memory().unwrap();
        for n in 0..5 {
            let id = store.put(&object(n, b"x"), 1).unwrap();
            store.journal_append(b"all", id).unwrap();
        }
        let (entries, more) = store.journal_after(b"all", 0, 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(more);

        let (entries, more) = store.journal_after(b"all", 3, 3).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(!more);
    }

    #[test]
    fn cursors_never_move_backwards() {
        let store = ObjectStore::open_in_memory().unwrap();
        assert_eq!(store.cursor(b"peer", b"all").unwrap(), 0);
        store.set_cursor(b"peer", b"all", 10).unwrap();
        store.set_cursor(b"peer", b"all", 4).unwrap();
        assert_eq!(store.cursor(b"peer", b"all").unwrap(), 10);
    }

    #[test]
    fn journal_range_is_bounded() {
        let store = ObjectStore::open_in_memory().unwrap();
        for n in 0..10 {
            let id = store.put(&object(n, b"x"), 1).unwrap();
            store.journal_append(b"all", id).unwrap();
        }
        assert_eq!(store.journal_range(b"all", 3, 5).unwrap().len(), 3);
    }

    #[test]
    fn node_state_round_trips_and_overwrites() {
        let store = ObjectStore::open_in_memory().unwrap();
        assert!(store.state("identity").unwrap().is_none());
        store.set_state("identity", b"first").unwrap();
        store.set_state("identity", b"second").unwrap();
        assert_eq!(
            store.state("identity").unwrap().as_deref(),
            Some(b"second".as_slice())
        );
    }

    #[test]
    fn peers_pin_on_first_use_and_never_silently_change() {
        let store = ObjectStore::open_in_memory().unwrap();
        store.peer_add("hub.example:4137", None, 1).unwrap();
        assert_eq!(store.peers().unwrap()[0].node_id, None);

        let first = NodeId::from_bytes([1; 32]);
        store.peer_pin("hub.example:4137", first).unwrap();
        assert_eq!(store.peers().unwrap()[0].node_id, Some(first));

        // A second identity at the same address must not overwrite the pin.
        store
            .peer_pin("hub.example:4137", NodeId::from_bytes([2; 32]))
            .unwrap();
        assert_eq!(store.peers().unwrap()[0].node_id, Some(first));
    }

    #[test]
    fn adding_a_peer_twice_keeps_the_pin() {
        let store = ObjectStore::open_in_memory().unwrap();
        let pinned = NodeId::from_bytes([7; 32]);
        store.peer_add("hub:4137", Some(pinned), 1).unwrap();
        store.peer_add("hub:4137", None, 2).unwrap();
        assert_eq!(store.peers().unwrap()[0].node_id, Some(pinned));
    }

    #[test]
    fn sync_results_are_recorded() {
        let store = ObjectStore::open_in_memory().unwrap();
        store.peer_add("hub:4137", None, 1).unwrap();
        store
            .peer_record_sync("hub:4137", 99, Some("connection refused"))
            .unwrap();
        let peer = store.peers().unwrap().remove(0);
        assert_eq!(peer.last_sync_at, Some(99));
        assert_eq!(peer.last_error.as_deref(), Some("connection refused"));

        store.peer_record_sync("hub:4137", 100, None).unwrap();
        assert_eq!(store.peers().unwrap()[0].last_error, None);
    }

    #[test]
    fn removing_a_peer_reports_whether_it_existed() {
        let store = ObjectStore::open_in_memory().unwrap();
        store.peer_add("hub:4137", None, 1).unwrap();
        assert!(store.peer_remove("hub:4137").unwrap());
        assert!(!store.peer_remove("hub:4137").unwrap());
    }

    #[test]
    fn subscriptions_are_a_set() {
        let store = ObjectStore::open_in_memory().unwrap();
        assert!(!store.is_subscribed("GOSUB.DEV").unwrap());
        store.subscribe("GOSUB.DEV").unwrap();
        store.subscribe("GOSUB.DEV").unwrap();
        store.subscribe("TECH.RUST").unwrap();
        assert_eq!(
            store.subscriptions().unwrap(),
            vec!["GOSUB.DEV", "TECH.RUST"]
        );
        assert!(store.is_subscribed("GOSUB.DEV").unwrap());

        store.unsubscribe("GOSUB.DEV").unwrap();
        assert_eq!(store.subscriptions().unwrap(), vec!["TECH.RUST"]);
    }

    #[test]
    fn lists_an_authors_chain_in_order() {
        let store = ObjectStore::open_in_memory().unwrap();
        for seq in [2, 0, 1] {
            store.put(&object(seq, b"x"), 1).unwrap();
        }
        let chain = store
            .objects_by_author(IdentityId::from_bytes([9; 32]))
            .unwrap();
        let sequences: Vec<u64> = chain.iter().map(|o| o.tbs().unwrap().sequence).collect();
        assert_eq!(sequences, vec![0, 1, 2]);
    }
}
