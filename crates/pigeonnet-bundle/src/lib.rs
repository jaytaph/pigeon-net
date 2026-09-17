//! Reading and writing `.pack` bundles for offline transport (§19).
//!
//! A bundle is a sync with the conversation removed. It carries the *data* plane
//! of D5 — journal entries and object bytes — and cannot carry the control plane,
//! because `Fetch` is a round trip and removable media does not have one. The
//! sender therefore cannot know what the receiver lacks, and sends everything
//! after a stated position.
//!
//! What it does share with a socket sync is everything that matters for safety:
//! the same [`Replica`] trait, the same limits, the same canonical decoding, the
//! same per-object signature check, and the same cursor semantics. A bundle from
//! a stranger's USB stick is exactly as safe to import as a sync with a peer,
//! because neither is trusted (§29).
//!
//! Two-pass exchange is supported the way FidoNet did it: a bundle may state
//! where its sender's cursors stand, so the bundle sent back can be targeted
//! rather than exhaustive.
//!
//! ```text
//! magic     8 bytes   "PGNPACK\0"
//! version   1 byte
//! body      canonical CBOR
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use minicbor::{Decode, Encode, bytes::ByteVec};
use pigeonnet_core::{NodeId, Object, ObjectId, cbor};
use pigeonnet_proto::{AcceptError, JournalEntry, Limits, Replica, StreamId};

const MAGIC: &[u8; 8] = b"PGNPACK\0";
const VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1;

/// Why a bundle could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BundleError {
    /// Not a bundle, or a version this build does not read.
    Format,
    /// The body was malformed or not canonically encoded.
    Malformed,
    /// The file is larger than this node is willing to read.
    TooLarge {
        /// Its size.
        size: usize,
        /// The configured ceiling.
        limit: usize,
    },
    /// The bundle declares more objects than this node will accept.
    TooManyObjects {
        /// How many it declares.
        count: usize,
        /// The configured ceiling.
        limit: usize,
    },
    /// An object inside exceeded the per-object size limit.
    ObjectTooLarge {
        /// Its size.
        size: usize,
        /// The configured ceiling.
        limit: usize,
    },
    /// A stream's journal entries did not strictly increase.
    NonMonotonicJournal {
        /// The position last seen.
        previous: u64,
        /// The position offered.
        offered: u64,
    },
    /// An object inside failed validation.
    InvalidObject(ObjectId),
    /// A journal entry referred to an object the bundle does not carry.
    DanglingEntry(ObjectId),
    /// Local storage failed.
    Local(String),
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format => f.write_str("not a recognised bundle"),
            Self::Malformed => f.write_str("bundle body was malformed or non-canonical"),
            Self::TooLarge { size, limit } => {
                write!(f, "bundle of {size} bytes exceeds limit of {limit}")
            }
            Self::TooManyObjects { count, limit } => {
                write!(f, "bundle declares {count} objects, limit is {limit}")
            }
            Self::ObjectTooLarge { size, limit } => {
                write!(f, "object of {size} bytes exceeds limit of {limit}")
            }
            Self::NonMonotonicJournal { previous, offered } => {
                write!(f, "journal went backwards: {previous} then {offered}")
            }
            Self::InvalidObject(id) => write!(f, "object {id} failed validation"),
            Self::DanglingEntry(id) => write!(f, "journal entry refers to absent object {id}"),
            Self::Local(message) => write!(f, "local failure: {message}"),
        }
    }
}

impl core::error::Error for BundleError {}

/// Where a cursor stands for one stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct StreamCursor {
    /// The stream.
    #[n(0)]
    pub stream: StreamId,
    /// Exclusive lower bound: everything after this.
    #[n(1)]
    pub after: u64,
}

/// One stream's journal slice.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Section {
    /// The stream.
    #[n(0)]
    pub stream: StreamId,
    /// Entries at the *origin's* journal positions, ascending.
    #[n(1)]
    pub entries: Vec<JournalEntry>,
}

/// A bundle's contents.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Bundle {
    /// Who packed it.
    #[n(0)]
    pub origin: NodeId,
    /// When, in milliseconds since the epoch.
    #[n(1)]
    pub created_at: i64,
    /// Journal slices, one per stream.
    #[n(2)]
    pub sections: Vec<Section>,
    /// Object bytes, deduplicated across sections.
    #[n(3)]
    pub objects: Vec<ByteVec>,
    /// Where the sender's own cursors stand, so a reply can be targeted.
    ///
    /// Purely advisory. A receiver may ignore it, and an attacker stating
    /// absurd cursors achieves nothing beyond a wasted reply.
    #[n(4)]
    pub requests: Vec<StreamCursor>,
}

impl Bundle {
    /// Pack everything a replica holds after the given positions.
    pub fn export<R: Replica>(
        replica: &R,
        origin: NodeId,
        created_at: i64,
        wanted: &[StreamCursor],
        requests: Vec<StreamCursor>,
        limits: &Limits,
    ) -> Result<Self, BundleError> {
        let mut sections = Vec::new();
        let mut objects = Vec::new();
        let mut seen = std::collections::BTreeSet::new();

        for request in wanted.iter().take(limits.max_streams) {
            let mut entries = Vec::new();
            let mut after = request.after;

            // Walk the whole journal, not just one window: a bundle has no
            // `more` flag to come back for.
            loop {
                let (batch, more) = replica
                    .journal_after(&request.stream, after, limits.max_have_entries)
                    .map_err(|e| BundleError::Local(e.0))?;
                if batch.is_empty() {
                    break;
                }
                for entry in &batch {
                    after = entry.position;
                    if seen.insert(entry.object) {
                        if objects.len() >= limits.max_bundle_objects {
                            return Err(BundleError::TooManyObjects {
                                count: objects.len() + 1,
                                limit: limits.max_bundle_objects,
                            });
                        }
                        let bytes = replica
                            .object_bytes(entry.object)
                            .map_err(|e| BundleError::Local(e.0))?;
                        if let Some(bytes) = bytes {
                            objects.push(bytes.into());
                        } else {
                            // Pruned between journaling and packing (D8). The
                            // entry is dropped rather than shipped dangling.
                            continue;
                        }
                    }
                    entries.push(*entry);
                }
                if !more {
                    break;
                }
            }
            sections.push(Section {
                stream: request.stream,
                entries,
            });
        }

        Ok(Self {
            origin,
            created_at,
            sections,
            objects,
            requests,
        })
    }

    /// Serialise, with magic and version.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        let body = cbor::to_canonical_vec(self).map_err(|_| BundleError::Malformed)?;
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse a bundle from untrusted bytes.
    ///
    /// Everything here runs before a single object is stored: size, magic,
    /// version, canonical encoding, object count, and per-object size.
    pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Self, BundleError> {
        if bytes.len() > limits.max_bundle_bytes {
            return Err(BundleError::TooLarge {
                size: bytes.len(),
                limit: limits.max_bundle_bytes,
            });
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(BundleError::Format);
        }
        if bytes.get(MAGIC.len()) != Some(&VERSION) {
            return Err(BundleError::Format);
        }
        let body = bytes.get(HEADER_LEN..).ok_or(BundleError::Format)?;

        let bundle: Self = cbor::from_canonical_slice(body).map_err(|_| BundleError::Malformed)?;

        if bundle.objects.len() > limits.max_bundle_objects {
            return Err(BundleError::TooManyObjects {
                count: bundle.objects.len(),
                limit: limits.max_bundle_objects,
            });
        }
        for object in &bundle.objects {
            if object.len() > limits.max_object_bytes {
                return Err(BundleError::ObjectTooLarge {
                    size: object.len(),
                    limit: limits.max_object_bytes,
                });
            }
        }
        Ok(bundle)
    }

    /// Validate and apply a bundle to a replica.
    ///
    /// Objects are validated and stored first, then cursors advance — and only
    /// to positions whose objects actually arrived. An interrupted or partial
    /// bundle therefore leaves the cursor where the data really reaches, rather
    /// than skipping what was never received.
    ///
    /// # Not atomic, on purpose
    ///
    /// A bundle containing one bad object may still have stored the good ones by
    /// the time it fails. That is intended. Objects are immutable and
    /// content-addressed, so a valid object is valid regardless of what it
    /// travelled with, and rolling it back would let a single corrupt entry deny
    /// an entire batch — which is a cheap denial of service to mount on
    /// removable media.
    ///
    /// The invariant that does hold is the one that matters: **no cursor
    /// advances unless the whole section's objects are present**, and no invalid
    /// object is ever stored. A refused bundle can therefore be re-sent, and
    /// re-importing it costs only the objects that were missing.
    pub fn import<R: Replica>(&self, replica: &mut R) -> Result<ImportReport, BundleError> {
        let mut report = ImportReport::default();

        // Index the payload by content address. A bundle's own claims about
        // which object is which are not taken on trust.
        let mut carried = std::collections::BTreeMap::new();
        for bytes in &self.objects {
            let object = Object::from_canonical_bytes(bytes)
                .map_err(|_| BundleError::InvalidObject(ObjectId::ZERO))?;
            carried.insert(object.id(), bytes.as_slice());
        }

        for section in &self.sections {
            let mut previous = 0u64;
            for entry in &section.entries {
                if entry.position <= previous {
                    return Err(BundleError::NonMonotonicJournal {
                        previous,
                        offered: entry.position,
                    });
                }
                previous = entry.position;
            }
        }

        for (id, bytes) in &carried {
            if replica.contains(*id).map_err(|e| BundleError::Local(e.0))? {
                report.already_held += 1;
                continue;
            }
            match replica.accept(bytes) {
                Ok(_) => report.accepted += 1,
                Err(AcceptError::Invalid) => return Err(BundleError::InvalidObject(*id)),
                Err(AcceptError::Local(e)) => return Err(BundleError::Local(e.0)),
            }
        }

        for section in &self.sections {
            let mut high = 0u64;
            for entry in &section.entries {
                if !carried.contains_key(&entry.object)
                    && !replica
                        .contains(entry.object)
                        .map_err(|e| BundleError::Local(e.0))?
                {
                    return Err(BundleError::DanglingEntry(entry.object));
                }
                high = high.max(entry.position);
            }
            if high > 0 {
                replica
                    .set_cursor(self.origin, &section.stream, high)
                    .map_err(|e| BundleError::Local(e.0))?;
                report.cursors_advanced += 1;
            }
        }

        Ok(report)
    }
}

/// What an import did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Objects newly stored.
    pub accepted: usize,
    /// Objects already held.
    pub already_held: usize,
    /// Streams whose cursor moved.
    pub cursors_advanced: usize,
}
