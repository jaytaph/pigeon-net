//! Resource limits, enforced before anything enters trusted state (§30.1).
//!
//! A replicated system is a storage-exhaustion target by construction: peers ask
//! us to keep bytes on their behalf. Every one of these is local policy — a node
//! that rejects an oversized object is behaving correctly, not violating the
//! protocol (§30).

/// Limits applied to one session and to everything arriving through it.
///
/// Deliberately *not* `#[non_exhaustive]`: these are policy a node operator is
/// expected to construct and adjust, and a config struct nobody can build with
/// struct-update syntax is a config struct nobody adjusts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest single frame this node will decode.
    pub max_frame_bytes: usize,
    /// Largest single object this node will accept.
    pub max_object_bytes: usize,
    /// Most journal entries a peer may offer in one `Have`.
    pub max_have_entries: usize,
    /// Most identifiers this node will request in one `Fetch`.
    pub max_fetch_ids: usize,
    /// Most objects a peer may pack into one `Deliver`.
    pub max_deliver_objects: usize,
    /// Most objects this node will accept across an entire session.
    pub max_objects_per_session: usize,
    /// Most object bytes this node will accept across an entire session.
    pub max_bytes_per_session: usize,
    /// Widest range a single inventory repair request may cover.
    pub max_inventory_span: u64,
    /// Most streams a session may work through.
    pub max_streams: usize,
    /// Largest bundle file this node will read (§19).
    ///
    /// A bundle arrives on removable media with no handshake and no back
    /// pressure, so the only thing standing between a hostile stick and this
    /// node's memory is this number.
    pub max_bundle_bytes: usize,
    /// Most objects a single bundle may carry.
    pub max_bundle_objects: usize,
}

impl Limits {
    /// Defaults sized for a small always-on node.
    pub const DEFAULT: Self = Self {
        max_frame_bytes: 1 << 20,
        max_object_bytes: 64 << 10,
        max_have_entries: 1024,
        max_fetch_ids: 1024,
        max_deliver_objects: 256,
        max_objects_per_session: 100_000,
        max_bytes_per_session: 256 << 20,
        max_inventory_span: 10_000,
        max_streams: 64,
        max_bundle_bytes: 256 << 20,
        max_bundle_objects: 100_000,
    };

    /// Tight limits, for tests and for nodes with very little to spare.
    pub const MINIMAL: Self = Self {
        max_frame_bytes: 64 << 10,
        max_object_bytes: 4 << 10,
        max_have_entries: 16,
        max_fetch_ids: 16,
        max_deliver_objects: 8,
        max_objects_per_session: 64,
        max_bytes_per_session: 1 << 20,
        max_inventory_span: 64,
        max_streams: 4,
        max_bundle_bytes: 1 << 20,
        max_bundle_objects: 64,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
