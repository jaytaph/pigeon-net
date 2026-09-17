//! Node core: wires the object store, key material and local policy together.
//!
//! Reaches transports through a trait, never through tokio types, so policy
//! stays testable without a runtime (§34.1).
//!
//! Takes the current time as an argument rather than reading a clock, so that
//! node behaviour is reproducible in a test.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod echo;
pub mod inbox;
pub mod message;
pub mod naming;
pub mod replication;
pub mod snapshot;

pub use echo::ThreadedPost;
pub use inbox::DeviceCredential;
pub use message::{MessageBody, ReceivedMessage};
pub use naming::Naming;
pub use replication::Replication;

use std::{
    fs,
    path::{Path, PathBuf},
};

use pigeonnet_bundle::{Bundle, BundleError, ImportReport, StreamCursor};
use pigeonnet_core::NodeId;
use pigeonnet_core::{
    IdentityId, Object, ObjectId, ObjectType, Tbs, Timestamp,
    payload::{Capabilities, DeviceKeyGranted, IdentityCreated, Payload},
};
use pigeonnet_crypto::{
    AgreementKeypair, CryptoError, IdentityError, IdentityState, Keyring, SigningKeypair,
    sign_object,
};
use pigeonnet_proto::{Replica as _, StreamId};
use pigeonnet_store::{ObjectStore, StoreError};
use zeroize::Zeroizing;

/// Node-level errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum NodeError {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// The object store failed.
    Store(StoreError),
    /// A cryptographic operation failed.
    Crypto(CryptoError),
    /// Key-chain validation failed.
    Identity(IdentityError),
    /// An object could not be encoded or decoded.
    Object(pigeonnet_core::Error),
    /// This node already holds an identity.
    AlreadyInitialised,
    /// This node holds no identity yet.
    NotInitialised,
    /// Nothing is known about that identity — resolve or sync first (D12).
    UnknownIdentity(IdentityId),
    /// A local label was empty or too long.
    BadLabel,
    /// A snapshot did not verify.
    Snapshot(pigeonnet_crypto::SnapshotError),
    /// A bundle could not be read or written.
    Bundle(BundleError),
}

macro_rules! from_error {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(impl From<$ty> for NodeError {
            fn from(e: $ty) -> Self { Self::$variant(e) }
        })*
    };
}
from_error! {
    std::io::Error => Io,
    StoreError => Store,
    CryptoError => Crypto,
    IdentityError => Identity,
    pigeonnet_core::Error => Object,
    BundleError => Bundle,
    pigeonnet_crypto::SnapshotError => Snapshot,
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Object(e) => write!(f, "{e}"),
            Self::AlreadyInitialised => f.write_str("this node already holds an identity"),
            Self::NotInitialised => f.write_str("no identity yet -- run `nodectl identity create`"),
            Self::Bundle(e) => write!(f, "{e}"),
            Self::BadLabel => write!(
                f,
                "a label must be 1 to {} characters",
                crate::naming::MAX_LABEL
            ),
            Self::UnknownIdentity(id) => {
                write!(f, "nothing known about {id} -- resolve or sync first")
            }
            Self::Snapshot(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for NodeError {}

/// What a freshly created identity hands back.
///
/// The recovery secret appears here and nowhere else. It is never written to the
/// keystore: a recovery key stored beside the root key it exists to outrank
/// would protect against nothing (D11).
pub struct CreatedIdentity {
    /// The new identity.
    pub identity: IdentityId,
    /// Its genesis object.
    pub genesis: ObjectId,
    /// The grant delegating authority to this device.
    pub device_grant: ObjectId,
    /// The recovery secret. Display once, then drop.
    pub recovery_secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for CreatedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreatedIdentity")
            .field("identity", &self.identity)
            .field("genesis", &self.genesis)
            .field("device_grant", &self.device_grant)
            .finish_non_exhaustive()
    }
}

/// Key under which a node records which identity is its own.
pub(crate) const LOCAL_IDENTITY: &str = "identity";

/// A node's on-disk state.
#[derive(Debug)]
pub struct Node {
    root: PathBuf,
    store: ObjectStore,
    limits: pigeonnet_proto::Limits,
}

impl Node {
    /// Open or create a node directory.
    pub fn open(root: &Path) -> Result<Self, NodeError> {
        fs::create_dir_all(root)?;
        let store = ObjectStore::open(&root.join("objects.db"))?;
        Ok(Self {
            root: root.to_path_buf(),
            store,
            limits: pigeonnet_proto::Limits::DEFAULT,
        })
    }

    /// The object store.
    #[must_use]
    pub const fn store(&self) -> &ObjectStore {
        &self.store
    }

    /// This node's resource limits (§30.1).
    #[must_use]
    pub const fn limits(&self) -> &pigeonnet_proto::Limits {
        &self.limits
    }

    /// Set this node's resource limits.
    pub const fn set_limits(&mut self, limits: pigeonnet_proto::Limits) {
        self.limits = limits;
    }

    /// A replication view of this node, with the clock supplied by the caller.
    #[must_use]
    pub const fn replication(&self, now: i64) -> Replication<'_> {
        Replication::new(self, now)
    }

    pub(crate) fn keystore_path(&self) -> PathBuf {
        self.root.join("keys.bin")
    }

    /// Whether this node holds an identity.
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.keystore_path().exists()
    }

    /// Create an identity: genesis object, device grant, and a sealed keystore.
    ///
    /// Four keys are generated. The root key signs the genesis object and the
    /// device grant, and then has no further work to do — which is what lets it
    /// go offline. The recovery key signs nothing now; it exists so that a
    /// stolen root key can be evicted later (§5.5).
    pub fn create_identity(
        &self,
        passphrase: &[u8],
        now: i64,
    ) -> Result<CreatedIdentity, NodeError> {
        if self.is_initialised() {
            return Err(NodeError::AlreadyInitialised);
        }

        let root_key = SigningKeypair::generate()?;
        let recovery_key = SigningKeypair::generate()?;
        let agreement_key = AgreementKeypair::generate()?;
        let device_key = SigningKeypair::generate()?;

        // Genesis: self-signed by the root key, because no prior authority
        // exists to sign it. Its identifier becomes the identity (D3).
        let genesis_payload = IdentityCreated {
            root_key: root_key.public(),
            recovery_key: recovery_key.public(),
            agreement_key: agreement_key.public(),
        }
        .encode_payload()?;

        let genesis = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: ObjectType::IdentityCreated.code(),
                author: IdentityId::ZERO,
                signing_key: root_key.public(),
                timestamp: Timestamp::from_millis(now),
                sequence: 0,
                payload: genesis_payload,
            },
            &root_key,
        )?;
        let identity = IdentityId::from_genesis(genesis.id());

        // Delegate to this device. `publish-prekeys` is included so the root key
        // never has to come back online for the daily prekey schedule (§8.1).
        let grant_payload = DeviceKeyGranted {
            device_key: device_key.public(),
            capabilities: Capabilities::POST
                | Capabilities::MESSAGE
                | Capabilities::PUBLISH_FILE
                | Capabilities::PUBLISH_PREKEYS,
            not_before: Timestamp::from_millis(now),
            not_after: None,
        }
        .encode_payload()?;

        let grant = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: ObjectType::DeviceKeyGranted.code(),
                author: identity,
                signing_key: root_key.public(),
                timestamp: Timestamp::from_millis(now),
                sequence: 1,
                payload: grant_payload,
            },
            &root_key,
        )?;

        // Replay what we just built, rather than trusting that we built it
        // correctly. If our own chain does not validate, nothing is written.
        let mut state = IdentityState::from_genesis(&genesis)?;
        state.admit(&grant)?;

        // Anchored at the current epoch: everything before it is unreachable
        // from this seed by construction, so an identity created today cannot
        // produce a prekey for last week even if asked.
        let prekeys = pigeonnet_crypto::PrekeySeed::generate(Self::epoch_at(now))?;
        let keyring = Keyring::new(&root_key, &device_key, &agreement_key, &prekeys);
        let sealed = keyring.seal(passphrase)?;
        write_private(&self.keystore_path(), &sealed)?;

        {
            use pigeonnet_proto::Replica as _;
            let mut replication = self.replication(now);
            let genesis_bytes = genesis.to_canonical_bytes()?;
            let grant_bytes = grant.to_canonical_bytes()?;
            replication
                .accept(&genesis_bytes)
                .map_err(|_| NodeError::Object(pigeonnet_core::Error::NonCanonical))?;
            replication
                .accept(&grant_bytes)
                .map_err(|_| NodeError::Object(pigeonnet_core::Error::NonCanonical))?;
        }

        self.store.set_state(LOCAL_IDENTITY, identity.as_bytes())?;

        Ok(CreatedIdentity {
            identity,
            genesis: genesis.id(),
            device_grant: grant.id(),
            recovery_secret: recovery_key.seed(),
        })
    }

    /// Open the sealed keystore.
    pub fn keyring(&self, passphrase: &[u8]) -> Result<Keyring, NodeError> {
        if !self.is_initialised() {
            return Err(NodeError::NotInitialised);
        }
        let sealed = fs::read(self.keystore_path())?;
        Ok(Keyring::open(&sealed, passphrase)?)
    }

    /// This node's identifier on the network.
    ///
    /// Derived from the device key, which conflates *who* with *where* more than
    /// §17 intends — a node and an identity are meant to be separable. Good
    /// enough while there is one device per node; a dedicated node key belongs
    /// with peer configuration.
    pub fn node_id(&self, passphrase: &[u8]) -> Result<NodeId, NodeError> {
        let keyring = self.keyring(passphrase)?;
        Ok(NodeId::from_bytes(*keyring.device().public().as_bytes()))
    }

    /// Pack everything this node holds into a bundle (§19).
    ///
    /// `wanted` states what the recipient is missing. An empty slice means
    /// everything, which is the right default for a first exchange and wasteful
    /// for any later one — hence the `requests` a bundle carries back.
    pub fn export_bundle(
        &self,
        origin: NodeId,
        now: i64,
        wanted: &[StreamCursor],
        for_peer: Option<NodeId>,
    ) -> Result<Vec<u8>, NodeError> {
        let wanted = if wanted.is_empty() {
            vec![StreamCursor {
                stream: StreamId::All,
                after: 0,
            }]
        } else {
            wanted.to_vec()
        };

        // Tell the recipient where we stand, so their reply can be targeted
        // rather than exhaustive.
        let requests = match for_peer {
            Some(peer) => {
                let replication = self.replication(now);
                vec![StreamCursor {
                    stream: StreamId::All,
                    after: replication
                        .cursor(peer, &StreamId::All)
                        .map_err(|e| NodeError::Bundle(BundleError::Local(e.0)))?,
                }]
            }
            None => Vec::new(),
        };

        let replication = self.replication(now);
        let bundle = Bundle::export(&replication, origin, now, &wanted, requests, &self.limits)?;
        Ok(bundle.encode()?)
    }

    /// Validate and apply a bundle from untrusted media.
    pub fn import_bundle(
        &self,
        bytes: &[u8],
        now: i64,
    ) -> Result<(ImportReport, Vec<StreamCursor>), NodeError> {
        let bundle = Bundle::decode(bytes, &self.limits)?;
        let requests = bundle.requests.clone();
        let mut replication = self.replication(now);
        let report = bundle.import(&mut replication)?;
        Ok((report, requests))
    }

    /// Sign an object as this node's identity and store it.
    ///
    /// Authority is checked against our own key chain *before* writing, rather
    /// than discovering on the next read that we signed something we were not
    /// entitled to.
    pub fn publish(
        &self,
        object_type: ObjectType,
        payload: Vec<u8>,
        required: Capabilities,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let identity = self.local_identity()?;
        let keyring = self.keyring(passphrase)?;
        let device = keyring.device();

        let state = self.identity_state(identity)?;
        state.check_device_authority(device.public(), Timestamp::from_millis(now), required)?;

        let sequence = self
            .store
            .highest_sequence(identity, device.public())?
            .map_or(0, |highest| highest.saturating_add(1));

        let object = sign_object(
            &Tbs {
                version: pigeonnet_core::OBJECT_VERSION,
                type_code: object_type.code(),
                author: identity,
                signing_key: device.public(),
                timestamp: Timestamp::from_millis(now),
                sequence,
                payload,
            },
            &device,
        )?;

        let bytes = object.to_canonical_bytes()?;
        let mut replication = self.replication(now);
        replication
            .accept(&bytes)
            .map_err(|_| NodeError::Object(pigeonnet_core::Error::NonCanonical))?;
        Ok(object.id())
    }

    /// Fetch an object.
    pub fn object(&self, id: ObjectId) -> Result<Option<Object>, NodeError> {
        Ok(self.store.get(id)?)
    }

    /// Replay an identity's key chain from stored objects.
    pub fn identity_state(&self, identity: IdentityId) -> Result<IdentityState, NodeError> {
        let genesis = self
            .store
            .get(identity.genesis_object())?
            .ok_or(NodeError::NotInitialised)?;
        let mut state = IdentityState::from_genesis(&genesis)?;
        // Key management only, in causal order. Replaying every object the
        // identity authored would mean replaying them in lexicographic key
        // order, where a post can precede the grant that authorised it.
        for object in self.store.key_chain(identity)? {
            state.admit(&object)?;
        }
        Ok(state)
    }
}

/// Write a file that only its owner may read.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_758_000_000_000;

    fn temp_root() -> PathBuf {
        let mut path = std::env::temp_dir();
        let mut seed = [0u8; 8];
        getrandom::fill(&mut seed).unwrap();
        path.push(format!("pigeonnet-test-{}", u64::from_le_bytes(seed)));
        path
    }

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_a_valid_identity() {
        let dir = Temp(temp_root());
        let node = Node::open(&dir.0).unwrap();
        assert!(!node.is_initialised());

        let created = node.create_identity(b"passphrase", NOW).unwrap();
        assert!(node.is_initialised());

        // The identity is its genesis object, and the chain replays.
        assert_eq!(created.identity.genesis_object(), created.genesis);
        let state = node.identity_state(created.identity).unwrap();
        assert_eq!(state.id(), created.identity);
    }

    #[test]
    fn device_key_is_delegated_with_prekey_capability() {
        let dir = Temp(temp_root());
        let node = Node::open(&dir.0).unwrap();
        let created = node.create_identity(b"passphrase", NOW).unwrap();

        let keyring = node.keyring(b"passphrase").unwrap();
        let state = node.identity_state(created.identity).unwrap();
        let capabilities = state.capabilities_of(keyring.device().public()).unwrap();

        // Without this, the root key would have to come back online daily (§8.1).
        assert!(capabilities.contains(Capabilities::PUBLISH_PREKEYS));
    }

    #[test]
    fn recovery_key_is_not_in_the_keystore() {
        // The whole point of D11: the recovery key outranks the root key, so
        // storing it beside the root key would protect against nothing.
        let dir = Temp(temp_root());
        let node = Node::open(&dir.0).unwrap();
        let created = node.create_identity(b"passphrase", NOW).unwrap();

        let sealed = fs::read(node.keystore_path()).unwrap();
        assert!(
            !sealed
                .windows(32)
                .any(|w| w == created.recovery_secret.as_slice())
        );

        let keyring = node.keyring(b"passphrase").unwrap();
        let recovery_public = SigningKeypair::from_seed(&created.recovery_secret).public();
        assert_ne!(keyring.root().public(), recovery_public);
        assert_ne!(keyring.device().public(), recovery_public);

        // ...but the public half is in the genesis object, permanently.
        let state = node.identity_state(created.identity).unwrap();
        assert_eq!(state.recovery_key(), recovery_public);
    }

    #[test]
    fn will_not_overwrite_an_existing_identity() {
        let dir = Temp(temp_root());
        let node = Node::open(&dir.0).unwrap();
        node.create_identity(b"passphrase", NOW).unwrap();
        assert!(matches!(
            node.create_identity(b"passphrase", NOW),
            Err(NodeError::AlreadyInitialised)
        ));
    }

    #[test]
    fn wrong_passphrase_does_not_open_the_keystore() {
        let dir = Temp(temp_root());
        let node = Node::open(&dir.0).unwrap();
        node.create_identity(b"correct", NOW).unwrap();
        assert!(matches!(node.keyring(b"wrong"), Err(NodeError::Crypto(_))));
    }

    #[test]
    fn a_bundle_carries_one_node_to_another() {
        // The same convergence M2 achieved over TCP, with a file in place of a
        // socket and nothing else in common between the two nodes.
        let a_dir = Temp(temp_root());
        let b_dir = Temp(temp_root());
        let a = Node::open(&a_dir.0).unwrap();
        let b = Node::open(&b_dir.0).unwrap();
        a.create_identity(b"pa", NOW).unwrap();
        b.create_identity(b"pb", NOW).unwrap();

        let origin = a.node_id(b"pa").unwrap();
        let bytes = a.export_bundle(origin, NOW, &[], None).unwrap();
        let (report, _) = b.import_bundle(&bytes, NOW).unwrap();

        assert_eq!(report.accepted, 2);
        assert_eq!(b.store().len().unwrap(), 4);
    }

    #[test]
    fn re_importing_a_bundle_changes_nothing() {
        let a_dir = Temp(temp_root());
        let b_dir = Temp(temp_root());
        let a = Node::open(&a_dir.0).unwrap();
        let b = Node::open(&b_dir.0).unwrap();
        a.create_identity(b"pa", NOW).unwrap();
        b.create_identity(b"pb", NOW).unwrap();

        let origin = a.node_id(b"pa").unwrap();
        let bytes = a.export_bundle(origin, NOW, &[], None).unwrap();
        b.import_bundle(&bytes, NOW).unwrap();
        let (again, _) = b.import_bundle(&bytes, NOW).unwrap();

        assert_eq!(again.accepted, 0);
        assert_eq!(again.already_held, 2);
        assert_eq!(b.store().len().unwrap(), 4);
    }

    #[test]
    fn a_bundle_carries_the_senders_cursor_back() {
        // So the reply can be targeted rather than exhaustive (§19).
        let a_dir = Temp(temp_root());
        let b_dir = Temp(temp_root());
        let a = Node::open(&a_dir.0).unwrap();
        let b = Node::open(&b_dir.0).unwrap();
        a.create_identity(b"pa", NOW).unwrap();
        b.create_identity(b"pb", NOW).unwrap();

        let a_id = a.node_id(b"pa").unwrap();
        let b_id = b.node_id(b"pb").unwrap();

        // First hop: A to B, telling B where A stands for B.
        let bytes = a.export_bundle(a_id, NOW, &[], Some(b_id)).unwrap();
        let (_, requests) = b.import_bundle(&bytes, NOW).unwrap();
        assert_eq!(requests.len(), 1, "A stated its cursor");

        // Second hop: B answers only what A asked for.
        let reply = b.export_bundle(b_id, NOW, &requests, Some(a_id)).unwrap();
        let (report, _) = a.import_bundle(&reply, NOW).unwrap();
        assert_eq!(report.accepted, 2);
        assert_eq!(a.store().len().unwrap(), 4);
    }

    #[test]
    fn a_tampered_bundle_is_refused() {
        let a_dir = Temp(temp_root());
        let b_dir = Temp(temp_root());
        let a = Node::open(&a_dir.0).unwrap();
        let b = Node::open(&b_dir.0).unwrap();
        a.create_identity(b"pa", NOW).unwrap();
        b.create_identity(b"pb", NOW).unwrap();

        let origin = a.node_id(b"pa").unwrap();
        let bytes = a.export_bundle(origin, NOW, &[], None).unwrap();

        // Alter an object's bytes specifically, rather than a byte at some
        // arbitrary offset: the keys are random, so a positional flip lands on a
        // different field every run and sometimes produces a bundle that is
        // merely different rather than invalid.
        let mut bundle = pigeonnet_bundle::Bundle::decode(&bytes, a.limits()).unwrap();
        let victim = bundle.objects.first_mut().expect("bundle carries objects");
        let last = victim.len() - 1;
        victim[last] ^= 0x40;
        let victim_bytes = victim.to_vec();
        let tampered = bundle.encode().unwrap();

        let error = b.import_bundle(&tampered, NOW).unwrap_err();
        assert!(matches!(error, NodeError::Bundle(_)), "{error}");

        // Import is deliberately not atomic: a valid object that travelled
        // alongside a corrupt one is still valid, and rolling it back would let
        // one bad entry deny a whole batch. What must hold is that the tampered
        // object is not stored, and that no cursor moved.
        let tampered_id = pigeonnet_core::Object::from_canonical_bytes(&victim_bytes)
            .map(|o| o.id())
            .ok();
        if let Some(id) = tampered_id {
            assert!(!b.store().contains(id).unwrap(), "stored a tampered object");
        }
        assert_eq!(
            b.replication(NOW).cursor(origin, &StreamId::All).unwrap(),
            0,
            "a cursor moved on a bundle we refused"
        );
    }

    #[test]
    fn survives_reopening() {
        let dir = Temp(temp_root());
        let created = {
            let node = Node::open(&dir.0).unwrap();
            node.create_identity(b"passphrase", NOW).unwrap()
        };
        let node = Node::open(&dir.0).unwrap();
        let state = node.identity_state(created.identity).unwrap();
        assert_eq!(state.id(), created.identity);
    }
}
