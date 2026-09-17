//! Node core: wires the object store, key material and local policy together.
//!
//! Reaches transports through a trait, never through tokio types, so policy
//! stays testable without a runtime (§34.1).
//!
//! Takes the current time as an argument rather than reading a clock, so that
//! node behaviour is reproducible in a test.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod replication;

pub use replication::Replication;

use std::{
    fs,
    path::{Path, PathBuf},
};

use pigeonnet_core::{
    IdentityId, Object, ObjectId, ObjectType, Tbs, Timestamp,
    payload::{Capabilities, DeviceKeyGranted, IdentityCreated, Payload},
};
use pigeonnet_crypto::{
    AgreementKeypair, CryptoError, IdentityError, IdentityState, Keyring, SigningKeypair,
    sign_object,
};
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

    fn keystore_path(&self) -> PathBuf {
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

        let keyring = Keyring::new(&root_key, &device_key, &agreement_key);
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
        for object in self.store.objects_by_author(identity)? {
            state.admit(&object)?;
        }
        Ok(state)
    }
}

/// Write a file that only its owner may read.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
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
