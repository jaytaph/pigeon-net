//! Proving the right to read an inbox (§15.4, D15).

use pigeonnet_core::{IdentityId, PublicKeyBytes, SignatureBytes};
use pigeonnet_crypto::SigningKeypair;
use pigeonnet_proto::InboxSigner;

use crate::{Node, NodeError};

/// A credential backed by one of this node's device keys.
///
/// Holds the key rather than the node, so a session cannot reach the store
/// through it, and so its lifetime is obvious at the call site.
pub struct DeviceCredential {
    identity: IdentityId,
    key: SigningKeypair,
}

impl core::fmt::Debug for DeviceCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceCredential")
            .field("identity", &self.identity)
            .field("device", &self.key.public())
            .finish()
    }
}

impl InboxSigner for DeviceCredential {
    fn identity(&self) -> IdentityId {
        self.identity
    }

    fn signing_key(&self) -> PublicKeyBytes {
        self.key.public()
    }

    fn sign(&self, transcript: &[u8]) -> SignatureBytes {
        self.key.sign(transcript)
    }
}

impl Node {
    /// A credential for reading this node's own identity's inbox.
    pub fn inbox_credential(&self, passphrase: &[u8]) -> Result<DeviceCredential, NodeError> {
        Ok(DeviceCredential {
            identity: self.local_identity()?,
            key: self.keyring(passphrase)?.device(),
        })
    }
}
