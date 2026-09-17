//! Replaying an identity's key chain (D3).
//!
//! An identity is the object identifier of its genesis object. Everything else
//! about it — which keys may sign, with what authority, during which window —
//! is derived by replaying ordinary replicated objects from that genesis. No
//! node is told the answer; every node computes it.
//!
//! This is *authorisation*. [`verify_object`](crate::verify_object) establishes
//! that a key signed some bytes; this establishes that the key was ever entitled
//! to speak for the author, and still was at the moment it claims to have done
//! so.

use std::collections::BTreeMap;

use pigeonnet_core::{
    AgreementKeyBytes, IdentityId, Object, ObjectType, PublicKeyBytes, Timestamp,
    payload::{Capabilities, DeviceKeyGranted, DeviceKeyRevoked, IdentityCreated, Payload},
};

use crate::{CryptoError, verify_object};

/// An object was not validly authored by the identity it claims.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// The signature did not verify, or the envelope was unreadable.
    Crypto(CryptoError),

    /// A genesis object was expected, or was not one.
    NotGenesis,

    /// The object names a different identity.
    WrongIdentity {
        /// The identity this chain belongs to.
        expected: IdentityId,
        /// What the object claimed.
        found: IdentityId,
    },

    /// A genesis object must be signed by the root key it declares.
    GenesisNotSelfSigned,

    /// Key management must be signed by the root key (§5.4).
    NotSignedByRoot,

    /// The signing key was never delegated by this identity.
    UnknownSigningKey(PublicKeyBytes),

    /// The signing key's authority had not begun, or had ended.
    OutsideValidityWindow,

    /// The signing key was revoked before this object claims to exist.
    Revoked,

    /// The object's timestamp falls in a window the owner declared compromised.
    Invalidated,

    /// The signing key lacks a capability this object type requires.
    MissingCapability {
        /// What was needed.
        required: Capabilities,
        /// What the key holds.
        held: Capabilities,
    },

    /// Sequence numbers must be gapless and monotonic, per signing key (D3).
    SequenceOutOfOrder {
        /// What the chain expected next.
        expected: u64,
        /// What the object carried.
        found: u64,
    },

    /// Two different objects share one `(signing_key, sequence)` pair.
    ///
    /// Self-contained proof that the key signed two conflicting histories.
    Equivocation {
        /// The key that signed both.
        signing_key: PublicKeyBytes,
        /// The sequence position claimed twice.
        sequence: u64,
    },
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "{e}"),
            Self::NotGenesis => f.write_str("not a genesis object"),
            Self::WrongIdentity { expected, found } => {
                write!(f, "object belongs to {found}, not {expected}")
            }
            Self::GenesisNotSelfSigned => {
                f.write_str("genesis object was not signed by the root key it declares")
            }
            Self::NotSignedByRoot => f.write_str("key management must be signed by the root key"),
            Self::UnknownSigningKey(k) => write!(f, "signing key {k} was never delegated"),
            Self::OutsideValidityWindow => f.write_str("signing key was not valid at that time"),
            Self::Revoked => f.write_str("signing key was revoked"),
            Self::Invalidated => f.write_str("object falls in a window declared compromised"),
            Self::MissingCapability { required, held } => {
                write!(f, "key holds {held:?} but {required:?} was required")
            }
            Self::SequenceOutOfOrder { expected, found } => {
                write!(f, "expected sequence {expected}, found {found}")
            }
            Self::Equivocation {
                signing_key,
                sequence,
            } => {
                write!(
                    f,
                    "key {signing_key} signed two objects at sequence {sequence}"
                )
            }
        }
    }
}

impl core::error::Error for IdentityError {}

impl From<CryptoError> for IdentityError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<pigeonnet_core::Error> for IdentityError {
    fn from(e: pigeonnet_core::Error) -> Self {
        Self::Crypto(CryptoError::Object(e))
    }
}

/// What is known about one delegated device key.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Device {
    capabilities: Capabilities,
    not_before: Timestamp,
    not_after: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
    invalidate_from: Option<Timestamp>,
}

/// An identity's key state, derived from its chain.
#[derive(Clone, Debug)]
pub struct IdentityState {
    id: IdentityId,
    root_key: PublicKeyBytes,
    recovery_key: PublicKeyBytes,
    agreement_key: AgreementKeyBytes,
    devices: BTreeMap<PublicKeyBytes, Device>,
    /// Next expected sequence number, per signing key.
    next_sequence: BTreeMap<PublicKeyBytes, u64>,
}

impl IdentityState {
    /// Begin a chain from its genesis object.
    ///
    /// The genesis object is self-signed by the root key it declares: there is
    /// no prior authority to sign it, which is precisely why the identity is
    /// named by this object's hash rather than by any key.
    pub fn from_genesis(object: &Object) -> Result<Self, IdentityError> {
        verify_object(object)?;
        let tbs = object.tbs()?;

        if !tbs.is_genesis() || tbs.object_type() != Ok(ObjectType::IdentityCreated) {
            return Err(IdentityError::NotGenesis);
        }
        if tbs.sequence != 0 {
            return Err(IdentityError::SequenceOutOfOrder {
                expected: 0,
                found: tbs.sequence,
            });
        }

        let created = IdentityCreated::decode_payload(&tbs.payload)?;
        if tbs.signing_key != created.root_key {
            return Err(IdentityError::GenesisNotSelfSigned);
        }

        let mut next_sequence = BTreeMap::new();
        next_sequence.insert(created.root_key, 1);

        Ok(Self {
            id: IdentityId::from_genesis(object.id()),
            root_key: created.root_key,
            recovery_key: created.recovery_key,
            agreement_key: created.agreement_key,
            devices: BTreeMap::new(),
            next_sequence,
        })
    }

    /// The identity.
    #[must_use]
    pub const fn id(&self) -> IdentityId {
        self.id
    }

    /// The current root key.
    #[must_use]
    pub const fn root_key(&self) -> PublicKeyBytes {
        self.root_key
    }

    /// The recovery key (D11). Outranks the root key; the root cannot revoke it.
    #[must_use]
    pub const fn recovery_key(&self) -> PublicKeyBytes {
        self.recovery_key
    }

    /// The long-term agreement key (§8.1).
    #[must_use]
    pub const fn agreement_key(&self) -> AgreementKeyBytes {
        self.agreement_key
    }

    /// Capabilities currently held by a device key, if it is known and live.
    #[must_use]
    pub fn capabilities_of(&self, key: PublicKeyBytes) -> Option<Capabilities> {
        self.devices.get(&key).map(|d| d.capabilities)
    }

    /// Admit an object into this identity's history.
    ///
    /// Checks, in order: signature, authorship, authority of the signing key at
    /// the object's claimed time, the required capability, and the per-key
    /// sequence. On success the sequence advances, so applying the same object
    /// twice is an error rather than a no-op — duplicate suppression belongs to
    /// the store, which knows object identifiers.
    pub fn admit(&mut self, object: &Object) -> Result<(), IdentityError> {
        verify_object(object)?;
        let tbs = object.tbs()?;

        if tbs.author != self.id {
            return Err(IdentityError::WrongIdentity {
                expected: self.id,
                found: tbs.author,
            });
        }

        match tbs.object_type() {
            Ok(ObjectType::IdentityCreated) => return Err(IdentityError::NotGenesis),
            Ok(ObjectType::DeviceKeyGranted | ObjectType::DeviceKeyRevoked) => {
                // Key management is the root key's alone (§5.4). A device key
                // that could grant device keys would make revocation pointless.
                if tbs.signing_key != self.root_key {
                    return Err(IdentityError::NotSignedByRoot);
                }
            }
            // An object type from a newer vocabulary still has to be authorised.
            Ok(_) | Err(_) => {
                self.check_device_authority(tbs.signing_key, tbs.timestamp, Capabilities::NONE)?;
            }
        }

        self.check_sequence(tbs.signing_key, tbs.sequence)?;

        match tbs.object_type() {
            Ok(ObjectType::DeviceKeyGranted) => {
                let granted = DeviceKeyGranted::decode_payload(&tbs.payload)?;
                self.devices.insert(
                    granted.device_key,
                    Device {
                        capabilities: granted.capabilities,
                        not_before: granted.not_before,
                        not_after: granted.not_after,
                        revoked_at: None,
                        invalidate_from: None,
                    },
                );
            }
            Ok(ObjectType::DeviceKeyRevoked) => {
                let revoked = DeviceKeyRevoked::decode_payload(&tbs.payload)?;
                if let Some(device) = self.devices.get_mut(&revoked.device_key) {
                    device.revoked_at = Some(revoked.revoked_at);
                    device.invalidate_from = revoked.invalidate_from;
                } else {
                    return Err(IdentityError::UnknownSigningKey(revoked.device_key));
                }
            }
            _ => {}
        }

        self.next_sequence
            .insert(tbs.signing_key, tbs.sequence.saturating_add(1));
        Ok(())
    }

    /// Whether a device key was entitled to sign at a given moment.
    pub fn check_device_authority(
        &self,
        key: PublicKeyBytes,
        at: Timestamp,
        required: Capabilities,
    ) -> Result<(), IdentityError> {
        let device = self
            .devices
            .get(&key)
            .ok_or(IdentityError::UnknownSigningKey(key))?;

        if at < device.not_before {
            return Err(IdentityError::OutsideValidityWindow);
        }
        if let Some(not_after) = device.not_after
            && at > not_after
        {
            return Err(IdentityError::OutsideValidityWindow);
        }

        // Revocation is not retroactive by default (§5.4): objects signed before
        // `revoked_at` stay valid, because invalidating them would erase the
        // victim's own history, which a thief did not write.
        if let Some(revoked_at) = device.revoked_at
            && at >= revoked_at
        {
            return Err(IdentityError::Revoked);
        }

        // ...unless the owner declared an earlier compromise window.
        if let Some(invalidate_from) = device.invalidate_from
            && at >= invalidate_from
        {
            return Err(IdentityError::Invalidated);
        }

        if !device.capabilities.contains(required) {
            return Err(IdentityError::MissingCapability {
                required,
                held: device.capabilities,
            });
        }
        Ok(())
    }

    fn check_sequence(&self, key: PublicKeyBytes, sequence: u64) -> Result<(), IdentityError> {
        let expected = self.next_sequence.get(&key).copied().unwrap_or(0);
        if sequence == expected {
            return Ok(());
        }
        // A sequence already used is not merely out of order: the key has signed
        // two objects at one position, which is a portable proof of equivocation
        // (D3) rather than a transport mishap.
        if sequence < expected {
            return Err(IdentityError::Equivocation {
                signing_key: key,
                sequence,
            });
        }
        Err(IdentityError::SequenceOutOfOrder {
            expected,
            found: sequence,
        })
    }
}
