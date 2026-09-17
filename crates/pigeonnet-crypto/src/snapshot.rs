//! Identity snapshots: current state, fetched rather than replicated (D12, §5.6).
//!
//! An identity's state splits in two, with opposite requirements. The **key
//! chain** must be complete and ordered or nothing verifies, and its
//! distribution is already solved — any node holding an object must be able to
//! serve that object's author's chain (the chain invariant), because verifying
//! the object required it. **Current state** — prekeys, carriers, profile — is
//! latest-wins and aggressively pruned: nobody wants last year's carrier or an
//! expired prekey. Forcing the second into a journal is what made neither fit.
//!
//! So a snapshot is a fetch, not a stream: no cursor, no ordering, no session
//! state.
//!
//! **Everything inside is self-signed, so a stranger's cached copy is exactly as
//! trustworthy as the origin's.** A holder can withhold. A holder cannot forge.
//! That is what makes it safe for any node to serve and any node to cache.

use minicbor::{Decode, Encode, bytes::ByteVec};
use pigeonnet_core::{
    IdentityId, Object, ObjectType, PublicKeyBytes, Timestamp,
    payload::{
        Capabilities, CarriageAccepted, Carrier, EpochPrekey, IdentityProfile, Payload,
        ReachabilityClaim,
    },
};

use crate::{IdentityError, IdentityState, verify_object};

/// A snapshot did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotError {
    /// The key chain failed to replay, or belongs to a different identity.
    Chain(IdentityError),
    /// An object inside was malformed or unsigned.
    Malformed,
    /// An object inside was authored by somebody else.
    ForeignObject,
    /// An object was of a type that does not belong in a snapshot.
    UnexpectedType(u16),
    /// A `CarriageAccepted` was not signed by the node it names.
    CarrierMismatch,
    /// The snapshot has passed its expiry and must be refetched.
    Expired {
        /// When it lapsed.
        valid_until: Timestamp,
    },
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Chain(e) => write!(f, "key chain: {e}"),
            Self::Malformed => f.write_str("snapshot contained a malformed object"),
            Self::ForeignObject => f.write_str("snapshot contained another identity's object"),
            Self::UnexpectedType(t) => write!(f, "object type {t} does not belong in a snapshot"),
            Self::CarrierMismatch => {
                f.write_str("carriage acceptance was not signed by the node it names")
            }
            Self::Expired { valid_until } => {
                write!(f, "snapshot expired at {}ms", valid_until.as_millis())
            }
        }
    }
}

impl core::error::Error for SnapshotError {}

impl From<IdentityError> for SnapshotError {
    fn from(e: IdentityError) -> Self {
        Self::Chain(e)
    }
}

/// An identity's current state, as it travels.
///
/// Objects are carried as bytes rather than as decoded values: the receiver has
/// to verify them itself, and handing it anything pre-parsed would invite it to
/// trust the parse.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Snapshot {
    /// Whose state this is.
    #[n(0)]
    pub identity: IdentityId,

    /// The key chain, genesis first, in replay order.
    #[n(1)]
    pub chain: Vec<ByteVec>,

    /// Unexpired epoch prekeys, across every device.
    #[n(2)]
    pub prekeys: Vec<ByteVec>,

    /// The latest reachability claim, if any.
    #[n(3)]
    pub reachability: Option<ByteVec>,

    /// Carriage acceptances from the nodes that claim names.
    #[n(4)]
    pub carriage: Vec<ByteVec>,

    /// The identity's profile, if it published one.
    #[n(5)]
    pub profile: Option<ByteVec>,

    /// When the server says this stops being usable.
    ///
    /// Advisory: see [`ResolvedIdentity::valid_until`], which clamps it.
    #[n(6)]
    pub valid_until: Timestamp,
}

/// A verified snapshot.
#[derive(Clone, Debug)]
pub struct ResolvedIdentity {
    /// Key state, replayed from the chain.
    pub state: IdentityState,

    /// Usable prekeys, paired with the device that published each.
    pub prekeys: Vec<(PublicKeyBytes, EpochPrekey)>,

    /// Carriers that are both claimed by the identity **and** consented to by
    /// the node. A carrier named on only one side is absent from this list.
    pub carriers: Vec<Carrier>,

    /// Carriers the identity named but which have not consented, or whose
    /// consent expired. Surfaced rather than silently dropped: the usual cause
    /// is a misconfiguration the operator wants to know about.
    pub unconfirmed: Vec<Carrier>,

    /// The profile, if present and valid.
    pub profile: Option<IdentityProfile>,

    /// When this view stops being usable.
    ///
    /// **Clamped, not taken on trust.** The snapshot itself is not signed — it
    /// is an aggregate — so a server could otherwise staple a far-future expiry
    /// onto stale contents. Each object inside carries its own signed expiry, so
    /// the effective answer is the earliest of them and the server's claim.
    pub valid_until: Timestamp,
}

impl ResolvedIdentity {
    /// How stale this view is, given the moment it was fetched.
    ///
    /// Clients display this. Freshness must be a property of the snapshot rather
    /// than a side effect of prekey exhaustion (§5.6): the exhaustion signal
    /// disappears entirely if lookahead increases, so nothing may depend on it.
    #[must_use]
    pub const fn age_millis(&self, fetched_at: Timestamp, now: Timestamp) -> i64 {
        now.as_millis().saturating_sub(fetched_at.as_millis())
    }

    /// Whether this view may still be used.
    #[must_use]
    pub const fn is_usable_at(&self, now: Timestamp) -> bool {
        now.as_millis() < self.valid_until.as_millis()
    }
}

impl Snapshot {
    /// Verify every object, and reduce to usable state.
    ///
    /// Nothing here trusts the server. The chain is replayed from genesis, every
    /// object's signature is checked, every signing key is checked against the
    /// authority the chain grants it, and anything expired at `now` is dropped
    /// rather than reported.
    pub fn verify(&self, now: Timestamp) -> Result<ResolvedIdentity, SnapshotError> {
        let mut objects = self.chain.iter();
        let genesis = decode(objects.next().ok_or(SnapshotError::Malformed)?)?;
        let mut state = IdentityState::from_genesis(&genesis)?;
        if state.id() != self.identity {
            return Err(SnapshotError::Chain(IdentityError::WrongIdentity {
                expected: self.identity,
                found: state.id(),
            }));
        }
        for bytes in objects {
            state.admit(&decode(bytes)?)?;
        }

        let mut earliest = self.valid_until;
        let mut prekeys = Vec::new();
        for bytes in &self.prekeys {
            let (tbs, payload) = self.authored_payload::<EpochPrekey>(
                bytes,
                ObjectType::EpochPrekey,
                &state,
                Capabilities::PUBLISH_PREKEYS,
            )?;
            if payload.valid_until.as_millis() <= now.as_millis() {
                continue; // expired: garbage, not an error
            }
            earliest = earliest.min(payload.valid_until);
            prekeys.push((tbs, payload));
        }

        let mut claimed: Vec<Carrier> = Vec::new();
        if let Some(bytes) = &self.reachability {
            let (_, claim) = self.authored_payload::<ReachabilityClaim>(
                bytes,
                ObjectType::ReachabilityClaim,
                &state,
                Capabilities::NONE,
            )?;
            if claim.expires_at.as_millis() > now.as_millis() {
                earliest = earliest.min(claim.expires_at);
                claimed = claim.via;
            }
        }

        // A carriage acceptance is authored by the *carrier*, not by this
        // identity, so this node usually has no chain for it. The signature is
        // therefore checked against the device key the object names as the
        // carrier, and nothing more. That is sufficient because a node proves
        // its identity on connect (D14): a forged acceptance yields a failed
        // handshake rather than a hostile carrier.
        let mut consented = Vec::new();
        for bytes in &self.carriage {
            let object = decode(bytes)?;
            verify_object(&object).map_err(|_| SnapshotError::Malformed)?;
            let tbs = object.tbs().map_err(|_| SnapshotError::Malformed)?;
            if tbs.object_type() != Ok(ObjectType::CarriageAccepted) {
                return Err(SnapshotError::UnexpectedType(tbs.type_code));
            }
            let accepted = CarriageAccepted::decode_payload(&tbs.payload)
                .map_err(|_| SnapshotError::Malformed)?;
            if accepted.carrier.as_bytes() != tbs.signing_key.as_bytes() {
                return Err(SnapshotError::CarrierMismatch);
            }
            if accepted.identity != self.identity {
                return Err(SnapshotError::ForeignObject);
            }
            if accepted.expires_at.as_millis() > now.as_millis() {
                earliest = earliest.min(accepted.expires_at);
                consented.push(accepted.carrier);
            }
        }

        let (carriers, unconfirmed): (Vec<_>, Vec<_>) = claimed
            .into_iter()
            .partition(|c| consented.contains(&c.node));

        let profile = match &self.profile {
            Some(bytes) => Some(
                self.authored_payload::<IdentityProfile>(
                    bytes,
                    ObjectType::IdentityProfile,
                    &state,
                    Capabilities::NONE,
                )?
                .1,
            ),
            None => None,
        };

        if earliest.as_millis() <= now.as_millis() {
            return Err(SnapshotError::Expired {
                valid_until: earliest,
            });
        }

        Ok(ResolvedIdentity {
            state,
            prekeys,
            carriers,
            unconfirmed,
            profile,
            valid_until: earliest,
        })
    }

    /// Verify one object that this identity must have authored, and decode it.
    fn authored_payload<P: Payload>(
        &self,
        bytes: &[u8],
        expected: ObjectType,
        state: &IdentityState,
        required: Capabilities,
    ) -> Result<(PublicKeyBytes, P), SnapshotError> {
        let object = decode(bytes)?;
        verify_object(&object).map_err(|_| SnapshotError::Malformed)?;
        let tbs = object.tbs().map_err(|_| SnapshotError::Malformed)?;

        if tbs.object_type() != Ok(expected) {
            return Err(SnapshotError::UnexpectedType(tbs.type_code));
        }
        if tbs.author != self.identity {
            return Err(SnapshotError::ForeignObject);
        }
        state.check_device_authority(tbs.signing_key, tbs.timestamp, required)?;

        let payload = P::decode_payload(&tbs.payload).map_err(|_| SnapshotError::Malformed)?;
        Ok((tbs.signing_key, payload))
    }
}

fn decode(bytes: &[u8]) -> Result<Object, SnapshotError> {
    Object::from_canonical_bytes(bytes).map_err(|_| SnapshotError::Malformed)
}
