//! Assembling this node's view of an identity's current state (D12, §5.6).

use pigeonnet_core::{
    IdentityId, ObjectId, ObjectType, Timestamp,
    payload::{
        Capabilities, CarriageAccepted, Carrier, EpochPrekey, IdentityProfile, Payload,
        ReachabilityClaim,
    },
};
use pigeonnet_crypto::Snapshot;

use crate::{Node, NodeError};

/// How long a served snapshot claims to be usable (§5.6).
///
/// Advisory only: the receiver clamps this to the earliest expiry among the
/// objects inside, because the snapshot itself is an aggregate and is not
/// signed. A server cannot extend the life of its contents by saying so.
pub const SNAPSHOT_VALIDITY_MILLIS: i64 = 30 * 86_400_000;

impl Node {
    /// Assemble a snapshot for any identity this node knows enough about.
    ///
    /// Returns `None` when the genesis object is absent — without it there is no
    /// chain, and without a chain nothing else in the snapshot can be checked by
    /// whoever receives it.
    ///
    /// Anything expired is left out rather than shipped. A snapshot is
    /// latest-wins state, not history: an expired prekey is garbage, and last
    /// year's carrier is noise.
    pub fn snapshot(&self, identity: IdentityId, now: i64) -> Result<Option<Snapshot>, NodeError> {
        let Some(genesis) = self.store().get(identity.genesis_object())? else {
            return Ok(None);
        };

        // The chain invariant: genesis first, then key management in causal
        // order. Anyone serving an object must be able to serve this much.
        let mut chain = vec![genesis.to_canonical_bytes()?.into()];
        for object in self.store().key_chain(identity)? {
            chain.push(object.to_canonical_bytes()?.into());
        }

        let mut prekeys = Vec::new();
        for object in self
            .store()
            .objects_by_author_and_type(identity, ObjectType::EpochPrekey.code())?
        {
            let tbs = object.tbs()?;
            let prekey = EpochPrekey::decode_payload(&tbs.payload)?;
            if prekey.valid_until.as_millis() > now {
                prekeys.push(object.to_canonical_bytes()?.into());
            }
        }

        // Latest-wins: only the most recent unexpired claim is of any use.
        let mut reachability = None;
        let mut claimed_nodes = Vec::new();
        for object in self
            .store()
            .objects_by_author_and_type(identity, ObjectType::ReachabilityClaim.code())?
        {
            let tbs = object.tbs()?;
            let claim = ReachabilityClaim::decode_payload(&tbs.payload)?;
            if claim.expires_at.as_millis() > now {
                claimed_nodes = claim.via.iter().map(|c| c.node).collect();
                reachability = Some(object.to_canonical_bytes()?.into());
            }
        }

        // Carriage acceptances are authored by the carrier, so they cannot be
        // found by the carried identity. Only those matching a current claim are
        // included: the rest are someone else's business.
        let mut carriage = Vec::new();
        if !claimed_nodes.is_empty() {
            for object in self
                .store()
                .objects_of_type(ObjectType::CarriageAccepted.code())?
            {
                let tbs = object.tbs()?;
                let accepted = CarriageAccepted::decode_payload(&tbs.payload)?;
                if accepted.identity == identity
                    && accepted.expires_at.as_millis() > now
                    && claimed_nodes.contains(&accepted.carrier)
                {
                    carriage.push(object.to_canonical_bytes()?.into());
                }
            }
        }

        let mut profile = None;
        for object in self
            .store()
            .objects_by_author_and_type(identity, ObjectType::IdentityProfile.code())?
        {
            profile = Some(object.to_canonical_bytes()?.into());
        }

        Ok(Some(Snapshot {
            identity,
            chain,
            prekeys,
            reachability,
            carriage,
            profile,
            valid_until: Timestamp::from_millis(now.saturating_add(SNAPSHOT_VALIDITY_MILLIS)),
        }))
    }
}

/// One epoch, in milliseconds (§8.1).
///
/// Weekly, as D16 settles. Daily was D4's original figure; weekly moves the
/// worst-case message lifetime from 31 days to 37, which nobody notices, and
/// stops a node announcing its liveness every single day by publishing.
///
/// This is how time is addressed: an epoch number means nothing without it, so
/// changing it renumbers every prekey ever published. D16 makes the change now,
/// while that costs nothing.
pub const EPOCH_MILLIS: i64 = 604_800_000;

/// How long a private half survives past its epoch (`W` in D4).
pub const RETENTION_MILLIS: i64 = 30 * 86_400_000;

impl Node {
    /// Which epoch a moment falls in.
    #[must_use]
    pub const fn epoch_at(now: i64) -> u64 {
        now.div_euclid(EPOCH_MILLIS).cast_unsigned()
    }

    /// The public half this node would publish for `epoch`.
    ///
    /// Fails if the epoch has been ratcheted away or lies outside the current
    /// window — which is the same question as "could we still open a message
    /// sealed to it?", and is worth being able to ask directly.
    pub fn prekey_public(
        &self,
        passphrase: &[u8],
        epoch: u64,
    ) -> Result<pigeonnet_core::AgreementKeyBytes, NodeError> {
        Ok(self.keyring(passphrase)?.prekeys().public(epoch)?)
    }

    /// The derivation window this node currently holds (D16).
    ///
    /// Returns the first epoch it can still derive and the first it cannot.
    pub fn prekey_window(&self, passphrase: &[u8]) -> Result<(u64, u64), NodeError> {
        let windows = self.keyring(passphrase)?.prekeys();
        let current = windows.current();
        Ok((current.epoch(), current.window_end()))
    }

    /// The outgoing window, if one is still being held for retention (D16).
    pub fn previous_prekey_window(
        &self,
        passphrase: &[u8],
    ) -> Result<Option<(u64, u64)>, NodeError> {
        Ok(self
            .keyring(passphrase)?
            .prekeys()
            .previous()
            .map(|p| (p.epoch(), p.window_end())))
    }

    /// Whether the held windows cover `epoch` at all.
    ///
    /// False means this node cannot publish and cannot open anything sealed now.
    /// Two ways to get there: the window is spent, or the keystore predates a
    /// change to epoch numbering and its window is in the old units.
    pub fn prekey_window_covers(&self, passphrase: &[u8], epoch: u64) -> Result<bool, NodeError> {
        Ok(self.keyring(passphrase)?.prekeys().public(epoch).is_ok())
    }

    /// Replace the held windows with a single fresh one, from a new cold half.
    ///
    /// **A migration, not a rotation.** [`open_prekey_window`](Self::open_prekey_window)
    /// refuses to move backwards, because doing so resurrects destroyed epochs.
    /// This does move backwards, and is for the one case where that is correct: a
    /// keystore whose window is in units that no longer mean anything, because it
    /// predates D16's move from daily to weekly epochs. Such a window cannot be
    /// ratcheted to or from — nothing it holds corresponds to a reachable epoch —
    /// so nothing is lost by discarding it.
    ///
    /// Any prekey published under the old numbering becomes unopenable. That has
    /// already happened by the time this is reachable: the numbers changed, so no
    /// sender could select one of those keys anyway.
    pub fn reanchor_prekeys(
        &self,
        cold: &pigeonnet_crypto::ColdSeed,
        epoch: u64,
        passphrase: &[u8],
    ) -> Result<(u64, u64), NodeError> {
        let mut keyring = self.keyring(passphrase)?;
        let opened = cold.open_window(pigeonnet_crypto::window_of(epoch));
        let bounds = (opened.epoch(), opened.window_end());
        keyring.set_prekeys(&pigeonnet_crypto::PrekeyWindows::new(opened));
        let sealed = keyring.seal_with(passphrase, self.kdf)?;
        crate::write_private(&self.keystore_path(), &sealed)?;
        Ok(bounds)
    }

    /// Install the warm seed for the window containing `epoch`, from the cold half.
    ///
    /// This is the quarterly act D16 asks for. It is deliberate, it needs material
    /// that is not on this machine, and it is the only way past a window boundary.
    ///
    /// Deterministic, so running it twice for the same window is harmless — the
    /// same warm seed comes back, and prekeys already published from it stay
    /// valid. Running it for a window *behind* the current one is refused: that
    /// would walk the ratchet backwards and resurrect destroyed epochs.
    pub fn open_prekey_window(
        &self,
        cold: &pigeonnet_crypto::ColdSeed,
        epoch: u64,
        passphrase: &[u8],
    ) -> Result<(u64, u64), NodeError> {
        let mut keyring = self.keyring(passphrase)?;
        let mut windows = keyring.prekeys();
        let window = pigeonnet_crypto::window_of(epoch);
        let opened = cold.open_window(window);
        let bounds = (opened.epoch(), opened.window_end());

        // Installed alongside the outgoing window rather than over it: the epochs
        // still inside their retention period must stay openable, or rotating at
        // the sensible moment would silently destroy live mail.
        windows.install(opened)?;
        keyring.set_prekeys(&windows);
        let sealed = keyring.seal_with(passphrase, self.kdf)?;
        crate::write_private(&self.keystore_path(), &sealed)?;
        Ok(bounds)
    }

    /// Publish epoch prekeys for this device, covering `lookahead` epochs.
    ///
    /// Requires `publish-prekeys`, which is what keeps the root key cold: a key
    /// published every day is not an offline key.
    ///
    /// Returns the epochs newly published; already-published ones are skipped,
    /// because re-minting a prekey for an epoch would give senders two keys for
    /// one epoch and no rule for choosing.
    pub fn publish_prekeys(
        &self,
        passphrase: &[u8],
        now: i64,
        lookahead: u64,
    ) -> Result<Vec<u64>, NodeError> {
        let identity = self.local_identity()?;
        let existing: std::collections::BTreeSet<u64> = self
            .store()
            .objects_by_author_and_type(identity, ObjectType::EpochPrekey.code())?
            .into_iter()
            .filter_map(|o| {
                o.tbs()
                    .ok()
                    .and_then(|tbs| EpochPrekey::decode_payload(&tbs.payload).ok())
                    .map(|p| p.epoch)
            })
            .collect();

        let seed = self.keyring(passphrase)?.prekeys();
        let first = Self::epoch_at(now);

        // Lookahead is capped by the derivation window, not by the caller (D16).
        // Publishing past it would mint public keys whose private halves this node
        // cannot derive -- senders would seal to them and nobody could open the
        // result, which is worse than having no prekey at all.
        let window_end = seed.current().window_end();
        if first >= window_end {
            return Err(NodeError::PrekeyWindowExhausted { window_end });
        }
        let last = first.saturating_add(lookahead.max(1)).min(window_end);

        let mut published = Vec::new();
        for epoch in first..last {
            if existing.contains(&epoch) {
                continue;
            }
            let epoch_end = epoch
                .cast_signed()
                .saturating_add(1)
                .saturating_mul(EPOCH_MILLIS);
            // Derived from the ratcheting seed, not generated and discarded:
            // the secret is recoverable for as long as the seed has not been
            // advanced past this epoch, and unrecoverable the moment it has.
            let payload = EpochPrekey {
                epoch,
                public_key: seed.public(epoch)?,
                valid_until: Timestamp::from_millis(epoch_end.saturating_add(RETENTION_MILLIS)),
            }
            .encode_payload()?;

            self.publish(
                ObjectType::EpochPrekey,
                payload,
                Capabilities::PUBLISH_PREKEYS,
                passphrase,
                now,
            )?;
            published.push(epoch);
        }
        Ok(published)
    }

    /// Claim the carriers this identity can be reached through (§5.7).
    ///
    /// A claim alone is not actionable: each named carrier must also publish a
    /// `CarriageAccepted`, or a sender will list it as unconfirmed and route
    /// elsewhere.
    pub fn publish_reachability(
        &self,
        carriers: &[Carrier],
        valid_for_millis: i64,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let payload = ReachabilityClaim {
            via: carriers.to_vec(),
            expires_at: Timestamp::from_millis(now.saturating_add(valid_for_millis)),
        }
        .encode_payload()?;
        self.publish(
            ObjectType::ReachabilityClaim,
            payload,
            Capabilities::NONE,
            passphrase,
            now,
        )
    }

    /// Consent to spool for another identity (§5.7).
    ///
    /// Obliges this node to hold that identity's `inbox:` stream and to serve
    /// its snapshot. Nothing else, and revocable by expiry rather than by a
    /// withdrawal object.
    pub fn accept_carriage(
        &self,
        identity: IdentityId,
        valid_for_millis: i64,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let payload = CarriageAccepted {
            carrier: self.node_id(passphrase)?,
            identity,
            expires_at: Timestamp::from_millis(now.saturating_add(valid_for_millis)),
        }
        .encode_payload()?;
        self.publish(
            ObjectType::CarriageAccepted,
            payload,
            Capabilities::NONE,
            passphrase,
            now,
        )
    }

    /// Publish what this identity calls itself.
    pub fn publish_profile(
        &self,
        display_name: Option<String>,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let payload = IdentityProfile { display_name }.encode_payload()?;
        self.publish(
            ObjectType::IdentityProfile,
            payload,
            Capabilities::NONE,
            passphrase,
            now,
        )
    }
}

impl Node {
    /// Destroy every epoch secret before `epoch`.
    ///
    /// Irreversible, and that is the point: this is the operation forward
    /// secrecy is made of (D4). Messages sealed to a destroyed epoch become
    /// unreadable by anyone, including this node and the sender.
    ///
    /// Returns how many epochs were destroyed.
    pub fn destroy_prekeys_before(&self, epoch: u64, passphrase: &[u8]) -> Result<u64, NodeError> {
        let mut keyring = self.keyring(passphrase)?;
        let mut prekeys = keyring.prekeys();
        let destroyed = prekeys.ratchet_to(epoch)?;
        if destroyed == 0 {
            return Ok(0);
        }
        keyring.set_prekeys(&prekeys);

        // Until this is written the destruction exists only in memory, which is
        // no destruction at all.
        let sealed = keyring.seal_with(passphrase, self.kdf)?;
        crate::write_private(&self.keystore_path(), &sealed)?;
        Ok(destroyed)
    }

    /// Destroy every epoch whose retention window has closed.
    ///
    /// An epoch `E` is readable until `epoch_end(E) + W` (§8.1). Past that, the
    /// secret is of no use to its owner and of considerable use to anyone who
    /// later obtains the keystore, so it goes.
    ///
    /// Meant to run on a schedule. A node that never calls this keeps every
    /// secret it has ever held, and its forward secrecy is a claim rather than a
    /// property.
    pub fn destroy_expired_prekeys(&self, passphrase: &[u8], now: i64) -> Result<u64, NodeError> {
        let cutoff = now.saturating_sub(RETENTION_MILLIS);
        if cutoff <= 0 {
            return Ok(0);
        }
        self.destroy_prekeys_before(cutoff.div_euclid(EPOCH_MILLIS).cast_unsigned(), passphrase)
    }
}
