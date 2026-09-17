//! Sending and reading private messages (§8).

use pigeonnet_core::{
    DirectMessage, ForwardSecrecy, IdentityId, ObjectId, ObjectType, PublicKeyBytes, Timestamp,
    cbor,
    payload::{Capabilities, EpochPrekey, Payload},
};
use pigeonnet_crypto::{CryptoError, ResolvedIdentity, Target, open_message, seal_message};
use pigeonnet_proto::StreamId;

use crate::{Node, NodeError};

/// Stands in for a device in a fallback wrap.
///
/// A `fs: none` message is sealed to the recipient's long-term identity key,
/// which is not any device's key, so there is nothing real to name. Zero means
/// "the identity key itself" — the same convention genesis objects use for
/// `author` (D3).
pub const IDENTITY_KEY_DEVICE: PublicKeyBytes = PublicKeyBytes::ZERO;

/// A message as this node can present it.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The object.
    pub id: ObjectId,
    /// Who wrote it.
    pub sender: IdentityId,
    /// When they say they did.
    pub timestamp: Timestamp,
    /// What kind of secrecy it was sealed with.
    pub fs: ForwardSecrecy,
    /// The content, or why it is not available.
    pub body: MessageBody,
}

/// Whether a message could be read, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageBody {
    /// The plaintext.
    Opened(String),
    /// The epoch it was sealed to has been ratcheted away.
    ///
    /// Not a failure. It is forward secrecy having happened, and it is reported
    /// rather than hidden so a person can tell it apart from a broken message.
    Expired,
    /// It carries no entry this node's device can open.
    NotForThisDevice,
    /// It did not decrypt, or the plaintext was not text.
    Unreadable,
}

impl Node {
    /// Send a private message to an identity this node can resolve.
    ///
    /// Requires a snapshot (D12) already held: there is no lookup here, because
    /// resolving is a network act and this is not. Run `nodectl resolve` or sync
    /// with someone who holds it first.
    pub fn send_message(
        &self,
        recipient: IdentityId,
        content: &str,
        passphrase: &[u8],
        now: i64,
    ) -> Result<ObjectId, NodeError> {
        let sender = self.local_identity()?;
        let resolved = self.resolve_locally(recipient, now)?;
        let mut targets = Self::targets_for(&resolved, now);

        if targets.is_empty() {
            // No usable prekey. Fall back to the long-term identity key rather
            // than refusing: a sender whose view is months stale can still get a
            // message through, and the message says plainly that it will never
            // expire (§8.1).
            targets.push(Target {
                device: IDENTITY_KEY_DEVICE,
                epoch: None,
                public_key: resolved.state.agreement_key(),
            });
        }

        // Seal to our own devices too, or our sent messages are unreadable to
        // us. Best effort: a node that has not published its own prekeys yet
        // simply loses that, rather than failing to send.
        if sender != recipient
            && let Ok(mine) = self.resolve_locally(sender, now)
        {
            targets.extend(Self::targets_for(&mine, now));
        }

        let message = seal_message(sender, recipient, &targets, content.as_bytes())?;
        self.publish(
            ObjectType::DirectMessage,
            message.encode_payload()?,
            Capabilities::MESSAGE,
            passphrase,
            now,
        )
    }

    /// Messages addressed to this node's identity, newest last.
    pub fn inbox(&self, passphrase: &[u8], now: i64) -> Result<Vec<ReceivedMessage>, NodeError> {
        let me = self.local_identity()?;
        let keyring = self.keyring(passphrase)?;
        let device = keyring.device().public();
        let prekeys = keyring.prekeys();
        let identity_key = keyring.agreement();

        let key = cbor::to_canonical_vec(&StreamId::Inbox(me))?;
        let (entries, _) = self.store().journal_after(&key, 0, usize::MAX)?;

        let mut messages = Vec::new();
        for (_, id) in entries {
            let Some(object) = self.store().get(id)? else {
                continue;
            };
            let tbs = object.tbs()?;
            if tbs.object_type() != Ok(ObjectType::DirectMessage) {
                continue;
            }
            let message = DirectMessage::decode_payload(&tbs.payload)?;
            if message.header.recipient != me {
                continue;
            }

            let body = Self::open_for(&message, tbs.author, device, &prekeys, &identity_key);
            messages.push(ReceivedMessage {
                id,
                sender: tbs.author,
                timestamp: tbs.timestamp,
                fs: message.header.fs,
                body,
            });
        }
        let _ = now;
        Ok(messages)
    }

    /// Verify a snapshot this node already holds.
    fn resolve_locally(
        &self,
        identity: IdentityId,
        now: i64,
    ) -> Result<ResolvedIdentity, NodeError> {
        let snapshot = self
            .snapshot(identity, now)?
            .ok_or(NodeError::UnknownIdentity(identity))?;
        Ok(snapshot.verify(Timestamp::from_millis(now))?)
    }

    /// One target per device, choosing each device's prekey by wall clock.
    ///
    /// §8.1: the sender selects by the calendar rather than by preference, so
    /// there is nothing to collide over and nothing to exhaust. The current
    /// epoch is used when the recipient published it; otherwise the latest they
    /// did, which is what makes a stale view degrade slowly instead of failing.
    fn targets_for(resolved: &ResolvedIdentity, now: i64) -> Vec<Target> {
        use std::collections::BTreeMap;

        let wanted = Self::epoch_at(now);
        let mut best: BTreeMap<PublicKeyBytes, &EpochPrekey> = BTreeMap::new();
        for (device, prekey) in &resolved.prekeys {
            let better = match best.get(device) {
                None => true,
                Some(current) if current.epoch == wanted => false,
                Some(current) => {
                    prekey.epoch == wanted
                        || (current.epoch < wanted && prekey.epoch > current.epoch)
                }
            };
            if better {
                best.insert(*device, prekey);
            }
        }

        best.into_iter()
            .map(|(device, prekey)| Target {
                device,
                epoch: Some(prekey.epoch),
                public_key: prekey.public_key,
            })
            .collect()
    }

    /// Try this node's keys against a message.
    fn open_for(
        message: &DirectMessage,
        sender: IdentityId,
        device: PublicKeyBytes,
        prekeys: &pigeonnet_crypto::PrekeySeed,
        identity_key: &pigeonnet_crypto::AgreementKeypair,
    ) -> MessageBody {
        let entry = message
            .header
            .recipients
            .iter()
            .find(|entry| entry.device == device)
            .or_else(|| {
                message
                    .header
                    .recipients
                    .iter()
                    .find(|entry| entry.device == IDENTITY_KEY_DEVICE)
            });

        let Some(entry) = entry else {
            return MessageBody::NotForThisDevice;
        };

        let opened = match entry.epoch {
            None => open_message(message, sender, IDENTITY_KEY_DEVICE, identity_key),
            Some(epoch) => match prekeys.keypair(epoch) {
                Ok(keypair) => open_message(message, sender, device, &keypair),
                // The ratchet has passed this epoch. The message is unreadable
                // by anyone, including its author. That is the mechanism, not a
                // fault, so it is reported as such.
                Err(CryptoError::EpochDestroyed { .. }) => return MessageBody::Expired,
                Err(_) => return MessageBody::Unreadable,
            },
        };

        match opened {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => MessageBody::Opened(text),
                Err(_) => MessageBody::Unreadable,
            },
            Err(_) => MessageBody::Unreadable,
        }
    }
}
