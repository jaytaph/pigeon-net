//! Sealing and opening direct messages (§8.1, D4).
//!
//! One message, one content key, wrapped once per recipient device:
//!
//! ```text
//!   plaintext ──AEAD(CK)──> ciphertext
//!        CK ──wrap(kek_laptop)──> recipients[0]
//!        CK ──wrap(kek_phone )──> recipients[1]
//!        CK ──wrap(kek_mine  )──> recipients[2]   (the sender's own devices)
//! ```
//!
//! Fan-out rather than one identity-wide key, because a shared key would have to
//! travel between a person's own machines, and one device's compromise would
//! then be every device's. A wrap costs a few dozen bytes; the alternative costs
//! a secret-syncing problem D4 explicitly rejected.
//!
//! Each wrapping key comes from a Diffie-Hellman against that device's epoch
//! prekey, so each device's forward secrecy is independent: destroying one
//! device's epoch secret makes the message unreadable there and nowhere else.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload as AeadPayload},
};
use hkdf::Hkdf;
use pigeonnet_core::{
    AgreementKeyBytes, DirectMessage, ForwardSecrecy, IdentityId, MessageHeader, PublicKeyBytes,
    WrappedKey,
};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{AgreementKeypair, CryptoError};

/// The primitive set this build seals with: X25519, HKDF-SHA256,
/// ChaCha20-Poly1305.
pub const SUITE_V1: u16 = 1;

/// Domain separator for deriving a wrapping key.
const KEK_CONTEXT: &[u8] = b"pigeonnet dm-kek v1\x00";

/// A single-use content key means a fixed nonce is safe, and a stored one would
/// be twelve bytes of ciphertext-adjacent state to get wrong.
const NONCE: [u8; 12] = [0u8; 12];

/// One device to seal to.
#[derive(Clone, Copy, Debug)]
pub struct Target {
    /// Which of the recipient's devices.
    pub device: PublicKeyBytes,
    /// The epoch its prekey belongs to, or `None` for the identity-key fallback.
    pub epoch: Option<u64>,
    /// The public half being sealed to.
    pub public_key: AgreementKeyBytes,
}

/// Seal a message for every listed device.
///
/// Fails on an empty target list rather than producing a message nobody can
/// open: a sender with no usable keys for a recipient has not sent anything, and
/// should be told so.
pub fn seal_message(
    sender: IdentityId,
    recipient: IdentityId,
    targets: &[Target],
    plaintext: &[u8],
) -> Result<DirectMessage, CryptoError> {
    if targets.is_empty() {
        return Err(CryptoError::NoRecipients);
    }

    let ephemeral = AgreementKeypair::generate()?;
    let mut content_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(content_key.as_mut()).map_err(|_| CryptoError::Entropy)?;

    let mut recipients = Vec::with_capacity(targets.len());
    // The weakest entry decides the label: a message readable forever on one of
    // the recipient's devices is not forward secret, whatever the others say.
    let mut fs = ForwardSecrecy::Epoch;

    for target in targets {
        if target.epoch.is_none() {
            fs = ForwardSecrecy::None;
        }
        let shared = ephemeral.agree(target.public_key);
        let kek = derive_kek(&shared, sender, recipient, target)?;
        let cipher = ChaCha20Poly1305::new((&*kek).into());
        let wrapped = cipher
            .encrypt(
                (&NONCE).into(),
                AeadPayload {
                    msg: &*content_key,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::Seal)?;
        recipients.push(WrappedKey {
            device: target.device,
            epoch: target.epoch,
            wrapped,
        });
    }

    let header = MessageHeader {
        recipient,
        suite: SUITE_V1,
        ephemeral_key: ephemeral.public(),
        fs,
        recipients,
    };

    // The content is bound to the whole header, so editing the recipient, the
    // claimed secrecy level or any wrap invalidates the message rather than
    // redirecting it.
    let aad = header.to_canonical_bytes()?;
    let cipher = ChaCha20Poly1305::new((&*content_key).into());
    let ciphertext = cipher
        .encrypt(
            (&NONCE).into(),
            AeadPayload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Seal)?;

    Ok(DirectMessage { header, ciphertext })
}

/// Open a message with one device's agreement key.
///
/// `device` says which entry to look for; `secret` must be the matching epoch
/// prekey, or the identity key for a fallback message.
pub fn open_message(
    message: &DirectMessage,
    sender: IdentityId,
    device: PublicKeyBytes,
    secret: &AgreementKeypair,
) -> Result<Vec<u8>, CryptoError> {
    if message.header.suite != SUITE_V1 {
        return Err(CryptoError::UnknownSuite(message.header.suite));
    }
    let entry = message
        .header
        .recipients
        .iter()
        .find(|entry| entry.device == device)
        .ok_or(CryptoError::NotAddressedToUs)?;

    let target = Target {
        device,
        epoch: entry.epoch,
        public_key: secret.public(),
    };
    let shared = secret.agree(message.header.ephemeral_key);
    let kek = derive_kek(&shared, sender, message.header.recipient, &target)?;

    let cipher = ChaCha20Poly1305::new((&*kek).into());
    let content_key = Zeroizing::new(
        cipher
            .decrypt(
                (&NONCE).into(),
                AeadPayload {
                    msg: &entry.wrapped,
                    aad: &[],
                },
            )
            .map_err(|_| CryptoError::Open)?,
    );
    let content_key: [u8; 32] = content_key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Open)?;
    let content_key = Zeroizing::new(content_key);

    let aad = message.header.to_canonical_bytes()?;
    let cipher = ChaCha20Poly1305::new((&*content_key).into());
    cipher
        .decrypt(
            (&NONCE).into(),
            AeadPayload {
                msg: &message.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Open)
}

/// Derive the key that wraps the content key for one device.
///
/// The Diffie-Hellman output is never used directly: X25519 outputs are not
/// uniformly distributed, and the binding below is what stops a wrap being
/// lifted from one message, device or epoch into another.
fn derive_kek(
    shared: &[u8; 32],
    sender: IdentityId,
    recipient: IdentityId,
    target: &Target,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut info = Vec::with_capacity(160);
    info.extend_from_slice(KEK_CONTEXT);
    info.extend_from_slice(&SUITE_V1.to_be_bytes());
    info.extend_from_slice(sender.as_bytes());
    info.extend_from_slice(recipient.as_bytes());
    info.extend_from_slice(target.device.as_bytes());
    info.extend_from_slice(target.public_key.as_bytes());
    match target.epoch {
        // Tagged, so an epoch-sealed wrap and a fallback wrap can never derive
        // the same key even if every other input matched.
        Some(epoch) => {
            info.push(0x01);
            info.extend_from_slice(&epoch.to_be_bytes());
        }
        None => info.push(0x00),
    }

    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut kek = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, kek.as_mut())
        .map_err(|_| CryptoError::Seal)?;
    Ok(kek)
}
