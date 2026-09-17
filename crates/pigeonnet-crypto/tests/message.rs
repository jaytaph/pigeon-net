//! Sealing and opening direct messages (§8.1, D4).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pigeonnet_core::{ForwardSecrecy, IdentityId, PublicKeyBytes};
use pigeonnet_crypto::{
    AgreementKeypair, CryptoError, PrekeySeed, Target, open_message, seal_message,
};

const ALICE: IdentityId = IdentityId::from_bytes([0xa1; 32]);
const BOB: IdentityId = IdentityId::from_bytes([0xb0; 32]);

/// One of Bob's devices, with an epoch prekey.
struct Device {
    key: PublicKeyBytes,
    seed: PrekeySeed,
}

impl Device {
    fn new(tag: u8) -> Self {
        Self {
            key: PublicKeyBytes::from_bytes([tag; 32]),
            seed: PrekeySeed::generate(100).unwrap(),
        }
    }

    fn target(&self, epoch: u64) -> Target {
        Target {
            device: self.key,
            epoch: Some(epoch),
            public_key: self.seed.public(epoch).unwrap(),
        }
    }

    fn open(
        &self,
        message: &pigeonnet_core::DirectMessage,
        epoch: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        open_message(message, ALICE, self.key, &self.seed.keypair(epoch).unwrap())
    }
}

#[test]
fn a_sealed_message_opens() {
    let bob = Device::new(1);
    let sealed = seal_message(
        ALICE,
        BOB,
        &[bob.target(100)],
        b"want to test file transfer?",
    )
    .unwrap();
    assert_eq!(
        bob.open(&sealed, 100).unwrap(),
        b"want to test file transfer?"
    );
    assert_eq!(sealed.header.fs, ForwardSecrecy::Epoch);
}

#[test]
fn every_device_opens_the_same_message() {
    // Fan-out: one ciphertext, one wrap per device (§8.1).
    let laptop = Device::new(1);
    let phone = Device::new(2);
    let sealed = seal_message(
        ALICE,
        BOB,
        &[laptop.target(100), phone.target(100)],
        b"readable on both",
    )
    .unwrap();

    assert_eq!(sealed.header.recipients.len(), 2);
    assert_eq!(laptop.open(&sealed, 100).unwrap(), b"readable on both");
    assert_eq!(phone.open(&sealed, 100).unwrap(), b"readable on both");
}

#[test]
fn one_devices_key_does_not_open_anothers_entry() {
    let laptop = Device::new(1);
    let phone = Device::new(2);
    let sealed = seal_message(ALICE, BOB, &[laptop.target(100), phone.target(100)], b"x").unwrap();

    // The phone's secret against the laptop's entry: the wrap is bound to the
    // device, so it does not transfer.
    let wrong = open_message(
        &sealed,
        ALICE,
        laptop.key,
        &phone.seed.keypair(100).unwrap(),
    );
    assert!(matches!(wrong, Err(CryptoError::Open)), "{wrong:?}");
}

#[test]
fn a_device_not_addressed_is_told_so() {
    let bob = Device::new(1);
    let stranger = Device::new(9);
    let sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"x").unwrap();

    let result = open_message(
        &sealed,
        ALICE,
        stranger.key,
        &stranger.seed.keypair(100).unwrap(),
    );
    assert!(matches!(result, Err(CryptoError::NotAddressedToUs)));
}

#[test]
fn destroying_an_epoch_destroys_the_message() {
    // The whole mechanism, end to end: forward secrecy is a deletion schedule.
    let mut bob = Device::new(1);
    let sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"burn after reading").unwrap();
    assert!(bob.open(&sealed, 100).is_ok());

    bob.seed.ratchet_to(101).unwrap();
    assert!(
        bob.seed.keypair(100).is_err(),
        "epoch 100 is gone, so the message is unreadable by anyone"
    );
}

#[test]
fn a_later_epoch_does_not_open_an_earlier_message() {
    let bob = Device::new(1);
    let sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"x").unwrap();
    let wrong = open_message(&sealed, ALICE, bob.key, &bob.seed.keypair(101).unwrap());
    assert!(matches!(wrong, Err(CryptoError::Open)));
}

#[test]
fn the_fallback_is_labelled_not_hidden() {
    // §8.1: the identity-key fallback keeps offline-first working when a
    // sender's view is stale, and the cost is that the message never expires.
    // Both parties are told.
    let identity_key = AgreementKeypair::generate().unwrap();
    let target = Target {
        device: PublicKeyBytes::from_bytes([1; 32]),
        epoch: None,
        public_key: identity_key.public(),
    };
    let sealed = seal_message(ALICE, BOB, &[target], b"no forward secrecy here").unwrap();

    assert_eq!(sealed.header.fs, ForwardSecrecy::None);
    let opened = open_message(
        &sealed,
        ALICE,
        PublicKeyBytes::from_bytes([1; 32]),
        &identity_key,
    )
    .unwrap();
    assert_eq!(opened, b"no forward secrecy here");
}

#[test]
fn one_weak_device_labels_the_whole_message() {
    // A message readable forever on one of the recipient's devices is not
    // forward secret, whatever the other entries say.
    let laptop = Device::new(1);
    let identity_key = AgreementKeypair::generate().unwrap();
    let fallback = Target {
        device: PublicKeyBytes::from_bytes([2; 32]),
        epoch: None,
        public_key: identity_key.public(),
    };
    let sealed = seal_message(ALICE, BOB, &[laptop.target(100), fallback], b"x").unwrap();
    assert_eq!(sealed.header.fs, ForwardSecrecy::None);
}

// -- what the header binds -------------------------------------------------

#[test]
fn a_redirected_message_will_not_open() {
    // The ciphertext is bound to the header, so editing the recipient
    // invalidates the message rather than redirecting it.
    let bob = Device::new(1);
    let mut sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"for bob").unwrap();
    sealed.header.recipient = IdentityId::from_bytes([0xee; 32]);
    assert!(matches!(bob.open(&sealed, 100), Err(CryptoError::Open)));
}

#[test]
fn a_downgraded_label_will_not_open() {
    // A relay cannot quietly relabel a message as forward-secret, or as not.
    let bob = Device::new(1);
    let mut sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"x").unwrap();
    sealed.header.fs = ForwardSecrecy::None;
    assert!(matches!(bob.open(&sealed, 100), Err(CryptoError::Open)));
}

#[test]
fn a_tampered_ciphertext_will_not_open() {
    let bob = Device::new(1);
    let mut sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"x").unwrap();
    let last = sealed.ciphertext.len() - 1;
    sealed.ciphertext[last] ^= 0x40;
    assert!(matches!(bob.open(&sealed, 100), Err(CryptoError::Open)));
}

#[test]
fn a_wrap_cannot_be_lifted_between_messages() {
    // Each wrap is bound to its own ephemeral key, so swapping one in from
    // another message yields a key that opens nothing.
    let bob = Device::new(1);
    let first = seal_message(ALICE, BOB, &[bob.target(100)], b"one").unwrap();
    let mut second = seal_message(ALICE, BOB, &[bob.target(100)], b"two").unwrap();
    second.header.recipients[0]
        .wrapped
        .clone_from(&first.header.recipients[0].wrapped);
    assert!(matches!(bob.open(&second, 100), Err(CryptoError::Open)));
}

#[test]
fn a_message_from_a_different_sender_will_not_open() {
    // The sender is bound into the key derivation, so a relay cannot reattribute
    // a message by editing the envelope around it.
    let bob = Device::new(1);
    let sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"x").unwrap();
    let wrong = open_message(
        &sealed,
        IdentityId::from_bytes([0xcc; 32]),
        bob.key,
        &bob.seed.keypair(100).unwrap(),
    );
    assert!(matches!(wrong, Err(CryptoError::Open)));
}

#[test]
fn sealing_to_nobody_is_refused() {
    // Better than producing a message nobody can open.
    let result = seal_message(ALICE, BOB, &[], b"x");
    assert!(matches!(result, Err(CryptoError::NoRecipients)));
}

#[test]
fn an_unknown_suite_is_refused() {
    let bob = Device::new(1);
    let mut sealed = seal_message(ALICE, BOB, &[bob.target(100)], b"x").unwrap();
    sealed.header.suite = 999;
    assert!(matches!(
        bob.open(&sealed, 100),
        Err(CryptoError::UnknownSuite(999))
    ));
}

#[test]
fn two_seals_of_one_plaintext_differ() {
    // Fresh ephemeral and fresh content key each time.
    let bob = Device::new(1);
    let a = seal_message(ALICE, BOB, &[bob.target(100)], b"same words").unwrap();
    let b = seal_message(ALICE, BOB, &[bob.target(100)], b"same words").unwrap();
    assert_ne!(a.ciphertext, b.ciphertext);
    assert_ne!(a.header.ephemeral_key, b.header.ephemeral_key);
}
