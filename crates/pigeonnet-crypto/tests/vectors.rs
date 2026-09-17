//! Committed test vectors: fixed inputs, fixed bytes, fixed identifiers.
//!
//! Everything here is derived from hard-coded seeds and a hard-coded clock, so
//! the output is fully determined. If any of it changes, the wire format changed
//! — deliberately or otherwise — and CI says so.
//!
//! This is what a future reimplementation checks itself against, and what stops
//! an innocuous-looking edit to the encoder from silently re-addressing every
//! object in the network.
//!
//! Regenerate deliberately with `PIGEONNET_BLESS=1 cargo test -p pigeonnet-crypto
//! --test vectors`, and read the diff before committing it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::{fmt::Write as _, path::PathBuf};

use pigeonnet_core::{
    IdentityId, Object, ObjectType, Tbs, Timestamp,
    payload::{Capabilities, DeviceKeyGranted, DeviceKeyRevoked, IdentityCreated, Payload},
};
use pigeonnet_crypto::{AgreementKeypair, SigningKeypair, sign_object, verify_object};

/// Fixed seeds. Never change these: they are the point.
const ROOT_SEED: [u8; 32] = [0x01; 32];
const RECOVERY_SEED: [u8; 32] = [0x02; 32];
const AGREEMENT_SECRET: [u8; 32] = [0x03; 32];
const DEVICE_SEED: [u8; 32] = [0x04; 32];

/// 2026-09-16T10:00:00.000Z
const T0: i64 = 1_789_552_800_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors.txt")
}

fn record(out: &mut String, name: &str, object: &Object) {
    let tbs = object.tbs().expect("envelope decodes");
    let _ = writeln!(out, "[{name}]");
    let _ = writeln!(out, "type_code = {}", tbs.type_code);
    let _ = writeln!(out, "sequence  = {}", tbs.sequence);
    let _ = writeln!(out, "tbs       = {}", hex(object.tbs_bytes()));
    let _ = writeln!(out, "id        = {}", object.id());
    let _ = writeln!(out, "signature = {}", object.signature());
    let _ = writeln!(out);
}

/// Build the corpus. Deterministic: no clock, no randomness.
fn generate() -> String {
    let root = SigningKeypair::from_seed(&ROOT_SEED);
    let recovery = SigningKeypair::from_seed(&RECOVERY_SEED);
    let agreement = AgreementKeypair::from_secret(&AGREEMENT_SECRET);
    let device = SigningKeypair::from_seed(&DEVICE_SEED);

    let mut out = String::new();
    out.push_str("# Pigeonnet canonical object test vectors, format v1.\n");
    out.push_str("# Generated from fixed seeds; see tests/vectors.rs.\n");
    out.push_str("# A change here is a change to the wire format.\n\n");

    let _ = writeln!(out, "[keys]");
    let _ = writeln!(out, "root      = {}", root.public());
    let _ = writeln!(out, "recovery  = {}", recovery.public());
    let _ = writeln!(out, "agreement = {}", agreement.public());
    let _ = writeln!(out, "device    = {}", device.public());
    let _ = writeln!(out);

    // Genesis: self-signed by the root key, sequence 0, no author.
    let genesis = sign_object(
        &Tbs {
            version: pigeonnet_core::OBJECT_VERSION,
            type_code: ObjectType::IdentityCreated.code(),
            author: IdentityId::ZERO,
            signing_key: root.public(),
            timestamp: Timestamp::from_millis(T0),
            sequence: 0,
            payload: IdentityCreated {
                root_key: root.public(),
                recovery_key: recovery.public(),
                agreement_key: agreement.public(),
            }
            .encode_payload()
            .expect("payload encodes"),
        },
        &root,
    )
    .expect("signs");

    let identity = IdentityId::from_genesis(genesis.id());
    let _ = writeln!(out, "[identity]");
    let _ = writeln!(out, "id = {identity}");
    let _ = writeln!(out);

    record(&mut out, "genesis", &genesis);

    let grant = sign_object(
        &Tbs {
            version: pigeonnet_core::OBJECT_VERSION,
            type_code: ObjectType::DeviceKeyGranted.code(),
            author: identity,
            signing_key: root.public(),
            timestamp: Timestamp::from_millis(T0 + 1000),
            sequence: 1,
            payload: DeviceKeyGranted {
                device_key: device.public(),
                capabilities: Capabilities::POST
                    | Capabilities::MESSAGE
                    | Capabilities::PUBLISH_PREKEYS,
                not_before: Timestamp::from_millis(T0 + 1000),
                not_after: None,
            }
            .encode_payload()
            .expect("payload encodes"),
        },
        &root,
    )
    .expect("signs");
    record(&mut out, "device_key_granted", &grant);

    // With `not_after` present, to pin how an absent optional differs from a
    // present one.
    let bounded = sign_object(
        &Tbs {
            version: pigeonnet_core::OBJECT_VERSION,
            type_code: ObjectType::DeviceKeyGranted.code(),
            author: identity,
            signing_key: root.public(),
            timestamp: Timestamp::from_millis(T0 + 2000),
            sequence: 2,
            payload: DeviceKeyGranted {
                device_key: device.public(),
                capabilities: Capabilities::POST,
                not_before: Timestamp::from_millis(T0 + 2000),
                not_after: Some(Timestamp::from_millis(T0 + 999_000)),
            }
            .encode_payload()
            .expect("payload encodes"),
        },
        &root,
    )
    .expect("signs");
    record(&mut out, "device_key_granted_bounded", &bounded);

    let revoked = sign_object(
        &Tbs {
            version: pigeonnet_core::OBJECT_VERSION,
            type_code: ObjectType::DeviceKeyRevoked.code(),
            author: identity,
            signing_key: root.public(),
            timestamp: Timestamp::from_millis(T0 + 3000),
            sequence: 3,
            payload: DeviceKeyRevoked {
                device_key: device.public(),
                revoked_at: Timestamp::from_millis(T0 + 3000),
                invalidate_from: Some(Timestamp::from_millis(T0 + 1500)),
            }
            .encode_payload()
            .expect("payload encodes"),
        },
        &root,
    )
    .expect("signs");
    record(&mut out, "device_key_revoked", &revoked);

    // Every recorded object must verify, or the corpus is recording a bug.
    for object in [&genesis, &grant, &bounded, &revoked] {
        verify_object(object).expect("recorded object verifies");
    }

    out
}

#[test]
fn vectors_are_unchanged() {
    let generated = generate();
    let path = vectors_path();

    if std::env::var("PIGEONNET_BLESS").is_ok() {
        std::fs::write(&path, &generated).expect("write vectors");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{} is missing; regenerate with PIGEONNET_BLESS=1",
            path.display()
        )
    });

    assert_eq!(
        generated, committed,
        "\n\nThe wire format changed.\n\
         Every object identifier in the network depends on these bytes.\n\
         If the change was deliberate, regenerate with PIGEONNET_BLESS=1 and read the diff.\n"
    );
}

/// Signatures are deterministic (Ed25519 is), so signing twice must agree.
#[test]
fn signing_is_deterministic() {
    assert_eq!(generate(), generate());
}
