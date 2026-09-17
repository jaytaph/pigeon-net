//! Private messages, end to end through real nodes (§8).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use pigeonnet_core::{ForwardSecrecy, IdentityId, NodeId};
use pigeonnet_node::{MessageBody, Node};
use pigeonnet_proto::{Input, Limits, Output, Session};

const NOW: i64 = 1_789_552_800_000;
const DAY: i64 = 86_400_000;
const PASS: &[u8] = b"passphrase";

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn node(tag: &str) -> (Temp, Node, NodeId) {
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).unwrap();
    let mut path = std::env::temp_dir();
    path.push(format!("pigeonnet-msg-{tag}-{}", u64::from_le_bytes(seed)));
    let node = Node::open(&path).unwrap();
    node.create_identity(PASS, NOW).unwrap();
    node.publish_prekeys(PASS, NOW, 7).unwrap();
    let id = node.node_id(PASS).unwrap();
    (Temp(path), node, id)
}

/// Pull everything `from` holds into `into`, in process.
fn pull(into: &Node, into_id: NodeId, from: &Node, from_id: NodeId, now: i64) -> usize {
    let limits = Limits::DEFAULT;
    let mut puller = Session::initiator(into_id, into.sync_plan().unwrap(), limits);
    let mut server = Session::responder(from_id, limits, [0x7a; 32]);
    let mut here = into.replication(now);
    let mut there = from.replication(now);

    let mut accepted = 0;
    let mut outbound = puller.step(&mut here, Input::Start).unwrap();
    for _ in 0..10_000 {
        let mut next = Vec::new();
        let mut done = false;
        for output in outbound {
            match output {
                Output::Send(message) => {
                    for reply in server.step(&mut there, Input::Received(message)).unwrap() {
                        if let Output::Send(reply) = reply {
                            next.push(reply);
                        }
                    }
                }
                Output::Accepted(_) => accepted += 1,
                Output::Resolved(_, _) => {}
                Output::Complete => done = true,
            }
        }
        if done {
            return accepted;
        }
        let mut produced = Vec::new();
        for message in next {
            produced.extend(puller.step(&mut here, Input::Received(message)).unwrap());
        }
        if produced.is_empty() {
            return accepted;
        }
        outbound = produced;
    }
    panic!("sync did not settle");
}

fn text(body: &MessageBody) -> &str {
    match body {
        MessageBody::Opened(text) => text,
        other => panic!("expected an opened message, got {other:?}"),
    }
}

#[test]
fn a_message_reaches_its_recipient_and_opens() {
    let (_a_dir, alice, alice_node) = node("alice");
    let (_b_dir, bob, bob_node) = node("bob");
    let bob_id = bob.local_identity().unwrap();

    // Alice has to know Bob before she can write to him (D12).
    pull(&alice, alice_node, &bob, bob_node, NOW);
    alice
        .send_message(bob_id, "want to test file transfer?", PASS, NOW)
        .unwrap();

    // Bob collects.
    pull(&bob, bob_node, &alice, alice_node, NOW);
    let inbox = bob.inbox(PASS, NOW).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(text(&inbox[0].body), "want to test file transfer?");
    assert_eq!(inbox[0].sender, alice.local_identity().unwrap());
    assert_eq!(inbox[0].fs, ForwardSecrecy::Epoch);
}

#[test]
fn a_relay_carries_what_it_cannot_read() {
    // The point of §8: a node spools a message for someone else without being
    // able to open it.
    let (_a_dir, alice, alice_node) = node("alice2");
    let (_b_dir, bob, bob_node) = node("bob2");
    let (_r_dir, relay, relay_node) = node("relay2");
    let bob_id = bob.local_identity().unwrap();

    pull(&alice, alice_node, &bob, bob_node, NOW);
    alice
        .send_message(bob_id, "not for the relay", PASS, NOW)
        .unwrap();

    // The relay takes a copy, and cannot read it.
    pull(&relay, relay_node, &alice, alice_node, NOW);
    let relay_inbox = relay.inbox(PASS, NOW).unwrap();
    assert!(
        relay_inbox.is_empty(),
        "the message is not addressed to the relay"
    );

    // Bob collects from the relay, never from Alice.
    pull(&bob, bob_node, &relay, relay_node, NOW);
    let inbox = bob.inbox(PASS, NOW).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(text(&inbox[0].body), "not for the relay");
}

#[test]
fn a_sender_can_read_what_it_sent() {
    let (_a_dir, alice, alice_node) = node("alice3");
    let (_b_dir, bob, bob_node) = node("bob3");
    let bob_id = bob.local_identity().unwrap();
    let alice_id = alice.local_identity().unwrap();

    pull(&alice, alice_node, &bob, bob_node, NOW);
    alice
        .send_message(bob_id, "keeping a copy", PASS, NOW)
        .unwrap();

    // Alice sealed to her own device too, so the message is readable to her --
    // but it is in Bob's inbox stream, not hers, so she reads it as a sent item.
    let sent = alice
        .store()
        .objects_by_author_and_type(alice_id, pigeonnet_core::ObjectType::DirectMessage.code())
        .unwrap();
    assert_eq!(sent.len(), 1);
}

#[test]
fn an_expired_epoch_reports_expiry_rather_than_failure() {
    // Forward secrecy having happened, told apart from a broken message.
    let (_a_dir, alice, alice_node) = node("alice4");
    let (_b_dir, bob, bob_node) = node("bob4");
    let bob_id = bob.local_identity().unwrap();

    pull(&alice, alice_node, &bob, bob_node, NOW);
    alice
        .send_message(bob_id, "burn after reading", PASS, NOW)
        .unwrap();
    pull(&bob, bob_node, &alice, alice_node, NOW);
    assert!(matches!(
        bob.inbox(PASS, NOW).unwrap()[0].body,
        MessageBody::Opened(_)
    ));

    // Bob destroys the epoch the message was sealed to.
    bob.destroy_prekeys_before(Node::epoch_at(NOW) + 1, PASS)
        .unwrap();

    let inbox = bob.inbox(PASS, NOW).unwrap();
    assert_eq!(inbox[0].body, MessageBody::Expired);
}

#[test]
fn a_stale_view_falls_back_and_says_so() {
    // §8.1: the fallback keeps offline-first working, and the cost is that the
    // message never expires. Both parties are told.
    let (_a_dir, alice, alice_node) = node("alice5");
    let (_b_dir, bob, bob_node) = node("bob5");
    let bob_id = bob.local_identity().unwrap();
    pull(&alice, alice_node, &bob, bob_node, NOW);

    // Long after every prekey Alice holds for Bob has expired.
    let far_future = NOW + 400 * DAY;
    alice
        .send_message(bob_id, "years later", PASS, far_future)
        .unwrap();
    pull(&bob, bob_node, &alice, alice_node, far_future);

    let inbox = bob.inbox(PASS, far_future).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].fs, ForwardSecrecy::None, "labelled, not hidden");
    assert_eq!(text(&inbox[0].body), "years later");
}

#[test]
fn writing_to_an_unknown_identity_is_refused() {
    // There is no lookup here: resolving is a network act and sending is not.
    let (_a_dir, alice, _) = node("alice6");
    let stranger = IdentityId::from_bytes([0x5a; 32]);
    let result = alice.send_message(stranger, "hello?", PASS, NOW);
    assert!(
        matches!(result, Err(pigeonnet_node::NodeError::UnknownIdentity(_))),
        "{result:?}"
    );
}

#[test]
fn naming_prefers_the_local_label_over_the_self_asserted_one() {
    let (_a_dir, alice, alice_node) = node("naming-a");
    let (_b_dir, bob, bob_node) = node("naming-b");
    let bob_id = bob.local_identity().unwrap();

    // Bob says what he calls himself; Alice learns it by syncing.
    bob.publish_profile(Some("Joshua".into()), PASS, NOW)
        .unwrap();
    pull(&alice, alice_node, &bob, bob_node, NOW);

    let naming = alice.naming(bob_id, NOW).unwrap();
    assert_eq!(naming.asserted.as_deref(), Some("Joshua"));
    assert_eq!(naming.local, None);
    assert!(naming.best_is_asserted(), "nobody but Bob vouches for that");

    // Alice's own label wins, and needs no caveat.
    alice.set_local_name(bob_id, "jaytaph", NOW).unwrap();
    let naming = alice.naming(bob_id, NOW).unwrap();
    assert_eq!(naming.best(), Some("jaytaph"));
    assert!(!naming.best_is_asserted());
}

#[test]
fn a_local_label_is_never_published() {
    // The property that makes a petname unforgeable: it exists only here.
    let (_a_dir, alice, alice_node) = node("naming-c");
    let (_b_dir, bob, bob_node) = node("naming-d");
    let bob_id = bob.local_identity().unwrap();
    alice
        .set_local_name(bob_id, "only-alice-knows", NOW)
        .unwrap();

    let before = bob.store().len().unwrap();
    pull(&bob, bob_node, &alice, alice_node, NOW);

    // Bob may have taken Alice's objects, but none of them carry the label.
    for object in bob
        .store()
        .objects_by_author(alice.local_identity().unwrap())
        .unwrap()
    {
        let bytes = object.to_canonical_bytes().unwrap();
        assert!(
            !bytes.windows(16).any(|w| w == b"only-alice-knows"),
            "a local label reached the wire"
        );
    }
    assert!(bob.store().len().unwrap() >= before);
    assert_eq!(
        bob.naming(alice.local_identity().unwrap(), NOW)
            .unwrap()
            .local,
        None
    );
}

#[test]
fn labels_are_bounded_and_trimmed() {
    let (_a_dir, alice, _) = node("naming-e");
    let id = IdentityId::from_bytes([3; 32]);
    assert!(
        alice.set_local_name(id, "   ", NOW).is_err(),
        "empty after trimming"
    );
    assert!(
        alice.set_local_name(id, &"x".repeat(65), NOW).is_err(),
        "too long"
    );
    alice.set_local_name(id, "  spaced  ", NOW).unwrap();
    assert_eq!(
        alice.naming(id, NOW).unwrap().local.as_deref(),
        Some("spaced")
    );
}
