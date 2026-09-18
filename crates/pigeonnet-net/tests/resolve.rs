//! Resolving an identity from a node that is not its origin (M5's exit
//! criterion, D12 §5.6).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use pigeonnet_core::{IdentityId, NodeId, Timestamp, payload::Carrier};
use pigeonnet_net::{Framed, drive, run_session, serve_session};
use pigeonnet_node::Node;
use pigeonnet_proto::{Input, Limits, Session};
use tokio::net::{TcpListener, TcpStream};

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
    path.push(format!(
        "pigeonnet-resolve-{tag}-{}",
        u64::from_le_bytes(seed)
    ));
    let node =
        Node::open_with_kdf(&path, pigeonnet_crypto::KdfParams::insecure_for_tests()).unwrap();
    node.create_identity(PASS, NOW).unwrap();
    let id = node.node_id(PASS).unwrap();
    (Temp(path), node, id)
}

/// Pull everything `from` holds into `into`, over a real socket.
async fn pull(into: &Node, into_id: NodeId, from: &Node, from_id: NodeId) {
    let limits = Limits::DEFAULT;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let serving = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::responder(from_id, limits, [0x33; 32]);
        let mut replica = from.replication(NOW);
        serve_session(&mut framed, &mut session, &mut replica).await
    };
    let pulling = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::initiator(into_id, into.sync_plan().unwrap(), limits);
        let mut replica = into.replication(NOW);
        run_session(&mut framed, &mut session, &mut replica, Input::Start).await
    };
    let (served, pulled) = tokio::join!(serving, pulling);
    served.unwrap();
    pulled.unwrap();
}

/// Ask `from` about `identity`. Returns the raw snapshot, if it has one.
async fn resolve(
    asker: &Node,
    asker_id: NodeId,
    from: &Node,
    from_id: NodeId,
    identity: IdentityId,
) -> Option<Vec<u8>> {
    let limits = Limits::DEFAULT;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let serving = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::responder(from_id, limits, [0x33; 32]);
        let mut replica = from.replication(NOW);
        serve_session(&mut framed, &mut session, &mut replica).await
    };
    let asking = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::resolver(asker_id, identity, limits);
        let mut replica = asker.replication(NOW);
        drive(&mut framed, &mut session, &mut replica, Input::Start).await
    };
    let (served, asked) = tokio::join!(serving, asking);
    served.unwrap();
    asked.unwrap().snapshot
}

fn verify(bytes: &[u8]) -> pigeonnet_crypto::ResolvedIdentity {
    let snapshot: pigeonnet_crypto::Snapshot =
        pigeonnet_core::cbor::from_canonical_slice(bytes).unwrap();
    snapshot.verify(Timestamp::from_millis(NOW)).unwrap()
}

#[tokio::test]
async fn a_stranger_resolves_an_identity_it_has_never_heard_of() {
    let (_a_dir, alice, alice_node) = node("alice");
    let (_c_dir, carrier, carrier_node) = node("carrier");
    let (_s_dir, stranger, stranger_node) = node("stranger");
    let alice_id = alice.local_identity().unwrap();

    // Alice publishes her current state and names the carrier.
    alice.publish_prekeys(PASS, NOW, 3).unwrap();
    alice
        .publish_profile(Some("joshua".into()), PASS, NOW)
        .unwrap();
    alice
        .publish_reachability(
            &[Carrier {
                node: carrier_node,
                cost: 1,
            }],
            25 * DAY,
            PASS,
            NOW,
        )
        .unwrap();

    // The carrier consents, then takes a copy of Alice's objects.
    carrier
        .accept_carriage(alice_id, 25 * DAY, PASS, NOW)
        .unwrap();
    pull(&carrier, carrier_node, &alice, alice_node).await;

    // The stranger has never seen Alice. It asks the carrier.
    assert!(
        stranger
            .store()
            .get(alice_id.genesis_object())
            .unwrap()
            .is_none()
    );
    let bytes = resolve(&stranger, stranger_node, &carrier, carrier_node, alice_id)
        .await
        .expect("carrier holds Alice");

    let resolved = verify(&bytes);
    assert_eq!(resolved.state.id(), alice_id);
    assert_eq!(resolved.prekeys.len(), 3, "usable prekeys");
    assert_eq!(
        resolved.profile.unwrap().display_name.as_deref(),
        Some("joshua")
    );

    // And the carriage counter-signature was verified, not assumed.
    assert_eq!(resolved.carriers.len(), 1);
    assert_eq!(resolved.carriers[0].node, carrier_node);
    assert!(resolved.unconfirmed.is_empty());
}

#[tokio::test]
async fn a_claimed_carrier_that_never_consented_is_unconfirmed() {
    // Either half alone is not actionable (§5.7): otherwise any identity could
    // aim the network at any node.
    let (_a_dir, alice, alice_node) = node("alice2");
    let (_c_dir, carrier, carrier_node) = node("carrier2");
    let (_s_dir, stranger, stranger_node) = node("stranger2");
    let alice_id = alice.local_identity().unwrap();

    alice.publish_prekeys(PASS, NOW, 1).unwrap();
    // Alice names the carrier; the carrier never accepts.
    alice
        .publish_reachability(
            &[Carrier {
                node: carrier_node,
                cost: 1,
            }],
            25 * DAY,
            PASS,
            NOW,
        )
        .unwrap();
    pull(&carrier, carrier_node, &alice, alice_node).await;

    let bytes = resolve(&stranger, stranger_node, &carrier, carrier_node, alice_id)
        .await
        .unwrap();
    let resolved = verify(&bytes);
    assert!(resolved.carriers.is_empty(), "not routable");
    assert_eq!(resolved.unconfirmed.len(), 1, "surfaced for the operator");
}

#[tokio::test]
async fn resolving_an_unknown_identity_answers_absent_not_an_error() {
    let (_a_dir, _alice, _) = node("alice3");
    let (_c_dir, carrier, carrier_node) = node("carrier3");
    let (_s_dir, stranger, stranger_node) = node("stranger3");

    let nobody = IdentityId::from_bytes([0x5a; 32]);
    let answer = resolve(&stranger, stranger_node, &carrier, carrier_node, nobody).await;
    assert!(answer.is_none());
}

#[tokio::test]
async fn a_relayed_snapshot_is_as_good_as_the_origins() {
    // The property the whole design rests on: everything inside is self-signed,
    // so a third party's cache is exactly as trustworthy as the source.
    let (_a_dir, alice, alice_node) = node("alice4");
    let (_c_dir, carrier, carrier_node) = node("carrier4");
    let (_s_dir, stranger, stranger_node) = node("stranger4");
    let alice_id = alice.local_identity().unwrap();

    alice.publish_prekeys(PASS, NOW, 2).unwrap();
    pull(&carrier, carrier_node, &alice, alice_node).await;

    let from_origin = resolve(&stranger, stranger_node, &alice, alice_node, alice_id)
        .await
        .unwrap();
    let from_carrier = resolve(&stranger, stranger_node, &carrier, carrier_node, alice_id)
        .await
        .unwrap();

    let a = verify(&from_origin);
    let b = verify(&from_carrier);
    assert_eq!(a.state.id(), b.state.id());
    assert_eq!(a.prekeys.len(), b.prekeys.len());
}

#[tokio::test]
async fn prekeys_are_not_minted_twice_for_one_epoch() {
    // Two keys for one epoch would give senders no rule for choosing.
    let (_a_dir, alice, _) = node("alice5");
    assert_eq!(alice.publish_prekeys(PASS, NOW, 3).unwrap().len(), 3);
    assert_eq!(alice.publish_prekeys(PASS, NOW, 3).unwrap().len(), 0);
    assert_eq!(
        alice.publish_prekeys(PASS, NOW, 5).unwrap().len(),
        2,
        "only the new ones"
    );
}
