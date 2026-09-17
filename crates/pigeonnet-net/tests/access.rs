//! Stream access classes (§15.4, D15).
//!
//! The asymmetry under test: an echo area is readable by anyone who connects,
//! and an inbox is readable only by its owner. An inbox open to every peer would
//! make any identity's complete correspondence graph — senders, sizes, timing —
//! globally fetchable from any carrier in the world.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use pigeonnet_core::{AreaName, IdentityId, NodeId};
use pigeonnet_net::{Framed, NetError, run_session, serve_session};
use pigeonnet_node::Node;
use pigeonnet_proto::{Input, Limits, ProtocolError, Session, StreamId};
use tokio::net::{TcpListener, TcpStream};

const NOW: i64 = 1_789_552_800_000;
const PASS: &[u8] = b"passphrase";
const NONCE: [u8; 32] = [0x5e; 32];

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
        "pigeonnet-access-{tag}-{}",
        u64::from_le_bytes(seed)
    ));
    let node = Node::open(&path).unwrap();
    node.create_identity(PASS, NOW).unwrap();
    let id = node.node_id(PASS).unwrap();
    (Temp(path), node, id)
}

/// Ask `server` for `streams`, optionally proving an identity.
async fn request(
    client: &Node,
    client_id: NodeId,
    server: &Node,
    server_id: NodeId,
    streams: Vec<StreamId>,
    credential: bool,
) -> Result<usize, NetError> {
    let limits = Limits::DEFAULT;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let serving = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::responder(server_id, limits, NONCE);
        let mut replica = server.replication(NOW);
        serve_session(&mut framed, &mut session, &mut replica).await
    };
    let asking = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::initiator(client_id, streams, limits);
        if credential {
            session = session.with_inbox_signer(Box::new(client.inbox_credential(PASS).unwrap()));
        }
        let mut replica = client.replication(NOW);
        run_session(&mut framed, &mut session, &mut replica, Input::Start).await
    };
    let (_, asked) = tokio::join!(serving, asking);
    asked
}

/// Give `carrier` the chain it needs to judge `subject`'s proofs.
async fn share_chain(carrier: &Node, carrier_id: NodeId, subject: &Node, subject_id: NodeId) {
    request(
        carrier,
        carrier_id,
        subject,
        subject_id,
        vec![StreamId::All],
        false,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_stranger_may_read_a_public_area() {
    // The network must be readable before anyone has a reason to join it.
    let (_s_dir, server, server_id) = node("srv1");
    let (_c_dir, client, client_id) = node("cli1");
    let area = AreaName::parse("GOSUB.DEV").unwrap();
    server.subscribe(&area).unwrap();
    server.post(&area, "public", PASS, NOW).unwrap();

    let moved = request(
        &client,
        client_id,
        &server,
        server_id,
        vec![StreamId::Echo(area)],
        false,
    )
    .await
    .unwrap();
    assert!(
        moved > 0,
        "a node with no relationship to the server read an area"
    );
}

#[tokio::test]
async fn an_inbox_is_refused_without_a_proof() {
    let (_s_dir, carrier, carrier_id) = node("srv2");
    let (_a_dir, alice, alice_id) = node("alice2");
    share_chain(&carrier, carrier_id, &alice, alice_id).await;
    let alice_identity = alice.local_identity().unwrap();

    let (_e_dir, eve, eve_id) = node("eve2");
    let error = request(
        &eve,
        eve_id,
        &carrier,
        carrier_id,
        vec![StreamId::Inbox(alice_identity)],
        false,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, NetError::Protocol(ProtocolError::AccessDenied)),
        "{error}"
    );
}

#[tokio::test]
async fn an_inbox_is_refused_to_the_wrong_identity() {
    // Eve has a credential -- for her own inbox, not Alice's.
    let (_s_dir, carrier, carrier_id) = node("srv3");
    let (_a_dir, alice, alice_id) = node("alice3");
    share_chain(&carrier, carrier_id, &alice, alice_id).await;
    let alice_identity = alice.local_identity().unwrap();

    let (_e_dir, eve, eve_id) = node("eve3");
    let error = request(
        &eve,
        eve_id,
        &carrier,
        carrier_id,
        vec![StreamId::Inbox(alice_identity)],
        true,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, NetError::Protocol(ProtocolError::AccessDenied)),
        "{error}"
    );
}

#[tokio::test]
async fn an_owner_may_read_its_own_inbox() {
    let (_s_dir, carrier, carrier_id) = node("srv4");
    let (_a_dir, alice, alice_id) = node("alice4");
    share_chain(&carrier, carrier_id, &alice, alice_id).await;
    let alice_identity = alice.local_identity().unwrap();

    // Empty, but answered: the inbox has no messages until M6 puts some there.
    let moved = request(
        &alice,
        alice_id,
        &carrier,
        carrier_id,
        vec![StreamId::Inbox(alice_identity)],
        true,
    )
    .await
    .unwrap();
    assert_eq!(moved, 0);
}

#[tokio::test]
async fn a_carrier_that_does_not_know_the_identity_refuses() {
    // Judging a proof needs the identity's key chain. A node that has never
    // heard of the identity cannot, and refuses rather than guessing.
    //
    // It refuses by closing, so the asker sees a disconnect rather than a
    // reason. That is deliberate: a server distinguishing "denied" from "gone"
    // would confirm to a prober that an inbox exists and is guarded. The two
    // earlier tests get `AccessDenied` because the *client* can see it has no
    // usable credential without asking anyone.
    let (_s_dir, carrier, carrier_id) = node("srv5");
    let (_a_dir, alice, alice_id) = node("alice5");
    let alice_identity = alice.local_identity().unwrap();

    let error = request(
        &alice,
        alice_id,
        &carrier,
        carrier_id,
        vec![StreamId::Inbox(alice_identity)],
        true,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, NetError::Disconnected), "{error}");
}

#[test]
fn access_is_a_property_of_the_stream_not_the_asker() {
    use pigeonnet_proto::Access;
    let identity = IdentityId::from_bytes([7; 32]);
    assert_eq!(StreamId::All.access(), Access::Open);
    assert_eq!(StreamId::Identity(identity).access(), Access::Open);
    assert_eq!(
        StreamId::Echo(AreaName::parse("X").unwrap()).access(),
        Access::Open
    );
    assert_eq!(StreamId::Inbox(identity).access(), Access::Owner(identity));
}

#[test]
fn the_auth_transcript_cannot_be_confused_with_an_object() {
    // A device key signs both objects and inbox challenges. If a challenge
    // transcript could also parse as an object's signed bytes, a signature
    // collected here could be presented as an object that key authored.
    use pigeonnet_proto::inbox_auth_transcript;
    let transcript = inbox_auth_transcript(
        &StreamId::Inbox(IdentityId::from_bytes([7; 32])),
        &NONCE,
        NodeId::from_bytes([9; 32]),
    );
    assert!(transcript.starts_with(b"pigeonnet inbox-auth v1"));
    assert!(
        pigeonnet_core::Tbs::try_from_canonical(&transcript).is_err(),
        "a challenge transcript must never parse as a signed object"
    );
}

#[test]
fn a_transcript_binds_the_stream_the_nonce_and_the_server() {
    use pigeonnet_proto::inbox_auth_transcript;
    let stream = StreamId::Inbox(IdentityId::from_bytes([7; 32]));
    let other = StreamId::Inbox(IdentityId::from_bytes([8; 32]));
    let server = NodeId::from_bytes([9; 32]);
    let elsewhere = NodeId::from_bytes([10; 32]);
    let base = inbox_auth_transcript(&stream, &NONCE, server);

    assert_ne!(
        base,
        inbox_auth_transcript(&other, &NONCE, server),
        "stream"
    );
    assert_ne!(
        base,
        inbox_auth_transcript(&stream, &[0x00; 32], server),
        "nonce"
    );
    assert_ne!(
        base,
        inbox_auth_transcript(&stream, &NONCE, elsewhere),
        "server"
    );
}
