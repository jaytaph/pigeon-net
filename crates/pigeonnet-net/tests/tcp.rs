//! Two real nodes, real SQLite stores, real sockets (M2's exit criterion).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use pigeonnet_core::NodeId;
use pigeonnet_net::{Framed, NetError, run_session, serve_session};
use pigeonnet_node::Node;
use pigeonnet_proto::{Input, Limits, Message, Session, StreamId};
use tokio::net::{TcpListener, TcpStream};

const NOW: i64 = 1_789_552_800_000;
const NODE_A: NodeId = NodeId::from_bytes([0xa1; 32]);
const NODE_B: NodeId = NodeId::from_bytes([0xb0; 32]);

struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_node(tag: &str) -> (Temp, Node) {
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).unwrap();
    let mut path = std::env::temp_dir();
    path.push(format!("pigeonnet-net-{tag}-{}", u64::from_le_bytes(seed)));
    let node =
        Node::open_with_kdf(&path, pigeonnet_crypto::KdfParams::insecure_for_tests()).unwrap();
    (Temp(path), node)
}

/// Pull everything `server` has into `client`.
async fn pull(
    client: &Node,
    client_id: NodeId,
    server: &Node,
    server_id: NodeId,
    limits: Limits,
) -> Result<usize, NetError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let serving = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::responder(server_id, limits, [0x22; 32]);
        let mut replica = server.replication(NOW);
        serve_session(&mut framed, &mut session, &mut replica).await
    };

    let pulling = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut framed = Framed::new(socket, limits);
        let mut session = Session::initiator(client_id, vec![StreamId::All], limits);
        let mut replica = client.replication(NOW);
        run_session(&mut framed, &mut session, &mut replica, Input::Start).await
    };

    // `join!` rather than `spawn`: a node holds a SQLite connection, which is
    // not `Sync`, so the futures stay on one task by construction.
    let (served, pulled) = tokio::join!(serving, pulling);
    served?;
    pulled
}

#[tokio::test]
async fn two_nodes_converge_over_tcp() {
    let (_a_dir, a) = temp_node("a");
    let (_b_dir, b) = temp_node("b");

    // Each node creates an identity: a genesis object and a device grant.
    a.create_identity(b"passphrase-a", NOW).unwrap();
    b.create_identity(b"passphrase-b", NOW).unwrap();
    assert_eq!(a.store().len().unwrap(), 2);
    assert_eq!(b.store().len().unwrap(), 2);

    let moved = pull(&a, NODE_A, &b, NODE_B, Limits::DEFAULT).await.unwrap();
    assert_eq!(moved, 2, "A pulled B's two objects");
    assert_eq!(a.store().len().unwrap(), 4);
    assert_eq!(b.store().len().unwrap(), 2, "a pull is one-directional");

    let moved = pull(&b, NODE_B, &a, NODE_A, Limits::DEFAULT).await.unwrap();
    assert_eq!(moved, 2, "B pulled A's two objects");
    assert_eq!(b.store().len().unwrap(), 4);
}

#[tokio::test]
async fn a_second_sync_moves_nothing() {
    // The cursor persisted to SQLite, not merely to memory (D5).
    let (_a_dir, a) = temp_node("a2");
    let (_b_dir, b) = temp_node("b2");
    a.create_identity(b"pa", NOW).unwrap();
    b.create_identity(b"pb", NOW).unwrap();

    assert_eq!(
        pull(&a, NODE_A, &b, NODE_B, Limits::DEFAULT).await.unwrap(),
        2
    );
    assert_eq!(
        pull(&a, NODE_A, &b, NODE_B, Limits::DEFAULT).await.unwrap(),
        0
    );
    assert_eq!(a.store().len().unwrap(), 4);
}

#[tokio::test]
async fn cursors_survive_reopening_the_node() {
    let (a_dir, a) = temp_node("a3");
    let (_b_dir, b) = temp_node("b3");
    a.create_identity(b"pa", NOW).unwrap();
    b.create_identity(b"pb", NOW).unwrap();
    pull(&a, NODE_A, &b, NODE_B, Limits::DEFAULT).await.unwrap();
    drop(a);

    let reopened =
        Node::open_with_kdf(&a_dir.0, pigeonnet_crypto::KdfParams::insecure_for_tests()).unwrap();
    assert_eq!(
        pull(&reopened, NODE_A, &b, NODE_B, Limits::DEFAULT)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_declared_frame_length_cannot_reserve_memory() {
    // The length prefix is checked before allocation, so claiming to send four
    // gigabytes costs the claimant, not us (§30.1).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let attacker = async {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt as _;
        socket.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        socket.flush().await.unwrap();
    };

    let victim = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, Limits::DEFAULT);
        framed.read_frame().await
    };

    let (_, result) = tokio::join!(attacker, victim);
    assert!(
        matches!(
            result,
            Err(NetError::Protocol(
                pigeonnet_proto::ProtocolError::FrameTooLarge { .. }
            ))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_truncated_stream_is_a_disconnect_not_a_hang() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let attacker = async {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt as _;
        // A length prefix promising 100 bytes, followed by three and a hangup.
        socket.write_all(&100u32.to_be_bytes()).await.unwrap();
        socket.write_all(&[1, 2, 3]).await.unwrap();
        socket.shutdown().await.unwrap();
    };

    let victim = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, Limits::DEFAULT);
        framed.read_frame().await
    };

    let (_, result) = tokio::join!(attacker, victim);
    assert!(matches!(result, Err(NetError::Disconnected)), "{result:?}");
}

#[tokio::test]
async fn frames_survive_a_round_trip_over_a_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sent = Message::Want {
        stream: StreamId::All,
        after: 7,
        limit: 16,
    };
    let expected = sent.clone();

    let writer = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let mut framed = Framed::new(socket, Limits::DEFAULT);
        framed.write_frame(&sent).await.unwrap();
    };
    let reader = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(socket, Limits::DEFAULT);
        framed.read_frame().await.unwrap()
    };

    let (_, received) = tokio::join!(writer, reader);
    assert_eq!(received, expected);
}
