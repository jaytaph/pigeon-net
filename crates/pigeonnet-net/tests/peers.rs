//! Dialling configured peers, and pinning who answers (§17.1, D14).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use pigeonnet_core::{AreaName, NodeId};
use pigeonnet_net::{NetError, serve, sync_peer};
use pigeonnet_node::Node;
use pigeonnet_proto::{Limits, ProtocolError};
use tokio::net::TcpListener;

const NOW: i64 = 1_789_552_800_000;
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
        "pigeonnet-peers-{tag}-{}",
        u64::from_le_bytes(seed)
    ));
    let node = Node::open(&path).unwrap();
    node.create_identity(PASS, NOW).unwrap();
    let id = node.node_id(PASS).unwrap();
    (Temp(path), node, id)
}

fn area() -> AreaName {
    AreaName::parse("GOSUB.DEV").unwrap()
}

/// Run `server` until `client_work` finishes, then stop it.
///
/// `serve` never returns on its own, so the test decides when it is over.
async fn with_server<F, T>(
    server: &Node,
    server_id: NodeId,
    client_work: impl FnOnce(String) -> F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();

    let serving = serve(server, server_id, &listener, Limits::DEFAULT, || NOW);
    tokio::select! {
        result = serving => panic!("server stopped early: {result:?}"),
        outcome = client_work(address) => outcome,
    }
}

#[tokio::test]
async fn a_peer_sync_moves_objects_and_reveals_the_peer() {
    let (_h_dir, hub, hub_id) = node("hub");
    let (_l_dir, leaf, leaf_id) = node("leaf");
    hub.subscribe(&area()).unwrap();
    leaf.subscribe(&area()).unwrap();
    hub.post(&area(), "the hub is up", PASS, NOW).unwrap();

    let leaf_ref = &leaf;
    let report = with_server(&hub, hub_id, |address| async move {
        sync_peer(leaf_ref, leaf_id, &address, None, Limits::DEFAULT, NOW)
            .await
            .unwrap()
    })
    .await;

    assert!(report.accepted > 0);
    assert_eq!(report.peer, Some(hub_id), "the peer proved its identity");

    let posts = leaf.read_area(&area()).unwrap();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].post.content, "the hub is up");
}

#[tokio::test]
async fn syncing_twice_moves_nothing_the_second_time() {
    let (_h_dir, hub, hub_id) = node("hub2");
    let (_l_dir, leaf, leaf_id) = node("leaf2");
    hub.subscribe(&area()).unwrap();
    leaf.subscribe(&area()).unwrap();
    hub.post(&area(), "once", PASS, NOW).unwrap();

    let leaf_ref = &leaf;
    let second = with_server(&hub, hub_id, |address| async move {
        sync_peer(leaf_ref, leaf_id, &address, None, Limits::DEFAULT, NOW)
            .await
            .unwrap();
        sync_peer(leaf_ref, leaf_id, &address, None, Limits::DEFAULT, NOW)
            .await
            .unwrap()
    })
    .await;
    assert_eq!(second.accepted, 0);
}

#[tokio::test]
async fn a_pinned_peer_that_does_not_answer_is_refused() {
    // Trust on first use, enforced. If the address now points somewhere else,
    // or something is answering in its place, the handshake fails rather than
    // the conversation continuing with a stranger.
    let (_h_dir, hub, hub_id) = node("hub3");
    let (_i_dir, impostor, impostor_id) = node("impostor3");
    let (_l_dir, leaf, leaf_id) = node("leaf3");
    impostor.subscribe(&area()).unwrap();
    impostor.post(&area(), "trust me", PASS, NOW).unwrap();

    // The leaf expects the hub; the impostor answers.
    let leaf_ref = &leaf;
    let error = with_server(&impostor, impostor_id, |address| async move {
        sync_peer(
            leaf_ref,
            leaf_id,
            &address,
            Some(hub_id),
            Limits::DEFAULT,
            NOW,
        )
        .await
        .unwrap_err()
    })
    .await;

    match error {
        NetError::Protocol(ProtocolError::WrongPeer { expected, found }) => {
            assert_eq!(expected, hub_id);
            assert_eq!(found, impostor_id);
        }
        other => panic!("expected WrongPeer, got {other}"),
    }
    drop(hub);
}

#[tokio::test]
async fn a_pinned_peer_that_does_answer_is_accepted() {
    let (_h_dir, hub, hub_id) = node("hub4");
    let (_l_dir, leaf, leaf_id) = node("leaf4");
    hub.subscribe(&area()).unwrap();
    leaf.subscribe(&area()).unwrap();
    hub.post(&area(), "still me", PASS, NOW).unwrap();

    let leaf_ref = &leaf;
    let report = with_server(&hub, hub_id, |address| async move {
        sync_peer(
            leaf_ref,
            leaf_id,
            &address,
            Some(hub_id),
            Limits::DEFAULT,
            NOW,
        )
        .await
        .unwrap()
    })
    .await;
    assert!(report.accepted > 0);
}

#[tokio::test]
async fn an_unreachable_peer_fails_without_taking_the_node_with_it() {
    let (_l_dir, leaf, leaf_id) = node("leaf5");
    // Port 1 on loopback: nothing listens, and connecting is refused promptly.
    let error = sync_peer(&leaf, leaf_id, "127.0.0.1:1", None, Limits::DEFAULT, NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, NetError::Io(_)), "{error}");
    assert!(leaf.local_identity().is_ok(), "the node is still usable");
}

#[tokio::test]
async fn one_failing_peer_does_not_stop_the_server() {
    // A server answers whoever connects next, whatever the last one did.
    let (_h_dir, hub, hub_id) = node("hub6");
    let (_l_dir, leaf, leaf_id) = node("leaf6");
    hub.subscribe(&area()).unwrap();
    leaf.subscribe(&area()).unwrap();
    hub.post(&area(), "after the noise", PASS, NOW).unwrap();

    let leaf_ref = &leaf;
    let report = with_server(&hub, hub_id, |address| async move {
        // Connect and hang up without saying anything.
        let socket = tokio::net::TcpStream::connect(&address).await.unwrap();
        drop(socket);
        // Then a real sync must still work.
        sync_peer(leaf_ref, leaf_id, &address, None, Limits::DEFAULT, NOW)
            .await
            .unwrap()
    })
    .await;
    assert!(report.accepted > 0);
}
