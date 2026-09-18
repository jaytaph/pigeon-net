//! Three nodes in a triangle, one echo area, identical threads (M4's exit
//! criterion).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use pigeonnet_core::{AreaName, NodeId, ObjectId};
use pigeonnet_node::Node;
use pigeonnet_proto::{Input, Limits, Output, Replica as _, Session};

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
    path.push(format!("pigeonnet-echo-{tag}-{}", u64::from_le_bytes(seed)));
    let node =
        Node::open_with_kdf(&path, pigeonnet_crypto::KdfParams::insecure_for_tests()).unwrap();
    node.create_identity(PASS, NOW).unwrap();
    let id = node.node_id(PASS).unwrap();
    (Temp(path), node, id)
}

fn area() -> AreaName {
    AreaName::parse("GOSUB.DEV").unwrap()
}

/// Pull everything `from` has into `into`. Returns objects transferred.
///
/// No sockets: the session is sans-io, so a sync between two nodes is a loop
/// over `step`, and a triangle is three of them.
fn pull(into: &Node, into_id: NodeId, from: &Node, from_id: NodeId) -> usize {
    let limits = Limits::DEFAULT;
    let mut puller = Session::initiator(into_id, into.sync_plan().unwrap(), limits);
    let mut server = Session::responder(from_id, limits, [0x44; 32]);
    let mut here = into.replication(NOW);
    let mut there = from.replication(NOW);

    let mut accepted = 0;
    let mut outbound = puller.step(&mut here, Input::Start).unwrap();

    for _ in 0..100_000 {
        let mut next = Vec::new();
        let mut finished = false;
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
                Output::Complete => finished = true,
            }
        }
        if finished {
            return accepted;
        }
        let mut produced = Vec::new();
        for message in next {
            for output in puller.step(&mut here, Input::Received(message)).unwrap() {
                produced.push(output);
            }
        }
        if produced.is_empty() {
            return accepted;
        }
        outbound = produced;
    }
    panic!("sync did not settle");
}

fn ids(node: &Node) -> Vec<ObjectId> {
    let mut all = Vec::new();
    for (_, id) in node
        .store()
        .journal_after(&[0x80], 0, usize::MAX)
        .unwrap()
        .0
    {
        all.push(id);
    }
    all.sort_unstable();
    all
}

fn rendered(node: &Node) -> Vec<(usize, String)> {
    node.read_area(&area())
        .unwrap()
        .into_iter()
        .map(|post| (post.depth, post.post.content))
        .collect()
}

#[test]
fn three_nodes_in_a_triangle_converge_on_one_thread() {
    let (_a_dir, a, a_id) = node("a");
    let (_b_dir, b, b_id) = node("b");
    let (_c_dir, c, c_id) = node("c");
    for n in [&a, &b, &c] {
        n.subscribe(&area()).unwrap();
    }

    // A starts a thread; B and C reply after they have seen it.
    let root = a
        .post(&area(), "Hello from the new network", PASS, NOW)
        .unwrap();

    pull(&b, b_id, &a, a_id);
    pull(&c, c_id, &a, a_id);
    let b_reply = b
        .reply(root, "Works here too, Debian 13.", PASS, NOW + 1000)
        .unwrap();
    c.reply(root, "And on the Pi.", PASS, NOW + 2000).unwrap();

    // Go round the triangle until nothing moves. A cycle in the peer graph is
    // the point: it must settle, not storm.
    let mut rounds = 0;
    loop {
        let moved = pull(&a, a_id, &b, b_id)
            + pull(&b, b_id, &c, c_id)
            + pull(&c, c_id, &a, a_id)
            + pull(&a, a_id, &c, c_id)
            + pull(&b, b_id, &a, a_id)
            + pull(&c, c_id, &b, b_id);
        rounds += 1;
        if moved == 0 {
            break;
        }
        assert!(rounds < 10, "the triangle did not settle");
    }

    // Convergence.
    assert_eq!(ids(&a), ids(&b));
    assert_eq!(ids(&b), ids(&c));

    // And a nested reply still lands in the right place once it propagates.
    a.reply(b_reply, "Which kernel?", PASS, NOW + 3000).unwrap();
    for _ in 0..3 {
        pull(&b, b_id, &a, a_id);
        pull(&c, c_id, &b, b_id);
    }

    let view = rendered(&a);
    assert_eq!(view, rendered(&b), "B renders the thread as A does");
    assert_eq!(view, rendered(&c), "C renders the thread as A does");
    assert_eq!(
        view,
        vec![
            (0, "Hello from the new network".to_owned()),
            (1, "Works here too, Debian 13.".to_owned()),
            (2, "Which kernel?".to_owned()),
            (1, "And on the Pi.".to_owned()),
        ]
    );
}

#[test]
fn a_cycle_transfers_nothing_on_the_second_pass() {
    // Content addressing makes deduplication free: a node that already holds an
    // object neither stores nor re-fetches it, whatever route it arrives by.
    let (_a_dir, a, a_id) = node("a2");
    let (_b_dir, b, b_id) = node("b2");
    let (_c_dir, c, c_id) = node("c2");
    for n in [&a, &b, &c] {
        n.subscribe(&area()).unwrap();
    }
    a.post(&area(), "once", PASS, NOW).unwrap();

    // Go round the cycle until it settles. One pass is not enough and should
    // not be: an object needs a hop per edge to reach the far side, so the first
    // few passes moving data is propagation, not duplication.
    let mut passes = 0;
    let mut moved = usize::MAX;
    while moved > 0 {
        moved = pull(&b, b_id, &a, a_id)
            + pull(&c, c_id, &b, b_id)
            + pull(&a, a_id, &c, c_id)
            + pull(&a, a_id, &b, b_id)
            + pull(&b, b_id, &c, c_id)
            + pull(&c, c_id, &a, a_id);
        passes += 1;
        assert!(passes < 10, "the cycle did not settle");
    }

    // Once settled, every edge in both directions moves nothing -- for as long
    // as anyone cares to keep going round. This is the storm test: content
    // addressing makes deduplication free, so a cycle has no fuel.
    for _ in 0..5 {
        let idle = pull(&b, b_id, &a, a_id)
            + pull(&c, c_id, &b, b_id)
            + pull(&a, a_id, &c, c_id)
            + pull(&a, a_id, &b, b_id)
            + pull(&b, b_id, &c, c_id)
            + pull(&c, c_id, &a, a_id);
        assert_eq!(idle, 0, "a settled cycle re-delivered objects");
    }
}

#[test]
fn an_area_stream_carries_only_that_area() {
    let (_a_dir, a, _) = node("a3");
    let one = AreaName::parse("TECH.RUST").unwrap();
    let two = AreaName::parse("RETRO.C64").unwrap();
    a.subscribe(&one).unwrap();
    a.subscribe(&two).unwrap();

    a.post(&one, "rust post", PASS, NOW).unwrap();
    a.post(&two, "c64 post", PASS, NOW + 1).unwrap();

    assert_eq!(rendered_area(&a, &one), vec![(0, "rust post".to_owned())]);
    assert_eq!(rendered_area(&a, &two), vec![(0, "c64 post".to_owned())]);
}

fn rendered_area(node: &Node, area: &AreaName) -> Vec<(usize, String)> {
    node.read_area(area)
        .unwrap()
        .into_iter()
        .map(|post| (post.depth, post.post.content))
        .collect()
}

#[test]
fn a_reply_inherits_its_parents_area_and_thread() {
    // Supplying the thread separately would let a reply claim one thread while
    // hanging off another.
    let (_a_dir, a, _) = node("a4");
    a.subscribe(&area()).unwrap();
    let root = a.post(&area(), "root", PASS, NOW).unwrap();
    let child = a.reply(root, "child", PASS, NOW + 1).unwrap();
    let grandchild = a.reply(child, "grandchild", PASS, NOW + 2).unwrap();

    let posts = a.read_area(&area()).unwrap();
    assert_eq!(posts.len(), 3);
    assert_eq!(posts[2].id, grandchild);
    assert_eq!(posts[2].depth, 2);
    assert_eq!(
        posts[2].post.thread,
        Some(root),
        "thread root is the root, not the parent"
    );
    assert_eq!(posts[2].post.parent, Some(child));
}

#[test]
fn a_reply_whose_parent_is_missing_still_appears() {
    // Dropping it would make a thread depend on replication order (§30.3).
    let (_a_dir, a, a_id) = node("a5");
    let (_b_dir, b, b_id) = node("b5");
    for n in [&a, &b] {
        n.subscribe(&area()).unwrap();
    }
    let root = a.post(&area(), "root", PASS, NOW).unwrap();
    pull(&b, b_id, &a, a_id);

    let middle = a.reply(root, "middle", PASS, NOW + 1).unwrap();
    let leaf = a.reply(middle, "leaf", PASS, NOW + 2).unwrap();

    // B learns of the leaf but never of its parent: copy the leaf's bytes across
    // by hand, standing in for a peer that pruned the middle post (D8).
    let bytes = a
        .object(leaf)
        .unwrap()
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    b.replication(NOW).accept(&bytes).unwrap();

    let contents: Vec<String> = b
        .read_area(&area())
        .unwrap()
        .into_iter()
        .map(|p| p.post.content)
        .collect();
    assert!(
        contents.contains(&"leaf".to_owned()),
        "orphaned reply vanished: {contents:?}"
    );
    assert!(!contents.contains(&"middle".to_owned()));
}

#[test]
fn area_stats_count_what_this_node_holds() {
    let (_a_dir, a, _) = node("stats-a");
    let one = AreaName::parse("TECH.RUST").unwrap();
    let two = AreaName::parse("RETRO.C64").unwrap();
    a.subscribe(&one).unwrap();
    a.subscribe(&two).unwrap();

    let root = a.post(&one, "first", PASS, NOW).unwrap();
    a.reply(root, "second", PASS, NOW + 1000).unwrap();
    a.post(&one, "another thread", PASS, NOW + 2000).unwrap();

    let stats = a.area_stats().unwrap();
    let rust = stats.iter().find(|s| s.area == one).unwrap();
    assert_eq!(rust.posts, 3);
    assert_eq!(
        rust.threads, 2,
        "a reply belongs to its root, not its own thread"
    );
    assert_eq!(rust.voices, 1);
    assert_eq!(rust.first_held.as_millis(), NOW);
    assert_eq!(rust.latest.as_millis(), NOW + 2000);
    assert!(rust.subscribed);

    // A subscribed but silent area still gets a row: "nothing yet" and "not
    // carrying this" are different answers.
    let c64 = stats.iter().find(|s| s.area == two).unwrap();
    assert_eq!(c64.posts, 0);
    assert!(c64.subscribed);
}

#[test]
fn an_area_held_without_subscribing_is_still_counted() {
    // After syncing, a node may hold posts in areas it never asked for.
    let (_a_dir, a, a_id) = node("stats-b");
    let (_b_dir, b, b_id) = node("stats-c");
    let area = AreaName::parse("GOSUB.DEV").unwrap();
    a.subscribe(&area).unwrap();
    a.post(&area, "over here", PASS, NOW).unwrap();

    // B never subscribes, but syncs everything.
    pull(&b, b_id, &a, a_id);

    let stats = b.area_stats().unwrap();
    let held = stats.iter().find(|s| s.area == area).unwrap();
    assert_eq!(held.posts, 1);
    assert!(!held.subscribed, "held, but not carried deliberately");
}

#[test]
fn two_voices_are_counted_separately() {
    let (_a_dir, a, a_id) = node("stats-d");
    let (_b_dir, b, b_id) = node("stats-e");
    let area = AreaName::parse("GOSUB.DEV").unwrap();
    a.subscribe(&area).unwrap();
    b.subscribe(&area).unwrap();

    let root = a.post(&area, "mine", PASS, NOW).unwrap();
    pull(&b, b_id, &a, a_id);
    b.reply(root, "yours", PASS, NOW + 1000).unwrap();
    pull(&a, a_id, &b, b_id);

    let stats = a.area_stats().unwrap();
    let s = stats.iter().find(|s| s.area == area).unwrap();
    assert_eq!(s.voices, 2);
    assert_eq!(s.threads, 1, "a reply does not start a thread");
}
