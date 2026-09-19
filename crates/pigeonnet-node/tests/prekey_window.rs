//! The derivation window bounds what a stolen keystore is worth (D16).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use pigeonnet_crypto::{ColdSeed, EPOCHS_PER_WINDOW, KdfParams, window_of, window_start};
use pigeonnet_node::{Node, NodeError};

const NOW: i64 = 1_789_552_800_000;
const PASS: &[u8] = b"passphrase";

struct Temp(std::path::PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn node(name: &str) -> (Temp, Node) {
    let dir = std::env::temp_dir().join(format!("pigeonnet-window-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let node = Node::open_with_kdf(&dir, KdfParams::insecure_for_tests()).unwrap();
    node.create_identity(PASS, NOW).unwrap();
    (Temp(dir), node)
}

#[test]
fn a_new_identity_starts_inside_one_window() {
    let (_dir, node) = node("fresh");
    let (first, end) = node.prekey_window(PASS).unwrap();
    let window = window_of(Node::epoch_at(NOW));

    assert_eq!(first, window_start(window));
    assert_eq!(end, window_start(window) + EPOCHS_PER_WINDOW);
}

#[test]
fn lookahead_is_capped_by_the_window_not_the_caller() {
    // Asking for a year of lookahead must not mint keys whose private halves this
    // node cannot derive: a sender would seal to them and nobody could open it.
    let (_dir, node) = node("cap");
    let (_, end) = node.prekey_window(PASS).unwrap();

    let published = node.publish_prekeys(PASS, NOW, 500).unwrap();
    assert!(!published.is_empty());
    assert!(
        published.iter().all(|&e| e < end),
        "published {published:?} past the window ending at {end}"
    );
    assert_eq!(published.iter().copied().max().unwrap(), end - 1);
}

#[test]
fn every_published_prekey_can_actually_be_opened() {
    // The property that matters: a published public key is useless unless this
    // node can still derive its private half.
    let (_dir, node) = node("derivable");
    for epoch in node.publish_prekeys(PASS, NOW, 500).unwrap() {
        assert!(
            node.prekey_public(PASS, epoch).is_ok(),
            "published epoch {epoch} has no derivable secret"
        );
    }
}

#[test]
fn an_exhausted_window_is_reported_not_silently_empty() {
    // A node that stops publishing without saying so leaves its correspondents
    // on `fs: none` with no explanation.
    let (_dir, node) = node("exhausted");
    let (_, end) = node.prekey_window(PASS).unwrap();

    // A moment inside the next window.
    let later = end.cast_signed() * pigeonnet_node::EPOCH_MILLIS;
    match node.publish_prekeys(PASS, later, 4) {
        Err(NodeError::PrekeyWindowExhausted { window_end }) => assert_eq!(window_end, end),
        other => panic!("expected the window to be reported exhausted, got {other:?}"),
    }
}

#[test]
fn the_cold_half_opens_the_next_window_and_nothing_else_does() {
    let (_dir, node) = node("cross");
    let created = node.create_identity(PASS, NOW);
    assert!(created.is_err(), "second identity should be refused");

    let (_, end) = node.prekey_window(PASS).unwrap();
    let later = end.cast_signed() * pigeonnet_node::EPOCH_MILLIS;

    // Without the cold half, the node is stuck at the boundary.
    assert!(node.publish_prekeys(PASS, later, 4).is_err());

    // A wrong cold half opens *a* window, but not the one this identity's
    // already-published prekeys belong to -- so it is not a way in.
    let wrong = ColdSeed::generate().unwrap();
    let (first, new_end) = node.open_prekey_window(&wrong, end, PASS).unwrap();
    assert_eq!(first, end);
    assert_eq!(new_end, end + EPOCHS_PER_WINDOW);

    // And now publishing works again, in the new window only.
    let published = node.publish_prekeys(PASS, later, 500).unwrap();
    assert!(published.iter().all(|&e| (end..new_end).contains(&e)));
}

#[test]
fn opening_a_window_already_behind_is_refused() {
    // Reopening an earlier window would walk the ratchet backwards and resurrect
    // epochs that were destroyed on purpose.
    let (_dir, node) = node("backwards");
    let cold = ColdSeed::generate().unwrap();
    let (_, end) = node.prekey_window(PASS).unwrap();

    node.open_prekey_window(&cold, end, PASS).unwrap();
    assert!(
        node.open_prekey_window(&cold, 0, PASS).is_err(),
        "an earlier window was reopened"
    );
}

#[test]
fn rotating_early_keeps_the_outgoing_window_readable() {
    // The regression this file exists for.
    //
    // An operator rotates before the current window runs out, because waiting
    // until it is spent would leave senders on `fs: none`. An earlier version of
    // this code replaced the warm seed on rotation, which destroyed the secrets
    // for epochs that were still inside their retention period and whose public
    // halves were already published. Mail sealed to them became undecryptable and
    // nothing reported it.
    let (_dir, node) = node("early");

    let published = node.publish_prekeys(PASS, NOW, 500).unwrap();
    assert!(!published.is_empty());
    let (_, end) = node.prekey_window(PASS).unwrap();

    let cold = ColdSeed::generate().unwrap();
    node.open_prekey_window(&cold, end, PASS).unwrap();

    // Every already-published epoch must still have a derivable secret.
    for epoch in &published {
        assert!(
            node.prekey_public(PASS, *epoch).is_ok(),
            "epoch {epoch} lost its secret when the window rotated"
        );
    }

    // And the outgoing window is held explicitly, not by accident. It is retained
    // from its own start, not from the first epoch that happened to be published:
    // publishing begins at the current epoch, part-way into the window.
    let previous = node.previous_prekey_window(PASS).unwrap();
    assert_eq!(previous, Some((window_start(window_of(published[0])), end)));
}

#[test]
fn only_two_windows_are_ever_held() {
    // Two is provably enough: retention is 30 days and a window is a quarter, so
    // a window is never needed once the one after it has been superseded. Holding
    // a third would be keeping a secret with nothing left to decrypt.
    let (_dir, node) = node("two");
    let cold = ColdSeed::generate().unwrap();

    let (_, first_end) = node.prekey_window(PASS).unwrap();
    node.open_prekey_window(&cold, first_end, PASS).unwrap();
    let (_, second_end) = node.prekey_window(PASS).unwrap();
    node.open_prekey_window(&cold, second_end, PASS).unwrap();

    // After two rotations the first window is gone, not accumulated.
    let previous = node.previous_prekey_window(PASS).unwrap();
    assert_eq!(previous, Some((first_end, second_end)));
    assert!(
        node.prekey_public(PASS, 0).is_err(),
        "an ancient epoch is still derivable"
    );
}

#[test]
fn reopening_the_current_window_changes_nothing() {
    // Idempotent, so an operator who runs it twice does not shunt a live window
    // into the retention slot and lose the one behind it.
    let (_dir, node) = node("idempotent");
    let cold = ColdSeed::generate().unwrap();
    let (first, end) = node.prekey_window(PASS).unwrap();

    node.open_prekey_window(&cold, end, PASS).unwrap();
    let after_one = node.previous_prekey_window(PASS).unwrap();

    node.open_prekey_window(&cold, end, PASS).unwrap();
    assert_eq!(
        node.prekey_window(PASS).unwrap(),
        (end, end + EPOCHS_PER_WINDOW)
    );
    assert_eq!(
        node.previous_prekey_window(PASS).unwrap(),
        after_one,
        "reopening shifted the windows again"
    );
    assert_eq!(after_one, Some((first, end)));
}

#[test]
fn a_window_in_the_old_epoch_units_can_be_reanchored() {
    // Epoch numbers are how time is addressed, so moving from daily to weekly
    // epochs (D16) renumbered them. A keystore written before that holds a window
    // in units that no longer correspond to anything: far ahead of the clock, and
    // unreachable in both directions.
    let (_dir, node) = node("legacy");
    let cold = ColdSeed::generate().unwrap();

    // Stand in for the old numbering by anchoring far ahead, as a daily number
    // would be relative to a weekly clock.
    let stale = Node::epoch_at(NOW) * 7;
    node.reanchor_prekeys(&cold, stale, PASS).unwrap();
    assert!(
        !node
            .prekey_window_covers(PASS, Node::epoch_at(NOW))
            .unwrap()
    );
    assert!(node.publish_prekeys(PASS, NOW, 4).is_err());

    // Re-anchoring at the current epoch makes it usable again.
    let fresh = ColdSeed::generate().unwrap();
    let (first, end) = node
        .reanchor_prekeys(&fresh, Node::epoch_at(NOW), PASS)
        .unwrap();
    assert_eq!(first, window_start(window_of(Node::epoch_at(NOW))));
    assert!(
        node.prekey_window_covers(PASS, Node::epoch_at(NOW))
            .unwrap()
    );

    let published = node.publish_prekeys(PASS, NOW, 500).unwrap();
    assert!(!published.is_empty());
    assert!(published.iter().all(|&e| e < end));

    // And it does not leave an outgoing window behind: the discarded one could
    // not decrypt anything, so keeping its seed would be keeping a liability.
    assert_eq!(node.previous_prekey_window(PASS).unwrap(), None);
}
