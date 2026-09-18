//! A keystore sealed for tests must announce itself as such.

#![allow(clippy::unwrap_used)]

use pigeonnet_crypto::KdfParams;
use pigeonnet_node::Node;

struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_test_sealed_keystore_records_that_it_is_weak() {
    let dir = std::env::temp_dir().join(format!("pigeonnet-weak-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _guard = Temp(dir.clone());

    let node = Node::open_with_kdf(&dir, KdfParams::insecure_for_tests()).unwrap();
    node.create_identity(b"passphrase", 1_789_552_800_000)
        .unwrap();

    let params = node.keystore_params().unwrap();
    assert!(
        !params.is_production(),
        "weak parameters reported as production"
    );
    assert_eq!(params, KdfParams::insecure_for_tests());

    // And the default really is production, on the same code path.
    let dir2 = dir.with_extension("prod");
    let _guard2 = Temp(dir2.clone());
    let prod = Node::open(&dir2).unwrap();
    prod.create_identity(b"passphrase", 1_789_552_800_000)
        .unwrap();
    assert!(prod.keystore_params().unwrap().is_production());
}
