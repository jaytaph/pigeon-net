# Pigeonnet

A decentralised store-and-forward communication network — FidoNet and Usenet
ideas, modern cryptography, untrusted relays, offline-first.

> There are no mailboxes. There are identities, immutable objects,
> subscriptions, peers, and replication.

**Status: M4 complete.** Identities, canonical objects, replication over TCP,
offline bundles, and public echo areas with threading. Private messaging is next,
behind the reachability work of M5.

Nobody should create an identity they care about yet: recovery lands in M8, and
until then a lost or stolen root key ends the identity. See the gate in the
milestone map.

## Documents

| | |
|---|---|
| [`pigeonnet-architecture.md`](docs/pigeonnet-architecture.md) | What the system is. Decisions D1–D11 in §33 |
| [`pigeonnet-milestones.md`](docs/pigeonnet-milestones.md) | What order to build it in, and how to tell a piece is done |
| [`deny.toml`](deny.toml) | Supply-chain policy: permitted licences, advisory and source rules |
| [`pigeonnet-quickstart.md`](docs/pigeonnet-quickstart.md) | The target user experience, written before the tool exists |

## Layout

```text
crates/
  pigeonnet-core     object model, canonical CBOR, ids, threading    pure, sync
  pigeonnet-crypto   keys, signatures, keystore, key-chain replay    pure, sync
  pigeonnet-store    SQLite objects, journals, cursors, subscriptions  sync
  pigeonnet-proto    replication state machine                       sans-io
  pigeonnet-bundle   .pack read/write for offline transport          pure, sync
  pigeonnet-node     node core: store + proto + echoes + policy
  pigeonnet-net      transports; the only crate that knows tokio
  nodectl            command line interface
```

`core`, `crypto`, `proto` and `bundle` take no I/O, no clock and no ambient
randomness — time and entropy are passed in. That is what makes validation
reproducible in a test and fuzzable without a network.

## Building

```bash
./scripts/check-all.sh     # everything CI runs
```

Individually:

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/check-layering.sh    # crate boundaries from architecture §34.1
cargo deny check               # advisories, licences, sources
cargo +1.88.0 build --workspace # MSRV
```

Lint policy is set once in the workspace manifest and inherited by every crate.
`unwrap`, `expect` and `panic` are denied: nothing on a path that touches bytes
from outside the process may panic.
