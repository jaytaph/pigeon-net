# Pigeonnet

A decentralised store-and-forward communication network — FidoNet and Usenet
ideas, modern cryptography, untrusted relays, offline-first.

> There are no mailboxes. There are identities, immutable objects,
> subscriptions, peers, and replication.

**Status: M5 complete, and usable between two machines.** Identities, canonical
objects, replication over TCP, offline bundles, public echo areas with threading,
and identity resolution. Private messaging is next.

Nobody should create an identity they care about yet: recovery lands in M8, and
until then a lost or stolen root key ends the identity. See the gate in the
milestone map.

## Two nodes, one conversation

On the machine that stays up:

```bash
export PIGEONNET_PASSPHRASE='...'          # no prompt yet
nodectl identity create
nodectl echo subscribe GOSUB.DEV
nodectl post GOSUB.DEV "The hub is up. Anyone home?"
nodectl serve --listen 0.0.0.0:4137
```

On the other:

```bash
export PIGEONNET_PASSPHRASE='...'
nodectl identity create
nodectl echo subscribe GOSUB.DEV
nodectl peer add hub.example.net                # port defaults to 4137
nodectl sync
nodectl echo read GOSUB.DEV
```

A peer's identity **pins on first sync**, like an SSH host key. If something else
later answers that address, the sync fails and says so rather than continuing with
a stranger. `nodectl peer list` shows what is pinned and why the last attempt
failed.

With no network at all, the same exchange works by file:

```bash
nodectl bundle export /media/usb/out.pack     # on one node
nodectl bundle import /media/usb/out.pack     # on the other
```

A node serves public areas and identity snapshots to anyone who connects, and an
inbox only to its owner. It is never obliged to answer: quotas are local policy.

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
