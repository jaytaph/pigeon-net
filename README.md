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

One outbound connection syncs **both ways**: the caller pulls, then serves while
the peer pulls. So a node behind NAT or a firewall does not need to be reachable
to be a full participant — it dials out, and its own posts leave with the same
connection. `nodectl serve --serve-only` turns the reciprocal half off for an
operator who wants to be a read-only source.

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

## Reading it like it is 1994

`nodectl` is the whole system, but nobody reads a message board through a CLI.
`pigeoned` is a full-screen reader in the shape of the FidoNet ones — GoldED,
Blue Wave, Msged — because they were built for exactly this kind of network: you
read and write against a local store, and a separate, deliberate step exchanges
mail with a peer.

```bash
export PIGEONNET_PASSPHRASE=...   # without it, the reader opens read-only
pigeoned
```

Areas, then messages, then the message. Replies are drawn as a tree, the way
`tree(1)` draws a directory, so the shape of a discussion is visible without
opening anything:

```text
7     2026-09-07 06:34 joshua            What is the actual threat model here?
8     2026-09-08 06:34 jaytaph*          ├── The part I find hard to dismiss is…
9     2026-09-08 06:41 joshua            │   └── Then the mitigation is not crypto…
10    2026-09-09 06:35 joshua            └── Worth separating the two cases.
```

Thread roots carry no connector: they share an area, which is not a relationship
the objects record, and a spine between them would claim one.

`Enter` goes in, `Esc` comes back,
`W` writes, `R` replies, `S` syncs, `T` changes the colour scheme and `?` lists
the keys. Writing a message ends with `Esc`, which asks whether to send it —
`Ctrl-S` would have been the obvious choice and is the wrong one, because it is
XOFF and the terminal eats it.

Four schemes: `Ice` (the blue-and-cyan default), `Ember`, `Phosphor` and `Amber`.
`PIGEONNET_THEME` picks the one it starts on.

A name shown with a trailing `*` is **self-asserted** — the author's own claim,
authenticated but vouched for by nobody. A name without one is a label set on
this machine (§5.2).

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
  pigeonnet-tui      `pigeoned`, the full-screen reader
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
