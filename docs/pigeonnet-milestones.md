# Pigeonnet: Milestone Map

_Companion to `pigeonnet-architecture.md`. The architecture document says what the
system is; this one says what order to build it in and how you know a piece is
finished._

> **No dates.** Sequencing and relative size only, because the time budget is
> unknown. Sizes are S / M / L / XL relative to each other, not to a calendar.

---

## The shape

```text
  M0  workspace & discipline                          S
   │
  M1  identity & objects                              L
   │
  M2  replication                                     L
   ├──────── M3  bundles                              S   (nearly free, see below)
   │
  M4  public echoes                                   M
   │
  M5  private messaging                               XL
   │
  M6  files                                           M
   │
  M7  identity operations                             L
   │        ══════ GATE: no outside users before this ══════
   │
  M8  communities & moderation                        L
   │
  M9  v1.0 hardening                                  M
```

M3 hangs off M2 rather than following it because a bundle is the replication
state machine driven by a file instead of a socket. Sans-io (§34.1) means the
protocol logic does not know the difference, so once M2 works, M3 is mostly
framing and a fuzz target. If M3 turns out to be expensive, something has gone
wrong in M2's layering and it is worth stopping to find out what.

---

## Definition of done

Applies to every milestone. A milestone is not finished until all of it holds.

- Property tests for anything with a round-trip or an invariant.
- `cargo-fuzz` target for anything that parses bytes from outside the process.
- No `unwrap`, `expect`, or panic on an ingest path — enforced by lint, not review.
- Test-vector corpus extended and committed for any wire-visible change.
- Adversarial test for any new object type: replayed, reordered, oversized,
  wrong-signer, expired-key, and malformed variants.
- The architecture document updated where the build contradicted the design.
  This has happened twice already and should be expected, not treated as failure.

---

# M0 — Workspace & discipline

**Goal.** A repository where the rest of the work cannot rot quietly.

**Ships**

- Cargo workspace, edition 2024, the eight crates of §34.1.
- `#![forbid(unsafe_code)]` workspace-wide; clippy lints denied in `core`,
  `crypto`, `proto`, `bundle`.
- CI: build, test, clippy, fmt, and a fuzz smoke run.
- `git init` and a first commit.

**Exit.** CI is green and fails loudly on a deliberately introduced `unwrap` in
`pigeonnet-core`, and on a dependency that violates the crate layering.

**Verified 2026-09-16.** Both tripwires tested by deliberate breakage, then
reverted. Also checked: the MSRV claim (`1.85` was wrong — `thiserror` needs
let-chains — corrected to `1.88`), crate layering by dependency tree, 149 crates
clean under `cargo audit`, and every transitive licence permissive.

**Risk.** None worth tracking; skipping it is the risk. But note that a check
which has never been observed to fail is not yet a check. Every gate here was
made to fail on purpose before being trusted.

---

# M1 — Identity & objects

**Goal.** Two local node instances create signed objects and verify each other's.

**Ships**

- Deterministic CBOR encoder/decoder, integer-keyed, with the **re-encode ingest
  check** (D2). This is the single most important function in the codebase.
- BLAKE3-256 object IDs in derive-key mode, computed over the to-be-signed bytes
  and **excluding the signature field** (D1).
- Base object: version, type, author, signing\_key, timestamp, sequence, payload,
  signature.
- Ed25519 signing and `verify_strict`.
- `IdentityCreated` genesis, identity = its object ID (D3).
- **Recovery key generated at genesis** (D11) — see the note below.
- Key-chain replay: `DeviceKeyGranted`, `DeviceKeyRevoked`, capability and
  validity-window checks, per-signing-key sequence rules.
- SQLite object store preserving original canonical bytes (§25).
- Keystore encrypted with Argon2id (D9).
- `nodectl identity create`, `nodectl object show`.
- **Committed test-vector corpus**: bytes → ID → signature.

**Exit.** Two instances exchange objects by file copy and each verifies the
other's signatures, delegation chains, and sequences. The corpus is committed and
CI fails if an encoding changes.

**Decisions exercised.** D1, D2, D3, D9 (keys only), D11 (generation only).

**Why the recovery key must be here.** It has to be in the genesis object for its
authority to be unambiguous (D11) — an identity created in M1 without one can
never acquire one safely. The *logic* that uses it lands in M7, but the key
material cannot wait. Getting this wrong means every identity created before M7
is permanently unrecoverable.

**Risk.** Canonical encoding is where malleability hides, and it hides quietly —
a subtly non-deterministic encoder produces two IDs for one object and nothing
fails until threading and dedup misbehave months later. The round-trip property
`encode(decode(bytes)) == bytes` on every accepted input is the defence; write it
first, not last.

---

# M2 — Replication

**Goal.** Two nodes converge on the same object set over a socket.

**Ships**

- Per-stream append-only journals and per-`(peer, stream)` cursors (D5).
- Sans-io protocol state machine: `step(input) -> Vec<Output>`.
- Capability negotiation from the first release (§31), so D5's deferred
  reconciliation strategies can arrive later without a flag day.
- Bounded inventory exchange as the repair path.
- TCP transport in `pigeonnet-net`; everything else stays transport-agnostic.
- Ingest limits (§30.1) enforced before anything enters trusted state.
- **Adversarial peer harness**: scripted hostile peer, in-process, no sockets.

**Exit.** Two nodes converge. The harness — replays, reordering, oversized
objects, invalid signatures, truncated streams, a peer that lies about its
cursor — produces no panic, no unbounded memory growth, and no accepted invalid
object.

**Decisions exercised.** D2, D5, D8 (limits).

**Risk.** This is the largest attack surface in the system and the place where
sans-io earns its keep. If the state machine needs a socket to test, it will not
be tested adversarially, and this milestone will look finished when it is not.

---

# M3 — Bundles

**Goal.** Sync two nodes with a USB stick.

**Ships**

- `.pack` reader and writer (§19).
- `nodectl bundle export` / `bundle import`.
- Fuzz target on the reader — §19 requires bundles to be safely importable from
  untrusted media, which is a promise that needs evidence.

**Exit.** A bundle carried between two air-gapped instances converges them, and
a corrupted or hostile bundle is rejected without panic. Importing from a
stranger's stick is exactly as safe as syncing with a peer, because neither is
trusted.

**Decisions exercised.** D2, D5.

**Risk.** Low, if M2 was layered properly. If it is expensive, that is a signal
about M2 rather than about M3.

---

# M4 — Public echoes

**Goal.** Three nodes hold the same discussion, threaded identically.

**Ships**

- Echo subscription; `EchoPost`.
- Explicit threading: `parent` and `thread` (§7).
- Subscription flooding, deduplicated by object ID.
- `seen_by` in the **unsigned transfer envelope**, plus a hop ceiling (D6).
- `nodectl echo subscribe`, `post`, `reply`, `echo read`.

**Exit.** Three nodes in a triangle converge, threads render identically on all
of them, and no object circulates twice. Deliberately re-introducing a cycle in
the peer graph does not produce a storm.

**Decisions exercised.** D5, D6.

**Risk.** `seen_by` belongs outside the signed object; putting it inside changes
the object ID every hop and destroys dedup, references, and the signature at
once. It is an easy mistake to make while chasing a loop bug, and the symptom
looks like a replication problem rather than a design error.

---

# M5 — Private messaging

**Goal.** An encrypted message crosses at least one untrusted relay, is readable
on two of the recipient's devices, and becomes unreadable on schedule.

The largest milestone. Consider splitting it in two — crypto first, then
delivery — if it stalls.

**Ships**

- Per-device epoch prekeys, signed by a device key holding `publish-prekeys`
  (§8.1). The root key stays cold.
- Prekey publication schedule, several epochs ahead.
- Sender **fan-out**: payload encrypted once under a content key, wrapped per
  recipient device.
- HKDF-SHA256 and ChaCha20-Poly1305, with the canonical header as associated data.
- Scheduled destruction of epoch private halves at `valid_until` (`epoch_end + W`).
- `fs` labelling and the static identity-key fallback, shown in the UI.
- Contact gate: `ContactRequest`, accept, and per-peer quotas (D7).
- Failure receipts: `undecryptable`, contact-gated, **carrying a fresh epoch
  prekey** (D10).
- At-rest: re-encrypt DM plaintext on receipt under a local storage key; the
  cryptographic-erasure alternative as config (D9).
- Routing toward a recipient with hop ceiling and TTL; no bounces (D6).

**Exit.** A message crosses a relay that cannot read it. It is readable on two
devices of the recipient and on the sender's other device. A message delivered
after `valid_until` **fails loudly** with a receipt that lets the sender retry in
one round trip. Destroying an epoch key renders archived ciphertext permanently
unreadable, verified by test rather than by assertion.

**Decisions exercised.** D3, D4, D6, D7, D9, D10.

**Risk.** Key destruction scheduling cuts both ways: too eager and messages are
lost permanently and silently, too lazy and forward secrecy is nominal. **`W`'s
default of 30 days is an assumption, not a measured number** — this milestone is
where it gets validated against real sync intervals, and it should be treated as
an open question until then. The second risk is that fan-out makes it tempting to
share one prekey across devices to save bytes; that reintroduces the
secret-syncing problem D4 rejected.

---

# M6 — Files

**Goal.** A file published on one node is fetched and verified from another,
resumably, without trusting the source.

**Ships**

- `FileManifest` over the BLAKE3 root — the hash tree *is* the chunk list (§9).
- Verified streaming: per-chunk verification against the root, no whole-file
  trust.
- Resumable fetch, including resuming from a different peer.
- File echoes and mirroring (§10).
- `nodectl file publish`, `file get`, `files subscribe`.

**Exit.** A 50 MB file transfers, is interrupted, and resumes from a *different*
mirror to a byte-identical result. A mirror serving altered bytes is detected at
the first bad chunk, not at the end.

**Decisions exercised.** D1, D5.

**Risk.** Low. The main trap is reimplementing a chunk list that BLAKE3 already
provides.

---

# M7 — Identity operations

**Goal.** Keys can be rotated, devices revoked, and a stolen identity reclaimed.

**Ships**

- `KeyRotated`, and `invalidate_from` semantics for non-retroactive revocation.
- `RootKeyReplaced` and `RecoveryKeyReplaced` (D11).
- **Role-based ranking**: recovery-signed outranks root-signed, always, never by
  timestamp.
- `IdentitySuccession` in all three flavours — recovery-signed final, root-signed
  voidable, contact-attested per-observer — plus `SuccessionRevoked`.
- Signed introductions and the depth-1 trust graph (§13.1, D7).
- Invitation tokens (§14.3).
- `nodectl device grant` / `device revoke` / `identity recover`.

**Exit.** A simulated theft is reversed: the thief rotates the root and grants
themselves a device, the owner publishes one recovery-signed `RootKeyReplaced`
with `invalidate_from`, and **every node independently reaches the same verdict**
— including nodes that saw the two chains in opposite orders, and nodes that were
offline throughout and learn of both at once.

That last clause is the whole milestone. Test it explicitly.

**Decisions exercised.** D3, D7, D11.

**Risk.** Highest-stakes code in the system. A bug here means either identity
theft or permanent loss, and both are unrecoverable by definition. The ranking
rules need adversarial tests of their own: two competing chains, presented in
every order, to every node, must converge. If they can be made to disagree, the
identity forks — which §5.5 argues is worse than losing it.

---

## Gate: no outside users before M7

Until M7 ships, an identity is one disk failure from death and one stolen key
from permanent hijack. Anyone creating an identity they care about before then is
being set up to lose it.

Run the network with throwaway identities and say so plainly. Do not let this
gate slide because M5 produced a demo that felt finished.

---

# M8 — Communities & moderation

**Goal.** A community with roles, membership, and moderation that nodes may
choose to honour.

**Ships**

- `CommunityCreated`, membership add/remove, role grant/revoke (§11).
- `ModerationAction` as hiding rather than deletion (§12).
- Local policy: honour, ignore, or override a community's moderation.
- Community-scoped echo and file areas.

**Exit.** Two nodes subscribed to one community render the same moderated view,
and a third node that declines the community's moderation renders the unmoderated
view — without either node being wrong, and without any object being deleted.

**Decisions exercised.** D7, D8.

**Risk.** Scope creep. Communities invite governance features indefinitely.
Ship membership, roles, and hiding; defer everything else until asked for twice.

---

# M9 — v1.0 hardening

**Goal.** Something a stranger can run.

**Ships**

- Sustained fuzzing across every parser and the protocol state machine.
- An external security review, with the threat model of §29 as its brief.
- Documented resource limits and sane defaults for every knob in §30.
- Operational documentation: key backup, `W` selection, retention profiles.
- Reproducible builds and signed releases, distributed over a file echo — the
  network distributing itself is both a good demo and a real test.
- Quickstart re-verified end to end against the built tool rather than against
  the design.

**Exit.** A stranger follows `pigeonnet-quickstart.md` on clean hardware and
reaches the end without reading the architecture document.

---

## Deliberately not in this map

Each was considered and deferred with reasons recorded in the architecture:

| Deferred | Where it is argued |
|---|---|
| Merkle / IBLT set reconciliation | D5 — journals first; add behind capability negotiation |
| Per-contact ratchet | D4 — defends a gap already closed from both sides |
| Group and community encryption (MLS) | D4 — no bespoke group scheme |
| Onion routing, sealed metadata | §8.4 |
| Distributed peer discovery, DHT | D6 |
| `k`-of-`n` social recovery | D11 — quorum collusion, delegate rot |
| Postage tokens, global reputation | D7 — both need network-wide agreement |
| Snapshots, archival-peer discovery | D8 |
| SMTP and NNTP bridges | §2 — must not shape the core protocol |

---

## Open questions, and where they close

| Question | Closes at |
|---|---|
| `W` default — 30 days is assumed, not measured | M5, against real sync intervals |
| Document title is generic; the project is Pigeonnet | any time; cosmetic |
| Whether M5 should split into crypto and delivery | decide when M5 is scoped |
| Whether contact-attested succession needs a depth rule | M7, if attestation proves noisy |
