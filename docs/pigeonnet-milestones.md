# Pigeonnet: Milestone Map

_Companion to `pigeonnet-architecture.md`. The architecture document says what the
system is; this one says what order to build it in and how you know a piece is
finished._

> **No dates.** Sequencing and relative size only, because the time budget is
> unknown. Sizes are S / M / L / XL relative to each other, not to a calendar.

---

## The shape

```text
  M0  workspace & discipline                          S   done
   │
  M1  identity & objects                              L   done
   │
  M2  replication                                     L   done
   ├──────── M3  bundles                              S   done
   │
  M4  public echoes                                   M   done
   │
  M5  reachability: identity state, carriage          L
   │
  M6  private messaging                               L
   │
  M7  files                                           M
   │
  M8  identity operations & naming                    L
   │        ══════ GATE: no outside users before this ══════
   │
  M9  communities & moderation                        L
   │
  M10 v1.0 hardening                                  M
```

M5 was inserted by the architecture's v2 revision. Private messaging was
previously sized XL and carried a note suggesting it be split; v2 split it for
us, by finding the missing half. A sender needs an identity's current keys and
its carriers before it can send anything, and nothing in the design said how to
get them. That is now M5, and M6 is the messaging proper — which drops from XL to
L as a result.

M3 hangs off M2 rather than following it, on the theory that a bundle would be
the replication state machine driven by a file instead of a socket. Building it
showed that half right: `Fetch` is a round trip and removable media has none, so
a bundle is the data plane without the control plane. What did transfer was
everything that mattered for safety — the `Replica` trait, the limits, canonical
decoding, per-object signature checks and cursor semantics — and M3 was
correspondingly cheap. The layering bet paid; the description of why did not.

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

**Verified 2026-09-16.** 78 tests across the workspace. The corpus tripwire was
proven by moving one field index and watching it fail. Two fuzz targets ran 5.8M
executions without a crash and are now in CI. `nodectl identity create`,
`identity show` and `object show` work end to end, keystore at `0600`.

Two things the build corrected in the design: the architecture said
`ed25519-dalek` 2 (it is 3), and integration tests needed their own lint
allowances because `cfg_attr(test, ...)` in a library does not reach a separate
test crate.

Still open from M1: the recovery secret renders as base32, not the twelve-word
mnemonic the quickstart shows. A 256-bit Ed25519 seed is twenty-four BIP39 words,
not twelve, so the mnemonic needs a decision about seed width before it needs a
wordlist. Passphrases come from `PIGEONNET_PASSPHRASE` rather than a prompt.

**Decisions exercised.** D1, D2, D3, D9 (keys only), D11 (generation only).

**Why the recovery key must be here.** It has to be in the genesis object for its
authority to be unambiguous (D11) — an identity created in M1 without one can
never acquire one safely. The *logic* that uses it lands in M7, but the key
material cannot wait. Getting this wrong means every identity created before M8
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

**Verified 2026-09-16.** 109 tests. Two real nodes with SQLite stores converge
over TCP; cursors survive reopening the node. 19 harness cases drive a scripted
hostile peer entirely in-process. Two new fuzz targets (frame decoding and the
session state machine) ran 6.3M executions without a crash, and are in CI.

One boundary the build made explicit: `Replica::accept` validates structure and
the signature of the key an object's own envelope names — and deliberately not
whether that key was *authorised*, which needs the author's key chain. A relay
usually does not have it and has no business demanding it before carrying
traffic. **Authority is evaluated on read.** Anything else would mean a node
refusing to relay for identities it has never heard of, which is not a relay.

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

**Verified 2026-09-16.** 130 tests. Two nodes converge through a 625-byte file
with no socket involved; `nodectl bundle export` / `import` work end to end, and
a tampered, random, or truncated stick is refused with a legible message. A fifth
fuzz target ran 7.1M executions on the reader without a crash.

**The prediction above was half right.** A bundle reuses the `Replica` trait, the
limits, canonical decoding, per-object signature checks and cursor semantics —
but *not* the session state machine, because `Fetch` is a round trip and
removable media does not have one. A bundle is the data plane without the control
plane: the sender cannot know what the receiver lacks, so it sends everything
after a stated position. Two-pass exchange is supported the way FidoNet did it,
by carrying the sender's own cursors so the reply can be targeted.

That the state machine did not transfer is not a layering failure; it is a real
difference between a conversation and a parcel. Everything that matters for
*safety* did transfer, which was the actual bet.

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

**Verified 2026-09-16.** 147 tests. Three nodes converge on one nested thread and
render it identically; a settled cycle moves nothing across five further passes in
both directions on every edge. `nodectl echo subscribe / read`, `post` and `reply`
work end to end, including a thread carried between two nodes on a bundle.

**D6 amended.** `seen_by` and hop ceilings turned out to be unnecessary for echo
propagation. We built *pull* (D5 journal cursors), not flooding: nobody pushes, so
there is no storm to suppress, and content addressing deduplicates for free. They
remain the right answer for directed forwarding of private messages (M5), which is
a different problem that D6 had bundled in with this one.

**Two bugs, both invisible until a node held someone else's data.**

*Replay order.* `objects_by_author` orders by `(signing_key, sequence)`, which is
lexicographic rather than causal — so when a device key happened to sort below the
root key, a post replayed *before* the grant that authorised it and the chain
appeared to contain a key it never delegated. A coin flip on randomly generated
keys, which is why it presented as a flaky test. Key-chain replay now reads
key-management objects only, where the single signer makes sequence order causal.

*Self-identification.* `local_identity()` scanned the store for a genesis object.
That works exactly until the first sync, after which the node holds everyone's
genesis objects and returns whichever root key sorts first. A node's own identity
is now recorded in a `node_state` table when it is created, because it is a fact
about the node rather than something inferable from its contents.

**Decisions exercised.** D5, D6.

**Risk.** `seen_by` belongs outside the signed object; putting it inside changes
the object ID every hop and destroys dedup, references, and the signature at
once. It is an easy mistake to make while chasing a loop bug, and the symptom
looks like a replication problem rather than a design error.

---

# M5 — Reachability: identity state, carriage, node discovery

**Goal.** A sender can obtain a stranger's current keys and find out where to
send to them, without a directory, a search, or a permanent server.

This milestone did not exist when the map was written. It was created by the
architecture's v2 revision, which found that four unrelated mechanisms —
encryption (§8.1), routing to an identity (§5.7), naming (§5.2) and inbox
authentication (§15.4) — all needed an identity's current state and none had a
way to obtain it. Private messaging cannot be built without it: a sender with no
prekeys has nothing to encrypt to.

**Ships**

- **Identity snapshots** (D12). `current id:b3:…` returns unexpired
  `EpochPrekey`s for every device, the latest `ReachabilityClaim`, and the
  `IdentityProfile`. No cursor, no session state, ~14 KB for three devices.
- The snapshot's own `valid_until`, and clients that **display its age**.
  Freshness is a property of the snapshot, never a side effect of prekey
  exhaustion.
- The **chain invariant**: a node serving an object must be able to serve that
  object's author's key chain up to the object's timestamp.
- `resolve id:b3:…` to configured peers, **one hop, never forwarded**.
- **`ReachabilityClaim` + `CarriageAccepted`** (D13). Both signatures required
  before a sender routes toward a carrier; carrier-to-carrier inbox replication
  for identities each independently accepted.
- **Stream access classes** (D15). `echo://`, `files://` and `current` open to
  anyone; `inbox:id:b3:X` requires a device-key signature over a nonce the
  serving node supplies.
- **`NodeProfile`** (D14), self-signed, relayed freely, scored locally. Opt-in;
  leaves never publish. `peer add` stays manual. Separable from the rest of this
  milestone and the first thing to cut if it runs long.

**Exit.** A node that has never heard of an identity resolves it from a peer,
obtains usable prekeys, and learns which carriers accept for it — with the
`CarriageAccepted` counter-signature verified, not assumed. A cached snapshot
served by a third party verifies identically to one from the origin. An
unauthenticated `inbox:` query is refused; an authenticated one succeeds.

**Partly verified 2026-09-17.** 167 tests. A stranger holding nothing resolves an
identity from a carrier over TCP, verifies the chain from genesis, gets usable
prekeys and a confirmed carrier; a carrier claimed but not consented to is
reported as *unconfirmed* rather than silently dropped. Origin and relayed
snapshots verify identically.

One refinement to D12 came out of building it: a snapshot's `valid_until` is
advisory and a reader clamps it to the earliest signed expiry inside. Folded back
into the architecture — see §5.6 and D12.

**Stream access (D15) verified 2026-09-17.** `StreamId::Inbox` is the only
restricted stream; everything else answers anyone who connects. The responder's
nonce is injected at construction and the initiator's credential is a trait
object, so `pigeonnet-proto` still holds no randomness and no cryptography.

Two details the implementation had to settle. The challenge transcript is
domain-separated with an ASCII prefix, and there is a test asserting it cannot
parse as a signed object — a device key signs both, so without that a signature
gathered as a challenge answer could be replayed as an object the key authored.
And refusal is **asymmetric on purpose**: a client raises `AccessDenied` locally
when it can see it has no usable credential, while a server that rejects a proof
simply stops talking. A server distinguishing "denied" from "gone" would confirm
to a prober that an inbox exists and is guarded, and a legitimate owner never
needs the distinction.

**Peering added 2026-09-17, outside the plan.** `nodectl peer add`, `sync` and
`serve` — §27 listed all three and no milestone had claimed them, because M2's
exit criterion was convergence and its tests drove sessions directly. The
transport worked; nothing could reach it. Two nodes on two machines now hold a
threaded conversation over TCP.

A peer's identity **pins on first sync** and is enforced at the handshake
(`ProtocolError::WrongPeer`), so a changed address fails rather than continuing
with whoever answered — the same trust-on-first-use shape as §5.2's naming, and
what D14 means by "a wrong address yields a failed handshake rather than a hostile
peer". `serve` handles one connection at a time on purpose: a node holds a SQLite
connection, which is not `Sync`, and §15.4 is explicit that a node is never
obliged to answer. Concurrency there would be a change of posture, not an
optimisation.

**Still open:** `NodeProfile` (D14), flagged from the start as the first thing to
cut, and never needed by M6.

**Decisions exercised.** D12, D13, D14, D15.

**Risk.** Two sit in the architecture rather than the code. **`resolve` must
never be forwarded** — one hop makes it a cache lookup against peers already
chosen, forwarding makes it a DHT that learns who asks about whom. And the
snapshot is world-readable by necessity: device count, carriers, and a liveness
signal are visible to anyone who asks, because letting strangers encrypt to you
means letting strangers read your keys. Neither has a fix; both need stating
rather than solving.

Section 37.4 is the one worth watching: a carrier sees an identity's complete
correspondence metadata for its whole catchment, and D13 recommends *two*.

---

# M6 — Private messaging

**Goal.** An encrypted message crosses at least one untrusted relay, is readable
on two of the recipient's devices, and becomes unreadable on schedule.

**Depends on M5.** Prekeys come from a snapshot (D12) and delivery goes to a
carrier (D13); neither existed when this milestone was first written, which is
why it was sized XL and flagged for splitting.

**Ships**

- Per-device epoch prekeys, signed by a device key holding `publish-prekeys`
  (§8.1). The root key stays cold. Published into the snapshot of M5, which is
  how a sender obtains them.
- Prekey publication schedule, with lookahead — **decided by D16**, after being
  the largest open question in the design (§37.1). The question named the wrong
  quantity: publishing is not what creates exposure, derivability is, and the
  first implementation let a leaked keystore derive roughly eleven years forward.
  D16 splits the seed cold and warm so a window bounds it, binds each prekey to
  its epoch, and moves epochs from daily to weekly. **Implemented 2026-09-19.**
  `PrekeySeed` is bounded to a window, `ColdSeed` opens the next one, and the node
  holds exactly two windows at once — provably enough, since retention is thirty
  days and a window is a quarter. Building it found a flaw in the first attempt:
  replacing the window on rotation destroyed the secrets for epochs still inside
  their retention period, so an operator rotating at the sensible moment lost live
  mail silently. `nodectl prekeys status` / `open-window` / `reanchor` are the
  operator surface; `MAX_DERIVATION_SPAN` is now only a backstop.
- Inbox spooling at a carrier, and the authenticated `inbox:` query (D15).
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

**Progress 2026-09-17.** The crypto core is built and tested: a ratcheting
prekey seed (§37.1's option 2), and seal/open with per-device fan-out.

Two things worth recording. Prekey secrets now come from a **one-way ratcheting
seed** rather than a pile of stored keys — the point is not size but that
advancing past an epoch destroys it arithmetically, instead of relying on an
erasure the filesystem may quietly decline to perform. And the content is bound
to the whole message header as associated data, so editing the recipient, the
claimed `fs` level, or any wrap invalidates the message rather than redirecting
or relabelling it.

**Messages deliver 2026-09-17.** `DirectMessage` objects, inbox spooling, and
scheduled destruction. Two nodes exchange a private message over TCP; a relay
carries one it cannot read; destroying an epoch makes an already-delivered
message unreadable, and the inbox says *expired* rather than *failed*, because
forward secrecy having happened is not a fault.

Three things the implementation settled. A message sealed to a destroyed epoch
reports `MessageBody::Expired` rather than a decryption error, so a person can
tell the mechanism from a bug. `send_message` refuses an identity it cannot
resolve rather than reaching for the network: resolving is a network act and
sending is not, and conflating them would make every send a lookup. And the
identity-key fallback names `PublicKeyBytes::ZERO` as its device, meaning "the
identity key itself" — the same convention genesis uses for `author`.

Still to do here: the contact gate (D7), failure receipts (D10), at-rest
re-encryption (D9), and routing toward a carrier rather than relying on a peer
happening to hold the message.

**Exit.** A message crosses a relay that cannot read it. It is readable on two
devices of the recipient and on the sender's other device. A message delivered
after `valid_until` **fails loudly** with a receipt that lets the sender retry in
one round trip. Destroying an epoch key renders archived ciphertext permanently
unreadable, verified by test rather than by assertion.

**Decisions exercised.** D3, D4, D6, D7, D9, D10.

**Risk.** Key destruction scheduling cuts both ways: too eager and messages are
lost permanently and silently, too lazy and forward secrecy is nominal. **`W`'s
default of 30 days is an assumption, not a measured number**, and §37.1 has since
reopened epoch length and lookahead as a genuine design question rather than a
tuning one. Both get settled here or they get settled by an incident. The second risk is that fan-out makes it tempting to
share one prekey across devices to save bytes; that reintroduces the
secret-syncing problem D4 rejected.

---

# M7 — Files

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

# M8 — Identity operations and naming

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
- **Human-readable names** (§5.2): `NameClaim` + `NameGranted`, both signatures
  required so neither a directory nor an identity can bind alone, and resolution
  **pinned on first use** — a later rebinding stops and asks rather than silently
  substituting someone. A directory is an ordinary identity added by hand, with
  no special status.
- `nodectl device grant` / `device revoke` / `identity recover` /
  `directory add`.

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

## Gate: no outside users before M8

Until M8 ships, an identity is one disk failure from death and one stolen key
from permanent hijack. Anyone creating an identity they care about before then is
being set up to lose it.

Run the network with throwaway identities and say so plainly. Do not let this
gate slide because M6 produced a demo that felt finished.

---

# M9 — Communities & moderation

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

# M10 — v1.0 hardening

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
| Distributed peer discovery, DHT | D6, D14 — self-signed profiles instead |
| `k`-of-`n` social recovery | D11 — quorum collusion, delegate rot |
| Forwarded `resolve` queries | D12 — forwarding builds a DHT that learns who asks about whom |
| Replicated peer quality scores | D14 — a global consensus artifact, and observer-relative anyway |
| Any people search or enumeration | D12 — resolution is by exact identity only, permanently |
| Postage tokens, global reputation | D7 — both need network-wide agreement |
| Snapshots, archival-peer discovery | D8 |
| SMTP and NNTP bridges | §2 — must not shape the core protocol |

---

## Open questions, and where they close

Architecture §37 now carries the design-level open questions, with reasoning.
This table is only the build-order view of them.

| Question | Closes at |
|---|---|
| ~~Epoch length and lookahead versus backup exposure (§37.1)~~ | **Decided: D16.** Implementation outstanding in M6 |
| `W` default — 30 days is assumed, not measured | M6, against real sync intervals |
| Public echo abuse, now also for `NodeProfile` objects (§37.2) | unresolved; blunted in M5, not solved |
| Cold identity resolution when no path reaches it (§37.3) | M5 — likely documented as a limit rather than fixed |
| Metadata concentration at carriers (§37.4) | M5 — needs plain statement in user-facing docs |
| Per-key sequence gaplessness under partial replication (§37.5) | M6 — see the note below |
| Whether contact-attested succession needs a depth rule | M8, if attestation proves noisy |
| Document title is generic; the project is Pigeonnet | any time; cosmetic |

**On §37.5.** §3.3 still requires `sequence` to be gapless per signing key, and
under partial replication a node sees only the fraction of a key's output that
landed in streams it carries, so gaps are normal and carry no information. The
build is currently on the safe side of this by accident: after M4, key-chain
replay reads *only* key-management objects, which are root-signed and arrive
whole via the chain invariant, so gaplessness genuinely holds there. Sequence
checking for ordinary objects was never implemented. The contradiction is open in
the document, not silently violated in the code — but the first code that checks
an `EchoPost`'s sequence will have to pick a side.

---

## Work the v2 revision created in already-finished milestones

Neither is urgent; both are wrong-mechanism rather than broken.

- **`StreamId::Identity` is superseded by D12.** `pigeonnet-proto` has the
  variant and `Replication::journal` writes key-management objects into it. D12
  replaces the dedicated stream with the chain invariant plus `current`
  snapshots. Remove it in M5, when the replacement exists.
- **`PeerAnnouncement` is gone from §24**, replaced by `NodeProfile` (D14). Never
  implemented, so this is a vocabulary correction only.
