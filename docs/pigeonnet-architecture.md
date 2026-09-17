# Modern Store-and-Forward Network Architecture

## Status

Draft architecture / experiment.

This document describes a modern decentralized communication network inspired by FidoNet, Usenet, and UUCP, but designed around modern cryptography, content-addressed objects, offline-first synchronization, and untrusted relays.

The system is intentionally **not email**.

The central model is:

> There are no mailboxes. There are identities, immutable objects, subscriptions, peers, and replication.

---

# 1. Goals

The network should support:

- Private person-to-person messaging
- Public discussion areas
- Mailing-list-like communication
- File distribution and mirroring
- Community membership
- Moderation
- Offline operation
- Store-and-forward routing
- Intermittently connected nodes
- End-to-end integrity
- End-to-end encryption for private content
- Untrusted relays
- Multiple transport mechanisms
- Human-readable identities without coupling identity to hosting

The system should work well for:

- Personal nodes
- Community servers
- Small VPS nodes
- Home servers
- Raspberry Pi-class hardware
- Intermittent connections
- LAN-only deployments
- Internet-wide deployments
- Potentially disconnected or delay-tolerant environments

---

# 2. Non-goals

The system should not attempt to be:

- SMTP-compatible
- IMAP-compatible
- A conventional email replacement with mailboxes
- Dependent on DNS for identity
- Dependent on X.509 or a global certificate authority hierarchy
- Dependent on permanently connected servers
- Dependent on one transport protocol
- Centrally hosted
- Globally consistent in real time

Compatibility bridges may be added later, but they should not shape the core protocol.

---

# 3. Architectural Principles

## 3.1 Objects, not commands

The protocol should primarily exchange immutable signed objects.

Avoid a protocol centered around commands such as:

```text
SEND MESSAGE
DELETE MESSAGE
JOIN CHANNEL
```

Prefer objects representing events or facts:

```text
MessageCreated
MessageSuperseded
MessageRetracted
ChannelMembershipGranted
ChannelMembershipRevoked
FilePublished
ModerationAction
KeyRotated
```

Nodes replicate these objects and derive local state from them.

This makes the system naturally:

- asynchronous
- eventually consistent
- cacheable
- resumable
- auditable
- replication-friendly
- offline-first

---

## 3.2 Content-addressed objects

Every object has a stable ID derived from its canonical serialized contents.

```text
obj:b3:kv7q2xjm4nfyz8h3wd5t...
```

The ID is BLAKE3 with 256-bit output, computed in derive-key mode with the fixed
context string `pigeonnet object-id v1`, over the canonical **to-be-signed**
bytes.

Two properties matter:

- The ID changes if any authenticated part of the object changes.
- The ID does **not** cover the signature field. Signature encodings are not
  guaranteed to be unique, so hashing them would let one logical object carry two
  IDs — which would in turn break deduplication, threading, retraction, and
  moderation.

The `b3` label comes from a small closed registry rather than a general multihash
namespace. v1 defines exactly one entry. An unknown label makes the object
*unknown* rather than *invalid* (section 31).

Because BLAKE3 is internally a Merkle tree over its input, one primitive serves
object IDs, file chunk trees (section 9), and any future range reconciliation
(section 15).

See D1.

---

## 3.3 Signed authorship

Every authored object is cryptographically signed.

The canonical shape is:

```text
object = {
    version,
    type,
    author,          # identity: the ID of the author's genesis object
    signing_key,     # the device key that signed this object
    timestamp,
    sequence,        # per signing key: monotonic, gapless, from 0
    payload,
    signature        # Ed25519, over everything above
}
```

Objects are signed by a **device key**, never by an identity's root key. The root
key signs only key-management objects (section 5.4).

Verifying an object therefore means:

1. the canonical re-encoding check (section 22),
2. strict Ed25519 verification against `signing_key`,
3. confirming `signing_key` was delegated by `author`, was valid at `timestamp`,
   and carries the capability this object type requires,
4. confirming `sequence` follows the last seen sequence for that key.

The signature proves who authored the object, that it has not been modified, and
that an untrusted relay cannot silently alter content.

Because `sequence` is scoped to a single signing key rather than to the identity,
two devices belonging to the same person never contend for a number. Two
distinct objects sharing one `(signing_key, sequence)` pair are a self-contained
proof of equivocation, and may be published as an `EquivocationProof`.

Relays are not trusted for integrity.

See D3.

---

## 3.4 Encryption belongs to the object layer

Transport encryption such as TLS or QUIC is useful, but it should not be the primary confidentiality boundary.

Private content should be encrypted before transport.

This means:

```text
Alice -> Relay A -> Relay B -> Bob
```

does not require Relay A or Relay B to read the message.

Transport security protects a hop.

Object encryption protects the message.

---

## 3.5 Offline-first

Nodes should not assume continuous connectivity.

A valid node may:

- connect once per minute
- connect once per hour
- connect once per day
- remain offline for several days
- exchange bundles through removable media

Store-and-forward operation is a primary feature rather than a fallback.

---

## 3.6 Transport independence

The logical replication protocol should not depend on one transport.

Potential transports include:

- TCP
- QUIC
- Tor
- I2P
- LAN sockets
- Bluetooth
- serial links
- USB / removable media
- satellite links

The essential operation is:

```text
exchange bundle
```

not:

```text
open permanent Internet session
```

---

# 4. System Model

A participant runs a **node**.

A node contains:

- one or more identities
- an object database
- subscription state
- routing information
- peer configuration
- cryptographic keys
- optional community state
- optional file cache

Nodes exchange objects with peers.

A basic topology might look like:

```text
           ┌──── Node B ────┐
           │                │
Node A ────┼──── Node C ────┼──── Node E
           │                │
           └──── Node D ────┘
```

No individual node has to be globally authoritative.

---

## 4.1 Node roles are behavioural, not structural

The words *hub*, *relay*, and *client* appear throughout this document as
shorthand. **None of them is a protocol role.** There is no hub object, no
hub-only capability, and no operation a hub can perform that an ordinary node
cannot. A "hub" is a node with a stable address, good uptime, and a willingness
to carry things it has no personal interest in.

Four behaviours are worth naming, because they have different costs and should
usually run on different machines:

| Behaviour | What it does | Cost |
|---|---|---|
| **leaf** | subscribes, reads, sends; carries nothing for others | negligible |
| **carrier** | holds `inbox:` journals for identities that named it, and serves their current state (5.6) | storage, metadata exposure |
| **mirror** | prefetches file areas (section 10) | bandwidth |
| **archive** | prunes nothing (D8) | storage |

Same binary, same protocol, different configuration. A node may do all four or
none.

The invariant that matters, for any node acting as a carrier or relay:

| Can | Cannot |
|---|---|
| see who talks to whom, when, and how much | read any private payload |
| withhold, delay, reorder, or drop | forge, alter, or re-attribute an object |
| refuse to carry an identity at all | bounce, or generate anything on its behalf |
| lie about what it holds | hold an identity or a name hostage |

Everything in the left column is real damage, and nothing in this design
prevents it. What is prevented is the right column. **A node can hurt you by not
acting, never by acting.**

The design test for any proposed carrier feature is therefore **exit cost**:
does it raise the price of switching away? Spooling an inbox passes — publish a
new state snapshot and go. Owning a name fails, which is why section 5.2 pins
names locally.

---

# 5. Identity

## 5.1 Cryptographic identity

An identity **is** the object ID of its genesis `IdentityCreated` object.

```text
id:b3:9fq2m4x7...
```

That genesis object carries the identity's first root Ed25519 signing key, its
**recovery key** (section 5.5), and its first X25519 identity key. All can later
be replaced. The identity name cannot.

That is the entire point. If the identity *were* the key, then the key rotation
of section 5.4 would silently become an identity change, breaking every existing
reference to that person — every thread parent, every contact entry, every
membership record.

Current key material is derived by replaying the identity's key-management chain
from genesis:

```text
IdentityCreated -> DeviceKeyGranted -> KeyRotated -> DeviceKeyRevoked -> ...
```

That chain is made of ordinary replicated objects, so any node can compute it
independently and no node has to be told the answer.

Human-readable names remain metadata or signed mappings (section 5.2).

Identity is not tied to:

- a hostname
- a DNS domain
- a server
- an IP address
- any single key

A user can move between nodes, and between devices, without changing identity.

See D3.

---

## 5.2 Human-readable addressing

The network may expose FidoNet-inspired human-readable names, scoped to a
**directory** — typically a community that already knows its members:

```text
joshua@gosub
```

A directory is an ordinary identity that publishes name bindings. It is not
infrastructure, has no special status, and is added by hand
(`nodectl directory add`) exactly as a peer is.

### A binding takes two signatures

Neither side may bind unilaterally:

```text
NameClaim   { namespace: "gosub", name: "joshua",
              identity: id:b3:9fq2..., signature_by_device_key }

NameGranted { namespace: "gosub", name: "joshua",
              identity: id:b3:9fq2..., expires_at,
              signature_by_directory }
```

A directory alone cannot attach a name to an identity, so it cannot squat a
name onto someone or attribute a loaded name to them. An identity alone cannot
mint a name in someone else's namespace.

### Resolution is pin-on-first-use

The first time `joshua@gosub` resolves to `id:b3:9fq2...`, **that pair is
written to the local address book.** A later `NameGranted` rebinding the name is
not a new answer, it is a *change*, and it stops and asks the user.

This is what reduces a directory from an authority to a convenience: it can help
find someone the first time, and it can never silently substitute them
afterwards. SSH host keys, essentially.

### Directories are mechanically accountable

A directory is an identity, so its bindings are signed objects with per-key
gapless sequences (D3). A directory that tells one node `joshua -> A` and
another `joshua -> B` has published two objects that anyone can hold up side by
side; if they collide on `(signing_key, sequence)` it is an automatic
`EquivocationProof`. DNS and X.509 needed Certificate Transparency bolted on to
obtain this property. Here it falls out of everything being an immutable
replicated object.

### Display in three tiers

```text
alice                 local petname, assigned by the user      — strongest
joshua@gosub          directory name, pinned, namespace always shown
id:b3:9fq2m4x7...     raw identity                             — always available
```

**A bare name is never displayed without its namespace.** A name with no
namespace attached is a phishing vector.

The name is convenience. The identity is the genesis object ID (section 5.1).

See D12.

---

## 5.3 Reachability

Identity and reachability are separate.

Example:

```text
Joshua
  identity: id:b3:9fq2m4x7...
  reachable through:
    node:ams23
    node:home42
```

A user can therefore move between relay nodes or advertise multiple delivery paths.

---

## 5.4 Key rotation and device keys

An identity has one **root key** and any number of **device keys**.

The root key is expected to live offline. It signs only key-management objects:

```text
KeyRotated
DeviceKeyGranted
DeviceKeyRevoked
IdentitySuccession        # voidable when root-signed; see 5.5
```

It does **not** sign epoch prekeys. Those are published daily by device keys
holding a `publish-prekeys` capability (section 8.1) — a key used every day is
not a cold key.

An identity also has a **recovery key**, which outranks the root and is covered
in section 5.5.

Everything else — posts, messages, receipts, route advertisements — is signed by
a device key.

Granting a device:

```text
DeviceKeyGranted {
    identity:     id:b3:9fq2m4x7...,
    device_key:   ed25519:c3a81f...,
    capabilities: [post, message, publish-file, publish-prekeys],
    not_before:   ...,
    not_after:    ...,
    signature_by_root
}
```

Revoking one:

```text
DeviceKeyRevoked {
    identity:   id:b3:9fq2m4x7...,
    device_key: ed25519:c3a81f...,
    revoked_at: ...,
    reason:     "lost device",
    signature_by_root
}
```

Rotating the root key itself:

```text
KeyRotated {
    identity:     id:b3:9fq2m4x7...,
    old_root:     ed25519:...,
    new_root:     ed25519:...,
    effective_at: ...,
    signature_by_old_root
}
```

Revocation is **not retroactive by default**. Objects signed by a device key
before its `revoked_at` remain valid, because retroactively invalidating them
would erase history that a compromised device did not actually forge — including
the victim's own past posts. A revocation may set `invalidate_from` to an earlier
timestamp when the owner believes the key was compromised before it was noticed;
nodes then re-evaluate objects in that window.

## 5.5 Recovery

Every recovery path is an attack path. A mechanism that restores control without
the root key is, by construction, a mechanism someone else can use to take
control. The design below buys a specific attack in exchange for refusing a
specific failure, and says which.

It is also shaped by a constraint particular to this network: **there is no
authority to adjudicate.** Each node replays the key chain independently
(section 5.1), so if two validly-signed chains descend from one genesis object,
nodes reach different answers depending on what they have seen. The identity
forks, and two parties both *are* you to different halves of the network — which
is worse than losing it, because a dead identity is unambiguous and a forked one
is an impersonation engine.

So recovery must produce an outcome every honest node reaches independently,
with no consensus, no clock, and no liveness assumption.

### The recovery key

`identity create` generates a second Ed25519 key — the **recovery key** — named
in the genesis object alongside the root key. This is mandatory and cannot be
skipped. It belongs on paper or other cold media, never on the node.

It signs one thing:

```text
RootKeyReplaced {
    identity:        id:b3:9fq2m4x7...,
    new_root:        ed25519:...,
    invalidate_from: 2026-09-02T00:00:00Z,     # optional
    signature_by_recovery_key
}
```

Three rules make it work:

- **Recovery-signed objects outrank root-signed objects.** Always, by role,
  never by timestamp. Two competing chains are therefore ranked identically by
  every node, with no clock and no agreement. This is what buys fork-freedom.
- **The operational root cannot revoke or replace the recovery key.** Otherwise a
  thief revokes it first and the whole mechanism is theatre.
- **Only the current recovery key may replace itself**, via
  `RecoveryKeyReplaced`. Rotation without opening a path.

The payoff is that this handles *compromise*, which nothing else here does. A
thief with your root key rotates it to their own, grants themselves devices, and
signs as you. You surface with the paper backup, publish one `RootKeyReplaced`
with `invalidate_from` set before the theft, and their entire chain is void —
deterministically, on every node, whenever you get around to it.

You cannot lose that race, because there is no race.

### Succession

The recovery key does not help if both keys burned in the same fire. For that,
stop trying to recover the identity and make migration cheap instead, using the
trust graph that already exists.

```text
IdentitySuccession {
    predecessor: id:b3:<old>,
    successor:   id:b3:<new>,
    timestamp,
    signature
}
```

Two flavours, and the difference matters:

**Voluntary** — signed by the predecessor's recovery key, or by its root key.
Recovery-signed succession is final. Root-signed succession is valid but
*voidable*, because the root is a warm key and should not be able to give your
identity away irreversibly: a later recovery-signed `RootKeyReplaced` or
`SuccessionRevoked` annuls it, and nodes replaying the chain simply arrive at a
different answer. This is what stops a thief with your root key from walking your
social graph over to an identity they control.

**Attested** — signed by a contact of the predecessor, asserting that the
successor is the same person. Each contact verifies you the way section 13
already assumes they can: they have met you, they hold your fingerprint, they can
telephone you.

Attested succession makes **no global truth claim**. It is evaluated per
observer, exactly like the signed introductions of section 13.1. Nodes that trust
your contacts follow it; nodes that do not, do not. There is nothing to fork over
because there was never a single contested answer — and it adds no attack surface
to the old identity, since an attacker would have to convince your friends out of
band that they are you. That is social engineering, which no cryptography has
ever fixed.

Succession does not restore your message history. Anything sealed to a dead epoch
key is gone permanently (section 8.1). Your old posts keep their old attribution,
which is correct — that identity did sign them.

### The floor

```text
root key and recovery key both lost, or both stolen
    -> the identity is gone
```

There is no mechanism for this, and none will be added. It is written here
plainly because a recovery story people over-trust is worse than one they
understand.

### What was rejected

**`k`-of-`n` social recovery.** A quorum of `k` colluding delegates would own you
permanently; the delegate set rots as delegates lose their own identities, which
is the same problem recursively; and updating the set has no safe answer — if the
root may change delegates then a thief closes the door behind them, and if it may
not, the set is frozen for life.

**Time-locked recovery with a veto window.** Requires agreement on elapsed time
and on the *absence* of a veto, both of which section 3.5 disclaims. A node
offline for forty days sees the recovery complete while its peer saw the veto:
guaranteed fork. And a thief holding the root vetoes forever, which deadlocks.

**Community reassertion.** Only true inside one community, which is a fork by
design, and it hands community administrators power over member identity —
inverting the separation section 12 is careful to draw.

See D11.

---

## 5.6 Identity state distribution

Four separate mechanisms need the same thing and none of them had a way to get
it: a sender needs an identity's current encryption keys (8.1), a sender needs
its reachability (5.7), a directory lookup needs its key chain, and a carrier
needs its key chain to authenticate an inbox query (15.4).

What has to travel splits into two halves with opposite requirements. Trying to
serve both with one mechanism is why neither fitted D5's journal model.

### The chain: complete, ordered, never pruned

`IdentityCreated`, `DeviceKeyGranted`, `DeviceKeyRevoked`, `KeyRotated`,
`RootKeyReplaced`, `RecoveryKeyReplaced`, `IdentitySuccession`. All of it, in
order, or nothing verifies. It is also tiny — a few dozen objects over a
lifetime.

**Its distribution is already solved and needs no new mechanism.** To verify any
object a node must replay its author's key chain (3.3), so any node holding an
object necessarily holds enough chain to verify it. This is promoted from an
accident to a rule:

> **Chain invariant.** A node that serves an object must be able to serve its
> author's key chain up to that object's timestamp.

That replaces section 16's vague "replicate wherever the identity is known" with
something enforceable.

### Current state: latest-wins, aggressively pruned

`EpochPrekey`, `ReachabilityClaim`, `IdentityProfile`. Nobody ever wants the
history: an expired prekey is garbage and last year's carrier is noise. This is
a **snapshot fetch, not a journal** — no cursor, no ordering, no session state:

```text
A -> B   current id:b3:9fq2...
B -> A   chain tip
         + unexpired EpochPrekeys (all devices)
         + latest ReachabilityClaim
         + IdentityProfile
         + valid_until
```

Roughly 14 KB for a three-device identity at six weeks of prekey coverage.

### The snapshot carries its own expiry

The snapshot has a `valid_until` — 30 days by default — covering everything
inside it: carriers, device list, prekeys. Past that date a client refuses to
use it and refetches.

**Freshness is a property of the snapshot, not a consequence of running out of
prekeys.** Section 8.1 currently leaks freshness by accident: a sender with a
stale profile exhausts the prekeys it holds and falls back. That signal
disappears entirely if lookahead is increased (section 37), so it must not be
load-bearing. A client displays *"your view of this identity is 41 days old"*
rather than silently degrading.

### Who holds it

- **Carriers**, as an obligation of `CarriageAccepted` (5.7). A carrier needs the
  chain anyway to authenticate inbox queries, so it is holding most of it
  regardless.
- **Contacts**, refreshed on sync. This is what keeps prekeys fresh between
  people who actually correspond.
- **Any node that has ever fetched it**, since every object in the snapshot is
  self-signed and a stranger's cached copy is exactly as trustworthy as the
  origin's.

That last property is what makes the whole thing cheap: the snapshot may be
served by anyone, cached by anyone, and relayed through anyone, because nothing
in it can be forged by a holder. A holder can only **withhold**.

### Bootstrapping, in order of likelihood

1. **Already held** — any prior contact, or a cached fetch.
2. **Ask configured peers**: `resolve id:b3:9fq2...`, **one hop, never
   forwarded**. Whoever has it answers. Forwarding this query would build a DHT:
   every node would learn who is asking about whom, and the query would be
   floodable. One hop keeps it a cache lookup.
3. **Reverse path** — the node knows which peer handed it the post that carried
   the identity. Ask that peer (17.1).
4. **First contact carries it** — a `ContactRequest` includes the sender's own
   snapshot, so replying never requires a lookup.

**Resolution is by exact identity, never by search.** There is no query that
enumerates identities, and none will be added: a searchable directory of people
is an address harvester and a surveillance tool, and the spam model of section 14
assumes unknown identities cannot cheaply find a target. Resolving an ID already
held reveals nothing, because the asker must already possess the 32-byte name.

### What this costs

- **The snapshot is world-readable.** Device count, carrier list, and — because
  prekeys are published on a schedule — a liveness signal. Anyone may poll it.
  There is no fix compatible with letting strangers encrypt to you; it belongs
  in section 8.2 beside the metadata concession.
- **Withholding is the real attack, and it is the `fs: none` downgrade.** A
  carrier that quietly stops serving fresh prekeys pushes every sender onto the
  long-term identity key. Mitigated by publishing far enough ahead that
  withholding must be sustained for weeks, and by surfacing snapshot age in the
  client. Not eliminated.
- **A cold ID from a stranger may be unresolvable.** If none of the four paths
  above reaches it, the identity cannot be contacted in v1. See section 37.

See D12.

---

## 5.7 Reachability and carriage

Identity and reachability are separate (5.3). The binding between them is two
objects, and both are required.

### The identity claims

```text
ReachabilityClaim {
    identity:   id:b3:9fq2...,
    via:        [ node:ams-hub (cost 1), node:gosub-hub (cost 3) ],
    expires_at: ...,
    signature_by_device_key
}
```

This is **not** a `RouteAdvertisement`, and conflating the two is an error:

| | `RouteAdvertisement` (17.1) | `ReachabilityClaim` |
|---|---|---|
| Signed by | a peer, about third parties | the identity, about itself |
| Forgeable | yes — this is route poisoning | no |
| Propagation | one hop, never forwarded | replicates freely, in the snapshot |

D6's paranoia is entirely about third-party assertions. A self-signed claim can
poison nobody but its own author, whose worst outcome is directing their own
mail at a node that drops it. It is therefore safe to propagate without policy,
which is what makes 5.6 work: a sender does not have to *ask* anyone, only to
*hold* the object.

### The carrier consents

A claim alone is not actionable. Without a counter-signature, any identity could
name any node and aim the network at it — reflection, with the target chosen by
the attacker. Local policy at the victim is not sufficient: dropping unwanted
spool traffic still means the traffic arrived.

```text
CarriageAccepted {
    carrier:    node:ams-hub,
    identity:   id:b3:9fq2...,
    expires_at: ...,
    signature_by_carrier_device_key
}
```

**A sender routes toward a carrier only when both objects are present and
current.** Neither party can bind alone — the same shape as the name binding in
5.2.

Accepting carriage obliges the carrier to spool `inbox:id:b3:...` and to serve
that identity's snapshot (5.6). It obliges nothing else, and is revocable by
expiry.

### Always list two carriers

A single carrier is the configuration that turns a node outage into an identity
outage, and it is what people will choose by default because it is simpler.

With two listed, a carrier disappearing is an inconvenience: senders holding the
snapshot already know the second address and fail over on timeout (20.4), with
nothing to update and nothing to look up. **The second carrier must be listed
before the outage** — that is the entire mechanism.

Carriers must be independently operated. Two machines at one provider, on one
account, are one carrier with extra steps.

### Carriers may sync an inbox between themselves

Two carriers named in the same current `ReachabilityClaim` may replicate that
identity's `inbox:` stream to each other, as an ordinary stream sync (D5).

This is better than sender-side fan-out: it does not double every sender's
traffic, and it repairs *backwards* — objects that reached ams-hub before it
died are already at gosub-hub. Deduplication is free by content address.

Two constraints:

- **A carrier accepts inbox objects from another carrier only for identities for
  which it independently holds a valid `CarriageAccepted`.** Without this the
  mechanism is an open relay: anyone could name a node in a claim and push
  traffic through it.
- **Each carrier is a full copy of the identity's metadata**, not an extra
  chance of exposure. Redundancy here is not free; it is paid in traffic-graph
  copies.

Normal sending is to the lowest-cost carrier only. Fan-out happens on timeout,
not by default.

### Migration

Moving carriers changes no identity, no name, and nothing held by any
correspondent. It is not instant, and the overlap is the delicate part.

```text
1. publish a snapshot listing BOTH carriers, new one at lower cost
2. push it to peers, contacts, and both carriers — not to one place
3. keep collecting from the old carrier until its traffic stops
4. publish a snapshot listing the new carrier only
5. release carriage at the old carrier
```

The snapshot's `valid_until` is what bounds the tail: after that date no
correspondent is using a stale copy, because their client refuses to.

Failure modes, none of which are eliminated:

- **Cut over too early and mail is lost silently.** The old carrier no longer
  spools, the object expires at some intermediate node, and no bounce is
  generated (section 16). The sender learns only from a local timeout.
- **Uncollected spool at the old carrier is stranded.** Sync once more before
  releasing.
- **A hostile old carrier can serve a stale snapshot for one `valid_until`.** It
  cannot forge a new one. Short expiry bounds the damage; asking several peers
  routes around it.
- **Both carriers dying at once** requires publishing a new snapshot and waiting
  for it to spread — days, not seconds. There is no fast path without a global
  directory, and there will not be one.

`nodectl carrier move <new>` should perform the whole sequence. Performed by
hand in the wrong order, it loses mail.

See D13.

---

# 6. Public Communication: Areas / Echoes

Public discussion should use replicated **areas** or **echoes**.

Examples:

```text
TECH.RUST
TECH.BROWSERS
LOCAL.NETHERLANDS
GOSUB.DEV
GOSUB.SECURITY
RETRO.C64
```

A URI-like notation could be:

```text
echo://TECH.RUST
echo://GOSUB.DEV
```

Nodes subscribe to selected areas.

Posts propagate through subscribed peers.

Example:

```text
                 TECH.RUST

Amsterdam ────── Berlin ───── Helsinki
     │             │
     │             └──── London
     │
     └──── Utrecht ───── Home node
```

A public post is normally:

- signed
- not encrypted
- immutable
- content-addressed

---

# 7. Threading

Threading should be explicit rather than reconstructed from email headers.

Example message metadata:

```text
parent: obj:45f1...
thread: obj:102a...
```

A root post may set:

```text
thread = self
parent = null
```

Replies point to:

- the immediate parent
- the root thread

This makes threaded conversation deterministic.

---

# 8. Private Messaging

A private message is a signed object carrying an encrypted payload.

```text
DirectMessage {
    version:       1,
    type:          "direct-message",
    author:        id:b3:<alice genesis>,
    signing_key:   ed25519:<alice device key>,
    recipient:     id:b3:<bob genesis>,
    timestamp:     ...,
    sequence:      ...,
    suite:         1,
    ephemeral_key: x25519:<one-shot public key>,
    recipients: [
        { device: ed25519:<bob laptop>, epoch: 118,        wrapped_key: <...> },
        { device: ed25519:<bob phone>,  epoch: 118,        wrapped_key: <...> },
        { device: ed25519:<alice phone>, epoch: 204,       wrapped_key: <...> }
    ],
    fs:            "epoch",          # weakest entry; "none" if any fell back
    payload:       <AEAD ciphertext under the content key>,
    signature:     ...
}
```

The payload is encrypted once. The content key that opens it is wrapped
separately for each of the recipient's devices, and usually for the sender's own
devices too, so a sent message is readable everywhere the sender reads mail. An
entry whose `epoch` is `"identity"` rather than a number is the fallback of
section 8.1, and drags the envelope's `fs` down to `"none"`.

---

## 8.1 Epoch prekeys

Each of an identity's devices publishes its own rolling series of prekeys,
signed by that device's key under a `publish-prekeys` capability (section 5.4):

```text
EpochPrekey {
    epoch:       118,
    identity:    id:b3:9fq2m4x7...,
    device:      ed25519:c3a81f...,          # whose key this is
    public_key:  x25519:...,
    valid_until: 2026-10-16T00:00:00Z,       # when the private half is destroyed
    signature_by_device
}
```

One epoch per day, published several epochs ahead so a sender always has a
current one to hand. The sender selects by wall clock rather than by choice,
which is the property that makes this scale: nothing is consumed, so nothing
collides and nothing runs out — at ten correspondents or ten thousand.

**Prekeys are signed by a device key, not by the root key.** A prekey is
published daily, and a key used daily is not cold; having the root sign them
would contradict section 5.4's requirement that it live offline. The exposure
this accepts — a compromised device can publish prekeys whose private half the
attacker holds — is an ordinary device compromise, already in the threat model
and already revocable.

### Fan-out across devices

Because prekeys are per-device, a sender seals to **every currently valid device**
of the recipient:

```text
recipients: [
    { device: ed25519:<bob laptop>, epoch: 118, wrapped_key: <...> },
    { device: ed25519:<bob phone>,  epoch: 118, wrapped_key: <...> }
]
```

The payload is encrypted once under a content key `CK`. For each recipient device
the sender derives a wrapping key and wraps `CK`:

```text
kek         = HKDF-SHA256(DH(EK, EpochPrekey_device), salt, info)
wrapped_key = AEAD(kek, CK)
```

`EK` is a single one-shot ephemeral X25519 key, shared across all entries and
destroyed immediately after use. `info` binds the protocol version, both
identities, the target device, and the epoch number.

The alternative — one identity-wide prekey shared between devices — would require
synchronising private keys between your own machines, and would make one device's
compromise everyone's. Fan-out costs a few dozen bytes per device, gives each
device independent forward secrecy, and needs no secret to travel between them.

A sender normally includes their own devices among the recipients, so their sent
messages are readable on all of them. A device added later cannot read older
messages, which is a consequence of forward secrecy rather than a defect.

The payload is sealed with ChaCha20-Poly1305, using the canonical encoding of the
object header as associated data, so a relay cannot lift the ciphertext and
re-attribute it to a different sender or recipient.

The finished object is signed by the sender's device key. Authorship comes from
that signature, which is why no authenticated key-exchange mode is needed: the
extra Diffie-Hellman terms in a scheme like X3DH exist to prove who the sender
is, and a signature already does that.

Signing and key agreement always use separate keys. Ed25519 keys are never
converted to X25519 keys via the birational map.

### Two clocks

`valid_until` is `epoch_end + W`, where `W` is the recipient's configured
retention window — thirty days by default. The private half is destroyed then,
and **that destruction is the forward secrecy**. There is no ratchet and no
handshake.

```text
day 0    epoch key 118 published, current
day 1    epoch ends; 119 becomes current, but 118 still decrypts
day 31   private half of 118 destroyed          <- the deadline
```

The clock starts when the key was minted, not when a message was sent. A sender
who has not synced in three weeks holds a key with nine days left on it, and
consumes the remaining budget before pressing send. `valid_until` is published in
the object precisely so the sender can see this and decide.

`W` is per-node configuration. It must exceed worst-case replication lag plus
worst-case delivery delay. Thirty days is generous for anything on a network, and
possibly too tight for two air-gapped nodes trading removable media quarterly.

### Fallback

When every epoch prekey a sender holds has passed `valid_until`, the sender may
encrypt to the recipient's long-term X25519 identity key from the genesis object.
The message then carries `fs: none`, and **both clients display it as not forward
secret**.

This keeps offline-first intact when contacting someone whose profile has not
been refreshed in months, and makes the degradation visible rather than silent.

### Why there are no one-time prekeys

X3DH uses one-time prekeys, and an earlier draft of this document did too. They
do not work here.

One-time prekeys require a trusted dispenser that hands each sender a distinct
key and deletes it. Pigeonnet has no such component by design: a prekey bundle is
a replicated object, so every sender holds the entire pool and picks from it.

With a pool of `N` and `k` senders choosing at random, a collision appears with
probability roughly `1 - e^(-k²/2N)` — about 50% at twelve senders against a
hundred keys. Since the recipient destroys the key on first use, every other
message sealed to that key is permanently lost.

Reordering breaks it even for a single sender:

```text
T+0    Alice sends msg1 with prekey 41  ->  stuck behind a down hub
T+1h   Alice sends msg2 with prekey 41  ->  arrives, decrypted, 41 destroyed
T+3d   msg1 arrives                     ->  undecryptable, permanently
```

Destroy-on-first-use presumes ordered delivery. Section 18 guarantees the
opposite. Exhaustion was never the real problem.

---

## 8.2 What this protects, and what it does not

Provided:

- confidentiality against relays, and against everyone but the recipient
- authenticity and integrity of authorship
- forward secrecy bounded by the epoch schedule — a message becomes
  unrecoverable by anyone, including every relay that archived it, at its
  epoch's `valid_until`
- fully offline delivery — the recipient need never be online while sending

**Not** provided, and this must reach user-facing documentation rather than
living only here:

- **Immediate forward secrecy.** The guarantee is *within about a month*, not
  *at once*. Until `valid_until`, the message's secrecy rests on a key on the
  recipient's disk, protected by encryption at rest (section 25.1).
- **Any forward secrecy for `fs: none` messages.** The fallback trades it for
  delivery, visibly.
- **Post-compromise security.** A stolen device key decrypts future messages
  until it is revoked and the identity's keys rotate. Because prekeys are
  per-device, this exposes what that device could read, not what the identity
  as a whole could.
- **Metadata privacy.** `author` and `recipient` are cleartext by necessity —
  relays route on them. Timing, size, and frequency are visible too.
- **Anything against a live compromise of a running node**, where the store is
  unlocked and plaintext is in memory. See section 29.

Group and community encryption is out of scope for v1. Public echoes are signed
and not encrypted (section 6). If encrypted communities are added later, MLS is
the intended path; a bespoke group scheme must not be invented.

A message arriving after `valid_until` cannot be read — but it fails loudly
rather than silently. See section 20.

See D4, D9.

---

## 8.3 Relay behavior

A relay stores and forwards a private message without reading its payload.

```text
Joshua
   ↓
Home node
   ↓
Amsterdam hub
   ↓
Frankfurt hub
   ↓
Alice's server
   ↓
Alice's laptop
```

Intermediate nodes need only the routing metadata required for delivery:
`recipient`, plus the envelope fields of section 16.

---

## 8.4 Possible future privacy enhancement

A later version could add:

- onion-style routing
- sealed recipient metadata
- anonymous reply blocks
- metadata-resistant relay paths

These are not required for the first version, and section 8.2 is honest that v1
does not have them.

---

# 9. Files as First-Class Objects

Files are not attachments. They are content-addressed objects.

Because object IDs are BLAKE3 (section 3.2), and BLAKE3 is itself a Merkle tree
over its input, a file needs no hand-written chunk list. **The hash is the tree.**

```text
FileManifest {
    root:       b3:9c41f0a2...,      # BLAKE3 root hash of the file contents
    size:       48213712,
    media_type: "application/zstd",
    name:       "gosub-0.3.1.tar.zst",
    signature:  ...
}
```

A post references a file by its root hash:

```text
Here's Gosub 0.3.1:

file:b3:9c41f0a2...
```

Chunks are fetched by position and verified against the root incrementally: a
node can accept, verify, and write out a single chunk without holding the whole
file and without trusting the sender. A transfer interrupted at 60% resumes at
60%, from a different peer if necessary.

This gives:

- deduplication — identical bytes have identical roots, network-wide
- caching and mirroring by any node, trusted or not
- resumable transfer
- integrity verification per chunk rather than per file
- efficient distribution to many recipients

A `FileManifest` is a small signed object and replicates like any other. The
bytes themselves are fetched on demand, or eagerly by file-echo mirrors
(section 10).

See D1.

---

# 10. File Echoes

The system can support FidoNet-inspired **FileEchos**.

Examples:

```text
files://GOSUB.RELEASES
files://LINUX.RUST
files://RETRO.C64
```

A node subscribing to a file area can automatically mirror newly published files.

This creates a simple decentralized software or media distribution mechanism.

---

# 11. Communities

A community is a signed namespace containing communication areas, file areas, membership, roles, and policy.

Example:

```text
community:gosub

channels:
    announcements
    development
    security
    random

files:
    releases
    nightly
    documentation

members:
    Joshua
    Alice
    Bob
```

Communities are themselves represented through signed objects.

---

## 11.1 Membership

Membership can be represented as signed events.

Example:

```text
CommunityMemberAdded {
    community: "gosub",
    identity: "pubkey:xyz",
    role: "developer",
    issued_by: "admin-key"
}
```

Revocation should likewise be an object:

```text
CommunityMemberRemoved {
    community: "gosub",
    identity: "pubkey:xyz",
    issued_by: "admin-key"
}
```

---

## 11.2 Roles

Possible roles include:

- owner
- administrator
- moderator
- member
- publisher
- mirror

Role semantics belong to the community policy.

---

# 12. Moderation

Moderation should not require deletion of replicated history.

A moderation event can state that a community considers an object hidden or invalid.

Example:

```text
ModerationAction {
    community: "gosub",
    action: "hide-object",
    object: "obj:abc123",
    reason: "spam",
    signed_by: "moderator-key"
}
```

This separates:

```text
content exists
```

from:

```text
this community displays it
```

Individual nodes may choose whether to honor community moderation objects.

This permits:

- local policy
- community policy
- federation without universal censorship authority

---

# 13. Trust Model

The network should not require a single global PKI.

Possible trust sources include:

- direct key verification
- QR code exchange
- fingerprints
- signed introductions
- community directories
- local trust configuration
- optional external verification

Example fingerprint:

```text
B2A7 F912 02DE 8B41
91CD 772A D15F F821
```

---

## 13.1 Signed introductions

One identity can assert another identity.

Example:

```text
Joshua signs:

"public key ABCD belongs to Alice"
```

This can form a lightweight trust graph.

The system should avoid reproducing the complexity of traditional PGP web-of-trust interfaces.

Trust decisions should remain understandable to users.

---

# 14. Spam Resistance

The network must not let every identity in the world deliver unlimited
unsolicited private traffic.

Inbound policy is local. Every mechanism below is enforceable by the receiving
node alone, with no coordination and no agreement from anyone else.

---

## 14.1 Default inbound policy

```text
accept direct messages from:
    contacts
    friends-of-friends (depth 1)
    holders of a valid invitation token
    members of communities I have opted into

everyone else:
    one rate-limited ContactRequest, and nothing more
```

---

## 14.2 Trust graph gating

Signed introductions (section 13.1) form the graph. Direct contacts and depth-1
friends-of-friends pass by default.

Depth is capped at 1 deliberately. Beyond that the reachable set grows to most of
the network and stops being a filter at all.

---

## 14.3 Invitation tokens

An identity may issue signed, single-use, expiring tokens:

```text
InvitationToken {
    issuer:       id:b3:...,
    token_id:     ...,
    capabilities: [contact],
    expires_at:   ...,
    signature
}
```

Joshua grants Alice 20 tokens; Alice may use them to introduce 20 identities.
Redeeming one grants the sender contact status, subject to the recipient's local
policy.

This creates scarcity around unsolicited access without charging ordinary users
per message. Tokens are traceable to their issuer, so an issuer who hands them to
spammers can be discounted wholesale.

---

## 14.4 Contact requests

An unknown sender may deliver one `ContactRequest` per recipient per period:
size-capped, rate-limited at every relay along the path, and carrying nothing but
a short introduction. Nothing else from an unknown sender is accepted.

A `ContactRequest` may carry an optional proof-of-work field. Its computation and
verification are specified so that a node **may** require one. No node is obliged
to produce one, and no node may assume its peers demand it.

---

## 14.5 Quotas

The per-peer quotas and rate limits of section 30 apply underneath all of the
above, independent of trust. A trusted contact can still exceed a quota.

---

## 14.6 Explicitly rejected

**Postage tokens** and **global reputation** both require network-wide agreement
on value or on scoring, which contradicts section 2. Community-scoped reputation
remains possible as local policy, but is not part of the protocol.

See D7.

---

# 15. Replication

Replication is the heart of the system.

---

## 15.1 Journals and cursors

Each node keeps an append-only **journal** per replication stream — one per echo
area, one per file area, one per local identity inbox:

```text
(local_seq, object_id)
```

`local_seq` is node-local. It is never replicated as meaning; it is a cursor
anchor, not a claim about ordering in the world.

A sync is then:

```text
Node A -> Node B

A: stream echo://GOSUB.DEV, everything after cursor 4127
B: 4128..4193 -> [obj:b3:..., obj:b3:..., ...]
A: I lack 6 of those -> [obj:b3:..., ...]
B: <object bytes>
A: cursor for (B, echo://GOSUB.DEV) := 4193
```

Cursors are stored per `(peer, stream)`. Cost is proportional to what is new, not
to what is already known.

The naive alternative — each side sending its full object list — is O(total
objects) per sync. On the hardware this document targets, syncing once a day
against years of accumulated history, that is the difference between a working
node and an unusable one. Journals with high-water-mark cursors are the NNTP and
FidoNet model, and they are both simpler to implement *and* cheaper to run.

---

## 15.2 Repair

Cursors can be lost, corrupted, or distrusted. For that case there is a bounded
**inventory exchange**: both sides list object IDs within an explicit range and
reconcile the difference directly.

It is a repair tool, not the normal path.

---

## 15.3 Later

Capability negotiation is present from the first release (section 31), so Merkle
range reconciliation, bloom filters, or compact set reconciliation can be added
later as additional stream types without a flag day.

They stay deferred until measurement shows journals are the bottleneck.

---

## 15.4 Stream access classes

There is no account, no registration, and no acceptance step to read from a
node. A node answers whoever connects, subject only to its own quotas. What
gates a query is the **class of stream**, not the identity of the asker:

| Stream | Who may query |
|---|---|
| `echo://…` public areas | anyone |
| `files://…` manifests and chunks | anyone |
| `current id:b3:…` identity snapshots (5.6) | anyone |
| `inbox:id:b3:X` | X alone, proving it |
| closed community areas | members, proving it |

A brand-new identity nobody has heard of can pull an area, read years of
history, fetch a file, and leave. **The network must be readable before anyone
has a reason to join it.**

The asymmetry matters: an inbox stream open to all peers would make any
identity's complete correspondence graph — senders, sizes, timing — globally
fetchable from any carrier in the world. So the inbox query, and a closed-area
query, carry a device-key signature over a nonce supplied by the serving node.
Public streams carry nothing.

Three gates are easy to conflate, and none of them is "may I read this node":

- `peer add` — the asker's decision about whom *it* talks to. The peer does not
  consent to being peered with; it answers or it does not.
- `contact accept` — who may place objects in an inbox (section 14). Unrelated
  to reading.
- community membership — closed areas only.

**A node is never obliged.** Quotas are local policy (section 30), so serving
public echoes only to configured peers, throttling strangers, or refusing
unknown connections entirely is legitimate — a home node on a domestic line
probably should. "Anyone may ask" and "the node may decline" are both true.

Two consequences worth stating in user-facing documentation:

- **Public is permanent and global.** Every echo post is fetchable by any
  stranger, from any node that kept it, with its author cryptographically
  attached, with no deletion (section 21). That is a stronger exposure than email
  intuitions carry over.
- **A closed area limits distribution, never disclosure.** Nothing prevents a
  member republishing its contents into an open one, and nothing can.

See D15.

See D5.

---

# 16. Object Routing

Propagation policy is a function of object class.

| Object class | Propagation |
|---|---|
| Echo post | pulled by peers subscribed to that area |
| File manifest | replicate to subscribers of the file area |
| File chunks | fetched on demand; mirrors may prefetch |
| Direct message | forward along the best known route toward the recipient |
| Community membership | replicate to community participants |
| Key management | replicate wherever the identity is known |
| Route advertisement | one hop only, never forwarded |

Echo propagation is **pull-based**: a subscriber asks each peer what it holds in
an area after the subscriber's own cursor, and fetches only what it lacks (§15).
Nothing is pushed.

That removes the need for loop suppression rather than solving it. A cycle in the
peer graph has no fuel: a node offered the same object by two peers fetches its
bytes once, because content addressing makes deduplication free, and asks for
nothing on later passes because its cursor has already moved. A redundant edge
costs a list of identifiers, not a storm.

Loop suppression does apply to **directed forwarding**, where a node genuinely
pushes an object along a route toward a recipient. There a bounded `seen_by` node
list and a hop ceiling are used, after FidoNet's `SEEN-BY` and `PATH`.

**`seen_by` travels in the unsigned transfer envelope, never inside the signed
object.** Putting it in the object would change the object's ID at every hop,
which would destroy deduplication, break every existing reference to it, and
invalidate the author's signature.

Direct messages carry a hop ceiling and a TTL. An undeliverable message expires
silently at whichever node is holding it. **No bounce object is generated** — a
bounce is a mailbox concept (section 35), and generating one would turn every
relay into a source of unsolicited, attacker-steerable traffic aimed at a forged
sender.

See D6.

---

# 17. Routing

Routing is separate from identity. An identity is a name; a route is a guess
about where that name can currently be reached.

Routing tables hold:

```text
identity -> peer(s), cost, expiry
area     -> subscribed peer(s)
file     -> known cache(s)
```

For example:

```text
id:b3:9fq2m4x7... -> peer:ams-hub (cost 2, expires 12:40)
echo:GOSUB.DEV    -> peer:eu-hub, peer:home42
file:b3:9c41f0a2  -> peer:mirror3
```

---

## 17.1 Where routes come from

Two questions are routinely conflated and have different answers:

```text
where is node:ams-hub          -> an address. Static config, or 17.4 discovery.
where is id:b3:9fq2...         -> a carrier. The identity's own claim (5.7).
```

Neither is a routing protocol. **There is no discovery of paths, no distributed
table, and no mechanism that will find a route where none is configured or
claimed.** The reachable set is the operator's neighbourhood, not the world.
This is a consequence of refusing both a global authority (section 2) and a DHT
(below), and it is a real limit rather than an omission.

Route sources in v1, in decreasing authority:

**Static configuration.** Peers configured by the operator.

**Reachability claims.** An identity's own self-signed statement of its carriers
(5.7), obtained with its snapshot (5.6). This is how an identity is located; a
route advertisement is not.

**Signed route advertisements**, from configured peers, for reaching *nodes*:

```text
RouteAdvertisement {
    target:     id:b3:... | echo:... | file:b3:...,
    via:        node:ams-hub,
    cost:       2,
    expires_at: ...,          # short, absolute
    signature
}
```

---

## 17.2 Advertisement policy

Section 29 lists route poisoning as an expected attacker capability, and a node
that accepts unsolicited advertisements from strangers is trivially poisoned. The
rules are therefore strict:

- Advertisements are accepted **only** from directly configured peers.
- They are accepted **only** for targets inside a configured scope.
- They **never** override a static route.
- They expire on an absolute timestamp, and are not refreshed by use.
- They are ranked hints. A node is always free to ignore them.

Advertisements are not forwarded. Learning a route means learning it, one hop
away, from a peer already chosen and trusted for routing.

**Reverse-path hints.** When an object arrives, the node knows which peer handed
it over. That peer is a usable hint for reaching the object's author or its
carrier — ranked below everything else, expiring quickly, never overriding a
static route or a reachability claim. Without it, "reply to someone read in an
echo" does not work at all, which is the single most common way a contact begins
(5.6).

---

## 17.3 Deferred

Distributed discovery, community-scoped directories, and the multi-path or onion
routing of section 8.4 are out of scope for v1.

There is no global routing authority, and adding one would contradict section 2.

---

## 17.4 Node discovery

Addresses of *nodes* — not identities, and not people — may be discovered, and
this is safe in a way BGP-style advertisement is not.

```text
NodeProfile {
    node:        node:ams-hub,          # the node's own identity
    addresses:   [ tcp://node.example.net:4137 ],
    carries:     [ echo://GOSUB.DEV, files://GOSUB.RELEASES ],
    policy:      { spools_for: "members of community:gosub",
                   accepts_unknown_peers: true },
    expires_at:  ...,
    signature_by_node_device_key
}
```

**Publishing and relaying are different verbs.** A node signs its own profile;
anyone may relay that profile onward. Relaying is *carrying*, not *asserting* —
a relayed profile cannot be tampered with, and a false one is self-correcting,
because connecting to the address either produces the claimed node identity or
does not. This is the property BGP lacks, and it is why gossiping profiles does
not reproduce BGP's failure modes.

**Accepting a profile is passive.** It enters a local candidate table. It changes
no routing, adds no peer, and stores nothing on anyone's behalf. `peer add`
remains a command the operator types. Nobody can announce *at* a node; anyone may
announce *into the commons*.

**Publication is opt-in, and leaf nodes never appear.** Silence is the default.
A leaf that ends up in the global table receives connection attempts from
strangers forever.

### Quality is measured locally and never shared

```text
node:ams-hub    addr node.example.net:4137
                last ok 2026-09-16 08:12   latency 40ms
                attempts 412  failures 3
                relayed_via peer:eu-hub    first seen 2026-03-02
```

Everything below the address is local measurement, and none of it is replicated.
A shared score would be a global consensus artifact, which section 2 refuses,
and it would also be wrong: "fast" has a different answer in Utrecht than in
Sydney, and a node down for one observer may be healthy for another. **Gossip
addresses; measure quality; never relay quality.**

- **Rank unknowns by provenance.** A fresh entry has no measurements attached,
  which is exactly when junk arrives. `relayed_via` is the only signal available
  at that moment: a profile that came through a deliberately chosen peer
  outranks one that appeared from nowhere. Cap profiles accepted per peer per
  sync, so a peer relaying garbage has its whole batch discounted — which makes
  relaying garbage costly to the relayer.
- **Decay, do not blacklist.** Nodes go down for a week and return. Scores fade
  toward neutral with age; a single failure never evicts.
- **Address and identity stay separate.** A profile binds a node *identity* to an
  address, and the node proves that identity on connect before anything else
  happens. A stale or hijacked address therefore yields a failed handshake, not a
  hostile peer. Addresses may be wrong; identities may not.

### Why not a nodelist

A signed, curated nodelist file distributed through a file echo (section 10) is
the FidoNet answer and remains a perfectly good option — competing lists are
fine, since a list is a hint. It needs a maintainer, which is a social
institution, and FidoNet's died of exactly that. Gossiped self-signed profiles
obtain the same result with no institution, at the cost of admitting junk that
must be scored away.

The open area carrying profiles inherits the public-echo spam problem in a
consequential place (section 37).

See D14.

See D6.

---

# 18. Store-and-Forward Operation

A node may periodically contact a peer.

Example:

```text
10:00

node37 -> hub4

node37:
    "I have 42 new objects."

hub4:
    "I have 17 objects relevant to you."

exchange objects

disconnect
```

This should be a normal mode of operation.

Permanent sessions can also exist for low-latency use.

---

# 19. Bundle Format

A transport-independent bundle format would be useful.

Example:

```text
network-bundle-2026-09-16.pack
```

A bundle could contain:

- object manifests
- objects
- file chunks
- signatures
- optional routing hints
- acknowledgements

A bundle should be safely importable from untrusted media.

Potential uses:

- USB transfer
- air-gapped systems
- delayed network links
- disaster communication
- temporary physical synchronization

---

# 20. Delivery and Receipts

Delivery states:

```text
created
accepted-by-local-node
forwarded
arrived-at-recipient-node
read
undecryptable
```

Receipts are ordinary signed objects, not hidden server-side state.

```text
DeliveryReceipt {
    for_object: obj:b3:d41a99f2...,
    recipient:  id:b3:9fq2m4x7...,
    state:      "undecryptable",
    reason:     "epoch-key-expired",
    detail:     { epoch: 118, destroyed_at: ... },
    timestamp:  ...,
    signature
}
```

---

## 20.1 Failure receipts

When an object arrives and its signature verifies, but its payload cannot be
opened, the recipient emits an `undecryptable` receipt. Reasons include:

```text
epoch-key-expired      arrived after valid_until (section 8.1)
unknown-suite          suite not supported by this node
malformed-payload      decrypts, but the plaintext does not parse
```

A failure receipt **carries the recipient's current `EpochPrekey`**. One object
therefore both reports the failure and supplies what the sender needs in order to
retry, so the error heals in a single round trip — rather than sending the sender
off to re-sync a profile through the same slow path that caused the failure.

Clients should present it in terms the user can act on:

```text
message from alice, sent 2026-09-14, sealed to epoch key 118
(destroyed 2026-10-16) — cannot decrypt, arrived 4 days late
```

Not a decryption error. A silent failure here would repeat the mistake that
disqualified one-time prekeys (section 8.1).

---

## 20.2 This is not a bounce

Section 16 forbids relays from generating bounce objects, and that prohibition
stands. A failure receipt differs in every respect that made bounces dangerous:

| | Relay bounce (forbidden) | Failure receipt |
|---|---|---|
| Emitted by | a relay | the recipient |
| Sender authenticated | no | yes, signature verified |
| Provokable with a forged sender | yes | no |
| Amplification | possible | strictly 1:1 |

---

## 20.3 Constraints

- **Contact-gated.** Failure receipts go only to senders who have passed the
  gate of section 14. An unknown sender gets silence, because otherwise the
  receipt is a spam oracle — a probe confirming that a message reached a real and
  active identity.
- **Rate-limited** at ingest, under section 30.
- **Failure states default on; `read` stays opt-in.** A read receipt reveals
  user behaviour and should be a choice. "I could not open this" is not
  behavioural, and withholding it leaves the sender believing a message landed
  when it did not — strictly worse for both parties.
- **Senders keep an outbox.** Outbound plaintext is retained until a positive
  receipt arrives or a local timeout fires; you cannot resend what you have
  discarded. This is node-local state, not a mailbox on a server (section 35).

---

## 20.4 Silence remains ambiguous

Receipts cover only messages that arrived. A message that expired at a relay
three hops back produces nothing, because there is no authenticated party at the
far end to produce it, and section 16 refuses to let the relay invent one.

The recipient reports failures it witnessed. The sender resolves silence with a
local timeout — no receipt within `N` days, assume lost, tell the user.

That is weaker than SMTP appears to be, and about as strong as SMTP actually is.

See D10.

---

# 21. Deletion and Retraction

Because objects are replicated and immutable, true global deletion cannot be guaranteed.

Instead, an author can issue a signed retraction:

```text
MessageRetracted {
    target: "obj:abc123",
    author: "identity:alice",
    timestamp: "...",
    signature: "..."
}
```

Nodes may then hide the original object by default.

The distinction should be explicit:

- object removal from local storage
- author retraction
- moderation hiding
- cryptographic erasure of encrypted payloads

These are different operations.

---

# 22. Canonical Serialization

Signatures and content addressing both require that a logical object have exactly
one byte representation. Malleability — two encodings of the same value — means
two object IDs for one object, which breaks deduplication, threading, retraction,
and moderation simultaneously.

The wire format is **deterministic CBOR**, per RFC 8949 section 4.2.1.

Rules:

- Definite-length encoding only.
- Integers and lengths in shortest form.
- Struct fields are map entries with **integer** keys, assigned once and never
  reused. Renaming a field in code therefore cannot change the wire format.
- Map keys sorted bytewise by their encoded form. No duplicate keys.
- No floating point.
- No tags outside a closed registry.

---

## 22.1 The ingest rule

Every object arriving from anywhere — a peer, a bundle, removable media — is
subject to one mandatory check:

```text
decode(bytes)  -> value
encode(value)  -> bytes'
require bytes' == bytes
```

This runs **before** signature verification, and failure rejects the object
outright.

The point is structural. Without it, every decode path in the codebase carries a
standing obligation to reject non-canonical input, and a single oversight
anywhere reintroduces malleability everywhere. With it, that entire class of bug
lives in one function at the boundary.

Nodes store the original received bytes verbatim (section 25). Derived indexes
are rebuilt from those bytes, never from a re-serialization.

Canonical JSON appears only in debugging output and CLI display. It is never
hashed, never signed, and never sent to a peer.

See D2.

---

# 23. Example Base Object

Shown as JSON for readability. The wire encoding is deterministic CBOR with
integer keys (section 22).

```json
{
  "version": 1,
  "type": "echo-post",
  "author": "id:b3:9fq2m4x7...",
  "signing_key": "ed25519:c3a81f...",
  "created_at": "2026-09-16T10:00:00Z",
  "sequence": 1042,
  "body": {
    "area": "GOSUB.DEV",
    "thread": "obj:b3:...",
    "parent": "obj:b3:...",
    "content_type": "text/markdown",
    "content": "Hello world"
  },
  "signature": "..."
}
```

Notes:

- `author` is an identity — the ID of that person's genesis object — not a key.
- `signing_key` is the device key that produced `signature`. It must have been
  delegated by `author` and valid at `created_at` (section 5.4).
- `sequence` counts objects from `signing_key`, not from `author`.
- The object ID is BLAKE3 over the canonical encoding of everything **except**
  `signature`.

---

# 24. Example Object Types

The initial vocabulary. It should stay small.

Identity and keys:

```text
IdentityCreated          # genesis; its object ID is the identity
IdentityProfile
ReachabilityClaim
CarriageAccepted
NameClaim
NameGranted
KeyRotated
RootKeyReplaced
RecoveryKeyReplaced
DeviceKeyGranted
DeviceKeyRevoked
EpochPrekeyPublished
IdentitySuccession
SuccessionRevoked
EquivocationProof
```

Messaging:

```text
EchoPost
DirectMessage
ContactRequest
InvitationToken
Introduction
MessageRetracted
```

Files:

```text
FileManifest
FilePublished
```

Communities:

```text
CommunityCreated
CommunityMemberAdded
CommunityMemberRemoved
CommunityRoleGranted
CommunityRoleRevoked
ModerationAction
```

Network:

```text
RouteAdvertisement
NodeProfile
DeliveryReceipt
```

`PeerAnnouncement` is removed. It was never specified, and section 17.4's
self-signed `NodeProfile` covers the need without inventing a push channel for
"add me".

`FileChunk` is deliberately absent. Chunks are raw byte ranges verified against a
`FileManifest` root hash (section 9), not signed objects in their own right —
signing them would add a signature per kilobyte for no integrity gain.

---

# 25. Node Storage

SQLite is sufficient for an initial implementation.

Schema groups:

```text
objects
object_refs
peers
peer_state
subscriptions
identities
keys
epoch_prekeys
routes
files
file_chunks
communities
community_membership
receipts
journals
cursors
```

The object store preserves the original canonical serialized bytes (D2). Derived
indexes are rebuilt from those bytes, never from a re-serialization.

---

## 25.1 What is encrypted at rest

Not all of it, and the decomposition is worth stating:

| Group | At rest |
|---|---|
| `objects` holding public content — echo posts, file manifests | plain; the node is a mirror of public data |
| `objects` holding ciphertext relayed for others | already encrypted end to end |
| decrypted direct-message plaintext | encrypted under a local storage key |
| `keys`, `epoch_prekeys` | encrypted under an Argon2id passphrase key, always |

"Encrypt the database" is the wrong framing. Most of what a node stores is either
public, or is someone else's ciphertext. The sensitive surface is a keyring and a
plaintext cache.

Forward secrecy and encryption at rest defend different attackers, and the weaker
one sets the guarantee. Destroying epoch keys on a thirty-day schedule while the
decrypted archive sits readable on the same disk would be incoherent.

---

## 25.2 Two retention clocks

Object retention (D8) and key retention (D4) are independent, and both are local
policy:

```text
object retention    how long this node keeps objects at all
W                   how long this node keeps epoch prekey private halves
```

A node that has chosen cryptographic erasure keeps the ciphertext object long
after destroying the key that opens it. That is intentional: the object still
verifies, still replicates, and is still referenced by threads — it simply cannot
be read, by anyone, ever again.

See D9.

---

# 26. Local Node Architecture

A first implementation could use:

```text
                ┌───────────────┐
                │      CLI      │
                └───────┬───────┘
                        │
                ┌───────▼───────┐
                │   Node Core   │
                └───────┬───────┘
                        │
          ┌─────────────┼─────────────┐
          │             │             │
   ┌──────▼──────┐ ┌────▼────┐ ┌──────▼──────┐
   │ Object Store│ │ Routing │ │Replication  │
   └──────┬──────┘ └────┬────┘ └──────┬──────┘
          │              │             │
          └──────────────┼─────────────┘
                         │
                  ┌──────▼──────┐
                  │  Transport  │
                  └──────┬──────┘
                         │
                       Peer
```

---

# 27. Possible CLI

A proof-of-concept CLI might look like:

```bash
nodectl identity create
```

Add a peer:

```bash
nodectl peer add node.example.net:4137
```

Subscribe to an echo:

```bash
nodectl echo subscribe GOSUB.DEV
```

Post:

```bash
nodectl post GOSUB.DEV "Hello from the new network"
```

Send a private message:

```bash
nodectl message alice "Want to test file transfer?"
```

Publish a file:

```bash
nodectl file publish ./gosub.tar.zst
```

Synchronize:

```bash
nodectl sync
```

Inspect objects:

```bash
nodectl object show obj:b3:...
```

Export a bundle:

```bash
nodectl bundle export ./out.pack
```

Import one:

```bash
nodectl bundle import ./out.pack
```

---

# 28. Suggested MVP

The first version should deliberately be small.

> Sequencing, exit criteria, risks, and gates now live in
> `pigeonnet-milestones.md`. The phases below are the original sketch and are
> kept for continuity; the milestone map supersedes them where they differ.

## Phase 1: identity + objects

Implement:

- Ed25519 identity generation
- canonical object serialization
- signed objects
- object hashing
- SQLite object store

Goal:

Two local node instances can create and verify signed objects.

---

## Phase 2: peer synchronization

Implement:

- peer configuration
- transport connection
- inventory exchange
- missing-object request
- object transfer
- signature verification

Goal:

Two nodes converge to the same object set.

---

## Phase 3: public echoes

Implement:

- echo subscription
- public posts
- threading
- propagation rules

Goal:

Three nodes can participate in a shared replicated discussion area.

---

## Phase 4: private messages

Implement:

- encryption
- recipient addressing
- store-and-forward routing
- delivery receipt

Goal:

A private message can cross one or more untrusted relay nodes.

---

## Phase 5: files

Implement:

- file manifests
- chunking
- deduplication
- resumable retrieval
- file references in posts

Goal:

A file published by one node can be mirrored and fetched from another node.

---

# 29. Security Model

The security assumptions are explicit.

## Trusted

- the user's local private key storage, while unlocked
- the passphrase protecting it (section 25.1)

## Not trusted

- relay nodes
- peer nodes
- transport networks
- file mirrors
- public echo participants
- removable media and imported bundles

## Expected attacker capabilities

An attacker may:

- modify packets
- replay objects
- inject invalid objects
- run malicious relay nodes
- **archive ciphertext indefinitely** — normal behaviour for an `archival` node
  (D8), not an exotic capability
- withhold objects
- attempt spam
- attempt route poisoning
- attempt storage exhaustion
- publish malformed content
- obtain an old backup of key material
- seize a powered-off device
- steal a root key and attempt to rotate the identity away from its owner

The protocol validates, before accepting an object into trusted state:

- object size
- canonical encoding, by re-encoding and comparing (D2)
- hashes
- signatures, strictly
- key delegation chains and capabilities (D3)
- sequence rules
- encryption metadata
- routing advertisements
- resource limits

---

## 29.1 What defends what

| Attacker | Defence |
|---|---|
| Wire capture; hostile or archival relay | epoch prekey expiry (D4) |
| Seized powered-off device | encryption at rest (D9) |
| Leaked old key backup | epoch prekey expiry — an old leak opens only its own epoch |
| Forged authorship | device key signatures and delegation chains (D3) |
| Stolen root key | recovery key eviction, `invalidate_from` (D11) |
| Unsolicited traffic | contact gate, invitations, quotas (D7) |
| Storage exhaustion | ingest limits and local pruning (D8) |

---

## 29.2 What is not defended

**A live compromise of a running node.** The store is unlocked, epoch private
keys are loaded, and decrypted plaintext is in memory. Neither forward secrecy
nor encryption at rest helps, and neither claims to. An attacker with code
execution on an unlocked node reads everything that node can read, and can sign
as its device key until that key is revoked (section 5.4).

This is stated rather than left implied, because the two mechanisms above are
easy to mistake for protection against it.

---

# 30. Abuse and Resource Limits

Replicated systems are vulnerable to storage exhaustion, which section 29 lists
as an expected attack. Nodes defend with local policy.

---

## 30.1 Ingest limits

Enforced before an object enters trusted state:

```text
max object size
max echo post size
max direct message size
max file manifest size
max objects per peer per sync
max bytes per peer per sync
max route advertisements per peer
max unknown-sender traffic per period
```

These are local configuration. A node that rejects an oversized object is
behaving correctly, not violating the protocol.

---

## 30.2 Retention is local policy

**Any node may prune any object at any time. No protocol operation may depend on
another node still holding history.**

This is object retention. Key retention — how long epoch prekey private halves
survive — is a separate clock, set by `W` (D4, section 25.2).

Retention profiles are local configuration, never advertised as a promise:

```text
ephemeral   keep N days
standard    keep per-area policy
archival    keep everything
```

An object cannot request its own preservation or expiry from a third party. Such
a field would be unenforceable, and would encourage the false belief that
deletion works — section 21 already concedes that global deletion cannot be
guaranteed.

---

## 30.3 Stubs

Pruning an object leaves a **stub**:

```text
object_id, type, author, timestamp, thread, parent
```

The body is gone; the skeleton remains. Without stubs, pruning a parent post
makes its thread unreconstructable, and the deterministic threading of section 7
silently stops working on any node that prunes.

Stubs are a few dozen bytes, and are themselves prunable once nothing references
them.

---

## 30.4 Deferred

Snapshots, log checkpointing, and archival-peer discovery are out of scope for
v1.

See D8.

---

# 31. Versioning

Objects should contain a version field.

Example:

```text
version: 1
```

Unknown object versions should not be treated as valid known objects.

Protocol negotiation should allow nodes with different supported versions to interoperate where possible.

Avoid putting transport versioning and object versioning into one shared version number.

---

# 32. Naming

Some potentially useful terminology:

```text
Node
Identity
Peer
Object
Echo
FileEcho
Community
Bundle
Route
Relay
Introduction
Receipt
```

The old FidoNet terminology is useful where it still maps naturally.

"Echo" and "FileEcho" are particularly good concepts to preserve.

---

# 33. Locked Design Decisions

The questions previously listed here are now decided. Each decision is binding for
v1 of the object format and replication protocol, and records what it supersedes
earlier in this document. Where a decision contradicts an earlier section, the
decision wins and the earlier section is scheduled for rewrite.

Decisions are numbered `D1`..`D15` so they can be cited from code and commits.

---

## D1. Object hash: BLAKE3-256, domain-separated, self-describing prefix

**Decision**

- Object IDs are BLAKE3 with 256-bit output over the canonical serialized bytes.
- Hashing uses BLAKE3 **derive-key mode** with the fixed context string
  `pigeonnet object-id v1`. Separate contexts are used for file chunks, bundle
  manifests, and signature transcripts, so a hash from one context can never be
  mistaken for a hash from another.
- Text form:

```text
obj:b3:<base32-lowercase-unpadded>
```

- `b3` is an entry in a small closed registry, not free-form multihash. The v1
  registry contains exactly one entry. An unknown code makes the object
  *unknown*, not *invalid-but-parseable* (see section 31).
- **The ID covers the canonical to-be-signed bytes and excludes the signature
  field.** Signature encoding malleability therefore cannot produce two IDs for
  one logical object.

**Rationale**

BLAKE3 is internally a Merkle tree over 1 KiB chunks. Section 9 needs chunk
trees, and section 15 wants Merkle-based reconciliation; one primitive serves
object IDs, file manifests, and verified streaming (fetch one chunk and verify
it against the root without holding the whole file). SHA-256 offers none of that
structure for the same cost.

**Consequences**

File manifests in section 9 no longer need a hand-rolled chunk list — the BLAKE3
tree *is* the manifest. A `FileManifest` carries the root hash, total length, and
metadata; the chunk boundaries are implied by the hash construction.

*Supersedes: 3.2, 9.*

---

## D2. Serialization: deterministic CBOR, integer keys, re-encode on ingest

**Decision**

- RFC 8949 section 4.2.1 core deterministic encoding.
- Struct fields are encoded as maps with **integer** keys, assigned once and
  never reused.
- Banned in v1: indefinite-length items, floating point, duplicate map keys,
  non-minimal integer encodings, and all tags outside a closed registry.
- **Ingest rule (mandatory):** decode the received bytes, re-encode them
  canonically, and require the result to be byte-identical to what arrived.
  Reject before the signature is checked.
- The original received bytes are stored verbatim (section 25).
- Canonical JSON is debugging output only. It is never hashed and never signed.

**Rationale**

Signatures and content addressing both require exactly one byte representation
per logical value. Malleability is the ability to mint two IDs for one object,
which breaks deduplication, threading, and retraction. The re-encode check
collapses that entire class of bug into one function at the boundary, instead of
an audit obligation on every decode path. Integer keys keep objects compact and
mean renaming a Rust field cannot change the wire format.

*Supersedes: 22.*

---

## D3. Identity: genesis object ID, offline root key, delegated device keys

**Decision**

- An identity **is** the object ID of its genesis `IdentityCreated` object:

```text
id:b3:<base32-lowercase-unpadded>
```

  This name is stable across all subsequent key rotation.

- The genesis object carries the initial root Ed25519 signing key and the
  initial X25519 identity key.
- The **root key signs only identity-management objects**: `KeyRotated`,
  `DeviceKeyGranted`, `DeviceKeyRevoked`. It is expected to live offline, and
  does not sign epoch prekeys (D4). A separate **recovery key** outranks it
  (D11).
- **Device keys** are Ed25519, granted by the root key, and carry `capabilities`,
  `not_before`, and `not_after`. All day-to-day objects are signed by a device
  key, never by the root key.
- Verification means replaying the identity's key-management chain, then
  confirming the signing device key was valid at the object's claimed time and
  holds the required capability.
- **`sequence` is per signing key**, starting at 0, monotonic and gapless.

**Rationale**

Naming an identity by a raw public key makes the key rotation of section 5.4 an
*identity* change, which breaks every reference to that identity. Addressing by
genesis object gives a stable name under rotation and is consistent with content
addressing everywhere else.

Per-key sequences remove all cross-device coordination: two devices never race
for the same number. They also make equivocation self-evident — two different
objects signed by the same key at the same sequence are a portable proof of
misbehaviour, publishable as an `EquivocationProof` object.

**Consequences**

Delegation-chain validation joins the object ingest hot path. Resolved key state
is cached per identity and is rebuildable from objects, like every other derived
index (section 25).

*Supersedes: 3.3, 5.1, 5.4, and the former "Multiple devices" question.*

---

## D4. Encryption: epoch prekeys, forward secrecy by deletion schedule

**Decision**

- Each **device** of an identity publishes a rolling series of **epoch
  prekeys**, signed by that device's key under a `publish-prekeys` capability —
  not by the root key, which would otherwise have to be warm:

```text
EpochPrekey {
    epoch:       118,
    public_key:  x25519:...,
    device:      ed25519:c3a81f...,
    valid_until: 2026-10-16T00:00:00Z,     # when the private half is destroyed
    signature_by_device
}
```

- One epoch per day, published several epochs ahead. The sender selects by wall
  clock, not by choice — nothing is consumed, so nothing collides or runs out.
- The recipient destroys the private half at `valid_until`, which is
  `epoch_end + W`. `W` is per-node configuration, thirty days by default, and
  must exceed worst-case replication lag plus worst-case delivery delay.
- To send:

```text
key = HKDF-SHA256(DH(EK, EpochPrekey_recipient), salt, info)
```

  `EK` is a one-shot ephemeral X25519 key, destroyed immediately. `info` binds
  protocol version, both identities, and the epoch number.

- Senders **fan out**: the payload is encrypted once under a content key, which
  is then wrapped to every currently valid device of the recipient (section 8.1).
  Each device gets independent forward secrecy, and no secret has to travel
  between a user's own machines.
- Payload AEAD is ChaCha20-Poly1305, with the canonical object header as
  associated data, so a relay cannot re-attribute the ciphertext.
- The completed object is signed by the sender's device key (D3).
- **Fallback:** when every epoch prekey a sender holds has expired, the sender
  may seal to the recipient's long-term X25519 identity key. Such a message
  carries `fs: none`, and **both clients display it as not forward secret**.
- One-time prekeys are **not** used.
- A `suite` field selects the primitive set, for later agility.
- Ed25519 keys are never converted to X25519 keys via the birational map.

**Rationale**

Forward secrecy here is produced by destroying a private key on a schedule, not
by a handshake or a ratchet. That is the entire mechanism, and it is the only
kind that survives an offline recipient (section 3.5) together with multi-day
reordered delivery (section 18).

**Why one-time prekeys were rejected**

X3DH's one-time prekeys assume a trusted dispenser that hands each sender a
distinct key and deletes it. Pigeonnet has no such component by design: a prekey
bundle is a replicated object, so every sender holds the whole pool and picks
from it. Two failures follow, both worse than the exhaustion they were meant to
prevent:

- **Collision.** With a pool of `N` and `k` senders choosing at random, a
  collision appears with probability roughly `1 - e^(-k²/2N)` — about 50% at
  twelve senders against a hundred keys. Destroy-on-use then loses every other
  message sealed to that key.
- **Reordering.** A single sender suffices. A message sent first but delayed
  behind a down relay arrives after a later one using the same prekey; the key is
  already destroyed, and the earlier message is unrecoverable.

Destroy-on-first-use presumes ordered delivery. Section 18 guarantees the
opposite.

**Honest limits**

- Forward secrecy is bounded, not immediate: a message becomes unrecoverable at
  its epoch's `valid_until`, at most `epoch_length + W` after it was sealed.
- The clock starts when the key was minted, not when the message was sent. A
  sender with a stale profile spends the budget before pressing send, which is
  what the fallback exists for.
- `fs: none` messages have none at all, visibly.
- There is no post-compromise security.
- There is no metadata privacy (section 8.4).
- **None of this means anything without D9.** Destroying key material while
  keeping decrypted plaintext readable on the same disk is not a security
  posture.

**Out of scope for v1**

A per-contact ratchet was considered and dropped. With relays covered by epoch
expiry and local storage covered by D9, per-message forward secrecy defends a gap
already closed from both sides. It can be added later behind the `suite` field if
evidence demands finer granularity than one epoch.

Group and community encryption remains out of scope. Public echoes are signed and
not encrypted (section 6). MLS is the intended path if encrypted communities are
added; a bespoke group scheme must not be invented.

*Supersedes: 8, and the former "Encryption" question.*

---

## D5. Replication: per-stream journals with cursors, inventory as repair

**Decision**

- Each node maintains an append-only local **journal** per replication stream —
  per echo area, per file area, per identity inbox. Entries are
  `(local_seq, object_id)`, where `local_seq` is node-local and carries no
  meaning between nodes.
- A sync is: *"send me everything in stream S after cursor C."* The peer returns
  object IDs, the requester asks for the ones it lacks, the peer sends bytes.
- Cursors are stored per `(peer, stream)`.
- A **repair path** exists: explicit inventory exchange over a bounded range, for
  cursor loss, corruption, or distrust of a peer's journal.
- Capability negotiation is present from the first release (section 31), so
  Merkle range reconciliation or IBLT set reconciliation can be introduced later
  as additional stream types without a flag day.

**Rationale**

Section 15 says to favour simplicity, but naive inventory exchange is
O(total objects) per sync — it fails at exactly the scale this document claims
to target: Raspberry Pi-class hardware, once-a-day sync, years of accumulated
history. High-water-mark cursors are the NNTP and FidoNet model, and they are
both simpler to implement *and* O(new objects). Set reconciliation is deferred
until measurements justify it.

*Supersedes: 15.*

---

## D6. Routing: configured peers, plus scoped expiring signed advertisements

**Decision**

- Peers are statically configured in v1. No DHT, no global discovery.
- `RouteAdvertisement` is a signed object carrying a target, the advertising
  node, a hop cost, and a short absolute expiry.
- Hard policy: a node accepts route advertisements **only** from directly
  configured peers, **only** for targets inside a configured scope, and never
  lets an advertisement override a static route. Advertisements are ranked
  hints, never authority.
- Echo propagation is **pull-based**, not flooding. A node asks its peers what
  they hold in an area after its own cursor, and fetches only what it lacks (D5).
- **Amended after M4.** This originally specified subscription flooding with a
  bounded `seen_by` list and a hop ceiling, after FidoNet's `SEEN-BY` / `PATH`.
  Building it showed those are unnecessary for echoes: nobody pushes, so there is
  no storm to suppress, and content addressing deduplicates for free. In a
  triangle, a node offered one object by two peers fetches its bytes once and
  refetches nothing thereafter, however long the cycle runs. Verified by test.
- `seen_by` and hop ceilings remain the right answer for **directed forwarding** —
  carrying a private message toward a recipient (§8.3) — where a node does push,
  and for any future low-latency push mode (§18). They are not echo machinery.
- **Wherever push does apply, `seen_by` travels in the unsigned transfer
  envelope, never inside the signed object.** Putting it in the object would
  change the object ID at every hop and destroy content addressing.
- Private messages route along the best known path toward the recipient, under a
  hop ceiling and a per-object TTL. Undeliverable objects expire locally and
  generate no bounce — a bounce is a mailbox concept (section 35).
- Deferred: distributed discovery, community directories, and the multi-path or
  onion routing of section 8.4.

**Rationale**

Route poisoning is an expected attacker capability (section 29), and a network
that accepts unsolicited advertisements from strangers is trivially poisoned.
Restricting advertisements to configured peers means poisoning first requires
becoming a peer.

*Supersedes: 16, 17.*

---

## D7. Spam: layered local policy, nothing globally mandatory

**Decision** — v1 ships four mechanisms, all enforceable by the receiving node
alone:

1. **Trust graph gating.** Direct contacts and depth-1 friends-of-friends, via
   the signed introductions of section 13.1, are accepted by default. Everyone
   else is held.
2. **Invitation tokens** (section 14.1). Signed, single-use, bound to the issuer,
   expiring, and capability-scoped. Redeeming one grants the sender contact
   status.
3. **Contact requests.** An unknown sender may deliver one small, size-capped,
   rate-limited `ContactRequest` per recipient per period. Nothing else from an
   unknown sender is accepted.
4. **Quotas and rate limits** from section 30, enforced at ingest.

Specified but **optional**: a proof-of-work field on `ContactRequest`. The field
and its verification rule are defined so that a node *may* require it; no node is
obliged to produce one.

Out of scope: postage tokens and global reputation.

**Rationale**

Every mechanism above is enforceable unilaterally, with no coordination between
nodes, which is what "no single anti-spam mechanism needs to be globally
mandatory" requires. Reputation systems and postage need network-wide agreement
on value, which contradicts section 2.

*Supersedes: 14.*

---

## D8. Retention: local policy only, never a protocol dependency

**Decision**

- Any node may prune any object at any time. **No protocol operation may require
  that some other node still holds history.**
- Retention profiles are local configuration, not advertised promises:
  `ephemeral`, `standard`, `archival`.
- Pruning preserves a **stub**: object ID, type, author, timestamp, and
  thread/parent references. Threads stay navigable and replies remain verifiable
  as referencing something real; the body is gone. Stubs are small, and are
  themselves prunable.
- Retention is never a field that others honour. An object cannot request its
  own preservation or expiry from a third party.
- Deferred: snapshots, log checkpointing, archival-peer discovery.

**Rationale**

A "please keep this" field is unenforceable and encourages the false belief that
deletion works — section 21 already concedes that global deletion cannot be
guaranteed. Stubs are the minimum needed to keep the deterministic threading of
section 7 intact after pruning; without them, a pruned parent makes a thread
unreconstructable.

*Supersedes: 30, and refines 21.*

---

## D9. Encryption at rest: keys always, plaintext by policy

**Decision**

A node's store is not uniformly sensitive, and is not uniformly encrypted:

| Content | At rest |
|---|---|
| Echo posts, file manifests, public objects | plain — public by definition; the node is a mirror |
| Ciphertext relayed on behalf of others | already encrypted; nothing to do |
| Decrypted direct-message plaintext | **encrypted** |
| Root key, device keys, epoch prekey privates, identity key | **encrypted, unconditionally** |

- Key material is encrypted under a passphrase-derived key (Argon2id), always,
  with no opt-out. The root key especially: recovery is undesigned (section 5.4),
  so losing it ends the identity and leaking it ends everything.
- Received direct messages are **re-encrypted on receipt** under a local storage
  key — decrypt once with the epoch prekey, re-encrypt locally, then let the
  epoch key expire on D4's schedule. This is the default, because people expect
  to be able to read their own old messages.
- A node may instead choose **cryptographic erasure**: do not re-encrypt, and let
  the epoch key's destruction take the plaintext with it. The original ciphertext
  object is retained either way (section 25), so after `valid_until` the node
  holds an object it can no longer open. Section 21 already names this operation;
  this is how it is implemented.

**Rationale**

Forward secrecy and encryption at rest defend different attackers, and the weaker
one sets the guarantee. Destroying epoch keys on a thirty-day schedule while the
decrypted archive sits in plaintext on the same disk would be incoherent — the
effort spent making month-old traffic unrecoverable is undone by one `cat`.

The decomposition matters, though. "Encrypt the database" is the wrong framing,
because most of what a node stores is either public or is someone else's
ciphertext. The problem is narrow: a keyring and a plaintext cache.

**Why forward secrecy still earns its place**

Encryption at rest does not subsume it. Relays legitimately retain ciphertext —
for days during normal store-and-forward (section 18), and indefinitely on
`archival` nodes (D8). The adversary holding a copy of your ciphertext is not a
wiretap abstraction; it is any hop on the path behaving exactly as specified.

Forward secrecy also buys two things local disk encryption cannot:

- **Deletion that means something.** Section 21 concedes you cannot recall
  replicated copies. Epoch expiry kills the copies you cannot reach.
- **Old backup leaks.** A years-old backup containing a long-term key, combined
  with an archival node's store, would otherwise be total historical compromise.
  With epoch keys, an old leak opens only its own epoch.

*Extends: 25, 29.*

---

## D10. Failure receipts: the recipient reports, relays stay silent

**Decision**

- `DeliveryReceipt` gains an `undecryptable` state with a machine-readable
  `reason`, emitted by the **recipient** when an object arrives and its signature
  verifies but its payload cannot be opened.
- The receipt **carries the recipient's current `EpochPrekey`**, so one object
  both reports the failure and supplies what the sender needs to retry.
- Failure receipts go **only to senders who have passed the contact gate** (D7).
  Unknown senders get silence.
- Failure states default to enabled. `read` remains opt-in.
- Senders retain outbound plaintext until a positive receipt arrives or a local
  timeout fires.
- Relays still generate nothing. D6's prohibition is unchanged.

**Rationale**

This is not the bounce D6 forbids. There, a relay fabricates a message about an
object whose sender it cannot authenticate — that is backscatter, and it makes
every relay a weapon aimed at forged senders. Here the recipient emits it after
verifying the sender's signature, so a receipt can only be provoked by a
genuinely signed message from a real identity, and the ratio is strictly 1:1.

Carrying the prekey matters more than it looks. Without it, the sender must go
re-sync the recipient's profile through a network that has just demonstrated it
is slow — the same condition that caused the failure. With it, the error heals in
one round trip, which is what makes D4's thirty-day window tolerable rather than
frightening.

**Constraints and why**

- **Contact-gated**, or the receipt becomes a spam oracle: a probe confirming
  that a message reached a real, active identity.
- **Rate-limited** under section 30, like everything else at ingest.
- **Default-on for failures**, because withholding one leaves the sender
  believing a message landed when it did not. That is a different privacy
  character from a read receipt, and deserves a different default.

**What it cannot cover**

Only messages that arrived. A message that expired at a relay three hops back
produces no receipt, because there is no authenticated party at the far end to
produce one, and D6 correctly refuses to let the relay invent one.

The recipient reports failures it witnessed; silence remains ambiguous, and the
sender resolves it with a local timeout.

*Supersedes: 20.*

---

## D11. Identity recovery: a mandatory cold recovery key, plus succession

**Decision**

- `identity create` generates a second Ed25519 key — the **recovery key** —
  named in the genesis object beside the root key. **Mandatory; it cannot be
  skipped.** It belongs on cold media, never on the node.
- The recovery key signs `RootKeyReplaced` and `RecoveryKeyReplaced`, and may
  sign `IdentitySuccession` and `SuccessionRevoked`. Nothing else.
- **Recovery-signed objects outrank root-signed objects** — always, by role,
  never by timestamp.
- **The operational root cannot revoke or replace the recovery key.** Only the
  current recovery key may replace itself.
- `IdentitySuccession` binds a predecessor identity to a successor. Signed by the
  recovery key it is final; signed by the root key it is valid but voidable by a
  later recovery-signed `RootKeyReplaced` or `SuccessionRevoked`; signed by a
  contact it is an **attestation**, evaluated per observer like the introductions
  of section 13.1, and never a global claim.
- If both keys are lost or stolen together, the identity is gone. No mechanism,
  and none will be added.

**Rationale**

Every recovery path is an attack path, so the question is never "how do we add
recovery" but "which attack do we buy, to refuse which failure".

The binding constraint is fork-freedom. There is no authority to adjudicate here;
each node replays the key chain independently (section 5.1), so two validly
signed chains from one genesis make nodes disagree about who you are. A forked
identity is worse than a dead one — a dead identity is unambiguous, a forked one
is an impersonation engine. Recovery must therefore resolve identically on every
node with no consensus, no clock, and no liveness assumption.

Ranking by **role** rather than by timestamp is what achieves that. It needs no
agreement about time, which section 3.5 explicitly denies us.

**Why this handles compromise, not just loss**

Most recovery designs address a lost key and leave a stolen one permanent. Here a
thief who rotates your root to their own key, grants themselves devices and signs
as you is evicted by a single recovery-signed `RootKeyReplaced` carrying
`invalidate_from`. You cannot lose that race because role-ranking means there is
no race — only an eviction, whenever you get to it.

Root-signed succession is deliberately voidable for the same reason: a warm key
should not be able to hand your social graph to an attacker irreversibly.

**Why mandatory**

An optional recovery key is absent exactly when it is needed. It must also be
present in the genesis object for its authority to be unambiguous — designating
one later leaves a window in which a thief designates theirs instead.

There is a second-order argument. "No recovery, ever" makes losing the root
catastrophic, which pushes people to keep it somewhere convenient — on the
laptop, in cloud backup — precisely because they fear losing it. A cold recovery
key is what allows the operational root to be handled with appropriate paranoia.
No-recovery actively degrades key hygiene.

**Why `k`-of-`n` social recovery was rejected**

A quorum of `k` colluding delegates owns you permanently. The delegate set rots
as delegates lose their own identities — the same problem, recursively. And
updating the set has no safe answer: if the root may change delegates, a thief
closes the door behind them; if it may not, the set is frozen for life.

Attested succession covers the same case without any of that, because it claims
nothing globally and each observer decides for itself.

**Also rejected**

Time-locked recovery with a veto window needs agreement on elapsed time and on
the absence of a veto, both denied by section 3.5; a node offline for forty days
sees the recovery complete while its peer saw the veto. Community reassertion is
true only inside one community, which is a fork by design, and inverts the
separation section 12 draws.

*Supersedes: the recovery paragraph of 5.4; adds 5.5.*

---

## D12. Identity state: chain by invariant, current state by snapshot

**Decision**

- An identity's **key chain** replicates by the **chain invariant**: a node that
  serves an object must be able to serve that object's author's key chain up to
  the object's timestamp. No dedicated stream, because verification already
  requires it.
- An identity's **current state** — unexpired `EpochPrekey`s for every device,
  the latest `ReachabilityClaim`, and `IdentityProfile` — is fetched as a
  **snapshot**, not a journal: `current id:b3:...`, no cursor, no session state.
  About 14 KB for three devices.
- The snapshot carries its own `valid_until`, 30 days by default. **Freshness is
  a property of the snapshot, never a side effect of prekey exhaustion.** Clients
  display snapshot age rather than degrading silently.
- Everything in a snapshot is self-signed, so **any node may serve it and a
  cached copy is as trustworthy as the origin's.** A holder can withhold, never
  forge.
- Bootstrap order: already held; `resolve id:b3:...` to configured peers, **one
  hop, never forwarded**; reverse-path hint (17.1); or carried inside a
  `ContactRequest`.
- **Resolution is by exact identity only. There is no search, no enumeration,
  and no people directory — ever.**

**Rationale**

Four unrelated mechanisms — encryption (8.1), routing to an identity (5.7),
naming (5.2), and inbox authentication (15.4) — all needed identity state and
none had a way to obtain it. They divide cleanly into material that must be
complete and ordered, and material where only the latest version is ever wanted.
The first is free; the second does not fit a cursor model and should not have
been forced into one.

Forwarding `resolve` would build a DHT: every node would learn who asks about
whom, and the query would be floodable. One hop keeps it a cache lookup against
peers already chosen.

**Honest limits**

- The snapshot is world-readable: device count, carriers, and a liveness signal
  from prekey publication. No fix is compatible with letting strangers encrypt.
- Withholding fresh prekeys is a downgrade attack onto `fs: none` (D4).
- A cold identity whose snapshot none of the four paths reaches cannot be
  contacted in v1 (section 37).

*Supersedes: 5.2; extends 8.1, 16.*

---

## D13. Reachability: self-signed claims, counter-signed carriage

**Decision**

- `ReachabilityClaim` is signed by the **identity**, listing carrier nodes with
  costs and an expiry. It travels in the snapshot (D12) and replicates freely.
  It is **not** a `RouteAdvertisement` and is not subject to D6's restrictions,
  because a self-signed claim can only misdirect its own author's traffic.
- `CarriageAccepted` is signed by the **carrier**. A sender routes toward a
  carrier only when both objects are present and current. Neither party binds
  alone.
- Accepting carriage obliges the carrier to spool `inbox:id:b3:...` and to serve
  that identity's snapshot. Nothing else.
- **Two independently operated carriers are the recommended configuration**, and
  the second must be listed before an outage, not after.
- Carriers named in the same current claim may replicate that identity's inbox
  stream between themselves, **each accepting only for identities for which it
  independently holds a `CarriageAccepted`.** Normal sending goes to the
  lowest-cost carrier; fan-out is a timeout behaviour.
- Migration is: publish both, drain the old, publish the new alone, release. The
  snapshot's `valid_until` bounds the tail.

**Rationale**

Unilateral claims would let any identity aim network traffic at any node —
reflection with an attacker-chosen target — and local policy at the victim is
insufficient, since dropping unwanted traffic still means it arrived. The
counter-signature makes the pair verifiable, so senders never generate it.

Carrier-to-carrier sync beats sender-side fan-out: it does not double every
sender's traffic, and it repairs backwards, so objects delivered before a
carrier failed are already at the survivor.

**Honest limits**

Each carrier holds a complete copy of the identity's traffic metadata.
Redundancy is paid for in exposure, not free. A departing carrier can serve a
stale snapshot for one `valid_until`, though it cannot forge a new one. Losing
all carriers at once means republishing and waiting days.

*Supersedes: 5.3; extends 17, 20.*

---

## D14. Node discovery: self-signed profiles, relayed freely, scored locally

**Decision**

- A node may publish a self-signed `NodeProfile` carrying its identity,
  addresses, the areas it carries, and its policy. **Opt-in; silence is the
  default, and leaf nodes do not publish.**
- Profiles propagate as ordinary objects. **Anyone may relay any node's profile;
  only a node may author its own.**
- Accepting a profile is passive — it becomes a local candidate. `peer add`
  stays manual. There is no push channel by which a node can be announced *at*
  another node.
- Reachability, latency, and reliability are **measured locally and never
  replicated.** Unknown profiles are ranked by `relayed_via` provenance, capped
  per peer per sync. Scores decay rather than blacklist.
- A node proves its identity on connect, so a wrong address yields a failed
  handshake rather than a hostile peer.
- A curated signed nodelist distributed via a file echo remains a permitted
  alternative, with no special status.

**Rationale**

This is not BGP. BGP's danger is unverifiable third-party claims about
reachability; a self-signed profile is verified by connecting, and a lie is
self-correcting. Relaying is carrying, not asserting.

Sharing measured quality would be a global consensus artifact (section 2) and
would also be incorrect, since quality is observer-relative.

**Honest limits**

Profiles are cheap to mint, so the carrying area inherits the public-echo spam
problem (section 37). It is also a public census of infrastructure: every
participating carrier becomes enumerable and targetable. Acceptable for
carriers, which are public by nature — which is why leaves must never appear.

*Replaces the unspecified `PeerAnnouncement`; extends 17.*

---

## D15. Stream access: open echoes, authenticated inboxes

**Decision**

- No account, registration, or acceptance step exists for reading from a node.
  Access is gated by **stream class**, not by asker identity.
- `echo://`, `files://`, and `current id:b3:...` are answerable to anyone.
- `inbox:id:b3:X` requires a device-key signature from X over a nonce supplied by
  the serving node. Closed community areas require an equivalent membership
  proof.
- Any node may decline anyone under section 30 quotas. "Anyone may ask" and "the
  node may refuse" are both true.

**Rationale**

The network has to be readable before anyone has a reason to join it, which is
the Usenet property and is deliberate. But an unauthenticated inbox stream would
make any identity's complete correspondence graph globally fetchable from any
carrier, which is a far larger disclosure than section 8.2's concession that
relays on the path see metadata.

**Honest limits**

Public means permanent and global, with no deletion (section 21). A closed area
limits distribution, never disclosure: nothing stops a member republishing it.

*Extends: 15, 30.*

---

## Multiple devices

Decided in **D3**: one root identity, several delegated device keys, each with
its own sequence space. Since D4, each device also publishes its own epoch
prekeys, and senders fan out to all of them (section 8.1).

---

# 34. Rust Implementation

The implementation language is Rust, edition 2024.

Exact pinned versions live in the workspace manifest, not here; this table
records which crate was chosen and why.

## 34.1 Workspace layout

```text
pigeonnet/
├── Cargo.toml                # workspace, shared lints, pinned MSRV
└── crates/
    ├── pigeonnet-core/       # object model, deterministic CBOR, IDs, validation
    ├── pigeonnet-crypto/     # keys, signing, prekeys, AEAD, zeroizing secrets
    ├── pigeonnet-store/      # rusqlite object store, journals, derived indexes
    ├── pigeonnet-proto/      # sans-io replication state machine
    ├── pigeonnet-bundle/     # .pack reader/writer (section 19)
    ├── pigeonnet-node/       # node core: wires store, proto, and policy together
    ├── pigeonnet-net/        # tokio transports (TCP first, QUIC and Tor later)
    └── nodectl/              # CLI (section 27)
```

Structural rules:

- `core`, `crypto`, `proto`, and `bundle` contain no async, no I/O, no ambient
  clock, and no ambient RNG. Time and randomness are injected by the caller, so
  every validation and protocol decision is reproducible in a test.
- `#![forbid(unsafe_code)]` across the workspace.
- `pigeonnet-net` is the only crate that depends on tokio. `pigeonnet-node`
  reaches transports through a trait, never through tokio types.

The replication protocol is **sans-io**: a pure `step(input) -> Vec<Output>`
state machine. That is where the interesting attacks live (D5, D6), and as a
pure machine it can be driven by an adversarial peer script and fuzzed without
ever opening a socket.

## 34.2 Dependencies

| Purpose | Crate | Notes |
|---|---|---|
| Hashing | `blake3` | Derive-key mode per D1; verified streaming later |
| CBOR | `minicbor`, `minicbor-derive` | Explicit field indices. **Not** `serde_cbor`, which is unmaintained |
| Signatures | `ed25519-dalek` 3 | Always `verify_strict`, to reject small-order and non-canonical points |
| Key agreement | `x25519-dalek` 3 | Separate keys from signing (D4) |
| KDF | `hkdf`, `sha2` | HKDF-SHA256 per D4 |
| AEAD | `chacha20poly1305` | |
| Secrets | `zeroize`, `secrecy` | Wrapper types for all private key material |
| At-rest KDF | `argon2` | Passphrase-derived storage key (D9) |
| Randomness | `rand_core`, `getrandom` | OS entropy only |
| Storage | `rusqlite` | `bundled` feature, so no system SQLite dependency; WAL mode |
| Async | `tokio` | `pigeonnet-net` only |
| CLI | `clap` | Derive API |
| Errors | `thiserror` | `anyhow` is permitted in `nodectl` only |
| Logging | `tracing`, `tracing-subscriber` | |

Determinism (D2) is guaranteed by our own encoder rules and the ingest
re-encode check, not assumed from the CBOR library.

## 34.3 Testing strategy

- **Property tests** (`proptest`) for D2: `decode(encode(x)) == x`, and
  `encode(decode(bytes)) == bytes` for every accepted input. The second property
  *is* the ingest rule, expressed as an invariant.
- **Fuzzing** (`cargo-fuzz`) of the CBOR decoder, the object validator, the
  bundle reader — section 19 requires bundles to be safely importable from
  untrusted media — and the `pigeonnet-proto` state machine.
- **Committed test vectors**: canonical object bytes with their expected IDs and
  signatures, generated during Phase 1. Any accidental change to the wire format
  then fails CI, and a future reimplementation has something to check against.
- **Adversarial peer harness**: drive `pigeonnet-proto` with a scripted hostile
  peer — replays, reordering, oversized objects, invalid signatures, poisoned
  route advertisements — entirely in-process.
- No `unwrap`, `expect`, or panic on any ingest path. Enforced by denying
  `clippy::unwrap_used` and `clippy::expect_used` in `core`, `crypto`, `proto`,
  and `bundle`.

## 34.4 Phase 1 scope

Mapping to section 28, Phase 1 delivers `pigeonnet-core`, `pigeonnet-crypto`,
`pigeonnet-store`, and a minimal `nodectl` exposing `identity create` and
`object show`, plus the committed test-vector corpus.

Goal: two local node instances create signed objects and verify each other's.

---

# 35. Important Design Constraint

Do not accidentally rebuild SMTP.

Whenever a design starts looking like:

```text
sender
  -> destination server
      -> recipient mailbox
```

reconsider it.

**But be precise about what is forbidden.** A carrier holding an `inbox:`
journal for an identity (5.7) *is* a spool at a named server holding objects
addressed to one person, and pretending otherwise is dishonest. Storage at a
relay is inherent to store-and-forward; FidoNet spooled at hubs too.

What ruins email is not the spool. It is **the mailbox appearing in the
address**. Here it does not:

- the address is `id:b3:9fq2...`, which names no server
- the carrier cannot read the spool, sign as the identity, or hold its name
- an identity may list several carriers, and drop one, with no correspondent
  updating anything
- moving is a new snapshot, not a new identity

So the rule is not "no storage at relays". It is **no coupling between identity
and the node that stores for it**.

The intended abstraction is:

```text
identity
  creates signed object
      replicated between peers
          according to subscriptions and routing policy
```

The core system is a replicated communication network, not a mail transfer system.

---

# 36. Summary

The proposed network combines:

- FidoNet-style store-and-forward operation
- Usenet-style replicated public discussion
- UUCP-like tolerance for intermittent links
- content-addressed file distribution
- modern cryptographic identities
- signed immutable objects
- end-to-end encryption
- untrusted relays
- community-scoped trust and moderation

The architecture is intentionally decentralized and asynchronous.

The key rule is:

> **There are no mailboxes. There are identities, immutable objects, subscriptions, peers, and replication.**

That rule should guide protocol and implementation decisions throughout the experiment.

---

# 37. Open Questions

Unlike section 33, nothing here is decided. These are known gaps, recorded so
they are not rediscovered.

## 37.1 Epoch length and lookahead versus backup exposure

Weekly epochs instead of daily look clearly better: worst-case message lifetime
moves from 31 to 37 days, which nobody notices, and publishing becomes
infrequent enough that the daily-publication liveness leak disappears.

**Lookahead is the unresolved part, and it is the main control on the compromise
window — not a convenience parameter.** Publishing far ahead makes offline-first
work: a node that has not synced in months never runs its correspondents dry and
never forces them onto `fs: none`. But the private halves must be retained, so a
leaked backup stops being a window into the past and becomes a **standing
wiretap on the future**: a June backup with a year of lookahead decrypts traffic
through December, written by people who have no idea anything happened. That
directly contradicts D9's claim that an old leak opens only its own epoch.

Candidates, none adopted:

1. **Bind the epoch to the calendar.** A week-30 public key may only *seal*
   during week 30, recorded in the object. A stolen backup then yields only
   live-week traffic, which is ordinary device compromise. Needs a generous
   delivery window afterwards, or store-and-forward breaks.
2. **Derive private halves from a seed** rather than storing them, and ratchet
   the seed forward. Shrinks nothing by itself, but makes destruction coherent —
   there is no file the filesystem may have copied three times — and makes the
   others cheap.
3. **Split the seed, cold and warm.** The private key needs both halves; the
   warm half lives on the node, the cold half is advanced on a quarterly
   schedule. A leaked backup then exposes one quarter. Strongest guarantee,
   most friction.
4. **Exclude key material from node backups entirely**, by default. Not
   cryptography, free, and it removes the stated scenario rather than shrinking
   it.

Provisional leaning: 4 immediately, 2 in v1 so the seed structure does not need
a format break later, 1 or 3 only if measurement or threat model demands it.
Lookahead defaults to roughly a quarter, configurable, with the exposure stated
in the documentation rather than buried.

## 37.2 Public echo abuse

Section 14 and D7 gate **private** messages only. Public areas are open by
design: anyone may post to `GOSUB.DEV` and it replicates to every subscriber,
with moderation (section 12) applied after the fact and per community. That is
Usenet's model, and Usenet lost.

This now has a second, more consequential instance: the open area carrying
`NodeProfile` objects (17.4), where junk enters everyone's candidate table.
Per-peer ingest caps and provenance ranking blunt it. Neither is a solution.

## 37.3 Cold identity resolution

An identity obtained out of band — a bare ID on paper from a stranger — may be
unresolvable if none of D12's four paths reaches it. The realistic answers are
social rather than protocol: distribute a carrier alongside the ID, have the
introducer relay the snapshot, or accept the limit and document it. Every
ordinary way of meeting someone — reading an echo, an introduction, an
invitation, meeting in person — already carries the snapshot with the ID.

## 37.4 Metadata concentration at carriers

Section 8.2 concedes that a relay on the path sees author and recipient. A
carrier sees it for its entire catchment, continuously, and D13 encourages
listing two, which doubles the copies rather than halving the exposure. This is
the strongest argument for section 8.4's sealed recipient metadata eventually,
and until then it deserves plain statement in user-facing documentation: *your
carrier holds your complete social graph.*

## 37.5 Per-key sequence verification under partial replication

Section 3.3 step 4 requires confirming that `sequence` follows the last seen
sequence for a signing key. Under partial replication a node sees only the
fraction of a key's output that landed in streams it subscribes to, so gaps are
the normal case and carry no information. Either the check weakens to "never
decreases", or gaplessness requires a per-key stream that nothing obliges anyone
to carry.
