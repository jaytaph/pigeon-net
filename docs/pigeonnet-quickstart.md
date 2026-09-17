# Pigeonnet: Five Minute Quickstart

> **Nothing here is built yet.** This is the target user experience, written
> against the locked decisions in `pigeonnet-architecture.md` (D1–D8). Its job is
> to find out whether those decisions produce a tool anyone would want to use,
> *before* the tool exists. If a step below feels absurd, that is a bug in the
> architecture, not in the tutorial.

You will create an identity, join a public discussion, exchange a private
message, and pull down a file — in about five minutes.

---

## 0:00 — Create a node and an identity

```bash
nodectl init
nodectl identity create --name joshua
```

```text
Generating root key      ed25519 ........ ok
Generating recovery key  ed25519 ........ ok
Generating identity key  x25519  ........ ok
Writing genesis object   IdentityCreated  ok

  Your identity is
      id:b3:9fq2m4x7kv3nbz8hwd5tqr2xjm4nfyz8h3wd5tqr2xjm

  Fingerprint (read this aloud to verify in person)
      B2A7 F912 02DE 8B41
      91CD 772A D15F F821

Granting device key      "this-laptop"    ok
Publishing epoch prekeys 14 epochs ahead  ok
Locking keystore         argon2id         ok

  ⚠  RECOVERY KEY — write this down, on paper, now.

      truck  amber  vault  prism  otter  clove
      fennel gauge  marsh  tide   quill  ridge

     Not stored on this machine. Will not be shown again.

  ⚠  Your root key is at ~/.pigeonnet/root.key (encrypted)
     Back it up offline and remove it from this machine.
```

Four things just happened that are unlike email.

**Your identity is the hash of that genesis object, not a key and not an
address.** You can rotate every key you own and stay the same person, and you are
not `joshua@somewhere` — you are not hosted anywhere. The name `joshua` is a
local label.

**Your root key is not what you sign posts with.** It signed one thing: a
`DeviceKeyGranted` object for this laptop. The laptop's device key does the daily
work — including publishing your prekeys, which is why the root can live in a
drawer instead of being touched every day (architecture §5.4).

**And you wrote twelve words down.** That is the recovery key, and it outranks
the root key. If someone steals your root key and starts signing as you, those
twelve words evict them: you publish one `RootKeyReplaced`, and their entire
branch of your key chain goes void on every node that sees it. You cannot lose
that race, because ranking is by role and not by timestamp — there is no race,
only an eviction, whenever you get around to it.

Lose *both* keys and the identity is genuinely gone. That is the floor, and
nothing recovers from it (§5.5).

**You published two weeks of epoch prekeys.** Those are what let someone encrypt
to you while you are offline. One per day, and a sender picks by the calendar
rather than choosing from a pool — so there is nothing to run out of, whether you
have ten correspondents or ten thousand.

```bash
nodectl prekeys status
```

```text
epoch 118   current      valid_until 2026-10-16   (30d)
epoch 119   published    valid_until 2026-10-17
...
epoch 131   published    valid_until 2026-10-29
epoch 087   expired      private half destroyed 2026-09-15
```

The interesting column is `valid_until`. Thirty days after an epoch ends, you
destroy that key's private half — and that destruction is what makes messages
from that window permanently unrecoverable, including the copies sitting on
relays you will never see. Forward secrecy here is a deletion schedule, not a
handshake.

There is nothing to top up and no pool to monitor (architecture §8.1).

---

## 0:45 — Add a peer

You need somewhere to exchange objects with. A peer is not a server you have an
account on; it is just another node that agrees to swap objects with you.

```bash
nodectl peer add ams-hub tcp://node.example.net:4137
nodectl sync
```

```text
ams-hub  connected
  identity  id:b3:4kq8...  (unverified — run: nodectl peer verify ams-hub)
  streams   142 available
  received  0 objects
  sent      1 object (IdentityCreated)
done in 0.4s
```

---

## 1:15 — Join a public area and post

```bash
nodectl echo list --peer ams-hub
nodectl echo subscribe GOSUB.DEV
nodectl sync
```

```text
echo://GOSUB.DEV   cursor 0 -> 4193   received 4193 objects (2.1 MB)
```

Read it, then post:

```bash
nodectl echo read GOSUB.DEV --last 5
nodectl post GOSUB.DEV "Hello from a new node."
```

```text
created  obj:b3:c81faa27mn4k...
signed   ed25519:c3a81f... (this-laptop, seq 1)
queued   for 1 subscribed peer
```

Note it says **queued**. Nothing has left your machine. Posting is a local act
that creates a signed object; replication is a separate thing that happens when
you sync.

```bash
nodectl sync
```

Replying threads explicitly — no header archaeology:

```bash
nodectl reply obj:b3:7f22e1c9... "Works here too, Debian 13."
```

Your reply records both its immediate `parent` and the root `thread`, so the tree
is deterministic on every node that holds it (§7).

---

## 2:15 — Become someone's contact

Here is the biggest departure from email: **an unknown identity cannot simply
send you things.**

Alice wants to reach you. She gets exactly one shot, size-capped and
rate-limited:

```bash
# on Alice's node
nodectl contact request id:b3:9fq2m4x7... "Met you at the Rust meetup — Alice"
```

On your node, after a sync:

```bash
nodectl contact pending
```

```text
id:b3:2mx7q4...  "Met you at the Rust meetup — Alice"
                 introduced by: (none)  ·  received 12m ago
```

```bash
nodectl contact accept id:b3:2mx7q4... --name alice
```

Until you do that, Alice cannot send you a second thing. That is the whole spam
model: no filter guessing at content, just a gate that is closed by default (§14).

If you would rather skip the request dance, hand out an invitation instead:

```bash
nodectl invite create --count 5
```

```text
pgn-inv-8kq2m4x7nfyz8h3w   expires in 14d, single use
```

Anyone redeeming that token becomes your contact directly — and because tokens
are signed and traceable, if you hand them to a spammer, everyone can discount
*your* invitations wholesale.

---

## 3:15 — Send a private message

```bash
nodectl message alice "Want to test file transfer?"
```

```text
created   obj:b3:d41a99f2...
encrypted x25519 -> epoch key 118   chacha20-poly1305
          forward-secret until 2026-10-16
signed    ed25519:c3a81f... (this-laptop, seq 2)
routed    via ams-hub (cost 2)
queued
```

```bash
nodectl sync
```

The object crosses `ams-hub`, and possibly several more nodes, none of which can
read it. They see who it is from and who it is for — that metadata is what they
route on, and Pigeonnet does not hide it (§8.2). They cannot see a word of the
content.

Alice's side:

```bash
nodectl inbox
nodectl read obj:b3:d41a99f2...
```

```text
from      alice → you
received  via ams-hub, 2 hops, 40s in transit
verified  signature ok · device key valid at send time
secrecy   forward-secret from 2026-10-16 (epoch key 118)

Want to test file transfer?
```

Alice destroyed her ephemeral key the moment she sent this, so seizing her laptop
tomorrow recovers nothing. Your side is protected until 16 October by a key on
your disk behind your passphrase; after that date you destroy it, and the message
becomes unreadable to everyone — you, `ams-hub`, and any archival node that kept
a copy.

If you would rather keep a readable archive past that date, your node re-encrypts
messages under its own storage key on receipt. That is the default. The opposite
setting — let the plaintext die with the epoch key — is one line of config, and
is the honest version of "delete this message" (architecture §25.1).

---

## 4:00 — Receive a file

Files are not attachments. They are content-addressed objects, and a file area
works like a discussion area that carries bytes.

```bash
nodectl files subscribe GOSUB.RELEASES
nodectl sync
nodectl files list GOSUB.RELEASES
```

```text
file:b3:9c41f0a2...  gosub-0.3.1.tar.zst   46.0 MB  signed by id:b3:9fq2...
file:b3:1de77b40...  gosub-0.3.0.tar.zst   45.2 MB  signed by id:b3:9fq2...
```

You have the *manifests* — small signed objects naming the content. The bytes
come on demand:

```bash
nodectl file get file:b3:9c41f0a2... -o gosub-0.3.1.tar.zst
```

```text
  from ams-hub           28.1 MB / 46.0 MB   61%   3.2 MB/s
  verified continuously against BLAKE3 root
^C
```

Interrupt it, unplug the network, come back tomorrow, and fetch from somewhere
else entirely:

```bash
nodectl file get file:b3:9c41f0a2... -o gosub-0.3.1.tar.zst
```

```text
  resuming at 61%
  from mirror3          46.0 MB / 46.0 MB  100%
  root hash verified    b3:9c41f0a2...  ✓
```

Neither `ams-hub` nor `mirror3` had to be trusted. Every chunk was checked
against the root hash as it arrived, so a hostile mirror can refuse to serve you
but cannot hand you altered bytes (§9).

Publishing works the same way in reverse:

```bash
nodectl file publish ./gosub-0.3.2.tar.zst --area GOSUB.RELEASES \
  --notes "Fixes the CSS cascade bug"
```

---

## 4:45 — Sync without a network

Everything above assumed a socket. None of it requires one.

```bash
nodectl bundle export /media/usb/pigeonnet-2026-09-16.pack --for ams-hub
```

```text
  1,204 objects · 3 file manifests · 61.2 MB
  written to /media/usb/pigeonnet-2026-09-16.pack
```

Walk the stick across town. On the other node:

```bash
nodectl bundle import /media/usb/pigeonnet-2026-09-16.pack
```

```text
  1,204 objects offered
  1,198 accepted · 4 already held · 2 rejected (signature invalid)
  cursors advanced
```

A bundle from a stranger's USB stick is as safe to import as a sync with a
trusted peer, because *neither* is trusted: every object is size-checked,
canonicality-checked, hash-checked, and signature-checked before it counts
(§19, §29).

---

## 4:55 — When something arrives too late

Encrypt to an epoch key, and the message has to reach the recipient before that
key's `valid_until`. Usually irrelevant — thirty days is a lot. But a sender who
has not synced in weeks is already holding a key most of the way through its life,
and spends the rest of the budget before pressing send.

When it does miss, it fails loudly:

```bash
nodectl inbox
```

```text
alice   2026-09-14   cannot decrypt — epoch key 118 destroyed 2026-10-16,
                     arrived 4 days late.  Receipt sent with a fresh key.
```

Your node automatically sends Alice an `undecryptable` receipt — and that receipt
**carries your current epoch prekey**, so her client can re-seal and resend
without having to go and re-sync your profile through the same slow path that
caused the problem in the first place. On her side it is one command, or nothing
at all if she has retries enabled.

This is not a bounce. Relays never generate anything (architecture §16); this came
from you, after verifying Alice's signature, and only because she is already an
accepted contact. An unknown sender gets silence — otherwise a receipt would be a
handy tool for confirming which identities are real and active.

Silence is still ambiguous, though. A message that expired at a relay three hops
back produces no receipt at all, because there is nobody authenticated at the far
end to produce one. Your client resolves that the way you would expect: no
receipt within N days, assume lost, tell you.

---

## 5:00 — Add your phone

```bash
nodectl device grant --name phone
```

```text
  Scan on the new device:   [QR]
  Granted: ed25519:7b22c4...  capabilities: post, message
```

Your phone now signs as *you*, with its own key, its own sequence counter, and
its own epoch prekeys — so anyone writing to you now seals a copy for each device
you own. It cannot read messages sent before it existed, which is forward secrecy
working rather than a defect. If it is stolen:

```bash
nodectl device revoke ed25519:7b22c4... --reason "stolen"
```

Your identity survives. Your posts from that phone stay valid — revocation is not
retroactive by default, because a thief did not retroactively write your old
messages (§5.4).

---

## What you should take away

| Email habit | Pigeonnet |
|---|---|
| Your address is `you@server` | Your identity is a hash; servers are interchangeable |
| Mail arrives at a mailbox | Objects replicate to nodes that subscribed |
| Send now, delivered now | Create now, replicated at next sync |
| Anyone can mail you | Unknown senders get one contact request |
| Delete removes it | Retraction asks nicely; copies exist (§21) |
| Bad address bounces | Relays never bounce; the recipient reports what it saw (§20) |
| Mail is readable forever | Messages expire cryptographically, by schedule (§8.1) |
| Attachments are copies | Files are shared content-addressed objects |
| Lose your password, reset it | Root key lost? Use the paper one. Both gone? It's over |

The rule underneath all of it:

> There are no mailboxes. There are identities, immutable objects,
> subscriptions, peers, and replication.

## Where to go next

- `pigeonnet-architecture.md` §33 — the eight locked decisions and why
- `pigeonnet-architecture.md` §28 — the five implementation phases
- `pigeonnet-architecture.md` §5.4 — identity recovery, the open gap
