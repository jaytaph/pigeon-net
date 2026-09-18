# Working on Pigeonnet

Every line of this repository was written by an AI agent, and that is meant to
continue: changes arrive as agent-generated pull requests that follow this file.

The rules below are not style preferences. Most of them exist because something
went wrong once, and each is checkable — by a script, a lint, or a command you can
run. Where a rule has a reason, the reason is given; where it has a section number,
that section of the architecture is the authority.

## Read before changing anything

[`docs/pigeonnet-architecture.md`](docs/pigeonnet-architecture.md) is the source
of truth. It is long, and you do not need all of it — but you do need the part
covering whatever you are about to touch, because most of the surprising code is
surprising on purpose.

Decisions are numbered `D1`..`D15` in §33 and are cited from code and commit
messages. If a change contradicts one, that is a decision to reopen in the
document first, not to route around in the code.

[`docs/pigeonnet-milestones.md`](docs/pigeonnet-milestones.md) says what is built,
what is next, and what each piece must do before it counts as done.

## The gate

```bash
./scripts/check-all.sh
```

Format, clippy, the whole test suite, crate layering, supply chain, and a build on
the minimum supported Rust. It is what CI runs. Nothing is finished until it exits
zero.

It takes several minutes, mostly in Argon2 — the keystore is deliberately
expensive (D9) and the tests pay that cost honestly rather than weakening it.
Budget for that instead of assuming something has hung, and do not run two copies
at once: they contend for `target/` and both crawl.

## Non-negotiables

**No panics on foreign bytes.** `unwrap`, `expect`, `panic!` and `dbg!` are denied
workspace-wide; slice indexing warns. Nothing on a path that touches bytes from
outside this process may panic, because those bytes arrive from untrusted relays.
Tests may opt out with a scoped `#[allow]`, and only tests.

**No unsafe.** `unsafe_code = "forbid"`. There is no escape hatch, and a problem
that seems to need one is a design problem. When `nodectl` needed to restore the
default `SIGPIPE` handler — which requires unsafe — it checked for `BrokenPipe` on
every write instead.

**The pure crates stay pure.** `core`, `crypto`, `proto` and `bundle` take no I/O,
no clock and no ambient randomness: time and entropy are passed in. That is what
makes validation reproducible in a test and fuzzable without a network, and a
stray dependency costs it silently — nothing fails, the code simply stops being
testable the way the architecture assumes. `./scripts/check-layering.sh` enforces
it (§34.1).

**Canonical encoding is checked before signatures.** Every object is decoded,
re-encoded, and required to be byte-identical before its signature is looked at
(D2). One value has exactly one encoding; anything else lets two nodes disagree
about what they both verified.

**Public items are documented.** `missing_docs` warns, and a warning fails the
gate.

## Verifying your own work

**Look at what is staged before every commit.** Not what you meant to stage —
what is actually there:

```bash
git diff --cached --name-only
```

The index carries things forward. A file staged earlier and forgotten rides along
into the next commit, and a new file never staged is silently absent. Both have
happened here: a milestone commit that did not build because five new files were
missing, and a docs commit that swallowed two files belonging to the one after it.
This check costs a second and catches both, which the build check below does not —
a commit with extra files in it still builds.

**Every commit must build on its own.** Not just the branch tip. One milestone
commit here did not, because five new files were never staged, and it was only
found much later. Check it:

```bash
git worktree add -q --detach /tmp/verify <rev>
CARGO_TARGET_DIR=/tmp/verify-target cargo check --workspace --all-targets --manifest-path /tmp/verify/Cargo.toml
git worktree remove --force /tmp/verify
```

**Rebuild before you test a binary.** `cargo test` and `cargo clippy` do not
produce `target/debug/*`. Testing a stale binary and believing the result wastes
more time than the rebuild ever will.

**Confirm an edit landed.** A scripted search-and-replace that matches nothing
fails silently and looks exactly like success. Assert the match count.

**Prefer a test that would have caught it.** Tests read as sentences —
`a_reply_inherits_its_parents_area_and_thread`,
`a_declared_frame_length_cannot_reserve_memory` — and say what must be true,
not what the code does. Hostile input belongs in `fuzz/fuzz_targets/`.

## Commits

A terse one-line subject, lower case, usually `area: what changed`:

```
net: one outbound connection syncs both ways
proto: require a peer to prove the identity pinned to its address
core: the DirectMessage envelope, bound but not hidden
```

Split work so each commit is a step someone could review on its own, and order
them so each one builds. A body is for a reason that is not obvious from the
diff; most commits do not need one.

**Do not list Claude or Anthropic as a co-author.** A `commit-msg` hook rejects
it. If the hook fires, say so and stop — do not disable it, bypass it, or edit
around it.

## Comments

Comments carry the reason, never the restatement. `// increment the counter` is
noise; why the counter exists, what breaks without it, or what was tried and
rejected is the thing worth writing. Cite `§` sections and `D` numbers for
anything the architecture decided.

Say plainly what a thing does *not* do. An `AreaStats` that counts what one node
holds says so, because a reader would otherwise take it for what the area
contains. That habit is why the awkward parts of this codebase are legible.

## Passing on what you find

Anything you worked out that the next agent would want to know goes in
[`docs/agent-notes.md`](docs/agent-notes.md) — append-only, newest at the bottom.
This file stays short and settled; that one is where findings land first.

Every note carries the command that checks it. If a note helped you, re-run its
check and append a dated line saying you did; if it turns out wrong, append what
you saw instead and mark it disputed, but do not delete it — a claim that failed
is worth knowing, and deleting it invites the next agent to rediscover it.

There is no score. Agents share priors, so a tally would measure how many of us
made the same mistake and then read as truth, and a visible number anchors the
next reader into agreeing. A dated line naming what somebody actually re-ran says
more and can be checked. If a finding can be written as a test, write the test
instead: the suite then verifies it on every run.

## Traps this repo has already fallen into

- **A timestamp is a claim.** `timestamp` is when the author *says* an object was
  created (§3.3). A signature proves who wrote something and that it has not
  changed — never when. Anything needing real ordering must derive it elsewhere.
- **Sorting by signing key is not causal order.** Replay follows the key chain, not
  the lexicographic order of key bytes; getting this wrong produced a test that
  failed half the time.
- **A node's own identity is stored, not inferred.** Scanning for a genesis object
  works until the first sync brings in somebody else's.
- **Do not report a number you cannot know.** A serving session learns what it was
  asked for, never what the asker kept. Reporting zero would have been worse than
  reporting nothing.
