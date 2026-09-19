# Agent notes

Things agents working on this repository found out the hard way. Append-only.

This is the scratch layer beneath [`AGENTS.md`](../AGENTS.md). `AGENTS.md` holds
settled rules and stays short; anything you learned that the next agent would want
to know goes here first, at the bottom, with the evidence attached.

## How this works

**Adding.** Append a note. Do not edit existing ones except to add a Checked or
Contradicted line, or to change Status. Newest at the bottom, so two agents
appending in the same week rarely collide.

**Confirming.** If a note helped you, re-run its check and append a `Checked`
line. That is worth more than agreement: it says the claim still holds on your
machine, on today's toolchain, and names who verified it.

**Disagreeing.** Append a `Contradicted` line with what you observed instead, then
set `Status: disputed`. Do not delete the note. A claim that turned out wrong is
itself worth knowing, and deleting it invites the next agent to rediscover it.

**There are no scores.** Deliberately. Agents share priors, so a confidently wrong
claim attracts agreement from agents making the same mistake — a tally would
measure correlation and read as truth, and a visible score anchors the next reader
into agreeing with it. A dated line naming what somebody actually re-ran carries
the same information and can be audited.

**Graduating.** A note that keeps proving useful gets promoted into `AGENTS.md`;
the note stays here with `Status: promoted`. Better still, if the finding can be
written as a test, write the test — the suite then checks it on every run, which
beats any number of confirmations.

**Format.** Keep it to what a reader needs: the claim, how to check it, and what
it changes about how you work.

```markdown
## <short title>
- **Found:** <date> — <what you were doing when it bit you>
- **Claim:** one sentence, falsifiable
- **Check:** a command, a test name, or a file:line
- **So:** what to do differently
- **Status:** open | promoted | disputed | withdrawn (<reason>)
```

---

## Ctrl-S never reaches the program
- **Found:** 2026-09-18 — binding Ctrl-S to "send" in `pigeoned`; the keystroke did
  nothing and the screen sat unchanged.
- **Claim:** Ctrl-S is XOFF. The line discipline consumes it, so a TUI cannot use
  it as a keybinding on a normal terminal.
- **Check:** run any ratatui app under tmux, `tmux send-keys -t <s> C-s`, and watch
  the key handler never fire.
- **So:** this is why every FidoNet reader ended a message with `Esc` and then
  asked whether to send. Copy that, rather than rediscovering why.
- **Status:** promoted — the reasoning lives in `crates/pigeonnet-tui/src/app.rs`.

## `cargo test` and `cargo clippy` do not refresh the binary
- **Found:** 2026-09-18 — twice in one session, testing `target/debug/pigeoned`
  against behaviour that had already been fixed, and drawing a wrong conclusion
  from it both times.
- **Claim:** neither command writes `target/debug/<bin>`. Only `cargo build` and
  `cargo run` do.
- **Check:** edit a binary's `main`, run `cargo clippy`, then check the mtime of
  `target/debug/<bin>` — unchanged.
- **So:** `cargo build -p <crate>` before running a binary you just changed. A
  stale binary looks exactly like a bug that will not die.
- **Status:** promoted.

## tmux ignores `-x`/`-y` on a server that has attached clients
- **Found:** 2026-09-18 — trying to render a TUI at 80x24 to check narrow layouts,
  and getting a 193x48 pane every time.
- **Claim:** the global `window-size` option defaults to `latest`, which sizes a
  window from the most recently attached client. If you already have tmux open, a
  new detached session inherits *that* size and `-x`/`-y` are ignored. `-f /dev/null`
  does **not** help: the option lives in the running server, not in the config file
  a new client reads. Either use a separate server, or set the option:

  ```bash
  tmux -L probe new-session -d -s s -x 80 -y 25 'cmd'   # own server, no clients
  tmux set-option -t s window-size manual \; resize-window -t s -x 80 -y 25
  ```

  Note the pane is one row shorter than `-y`: the status line takes it. `-y 25`
  gives the 80x24 those readers were built for.
- **Check:** `tmux display -p -t <session> '#{pane_width}x#{pane_height}'`.
- **So:** print the pane size before trusting any small-terminal screenshot.
  Better, use ratatui's `TestBackend`, which takes exactly the size you give it —
  see the tests in `crates/pigeonnet-tui/src/ui.rs`.
- **Status:** open. An earlier version of this note claimed `-f /dev/null` fixed
  it; that was wrong, and writing down the check is what caught it.

## The suite is slow on purpose, and does not parallelise across runs
- **Found:** 2026-09-18 — a `check-all.sh` run crawling for 30 minutes, which
  looked like a hang.
- **Claim:** most of the wall clock is Argon2 at 64 MiB (D9). `tests/messages.rs`
  alone takes about 95 seconds. Two concurrent runs contend for `target/` and both
  slow to a crawl.
- **Check:** `grep 'finished in' <log>`, and `pgrep -f 'cargo test --workspace' | wc -l`.
- **So:** run one at a time. If you cancel a run, confirm its `cargo` actually
  died — an orphan reparents to systemd and keeps competing for the lock.
- **Status:** open.

## `git add <file>` does not mean only that file is staged
- **Found:** 2026-09-18 — splitting a documentation change into two commits. The
  first was meant to hold `README.md` alone; it took two other files with it,
  because they had been staged earlier in the session and forgotten.
- **Claim:** the index persists across commands. Staging one file does not unstage
  anything else, so a commit contains whatever has accumulated — and `git commit`
  reports nothing about it unless you look.
- **Check:** `git diff --cached --name-only` immediately before `git commit`. Read
  it against what the commit message claims.
- **So:** run that check every time. It also catches the opposite failure — a new
  file never staged at all, which is how a milestone commit here ended up not
  building. The build check does not catch the first case: a commit with extra
  files in it still compiles.
- **Note:** `git status --short` is a weaker check for this. It shows staged and
  unstaged together in two columns, and a file already committed earlier in the
  session simply does not appear, which reads as "nothing extra is staged".
- **Status:** promoted to `AGENTS.md`.

## `rust-toolchain.toml` overrides the toolchain a CI action installs
- **Found:** 2026-09-18 — the `fuzz` job had failed on every push since M3, so the
  fuzzers guarding untrusted input had never once run in CI. Nobody noticed,
  because the job failed during setup rather than on a finding.
- **Claim:** rustup resolves the toolchain by walking up from the working
  directory, and `rust-toolchain.toml` wins over whatever `dtolnay/rust-toolchain@nightly`
  made default. The fuzz crate is its own workspace, but it still sits under the
  repo root, so `cargo fuzz` ran under pinned stable and rustc rejected
  `-Zsanitizer=address` before trying a single input. The fix is an explicit
  `cargo +nightly fuzz run ...`; the action is still needed, to install nightly.
- **Check:** `cd fuzz && rustc --version` — prints the pinned stable, not nightly.
  Then `cargo fuzz run object_decode -- -max_total_time=5` reproduces it exactly.
- **So:** any step needing a different toolchain than the pinned one must say so
  with `+toolchain`. Installing it is not selecting it.
- **And:** a CI job that fails in setup looks the same as one that fails on a real
  finding. When a job has never been green, confirm it can run at all before
  trusting it as a guard. All five targets pass — 21 million runs across them with
  no crash — so nothing was hiding behind the broken setup, but that was luck and
  not something the red build could tell anyone.
- **Status:** open.

## A constant added as a performance guard was setting a security parameter
- **Found:** 2026-09-18 — answering §37.1, the design's largest open question.
  The document framed it as "how far ahead should prekeys be published?" and the
  answer turned out to be that publishing was never the control.
- **Claim:** `MAX_DERIVATION_SPAN` in `crates/pigeonnet-crypto/src/prekey.rs` was
  introduced to stop a caller spending an afternoon deriving an epoch a century
  away — its comment says exactly that, honestly. But `PrekeySeed::keypair` will
  derive anything within that span, so at 4096 daily epochs a stolen keystore
  opened about **eleven years** of future traffic. The performance bound was the
  security bound, and no document said so.
- **Check:** `grep -n 'MAX_DERIVATION_SPAN' crates/pigeonnet-crypto/src/prekey.rs`
  and `grep -n 'EPOCH_MILLIS' crates/pigeonnet-node/src/snapshot.rs`. Multiply.
- **So:** when a limit bounds what an attacker can do, it is policy, and belongs
  where policy is reviewed — not in a `const` justified by compute cost. D16 moves
  it into the keystore as a derivation window.
- **And:** the reframing is the reusable part. Before arguing about a parameter,
  check it is the quantity that actually controls the risk. Lookahead constrains
  honest senders; derivability constrains the thief. Cutting lookahead to one
  epoch would have changed nothing and felt like progress.
- **Status:** open — D16 is written, the implementation has not landed.

## A crypto parameter that is a compile-time constant is part of the build, not the file
- **Found:** 2026-09-18 — trying to make the suite faster. At production cost one
  Argon2 derive takes ~1.7 s in a debug build, and the suite opens keystores
  hundreds of times; `tests/messages.rs` alone took 73 s locally and 95 s in CI.
- **Claim:** the obvious fixes — a cargo feature, `cfg(test)`, `cfg(debug_assertions)`
  — are all wrong here, and not only for the usual reason that a feature can be
  enabled by any crate in the graph. The keystore did not record its cost, so the
  parameters were effectively part of the file format: a build that used different
  ones produced files no other build could open. Lowering the cost for tests would
  have made test keystores unreadable by the real binary, and raising the
  production cost later would have orphaned every keystore in existence.
- **Check:** `Keyring::params_of` on a v2 file, and the version byte at offset 8.
- **So:** record the parameters in the file, authenticated. Then any build opens
  any file, the default can move later, and tests pass an explicit cheap cost.
  Sealing takes the cost as an argument; only `KdfParams::insecure_for_tests()`
  is weak, and it is a function with an unpleasant name so every use shows in a
  diff. Result: 73 s to 4 s, with no way to reach it by accident.
- **And:** bumping a format version breaks whoever is already running it. Three
  live nodes had v2 keystores, one of them serving publicly, and identities
  cannot be recreated because recovery is not built (D11, M8). Reading the old
  version is a few lines; check for existing files before assuming a clean break.
- **Status:** open.

## Rotating a key window must not destroy the window it replaces
- **Found:** 2026-09-19 — implementing D16. The first version held one warm seed
  and replaced it when the next window opened. It passed every test I had written,
  because none of them rotated *early*.
- **Claim:** an operator rotates before the current window runs out — waiting until
  it is spent would leave senders on `fs: none`. Replacing the seed at that moment
  destroys the secrets for epochs that are still inside their retention period and
  whose public halves are already published. Mail sealed to them becomes
  undecryptable and nothing says so.
- **Check:** publish, open the next window, then ask for a secret from the first:
  `epoch 2959 was destroyed; earliest derivable is 2964`.
- **So:** hold both. Two windows, and provably never three — an epoch is needed
  until its end plus `W` (30 days), and a window is a quarter, so window `w` is
  live for 30 days into `w+1` and never reaches `w+2`. Do that arithmetic before
  choosing how much to keep; it turns "how many?" from taste into a fact.
- **And:** the flaw was invisible to tests that only ever rotated at the boundary.
  When a change is about *when* an operator does something, test the moment they
  would actually pick, not the moment the code makes easiest.
- **Status:** open.

## Changing a unit renumbers everything already stored in it
- **Found:** 2026-09-19 — D16 moved epochs from daily to weekly, which is a
  one-line constant. The live node then reported window `20594..20605` against
  current epoch `2959`, and could not publish at all.
- **Claim:** an epoch number is meaningless without the epoch length, so changing
  the length silently reinterprets every stored number. The keystore held a daily
  epoch; the clock now produced weekly ones. The window was unreachable in both
  directions, and `status` printed "about 123522 days remaining" rather than
  admitting it.
- **Check:** `nodectl prekeys status` against a keystore written before the change.
- **So:** a stored value in changed units needs a migration, not a reinterpretation.
  `prekeys reanchor` discards the meaningless window and anchors a new one; it is
  the only operation permitted to move backwards, and it says why in its own docs.
  Also: when a computed figure can be nonsense, check the precondition and say so
  instead of printing the figure.
- **Status:** open.
