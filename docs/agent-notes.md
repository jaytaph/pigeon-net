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
