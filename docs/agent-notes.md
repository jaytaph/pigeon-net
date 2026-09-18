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
