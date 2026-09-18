//! What the reader is doing, and what it knows.
//!
//! Deliberately a plain state machine over a `Node`: no async, no tasks, no
//! channels. The one blocking operation is a sync, and a reader that freezes for
//! a second while it talks to a peer is behaving exactly as its ancestors did.

use anyhow::{Context as _, Result};
use pigeonnet_core::{AreaName, ObjectId};
use pigeonnet_node::{AreaStats, Node, ThreadedPost};

use crate::theme::Theme;

/// Which screen is in front of the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum View {
    /// The area list. Where these readers always started.
    Areas,
    /// Messages within one area.
    Messages,
    /// One message, full text.
    Reader,
    /// Writing something.
    Compose,
    /// Key help.
    Help,
}

/// Work that takes long enough that the screen must be repainted first.
///
/// Signing opens the keystore, which is Argon2 over 64 MiB by design (§D9), and
/// a sync talks to another machine. Both take seconds. A key handler that did
/// them inline would freeze the display with no explanation, so they are handed
/// back to the event loop, which draws the notice and then performs them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Work {
    /// Sign and store what has been written.
    Send,
    /// Exchange with every configured peer.
    Sync,
}

/// What a composed message will become when sent.
#[derive(Clone, Debug)]
pub(crate) enum Target {
    /// A new thread in an area.
    Post(AreaName),
    /// A reply, which inherits its area and thread from the parent.
    Reply(ObjectId),
}

/// A message being written.
#[derive(Clone, Debug)]
pub(crate) struct Compose {
    /// Where it goes.
    pub(crate) target: Target,
    /// The text so far.
    pub(crate) body: String,
}

impl Compose {
    fn describe(&self) -> String {
        match &self.target {
            Target::Post(area) => format!("New message in {area}"),
            Target::Reply(_) => "Reply".to_owned(),
        }
    }
}

/// The reader.
pub(crate) struct App {
    node: Node,
    passphrase: Option<Vec<u8>>,
    /// The current colour scheme.
    pub(crate) theme: Theme,
    /// Which screen is showing.
    pub(crate) view: View,
    /// Where `Esc` goes back to.
    previous: View,
    /// Areas, with what this node holds in each.
    pub(crate) areas: Vec<AreaStats>,
    /// Selected area.
    pub(crate) area_cursor: usize,
    /// Messages in the selected area.
    pub(crate) messages: Vec<ThreadedPost>,
    /// Selected message.
    pub(crate) message_cursor: usize,
    /// Scroll offset while reading.
    pub(crate) scroll: u16,
    /// The line along the bottom.
    pub(crate) status: String,
    /// A message being written, if any.
    pub(crate) compose: Option<Compose>,
    /// Set when the user asks to leave.
    pub(crate) quit: bool,
    /// Whether `Esc` has raised the save prompt over a message being written.
    confirming: bool,
    /// Slow work the event loop should perform after the next repaint.
    pending: Option<Work>,
    /// Terminal size as of the last frame, for working out how far a post scrolls.
    size: (u16, u16),
}

impl App {
    /// Open a node and load the area list.
    pub(crate) fn new(node: Node, passphrase: Option<Vec<u8>>, theme: Theme) -> Result<Self> {
        let mut app = Self {
            node,
            passphrase,
            theme,
            view: View::Areas,
            previous: View::Areas,
            areas: Vec::new(),
            area_cursor: 0,
            messages: Vec::new(),
            message_cursor: 0,
            scroll: 0,
            status: String::new(),
            compose: None,
            quit: false,
            confirming: false,
            pending: None,
            size: (80, 24),
        };
        app.reload_areas()?;
        app.status = if app.passphrase.is_some() {
            "Ready.".to_owned()
        } else {
            // Say it once, at the start, rather than at the moment they try.
            "Read only: PIGEONNET_PASSPHRASE is not set.".to_owned()
        };
        Ok(app)
    }

    /// This node's own identity, for marking your own messages.
    pub(crate) fn me(&self) -> Option<pigeonnet_core::IdentityId> {
        self.node.local_identity().ok()
    }

    /// What to call whoever wrote something.
    pub(crate) fn who(&self, identity: pigeonnet_core::IdentityId) -> String {
        let now = now_millis();
        match self.node.naming(identity, now) {
            Ok(naming) => match naming.best() {
                Some(label) if naming.best_is_asserted() => format!("{label}*"),
                Some(label) => label.to_owned(),
                // Enough of the hash to tell two people apart, which is all a
                // list column can do.
                None => identity.to_string().chars().take(18).collect(),
            },
            Err(_) => identity.to_string().chars().take(18).collect(),
        }
    }

    /// The area under the cursor.
    pub(crate) fn current_area(&self) -> Option<&AreaStats> {
        self.areas.get(self.area_cursor)
    }

    /// The message under the cursor.
    pub(crate) fn current_message(&self) -> Option<&ThreadedPost> {
        self.messages.get(self.message_cursor)
    }

    pub(crate) fn reload_areas(&mut self) -> Result<()> {
        // Which area the cursor is on, by name. Sorting is by recency, so posting
        // to an area moves it up the list; holding the index rather than the name
        // would silently switch the user to a different area.
        let selected = self.current_area().map(|a| a.area.clone());

        let mut areas = self.node.area_stats()?;
        areas.retain(|a| a.subscribed || a.posts > 0);
        areas.sort_by(|a, b| b.latest.cmp(&a.latest).then_with(|| a.area.cmp(&b.area)));
        self.areas = areas;

        self.area_cursor = selected
            .and_then(|name| self.areas.iter().position(|a| a.area == name))
            .unwrap_or_else(|| self.area_cursor.min(self.areas.len().saturating_sub(1)));
        Ok(())
    }

    /// Open the selected area.
    pub(crate) fn enter_area(&mut self) -> Result<()> {
        let Some(area) = self.current_area().map(|a| a.area.clone()) else {
            return Ok(());
        };
        self.messages = self.node.read_area(&area)?;
        self.message_cursor = 0;
        self.scroll = 0;
        if self.messages.is_empty() {
            self.status = format!("{area} has no messages here yet.");
        } else {
            self.view = View::Messages;
            self.status = format!("{} message(s) in {area}.", self.messages.len());
        }
        Ok(())
    }

    pub(crate) fn open_message(&mut self) {
        if self.current_message().is_some() {
            self.scroll = 0;
            self.view = View::Reader;
        }
    }

    /// Back out one level.
    pub(crate) fn back(&mut self) {
        match self.view {
            View::Reader => self.view = View::Messages,
            View::Messages => self.view = View::Areas,
            View::Help => self.view = self.previous,
            View::Compose => {
                // Esc ends the message and asks what to do with it, which is how
                // every one of these readers worked -- and not by accident. The
                // obvious alternative, Ctrl-S, is XOFF: on a real terminal the
                // line discipline eats it and the keystroke never arrives.
                let written = self
                    .compose
                    .as_ref()
                    .is_some_and(|c| !c.body.trim().is_empty());
                if written {
                    self.confirming = true;
                    self.status =
                        "Save this message?  Y send   N discard   any other key resume".to_owned();
                } else {
                    // Nothing typed, so there is nothing to ask about.
                    self.discard();
                }
            }
            View::Areas => self.quit = true,
        }
    }

    pub(crate) fn show_help(&mut self) {
        if self.view != View::Help {
            self.previous = self.view;
            self.view = View::Help;
        }
    }

    pub(crate) fn cycle_theme(&mut self) {
        self.theme = self.theme.next();
        self.status = format!("Theme: {}.", self.theme.name());
    }

    pub(crate) fn move_cursor(&mut self, delta: isize) {
        let shift = |cursor: &mut usize, len: usize| {
            if len == 0 {
                return;
            }
            let last = len - 1;
            *cursor = cursor.saturating_add_signed(delta).min(last);
        };
        match self.view {
            View::Areas => shift(&mut self.area_cursor, self.areas.len()),
            View::Messages => shift(&mut self.message_cursor, self.messages.len()),
            View::Reader => {
                let step =
                    i16::try_from(delta).unwrap_or(if delta < 0 { i16::MIN } else { i16::MAX });
                self.scroll = self
                    .scroll
                    .saturating_add_signed(step)
                    .min(self.scroll_limit());
            }
            View::Compose | View::Help => {}
        }
    }

    /// Remember the terminal size, so scrolling knows where a post ends.
    pub(crate) fn note_size(&mut self, width: u16, height: u16) {
        self.size = (width, height);
    }

    /// How far the current message can scroll before its last line is on screen.
    ///
    /// The text is wrapped to work this out, because counting newlines would give
    /// a limit of zero for a post written as one long paragraph -- which would make
    /// it unscrollable, and most posts typed in one sitting look exactly like that.
    fn scroll_limit(&self) -> u16 {
        let Some(post) = self.current_message() else {
            return 0;
        };
        let (width, height) = self.size;
        // The reader's body: the frame less the title, status and key bars, less
        // the box borders, less the message header.
        let body = height.saturating_sub(3 + 2 + crate::ui::READER_HEADER);
        let wrapped = wrapped_lines(&post.post.content, width.saturating_sub(2));
        u16::try_from(wrapped.saturating_sub(usize::from(body))).unwrap_or(u16::MAX)
    }

    /// Space: a screenful, and then the next message once the end is reached.
    ///
    /// Which is what the space bar did in every one of these readers -- you held
    /// it down and walked the whole area without touching another key.
    pub(crate) fn advance(&mut self) {
        let limit = self.scroll_limit();
        if self.scroll < limit {
            let page = self.size.1.saturating_sub(10).max(1);
            self.scroll = self.scroll.saturating_add(page).min(limit);
        } else if !self.step_message(1) {
            self.status = "End of area. Esc goes back.".to_owned();
        }
    }

    /// Move to the next or previous message while still reading it.
    ///
    /// Returns whether it actually moved. At either end it stays put and keeps the
    /// scroll position, rather than silently jumping back to the top of the
    /// message already on screen.
    pub(crate) fn step_message(&mut self, delta: isize) -> bool {
        if self.messages.is_empty() {
            return false;
        }
        let last = self.messages.len() - 1;
        let moved = self.message_cursor.saturating_add_signed(delta).min(last);
        if moved == self.message_cursor {
            return false;
        }
        self.message_cursor = moved;
        self.scroll = 0;
        true
    }

    // -- writing ------------------------------------------------------------

    pub(crate) fn begin_post(&mut self) {
        let Some(area) = self.current_area().map(|a| a.area.clone()) else {
            return;
        };
        self.start_compose(Target::Post(area));
    }

    pub(crate) fn begin_reply(&mut self) {
        let Some(id) = self.current_message().map(|m| m.id) else {
            return;
        };
        self.start_compose(Target::Reply(id));
    }

    fn start_compose(&mut self, target: Target) {
        if self.passphrase.is_none() {
            self.status = "Cannot write: PIGEONNET_PASSPHRASE is not set.".to_owned();
            return;
        }
        self.previous = self.view;
        self.confirming = false;
        self.compose = Some(Compose {
            target,
            body: String::new(),
        });
        self.view = View::Compose;
        self.status = COMPOSE_HELP.to_owned();
    }

    /// Whether the save prompt is up.
    #[must_use]
    pub(crate) const fn confirming(&self) -> bool {
        self.confirming
    }

    /// Answer the save prompt.
    pub(crate) fn answer(&mut self, key: char) {
        self.confirming = false;
        match key {
            'y' | 'Y' => self.arm(Work::Send, "Signing..."),
            'n' | 'N' => self.discard(),
            // Anything else resumes editing. A prompt that treats an unexpected
            // key as "discard" is a prompt that loses messages.
            _ => self.status = COMPOSE_HELP.to_owned(),
        }
    }

    /// Queue slow work and say what is about to happen.
    fn arm(&mut self, work: Work, note: &str) {
        self.pending = Some(work);
        self.status = note.to_owned();
    }

    /// Queue a sync, so the notice is on screen before the connection is made.
    pub(crate) fn request_sync(&mut self) {
        self.arm(Work::Sync, "Syncing...");
    }

    /// Take whatever slow work is queued, to be run after a repaint.
    pub(crate) fn take_work(&mut self) -> Option<Work> {
        self.pending.take()
    }

    /// Do it.
    pub(crate) fn perform(&mut self, work: Work) -> Result<()> {
        match work {
            Work::Send => self.send(),
            Work::Sync => self.sync(),
        }
    }

    /// Throw away what was being written.
    fn discard(&mut self) {
        self.compose = None;
        self.confirming = false;
        self.view = self.previous;
        self.status = "Abandoned.".to_owned();
    }

    pub(crate) fn compose_char(&mut self, c: char) {
        if let Some(compose) = self.compose.as_mut() {
            compose.body.push(c);
        }
    }

    pub(crate) fn compose_backspace(&mut self) {
        if let Some(compose) = self.compose.as_mut() {
            compose.body.pop();
        }
    }

    /// Sign and store what has been written.
    fn send(&mut self) -> Result<()> {
        let Some(compose) = self.compose.take() else {
            return Ok(());
        };
        if compose.body.trim().is_empty() {
            self.status = "Nothing to send.".to_owned();
            self.compose = Some(compose);
            return Ok(());
        }
        let passphrase = self.passphrase.clone().context("no passphrase")?;
        let now = now_millis();

        let result = match &compose.target {
            Target::Post(area) => self.node.post(area, &compose.body, &passphrase, now),
            Target::Reply(parent) => self.node.reply(*parent, &compose.body, &passphrase, now),
        };

        match result {
            Ok(id) => {
                let short: String = id.to_string().chars().take(18).collect();
                // "Queued", not "sent": it is written locally and travels on the
                // next sync. The distinction matters here more than most places.
                self.status = format!("Queued {short}... Press S to sync.");
                self.view = self.previous;
                self.refresh_after_write()?;
            }
            Err(error) => {
                self.status = format!("Refused: {error}");
                self.compose = Some(compose);
                self.view = View::Compose;
            }
        }
        Ok(())
    }

    fn refresh_after_write(&mut self) -> Result<()> {
        self.reload_areas()?;
        if let Some(area) = self.current_area().map(|a| a.area.clone()) {
            self.messages = self.node.read_area(&area)?;
        }
        Ok(())
    }

    /// Sync with every configured peer.
    fn sync(&mut self) -> Result<()> {
        let Some(passphrase) = self.passphrase.clone() else {
            self.status = "Cannot sync: PIGEONNET_PASSPHRASE is not set.".to_owned();
            return Ok(());
        };
        let peers = self.node.store().peers()?;
        if peers.is_empty() {
            self.status = "No peers configured. Use: nodectl peer add <host>".to_owned();
            return Ok(());
        }

        let local = self.node.node_id(&passphrase)?;
        let limits = *self.node.limits();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("starting a runtime for the sync")?;

        let mut accepted = 0usize;
        let mut failures = Vec::new();
        for peer in peers {
            let now = now_millis();
            let outcome = runtime.block_on(pigeonnet_net::sync_peer(
                &self.node,
                local,
                &peer.address,
                peer.node_id,
                limits,
                now,
            ));
            match outcome {
                Ok(report) => {
                    accepted += report.accepted;
                    if let Some(proved) = report.peer {
                        self.node.store().peer_pin(&peer.address, proved)?;
                    }
                    self.node
                        .store()
                        .peer_record_sync(&peer.address, now, None)?;
                }
                Err(error) => {
                    self.node.store().peer_record_sync(
                        &peer.address,
                        now,
                        Some(&error.to_string()),
                    )?;
                    failures.push(peer.address);
                }
            }
        }

        self.reload_areas()?;
        if let Some(area) = self.current_area().map(|a| a.area.clone()) {
            self.messages = self.node.read_area(&area)?;
        }
        self.status = if failures.is_empty() {
            format!("Synced. {accepted} new message(s).")
        } else {
            format!(
                "Synced with errors ({}). {accepted} new.",
                failures.join(", ")
            )
        };
        Ok(())
    }

    /// What the compose screen should be titled.
    pub(crate) fn compose_title(&self) -> String {
        self.compose
            .as_ref()
            .map_or_else(String::new, Compose::describe)
    }
}

/// What the status line says while a message is being written.
const COMPOSE_HELP: &str = "Esc finishes the message and asks what to do with it.";

/// How many display lines some text occupies once wrapped to `width`.
///
/// Greedy word wrap, matching how the paragraph is actually rendered closely
/// enough to stop scrolling in the right place. A word longer than the width gets
/// a line of its own rather than looping forever.
fn wrapped_lines(text: &str, width: u16) -> usize {
    let width = usize::from(width).max(1);
    text.lines()
        .map(|line| {
            let mut rows = 1usize;
            let mut used = 0usize;
            for word in line.split_whitespace() {
                let len = word.chars().count();
                if used == 0 {
                    used = len;
                } else if used + 1 + len <= width {
                    used += 1 + len;
                } else {
                    rows += 1;
                    used = len;
                }
                // A word wider than the line spills onto further rows.
                while used > width {
                    rows += 1;
                    used -= width;
                }
            }
            rows
        })
        .sum()
}

/// Wall clock, in milliseconds. The one place this program reads a clock.
pub(crate) fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A node directory that cleans up after itself.
    struct Temp(std::path::PathBuf);

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// An empty node, with no passphrase. Cheap: nothing here opens a keystore.
    fn app() -> (Temp, App) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeoned-app-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let node = Node::open(&dir).unwrap();
        let app = App::new(node, Some(b"passphrase".to_vec()), Theme::Ice).unwrap();
        (Temp(dir), app)
    }

    fn writing(app: &mut App, body: &str) {
        app.start_compose(Target::Post(AreaName::parse("TEST").unwrap()));
        for c in body.chars() {
            app.compose_char(c);
        }
    }

    #[test]
    fn esc_over_a_written_message_asks_before_discarding() {
        // The whole point of the prompt: one keystroke must not lose a message.
        let (_temp, mut app) = app();
        writing(&mut app, "something worth keeping");
        app.back();
        assert!(app.confirming(), "no prompt was raised");
        assert_eq!(app.view, View::Compose, "left the editor before asking");
        assert!(app.compose.is_some(), "the text was thrown away");
    }

    #[test]
    fn an_unexpected_key_at_the_prompt_resumes_editing() {
        // A prompt that reads anything-but-N as "discard" is a prompt that loses
        // messages, so anything unrecognised must be the safe answer.
        let (_temp, mut app) = app();
        writing(&mut app, "still being written");
        app.back();
        app.answer('x');
        assert!(!app.confirming());
        assert_eq!(app.view, View::Compose);
        assert_eq!(
            app.compose.as_ref().map(|c| c.body.as_str()),
            Some("still being written")
        );
    }

    #[test]
    fn n_discards_and_y_queues_the_signing() {
        let (_temp, mut app) = app();

        writing(&mut app, "abandon me");
        app.back();
        app.answer('n');
        assert!(app.compose.is_none(), "not discarded");
        assert!(app.take_work().is_none(), "discarding queued work");

        writing(&mut app, "send me");
        app.back();
        app.answer('y');
        assert_eq!(app.take_work(), Some(Work::Send));
    }

    #[test]
    fn esc_over_an_empty_message_just_leaves() {
        // Nothing typed, so there is nothing to ask about.
        let (_temp, mut app) = app();
        writing(&mut app, "   ");
        app.back();
        assert!(!app.confirming());
        assert!(app.compose.is_none());
    }

    #[test]
    fn slow_work_is_announced_before_it_runs() {
        // Signing is Argon2 and a sync crosses a network. Both must be queued for
        // the event loop rather than run inside a key handler, or the screen
        // freezes with the old status still on it.
        let (_temp, mut app) = app();
        app.request_sync();
        assert_eq!(app.status, "Syncing...");
        assert_eq!(app.take_work(), Some(Work::Sync));
        assert!(app.take_work().is_none(), "work was queued twice");

        writing(&mut app, "x");
        app.back();
        app.answer('y');
        assert_eq!(app.status, "Signing...");
    }

    #[test]
    fn wrapping_counts_the_rows_text_really_takes() {
        // Nothing occupies nothing -- `str::lines` yields no lines for "".
        assert_eq!(wrapped_lines("", 20), 0);
        assert_eq!(wrapped_lines("short", 20), 1);
        assert_eq!(wrapped_lines("two\nlines", 20), 2);
        // Greedy over a width of ten: "one two" then "three four", which is
        // exactly ten. Two rows, not three.
        assert_eq!(wrapped_lines("one two three four", 10), 2);
        // A word nobody can fit still terminates, on lines of its own.
        assert_eq!(wrapped_lines(&"x".repeat(25), 10), 3);
        // Width zero must not divide by zero or spin.
        assert!(wrapped_lines("anything at all", 0) > 0);
    }

    #[test]
    fn stepping_past_either_end_stays_put() {
        // The cursor must not wrap, and a refused step must not reset the scroll
        // position of the message already being read.
        let (_temp, mut app) = app();
        assert!(!app.step_message(1), "moved with no messages");
        assert!(!app.step_message(-1), "moved with no messages");
    }

    #[test]
    fn a_sync_with_no_peers_says_what_to_do() {
        let (_temp, mut app) = app();
        app.request_sync();
        let work = app.take_work().unwrap();
        app.perform(work).unwrap();
        assert!(app.status.contains("peer add"), "{}", app.status);
    }
}
