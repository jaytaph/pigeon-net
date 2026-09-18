//! `pigeoned` — a full-screen reader for Pigeonnet echo areas.
//!
//! The ancestry is deliberate: GoldED, Blue Wave, Msged, Timed. Those readers
//! were built for exactly this shape of network — you read and write offline
//! against a local store, and a separate step exchanges mail with a peer. That is
//! not nostalgia, it is the same constraint (§1), so the same interface fits.
//!
//! Everything this program shows comes out of the local store. Nothing is fetched
//! to draw a screen; a sync is a visible, deliberate act.

#![forbid(unsafe_code)]

mod app;
mod theme;
mod ui;

use std::{io, path::PathBuf};

use anyhow::{Context as _, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use pigeonnet_core::Timestamp;
use pigeonnet_node::Node;
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    app::{App, View},
    theme::Theme,
};

fn main() -> Result<()> {
    let root = node_root()?;
    let node =
        Node::open(&root).with_context(|| format!("opening the node at {}", root.display()))?;

    // Absent rather than an error: reading is the common case and must not need a
    // passphrase. Writing and syncing do, and say so when attempted.
    let passphrase = std::env::var("PIGEONNET_PASSPHRASE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(String::into_bytes);

    let theme = std::env::var("PIGEONNET_THEME")
        .ok()
        .and_then(|name| Theme::parse(&name))
        .unwrap_or(Theme::Ice);

    let mut app = App::new(node, passphrase, theme)?;

    let mut terminal = enter()?;
    let outcome = run(&mut terminal, &mut app);
    // Restore the terminal whatever happened. A reader that leaves a shell in raw
    // mode after a panic-free error is worse than one that never started.
    leave(&mut terminal)?;
    outcome
}

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

fn enter() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout)).context("starting the terminal")
}

fn leave(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run(terminal: &mut Tui, app: &mut App) -> Result<()> {
    while !app.quit {
        // The reader needs the size to know where a post ends, and only the
        // terminal knows it.
        let size = terminal.size()?;
        app.note_size(size.width, size.height);

        terminal.draw(|frame| ui::draw(frame, app))?;

        // Slow work runs after the repaint that announced it, so the user sees
        // "Signing..." rather than a frozen screen.
        if let Some(work) = app.take_work() {
            app.perform(work)?;
            continue;
        }

        // Blocking read: there is nothing to animate, and a reader that wakes up
        // sixty times a second to redraw an unchanged screen is a poor neighbour
        // on the hardware this is meant to run on (§1).
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle(app, key)?;
        }
    }
    Ok(())
}

fn handle(app: &mut App, key: KeyEvent) -> Result<()> {
    // Compose swallows almost everything, so it is dealt with first.
    if app.view == View::Compose {
        return compose_key(app, key);
    }

    match key.code {
        KeyCode::Char('q' | 'Q') => app.quit = true,
        KeyCode::Esc => app.back(),
        KeyCode::Char('?') => app.show_help(),
        KeyCode::Char('t' | 'T') => app.cycle_theme(),
        KeyCode::Char('s' | 'S') => app.request_sync(),

        KeyCode::Up | KeyCode::Char('k') => app.move_cursor(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_cursor(1),
        KeyCode::PageUp => app.move_cursor(-10),
        KeyCode::PageDown => app.move_cursor(10),

        KeyCode::Enter => match app.view {
            View::Areas => app.enter_area()?,
            View::Messages => app.open_message(),
            _ => {}
        },

        // Left and right walk the area; space pages through it, then walks.
        KeyCode::Right if app.view == View::Reader => {
            app.step_message(1);
        }
        KeyCode::Left if app.view == View::Reader => {
            app.step_message(-1);
        }
        KeyCode::Char(' ') if app.view == View::Reader => app.advance(),

        KeyCode::Char('w' | 'W') => app.begin_post(),
        KeyCode::Char('r' | 'R') => app.begin_reply(),
        _ => {}
    }
    Ok(())
}

fn compose_key(app: &mut App, key: KeyEvent) -> Result<()> {
    // The save prompt takes priority: while it is up, every key answers it.
    if app.confirming() {
        let answer = match key.code {
            KeyCode::Char(c) => c,
            _ => ' ',
        };
        app.answer(answer);
        return Ok(());
    }

    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Esc => app.back(),
        KeyCode::Enter => app.compose_char('\n'),
        KeyCode::Backspace => app.compose_backspace(),
        // Kept for anyone whose terminal delivers it, but never advertised: Ctrl-S
        // is XOFF and most line disciplines swallow it before it gets here.
        KeyCode::Char('s' | 'S') if control => app.answer('y'),
        KeyCode::Char(c) if !control => app.compose_char(c),
        _ => {}
    }
    Ok(())
}

/// Where the node lives. The same rules `nodectl` uses.
fn node_root() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PIGEONNET_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME").context("neither $PIGEONNET_HOME nor $HOME is set")?;
    Ok(PathBuf::from(home).join(".pigeonnet"))
}

/// A date, for a list column. Minutes are as fine as a column needs.
fn date(timestamp: Timestamp) -> String {
    let c = timestamp.civil();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        c.year, c.month, c.day, c.hour, c.minute
    )
}

/// A full instant, for a message header.
fn timestamp(timestamp: Timestamp) -> String {
    let c = timestamp.civil();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}
