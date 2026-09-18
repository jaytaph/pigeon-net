//! Drawing the screen.
//!
//! The layout is copied, not invented. A title bar across the top, a reverse-video
//! key bar across the bottom, double-line boxes around everything in between, and
//! a hard-edged selection bar rather than a subtle highlight — on a 25-line
//! terminal you need to find the cursor in one glance, not two.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};

use crate::{
    app::{App, View},
    theme::Theme,
};

/// One rect out of a split, never panicking.
///
/// `Layout::split` always returns as many rects as there were constraints, so
/// the fallback is unreachable — but an empty rect draws nothing, which is a
/// better failure than a panic in a full-screen program.
fn at(rects: &[Rect], index: usize) -> Rect {
    rects.get(index).copied().unwrap_or_default()
}

/// Draw everything.
pub(crate) fn draw(frame: &mut Frame, app: &App) {
    let theme = app.theme;
    let area = frame.area();

    // Paint the whole field first. These readers had a coloured background, not
    // a terminal one showing through.
    frame.render_widget(Block::default().style(theme.base()), area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Min(3),    // body
            Constraint::Length(1), // status
            Constraint::Length(1), // keys
        ])
        .split(area);

    title_bar(frame, app, at(&rows, 0));
    match app.view {
        View::Areas => areas(frame, app, at(&rows, 1)),
        View::Messages => messages(frame, app, at(&rows, 1)),
        View::Reader => reader(frame, app, at(&rows, 1)),
        View::Compose => compose(frame, app, at(&rows, 1)),
        View::Help => {
            areas(frame, app, at(&rows, 1));
            help(frame, app, at(&rows, 1));
        }
    }
    status_bar(frame, app, at(&rows, 2));
    key_bar(frame, app, at(&rows, 3));
}

fn title_bar(frame: &mut Frame, app: &App, area: Rect) {
    let left = format!(" Pigeonnet Reader  {}", app.theme.name());
    let right = match app.view {
        View::Areas => "Areas".to_owned(),
        View::Messages | View::Reader => app
            .current_area()
            .map_or_else(|| "Messages".to_owned(), |a| a.area.to_string()),
        View::Compose => app.compose_title(),
        View::Help => "Help".to_owned(),
    };
    let pad =
        usize::from(area.width).saturating_sub(left.chars().count() + right.chars().count() + 1);
    let line = Line::from(vec![
        Span::raw(left),
        Span::raw(" ".repeat(pad)),
        Span::raw(right),
        Span::raw(" "),
    ]);
    frame.render_widget(Paragraph::new(line).style(app.theme.bar()), area);
}

fn status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let text = format!(" {}", app.status);
    frame.render_widget(Paragraph::new(text).style(app.theme.notice()), area);
}

fn key_bar(frame: &mut Frame, app: &App, area: Rect) {
    let keys: &[(&str, &str)] = match app.view {
        View::Areas => &[
            ("\u{2191}\u{2193}", "Move"),
            ("Enter", "Open"),
            ("S", "Sync"),
            ("T", "Theme"),
            ("?", "Help"),
            ("Q", "Quit"),
        ],
        View::Messages => &[
            ("\u{2191}\u{2193}", "Move"),
            ("Enter", "Read"),
            ("W", "Write"),
            ("R", "Reply"),
            ("S", "Sync"),
            ("Esc", "Areas"),
        ],
        View::Reader => &[
            ("\u{2190}\u{2192}", "Prev/Next"),
            ("\u{2191}\u{2193}", "Scroll"),
            ("R", "Reply"),
            ("W", "Write"),
            ("Esc", "Back"),
        ],
        View::Compose if app.confirming() => &[("Y", "Send"), ("N", "Discard"), ("Any", "Resume")],
        View::Compose => &[("Esc", "Finish"), ("Enter", "New line")],
        View::Help => &[("Esc", "Close")],
    };

    let mut spans = vec![Span::raw(" ")];
    for (key, label) in keys {
        spans.push(Span::styled((*key).to_owned(), app.theme.bar_key()));
        spans.push(Span::styled(format!(" {label}  "), app.theme.bar()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(app.theme.bar()),
        area,
    );
}

/// A double-line box, which is the whole look.
fn boxed<'a>(theme: Theme, title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(theme.border())
        .title(Span::styled(format!(" {title} "), theme.title()))
        .title_alignment(Alignment::Left)
        .style(theme.base())
}

/// Draw the reply structure the way `tree(1)` does.
///
/// `read_area` hands back a pre-order walk with a depth on each post, which is
/// all this needs: a post is the last of its siblings when no later post shares
/// its depth before one shallower than it appears. Knowing that for every post is
/// enough to decide, at each level, whether the line continues past it.
///
/// Thread roots get no connector. They are not siblings of each other in any
/// sense the objects record — they simply happen to share an area — and drawing a
/// spine between them would claim a relationship that is not there.
fn tree_prefixes(depths: &[usize]) -> Vec<String> {
    // Backwards: a post is the last of its siblings if nothing at its own depth
    // has been seen yet within the subtree we are still inside.
    let mut last = vec![true; depths.len()];
    let mut seen: Vec<bool> = Vec::new();
    for (index, &depth) in depths.iter().enumerate().rev() {
        if seen.len() <= depth {
            seen.resize(depth + 1, false);
        }
        // Anything deeper belonged to a subtree we have now walked out of.
        seen.truncate(depth + 1);
        if let Some(slot) = seen.get_mut(depth) {
            if let Some(entry) = last.get_mut(index) {
                *entry = !*slot;
            }
            *slot = true;
        }
    }

    // Forwards, carrying whether each open level still has siblings to come.
    let mut more: Vec<bool> = Vec::new();
    let mut prefixes = Vec::with_capacity(depths.len());
    for (index, &depth) in depths.iter().enumerate() {
        if more.len() <= depth {
            more.resize(depth + 1, false);
        }
        more.truncate(depth + 1);
        let is_last = last.get(index).copied().unwrap_or(true);
        if let Some(slot) = more.get_mut(depth) {
            *slot = !is_last;
        }

        let mut prefix = String::new();
        if depth > 0 {
            for level in 1..depth {
                prefix.push_str(if more.get(level).copied().unwrap_or(false) {
                    "\u{2502}   "
                } else {
                    "    "
                });
            }
            prefix.push_str(if is_last {
                "\u{2514}\u{2500}\u{2500} "
            } else {
                "\u{251c}\u{2500}\u{2500} "
            });
        }
        prefixes.push(prefix);
    }
    prefixes
}

/// Window onto a list: keep the cursor visible without scrolling more than needed.
fn window(cursor: usize, len: usize, height: usize) -> usize {
    if len <= height || height == 0 {
        return 0;
    }
    let half = height / 2;
    cursor.saturating_sub(half).min(len - height)
}

fn areas(frame: &mut Frame, app: &App, area: Rect) {
    let block = boxed(app.theme, "Message Areas");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!(
            "{:<24} {:>6} {:>7} {:>6}  {}",
            "AREA", "POSTS", "THREADS", "VOICES", "LATEST"
        ))
        .style(app.theme.label()),
        at(&rows, 0),
    );

    let height = usize::from(at(&rows, 1).height);
    let start = window(app.area_cursor, app.areas.len(), height);
    let lines: Vec<Line> = app
        .areas
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, stats)| {
            // An unsubscribed area we merely hold objects for is marked, so the
            // list never implies we are asking peers for it.
            let mark = if stats.subscribed { ' ' } else { '-' };
            let text = format!(
                "{mark}{:<23} {:>6} {:>7} {:>6}  {}",
                truncate(&stats.area.to_string(), 23),
                stats.posts,
                stats.threads,
                stats.voices,
                crate::date(stats.latest),
            );
            let style = if index == app.area_cursor {
                app.theme.selected()
            } else {
                app.theme.base()
            };
            Line::from(Span::styled(pad(&text, at(&rows, 1).width), style))
        })
        .collect();

    let body = if lines.is_empty() {
        Text::from("No areas yet. Subscribe with: nodectl echo subscribe <area>")
    } else {
        Text::from(lines)
    };
    frame.render_widget(Paragraph::new(body).style(app.theme.base()), at(&rows, 1));
}

fn messages(frame: &mut Frame, app: &App, area: Rect) {
    let name = app
        .current_area()
        .map_or_else(String::new, |a| a.area.to_string());
    let block = boxed(app.theme, &name);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!(
            "{:<5} {:<16} {:<16}  {}",
            "#", "DATE", "FROM", "TEXT"
        ))
        .style(app.theme.label()),
        at(&rows, 0),
    );

    let me = app.me();
    let width = at(&rows, 1).width;
    let height = usize::from(at(&rows, 1).height);
    let start = window(app.message_cursor, app.messages.len(), height);

    // Computed over the whole area, not the visible window: a reply's connector
    // depends on siblings that may be scrolled off either end.
    let depths: Vec<usize> = app.messages.iter().map(|post| post.depth).collect();
    let prefixes = tree_prefixes(&depths);

    let lines: Vec<Line> = app
        .messages
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, post)| {
            let columns = format!(
                "{:<5} {:<16} {:<16}  ",
                index + 1,
                crate::date(post.timestamp),
                truncate(&app.who(post.author), 16),
            );
            let prefix = prefixes.get(index).map_or("", String::as_str);
            let text = first_line(&post.post.content);

            // The tree is drawn in the border colour, so it reads as structure
            // rather than as part of anybody's message.
            let (column_style, tree_style) = if index == app.message_cursor {
                (app.theme.selected(), app.theme.selected())
            } else if me == Some(post.author) {
                (app.theme.strong(), app.theme.border())
            } else {
                (app.theme.base(), app.theme.border())
            };

            // Whatever the tree does not use is left for the message.
            let used = columns.chars().count() + prefix.chars().count();
            let room = usize::from(width).saturating_sub(used);
            let text = truncate(&text, room);
            let tail = room.saturating_sub(text.chars().count());

            Line::from(vec![
                Span::styled(columns, column_style),
                Span::styled(prefix.to_owned(), tree_style),
                Span::styled(format!("{text}{}", " ".repeat(tail)), column_style),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(app.theme.base()),
        at(&rows, 1),
    );
}

fn reader(frame: &mut Frame, app: &App, area: Rect) {
    let Some(post) = app.current_message() else {
        return;
    };
    let position = format!("{} of {}", app.message_cursor + 1, app.messages.len());
    let block = boxed(app.theme, &position);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(inner);

    // The kludge-line header these readers all showed. Every field here is from
    // the signed object; nothing is inferred.
    let header = vec![
        header_line(app, "From", &app.who(post.author)),
        header_line(app, "Date", &crate::timestamp(post.timestamp)),
        header_line(app, "Area", &post.post.area.to_string()),
        header_line(app, "Msg", &post.id.to_string()),
    ];
    frame.render_widget(Paragraph::new(Text::from(header)), at(&rows, 0));

    frame.render_widget(
        Paragraph::new(post.post.content.clone())
            .style(app.theme.base())
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0)),
        at(&rows, 1),
    );
}

fn header_line<'a>(app: &App, label: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<5}: "), app.theme.label()),
        Span::styled(value.to_owned(), app.theme.strong()),
    ])
}

fn compose(frame: &mut Frame, app: &App, area: Rect) {
    let title = app.compose_title();
    let block = boxed(app.theme, &title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let body = app.compose.as_ref().map_or("", |c| c.body.as_str());
    // A block cursor, because there is no real editor here and the user needs to
    // see where the next character lands.
    let text = format!("{body}\u{2588}");
    frame.render_widget(
        Paragraph::new(text)
            .style(app.theme.base())
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn help(frame: &mut Frame, app: &App, area: Rect) {
    let width = 56.min(area.width.saturating_sub(4));
    let height = 19.min(area.height.saturating_sub(2));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);

    let block = boxed(app.theme, "Keys");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let entries = [
        ("Up / Down", "move, or scroll while reading"),
        ("Left / Right", "previous / next message"),
        ("Space", "next message, as it always did"),
        ("PgUp / PgDn", "a screenful at a time"),
        ("Enter", "open an area or a message"),
        ("Esc", "back one level"),
        ("W", "write a new message in this area"),
        ("R", "reply to the selected message"),
        ("S", "sync with every configured peer"),
        ("T", "next colour scheme"),
        ("?", "this list"),
        ("Q", "quit"),
    ];
    let mut lines: Vec<Line> = entries
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(format!("  {key:<14}"), app.theme.strong()),
                Span::raw((*what).to_owned()),
            ])
        })
        .collect();
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "  A name ending in * is self-asserted.",
        app.theme.label(),
    )));
    lines.push(Line::from(Span::styled(
        "  There are no subject lines; TEXT is the opening words.",
        app.theme.label(),
    )));
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(app.theme.base()),
        inner,
    );
}

/// Pad to the full width, so a selection bar reaches the edge of the box.
fn pad(text: &str, width: u16) -> String {
    let width = usize::from(width);
    let mut out: String = text.chars().take(width).collect();
    let len = out.chars().count();
    if len < width {
        out.push_str(&" ".repeat(width - len));
    }
    out
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    // No room even for the ellipsis. A deep thread in a narrow terminal reaches
    // this, and returning one character anyway would overrun the box border.
    if width == 0 {
        return String::new();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// A post's first line, which is the closest thing we have to a subject.
///
/// There is no subject field in an `EchoPost` (§7) — threading is by object
/// identifier, not by matching text — so the list shows the opening words and
/// says so in the column heading rather than pretending otherwise.
fn first_line(content: &str) -> String {
    content.lines().next().unwrap_or("").trim().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Render a whole screen and flatten it to text, so a test can assert on what
    /// the user would actually see rather than on the widget tree that produced it.
    fn screen(app: &App, width: u16, height: u16) -> String {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| {
                        buffer
                            .cell((x, y))
                            .and_then(|cell| cell.symbol().chars().next())
                            .unwrap_or(' ')
                    })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A node directory that cleans up after itself.
    struct Temp(std::path::PathBuf);

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn empty_app() -> (Temp, App) {
        // Unique per call: tests run in parallel inside one process, and a shared
        // directory means one test's cleanup deletes another test's node.
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeoned-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let node = pigeonnet_node::Node::open(&dir).unwrap();
        let app = App::new(node, None, Theme::Ice).unwrap();
        (Temp(dir), app)
    }

    #[test]
    fn padding_fills_and_clips() {
        assert_eq!(pad("ab", 5), "ab   ");
        assert_eq!(pad("abcdef", 3), "abc");
    }

    #[test]
    fn truncation_marks_what_it_cut() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 4), "abc\u{2026}");
        assert_eq!(truncate("abc", 1), "\u{2026}");
        assert_eq!(truncate("abc", 0), "", "must never exceed the width given");
    }

    #[test]
    fn the_window_keeps_the_cursor_inside_it() {
        // Every position must be visible, at every list length.
        for len in 0usize..40 {
            for cursor in 0..len {
                let start = window(cursor, len, 10);
                assert!(cursor >= start, "cursor {cursor} above window {start}");
                assert!(
                    cursor < start + 10 || len <= 10,
                    "cursor {cursor} below window {start} (len {len})"
                );
            }
        }
    }

    #[test]
    fn a_short_list_does_not_scroll() {
        assert_eq!(window(3, 5, 10), 0);
    }

    /// Render a depth sequence as the screen would show it, one row per line.
    fn tree(depths: &[usize]) -> String {
        tree_prefixes(depths).join("|")
    }

    #[test]
    fn a_thread_root_gets_no_connector() {
        assert_eq!(tree(&[0]), "");
        assert_eq!(tree(&[0, 0, 0]), "||");
    }

    #[test]
    fn the_last_reply_closes_the_branch() {
        // root, two replies: the second is the last, so it corners.
        assert_eq!(
            tree(&[0, 1, 1]),
            "|\u{251c}\u{2500}\u{2500} |\u{2514}\u{2500}\u{2500} "
        );
    }

    #[test]
    fn a_spine_continues_past_a_nested_reply() {
        // root
        // |-- a
        // |   `-- a1      <- the spine must continue left of a1, because b follows
        // `-- b
        let drawn = tree_prefixes(&[0, 1, 2, 1]);
        assert_eq!(drawn[1], "\u{251c}\u{2500}\u{2500} ");
        assert_eq!(drawn[2], "\u{2502}   \u{2514}\u{2500}\u{2500} ");
        assert_eq!(drawn[3], "\u{2514}\u{2500}\u{2500} ");
    }

    #[test]
    fn the_last_branch_leaves_blank_space_below_it() {
        // root
        // `-- a
        //     `-- a1      <- nothing follows a, so no spine beside a1
        let drawn = tree_prefixes(&[0, 1, 2]);
        assert_eq!(drawn[1], "\u{2514}\u{2500}\u{2500} ");
        assert_eq!(drawn[2], "    \u{2514}\u{2500}\u{2500} ");
    }

    #[test]
    fn each_thread_is_drawn_on_its_own() {
        // Two roots in one area. The first root's replies must close before the
        // second root begins, and the roots must not be joined to each other.
        let drawn = tree_prefixes(&[0, 1, 0, 1]);
        assert_eq!(drawn[0], "");
        assert_eq!(drawn[1], "\u{2514}\u{2500}\u{2500} ");
        assert_eq!(drawn[2], "");
        assert_eq!(drawn[3], "\u{2514}\u{2500}\u{2500} ");
    }

    #[test]
    fn a_gap_in_the_depths_does_not_panic() {
        // `read_area` keeps a reply whose parent is missing, so the depths it
        // hands over need not step by one.
        let drawn = tree_prefixes(&[0, 3, 1]);
        assert_eq!(drawn.len(), 3);
        assert_eq!(tree_prefixes(&[]).len(), 0);
    }

    #[test]
    fn a_subject_is_the_first_line() {
        assert_eq!(first_line("  hello\nworld"), "hello");
        assert_eq!(first_line(""), "");
    }

    #[test]
    fn an_empty_node_still_draws_a_usable_screen() {
        // The first thing a new operator sees. It must say what to do next rather
        // than present an empty box.
        let (_temp, app) = empty_app();
        let text = screen(&app, 80, 24);
        assert!(text.contains("Pigeonnet Reader"), "{text}");
        assert!(text.contains("Message Areas"), "{text}");
        assert!(text.contains("echo subscribe"), "{text}");
        assert!(text.contains("Quit"), "{text}");
        // Read-only is stated up front, not on first refusal.
        assert!(text.contains("PIGEONNET_PASSPHRASE"), "{text}");
    }

    #[test]
    fn it_draws_on_a_terminal_the_size_they_used_to_have() {
        // 80x25 was the whole canvas these readers had. Nothing may panic or
        // overflow at that size, nor at anything smaller.
        let (_temp, mut app) = empty_app();
        for (width, height) in [(80, 25), (80, 24), (40, 10), (20, 6), (10, 4)] {
            let _ = screen(&app, width, height);
        }
        app.show_help();
        for (width, height) in [(80, 25), (40, 10), (20, 6)] {
            let _ = screen(&app, width, height);
        }
    }

    #[test]
    fn every_theme_draws() {
        let (_temp, mut app) = empty_app();
        for theme in Theme::ALL {
            app.theme = theme;
            let text = screen(&app, 80, 24);
            assert!(
                text.contains(theme.name()),
                "{} missing: {text}",
                theme.name()
            );
        }
    }
}
