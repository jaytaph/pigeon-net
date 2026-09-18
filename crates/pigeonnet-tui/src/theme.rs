//! Colour schemes, in the spirit of the readers this imitates.
//!
//! GoldED, Blue Wave, Msged and the rest all looked like this: a solid coloured
//! field, double-line boxes, a reverse-video status bar top and bottom, and one
//! bright accent colour doing all the signalling. The palette is sixteen colours
//! because that is what there was, and the constraint is why those screens still
//! read well.

use ratatui::style::{Color, Modifier, Style};

/// A named colour scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Theme {
    /// Blue field, cyan rules, white text. The Blue Wave look.
    Ice,
    /// Dark red field, yellow rules. Warmer, and harder on the eyes.
    Ember,
    /// Green on black, for anyone who misses a monochrome monitor.
    Phosphor,
    /// Amber on black, for anyone who misses a different monochrome monitor.
    Amber,
}

impl Theme {
    /// Every theme, in cycling order.
    pub(crate) const ALL: [Self; 4] = [Self::Ice, Self::Ember, Self::Phosphor, Self::Amber];

    /// Look up a theme by name, case-insensitively.
    ///
    /// Returns `None` for anything unrecognised, so a stale `$PIGEONNET_THEME`
    /// falls back to the default rather than refusing to start.
    #[must_use]
    pub(crate) fn parse(name: &str) -> Option<Self> {
        let name = name.trim();
        Self::ALL
            .into_iter()
            .find(|theme| theme.name().eq_ignore_ascii_case(name))
    }

    /// The next theme in the cycle.
    #[must_use]
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Ice => Self::Ember,
            Self::Ember => Self::Phosphor,
            Self::Phosphor => Self::Amber,
            Self::Amber => Self::Ice,
        }
    }

    /// What to call it on screen.
    #[must_use]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Ice => "Ice",
            Self::Ember => "Ember",
            Self::Phosphor => "Phosphor",
            Self::Amber => "Amber",
        }
    }

    /// The field the whole screen sits on.
    #[must_use]
    const fn field(self) -> Color {
        match self {
            Self::Ice => Color::Blue,
            Self::Ember => Color::Rgb(48, 0, 0),
            Self::Phosphor | Self::Amber => Color::Black,
        }
    }

    /// Ordinary text.
    #[must_use]
    const fn ink(self) -> Color {
        match self {
            Self::Ice => Color::Gray,
            Self::Ember => Color::Rgb(220, 180, 140),
            Self::Phosphor => Color::Rgb(0, 200, 0),
            Self::Amber => Color::Rgb(220, 160, 40),
        }
    }

    /// Borders and rules.
    #[must_use]
    const fn rule(self) -> Color {
        match self {
            Self::Ice => Color::Cyan,
            Self::Ember => Color::Rgb(200, 60, 40),
            Self::Phosphor => Color::Rgb(0, 140, 0),
            Self::Amber => Color::Rgb(150, 100, 20),
        }
    }

    /// The one bright colour that does all the signalling.
    #[must_use]
    const fn accent(self) -> Color {
        match self {
            Self::Ice => Color::White,
            Self::Ember => Color::Yellow,
            Self::Phosphor => Color::Rgb(160, 255, 160),
            Self::Amber => Color::Rgb(255, 210, 120),
        }
    }

    /// Something worth noticing: unread counts, warnings.
    #[must_use]
    const fn alert(self) -> Color {
        match self {
            Self::Ice => Color::Yellow,
            Self::Ember => Color::Rgb(255, 230, 120),
            Self::Phosphor => Color::Rgb(220, 255, 220),
            Self::Amber => Color::White,
        }
    }

    // -- styles, which is all the rest of the program should need -----------

    /// The background everything draws on.
    #[must_use]
    pub(crate) const fn base(self) -> Style {
        Style::new().bg(self.field()).fg(self.ink())
    }

    /// Box borders.
    #[must_use]
    pub(crate) const fn border(self) -> Style {
        Style::new().bg(self.field()).fg(self.rule())
    }

    /// A box's title.
    #[must_use]
    pub(crate) const fn title(self) -> Style {
        Style::new()
            .bg(self.field())
            .fg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    /// The status bars, top and bottom. Reverse video, as they always were.
    #[must_use]
    pub(crate) const fn bar(self) -> Style {
        Style::new().bg(self.rule()).fg(self.field())
    }

    /// A key name in the bottom bar.
    #[must_use]
    pub(crate) const fn bar_key(self) -> Style {
        Style::new()
            .bg(self.rule())
            .fg(self.field())
            .add_modifier(Modifier::BOLD.union(Modifier::UNDERLINED))
    }

    /// The selected row.
    #[must_use]
    pub(crate) const fn selected(self) -> Style {
        Style::new()
            .bg(self.rule())
            .fg(self.field())
            .add_modifier(Modifier::BOLD)
    }

    /// Emphasis inside a pane.
    #[must_use]
    pub(crate) const fn strong(self) -> Style {
        Style::new()
            .bg(self.field())
            .fg(self.accent())
            .add_modifier(Modifier::BOLD)
    }

    /// Something to notice.
    #[must_use]
    pub(crate) const fn notice(self) -> Style {
        Style::new().bg(self.field()).fg(self.alert())
    }

    /// A message header field label.
    #[must_use]
    pub(crate) const fn label(self) -> Style {
        Style::new().bg(self.field()).fg(self.rule())
    }
}

#[cfg(test)]
mod tests {
    use super::Theme;

    #[test]
    fn the_cycle_visits_every_theme_and_returns() {
        let mut seen = vec![Theme::Ice];
        let mut theme = Theme::Ice;
        for _ in 0..Theme::ALL.len() {
            theme = theme.next();
            if theme == Theme::Ice {
                break;
            }
            seen.push(theme);
        }
        assert_eq!(seen.len(), Theme::ALL.len(), "cycle must cover every theme");
        assert_eq!(theme, Theme::Ice, "and come back round");
    }

    #[test]
    fn every_theme_is_named() {
        for theme in Theme::ALL {
            assert!(!theme.name().is_empty());
        }
    }
}
