//! Custom widgets for NoirCast TUI

use ratatui::{
    layout::Rect,
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::Widget,
};

/// A status badge widget for displaying mode/status indicators
pub struct StatusBadge<'a> {
    text: &'a str,
    style: BadgeStyle,
}

/// Style variants for StatusBadge
#[derive(Clone, Copy)]
pub enum BadgeStyle {
    Success,
    Warning,
    Info,
    Default,
}

impl<'a> StatusBadge<'a> {
    pub fn new(text: &'a str, style: BadgeStyle) -> Self {
        Self { text, style }
    }
}

impl<'a> Widget for StatusBadge<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let (fg, bg) = match self.style {
            BadgeStyle::Success => (Color::Black, Color::Green),
            BadgeStyle::Warning => (Color::Black, Color::Yellow),
            BadgeStyle::Info => (Color::White, Color::Blue),
            BadgeStyle::Default => (Color::White, Color::DarkGray),
        };

        let style = Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD);
        let text = format!(" {} ", self.text);
        buf.set_string(area.x, area.y, &text, style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_badge() {
        let badge = StatusBadge::new("OK", BadgeStyle::Success);
        assert!(matches!(badge.style, BadgeStyle::Success));
    }
}
