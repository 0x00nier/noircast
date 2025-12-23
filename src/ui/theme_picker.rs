//! Theme picker popup
//!
//! Provides a searchable popup for selecting UI color themes

use crate::app::App;
use crate::ui::theme::ThemeType;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

/// Filter themes by search query
pub fn filter_themes(query: &str) -> Vec<ThemeType> {
    let query_lower = query.to_lowercase();
    ThemeType::all()
        .into_iter()
        .filter(|t| {
            let name = t.name().to_lowercase();
            let desc = t.description().to_lowercase();
            name.contains(&query_lower) || desc.contains(&query_lower)
        })
        .collect()
}

/// Render the theme picker popup
pub fn render_theme_picker(frame: &mut Frame, app: &App) {
    let colors = app.current_theme.colors();
    let area = frame.area();

    // Calculate popup size
    let popup_width = (area.width * 50 / 100).min(50).max(40);
    let popup_height = (area.height * 60 / 100).min(16).max(12);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block with search filter in title if active
    let title = if app.theme_picker_filter.is_empty() {
        " Select Theme ".to_string()
    } else {
        format!(" Select Theme [{}] ", app.theme_picker_filter)
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(colors.accent_bright).bold())
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(colors.accent))
        .style(Style::default().bg(colors.bg))
        .padding(Padding::uniform(1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Split inner area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // Theme list
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Help text
        ])
        .split(inner);

    // Get filtered themes
    let themes = filter_themes(&app.theme_picker_filter);

    // Render theme list
    render_theme_list(frame, app, chunks[0], &themes);

    // Render help text
    render_help_text(frame, app, chunks[2]);
}

/// Render the theme list
fn render_theme_list(frame: &mut Frame, app: &App, area: Rect, themes: &[ThemeType]) {
    let colors = app.current_theme.colors();

    if themes.is_empty() {
        let msg = Paragraph::new("No matching themes")
            .style(Style::default().fg(colors.fg_dim))
            .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let rows: Vec<Row> = themes
        .iter()
        .enumerate()
        .map(|(idx, theme)| {
            let is_selected = idx == app.theme_picker_index;
            let is_current = *theme == app.current_theme;

            let indicator = if is_selected { ">" } else { " " };
            let indicator_style = if is_selected {
                Style::default().fg(colors.accent_bright)
            } else {
                Style::default().fg(colors.bg)
            };

            let current_marker = if is_current { "*" } else { " " };
            let marker_style = if is_current {
                Style::default().fg(colors.success)
            } else {
                Style::default().fg(colors.fg_dim)
            };

            let name_style = if is_selected {
                Style::default().fg(colors.accent_bright).bold()
            } else if is_current {
                Style::default().fg(colors.success)
            } else {
                Style::default().fg(colors.fg_primary)
            };

            let desc_style = Style::default().fg(colors.fg_dim);

            Row::new(vec![
                Span::styled(indicator, indicator_style),
                Span::styled(current_marker, marker_style),
                Span::styled(format!("{:12}", theme.name()), name_style),
                Span::styled(theme.description(), desc_style),
            ])
        })
        .collect();

    // Calculate visible window based on selection
    let max_visible = (area.height as usize).saturating_sub(1);
    let start_idx = if app.theme_picker_index >= max_visible {
        app.theme_picker_index - max_visible + 1
    } else {
        0
    };

    let visible_rows: Vec<Row> = rows.into_iter().skip(start_idx).take(max_visible).collect();

    let table = Table::new(
        visible_rows,
        [
            Constraint::Length(2),  // Indicator
            Constraint::Length(2),  // Current marker
            Constraint::Length(13), // Name
            Constraint::Min(20),    // Description
        ],
    )
    .column_spacing(1);

    frame.render_widget(table, area);
}

/// Render help text at the bottom
fn render_help_text(frame: &mut Frame, app: &App, area: Rect) {
    let colors = app.current_theme.colors();

    let help_text = Line::from(vec![
        Span::styled("j/k", Style::default().fg(colors.accent)),
        Span::styled(" navigate  ", Style::default().fg(colors.fg_dim)),
        Span::styled("Enter", Style::default().fg(colors.accent)),
        Span::styled(" apply  ", Style::default().fg(colors.fg_dim)),
        Span::styled("Type", Style::default().fg(colors.accent)),
        Span::styled(" to filter  ", Style::default().fg(colors.fg_dim)),
        Span::styled("Esc", Style::default().fg(colors.accent)),
        Span::styled(" close", Style::default().fg(colors.fg_dim)),
    ]);

    let paragraph = Paragraph::new(help_text).alignment(Alignment::Center);
    frame.render_widget(paragraph, area);
}

/// Helper function to create a centered rectangle
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect { x, y, width, height }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_themes_by_name() {
        // Filter by exact name
        let noir = filter_themes("noir");
        assert_eq!(noir.len(), 1);
        assert_eq!(noir[0], ThemeType::Noir);

        // Filter by partial name
        let cyber = filter_themes("cyber");
        assert_eq!(cyber.len(), 1);
        assert_eq!(cyber[0], ThemeType::Cyberpunk);
    }

    #[test]
    fn test_filter_themes_by_description() {
        // Filter by description keywords
        let green = filter_themes("green");
        assert!(green.contains(&ThemeType::Noir));
        assert!(green.contains(&ThemeType::Matrix));

        // Filter by "dark"
        let dark = filter_themes("dark");
        assert!(dark.contains(&ThemeType::Dracula));
    }

    #[test]
    fn test_filter_themes_case_insensitive() {
        let upper = filter_themes("MATRIX");
        let lower = filter_themes("matrix");
        let mixed = filter_themes("MaTrIx");

        assert_eq!(upper.len(), lower.len());
        assert_eq!(lower.len(), mixed.len());
        assert!(upper.contains(&ThemeType::Matrix));
    }

    #[test]
    fn test_filter_themes_empty_query() {
        // Empty filter returns all themes
        let all = filter_themes("");
        assert_eq!(all.len(), ThemeType::all().len());
    }

    #[test]
    fn test_filter_themes_no_match() {
        let none = filter_themes("zzzznonexistent");
        assert!(none.is_empty());
    }

    #[test]
    fn test_filter_themes_multiple_matches() {
        // "oc" should match Ocean
        let oc = filter_themes("oc");
        assert!(oc.contains(&ThemeType::Ocean));

        // "er" should match Hacker (retro in description)
        let er = filter_themes("retro");
        assert!(er.contains(&ThemeType::Hacker));
    }

    #[test]
    fn test_centered_rect() {
        let area = Rect::new(0, 0, 100, 50);
        let centered = centered_rect(40, 20, area);

        // Check centering
        assert_eq!(centered.x, 30);  // (100 - 40) / 2
        assert_eq!(centered.y, 15);  // (50 - 20) / 2
        assert_eq!(centered.width, 40);
        assert_eq!(centered.height, 20);
    }

    #[test]
    fn test_centered_rect_larger_than_area() {
        // When popup is larger than area, should still work
        let area = Rect::new(0, 0, 30, 10);
        let centered = centered_rect(50, 20, area);

        // saturating_sub prevents underflow
        assert_eq!(centered.x, 0);
        assert_eq!(centered.y, 0);
    }

    #[test]
    fn test_all_themes_filterable() {
        // Each theme should be findable by its name
        for theme in ThemeType::all() {
            let filtered = filter_themes(theme.name());
            assert!(
                filtered.contains(&theme),
                "Theme {:?} should be found by name '{}'",
                theme,
                theme.name()
            );
        }
    }
}
