//! UI module - Rendering and widgets for NoirCast TUI
//!
//! Provides all the visual components using Ratatui

mod help;
mod packet_editor;
mod protocol_picker;
pub mod widgets;

use crate::app::{ActivePane, App, HttpDirection, InputMode, LogLevel, PacketDirection};
use widgets::{StatusBadge, BadgeStyle};
use crate::config::{PacketTemplate, Protocol, ScanType, TcpFlag};
use crate::network::packet::format_flags;
use crate::network::protocols::get_service_name;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols,
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, List, ListItem, Padding, Paragraph, Row,
        Table, Tabs,
    },
    Frame,
};

// Color scheme: minimal dark with neon green accents
// Using RGB(0,0,0) for true black background
const BG_COLOR: Color = Color::Rgb(0, 0, 0);            // True black
const FG_PRIMARY: Color = Color::White;
const FG_SECONDARY: Color = Color::Rgb(128, 128, 128);  // Gray
const FG_DIM: Color = Color::Rgb(80, 80, 80);           // Dark gray (increased from 60 for better readability)
const FG_HINT: Color = Color::Rgb(120, 120, 120);       // Lighter gray for help hints
const ACCENT: Color = Color::Rgb(80, 200, 100);         // Dull neon green
const ACCENT_BRIGHT: Color = Color::Rgb(100, 255, 120); // Brighter green for highlights
const BORDER_ACTIVE: Color = Color::Rgb(80, 200, 100);  // Green border when active
const BORDER_INACTIVE: Color = Color::Rgb(40, 40, 40);  // Dark border
const SUCCESS: Color = Color::Rgb(80, 200, 100);        // Green
const WARNING: Color = Color::Rgb(200, 180, 80);        // Muted yellow
const ERROR: Color = Color::Rgb(200, 80, 80);           // Muted red
const INFO: Color = Color::Rgb(100, 150, 200);          // Muted blue

/// Main render function
pub fn render(frame: &mut Frame, app: &App) {
    // Fill entire background with black
    let bg_block = Block::default().style(Style::default().bg(BG_COLOR));
    frame.render_widget(bg_block, frame.area());

    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Main content
            Constraint::Length(3),  // Status bar
        ])
        .split(frame.area());

    // Render header
    render_header(frame, app, chunks[0]);

    // Render main content area
    render_main_content(frame, app, chunks[1]);

    // Render status bar
    render_status_bar(frame, app, chunks[2]);

    // Render help overlay if active
    if app.show_help {
        help::render_help_popup(frame, app);
    }

    // Render key hint popup for pending keys
    help::render_key_hint(frame, app);

    // Render command line if in command mode
    if app.input_mode == InputMode::Command {
        render_command_line(frame, app);
    }

    // Render search line if in search mode
    if app.input_mode == InputMode::Search {
        render_search_line(frame, app);
    }

    // Render packet editor popup if active
    if app.show_packet_editor {
        packet_editor::render_packet_editor(frame, app);
    }

    // Render protocol picker popup if active
    if app.show_protocol_picker {
        protocol_picker::render_protocol_picker(frame, app);
    }
}

/// Render the header with title and tabs
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(25),
            Constraint::Min(20),
            Constraint::Length(20),
        ])
        .split(area);

    // Title
    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("◆ ", Style::default().fg(ACCENT)),
            Span::styled("NoirCast", Style::default().fg(FG_PRIMARY).bold()),
            Span::styled(" v0.1", Style::default().fg(FG_DIM)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_INACTIVE))
            .style(Style::default().bg(BG_COLOR)),
    );
    frame.render_widget(title, header_chunks[0]);

    // Protocol tabs
    let protocols: Vec<&str> = vec![
        "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "NTP",
        "SNMP", "SSDP", "SMB", "LDAP", "NetBIOS", "DHCP", "Kerberos", "ARP"
    ];
    let selected_idx = match app.selected_protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
        Protocol::Icmp => 2,
        Protocol::Http => 3,
        Protocol::Https => 4,
        Protocol::Dns => 5,
        Protocol::Ntp => 6,
        Protocol::Snmp => 7,
        Protocol::Ssdp => 8,
        Protocol::Smb => 9,
        Protocol::Ldap => 10,
        Protocol::NetBios => 11,
        Protocol::Dhcp => 12,
        Protocol::Kerberos => 13,
        Protocol::Arp => 14,
        Protocol::Raw => 0,
    };

    let tabs = Tabs::new(protocols)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Protocol ")
                .title_style(Style::default().fg(FG_PRIMARY))
                .border_style(Style::default().fg(BORDER_INACTIVE))
                .style(Style::default().bg(BG_COLOR)),
        )
        .select(selected_idx)
        .style(Style::default().fg(FG_SECONDARY))
        .highlight_style(
            Style::default()
                .fg(ACCENT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        )
        .divider(symbols::DOT);
    frame.render_widget(tabs, header_chunks[1]);

    // Mode indicator using StatusBadge widget
    let badge_style = match app.input_mode {
        InputMode::Normal => BadgeStyle::Info,
        InputMode::Insert => BadgeStyle::Warning,
        InputMode::Command => BadgeStyle::Success,
        InputMode::Help => BadgeStyle::Default,
        InputMode::Search => BadgeStyle::Info,
    };

    let badge_area = Rect {
        x: header_chunks[2].x + 2,
        y: header_chunks[2].y + 1,
        width: header_chunks[2].width.saturating_sub(4),
        height: 1,
    };

    let mode_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER_INACTIVE))
        .style(Style::default().bg(BG_COLOR));
    frame.render_widget(mode_block, header_chunks[2]);

    let mode_text = format!("{}", app.input_mode);
    let badge = StatusBadge::new(&mode_text, badge_style);
    frame.render_widget(badge, badge_area);
}

/// Render the main content area with multiple panes
fn render_main_content(frame: &mut Frame, app: &App, area: Rect) {
    // Split into left and right sections
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Left side: Configuration panes
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12), // Packet config
            Constraint::Length(12), // Flag selection
            Constraint::Min(6),     // Target config
        ])
        .split(main_chunks[0]);

    render_packet_config(frame, app, left_chunks[0]);
    render_flag_selection(frame, app, left_chunks[1]);
    render_target_config(frame, app, left_chunks[2]);

    // Right side: Results and logs
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30), // Response log
            Constraint::Percentage(45), // Packet capture
            Constraint::Percentage(25), // Statistics
        ])
        .split(main_chunks[1]);

    render_response_log(frame, app, right_chunks[0]);
    render_packet_capture(frame, app, right_chunks[1]);
    render_statistics(frame, app, right_chunks[2]);
}

/// Render packet configuration pane (protocol-aware)
fn render_packet_config(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::PacketConfig;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    let title = match app.selected_protocol {
        Protocol::Tcp => " TCP Config ",
        Protocol::Udp => " UDP Config ",
        Protocol::Icmp => " ICMP Config ",
        Protocol::Http | Protocol::Https => " HTTP Config ",
        Protocol::Dns => " DNS Config ",
        Protocol::Ntp => " NTP Config ",
        Protocol::Snmp => " SNMP Config ",
        Protocol::Ssdp => " SSDP Config ",
        Protocol::Smb => " SMB Config ",
        Protocol::Ldap => " LDAP Config ",
        Protocol::NetBios => " NetBIOS Config ",
        Protocol::Dhcp => " DHCP Config ",
        Protocol::Kerberos => " Kerberos Config ",
        Protocol::Arp => " ARP Config ",
        Protocol::Raw => " Raw Config ",
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR))
        .padding(Padding::horizontal(1));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Protocol-specific options
    match app.selected_protocol {
        Protocol::Tcp | Protocol::Udp => {
            // Show scan types for TCP/UDP
            let scan_type_shortcuts = ["F1", "F2", "F3", "F4", "F5", "F6", "F7"];
            // First filter, then enumerate to get correct filtered indices
            let filtered_scan_types: Vec<_> = ScanType::all()
                .into_iter()
                .filter(|st| {
                    // Filter scan types by protocol
                    match app.selected_protocol {
                        Protocol::Tcp => !matches!(st, ScanType::UdpScan),
                        Protocol::Udp => matches!(st, ScanType::UdpScan),
                        _ => true,
                    }
                })
                .collect();
            let scan_types: Vec<ListItem> = filtered_scan_types
                .iter()
                .enumerate()
                .map(|(i, st)| {
                    let is_selected = app.selected_scan_type == *st;
                    let is_cursor = is_active && i == app.scan_type_index;

                    let marker = if is_selected { "●" } else { "○" };
                    let marker_style = if is_selected {
                        Style::default().fg(ACCENT_BRIGHT).bold()
                    } else {
                        Style::default().fg(FG_DIM)
                    };

                    let name_style = if is_selected {
                        Style::default().fg(ACCENT_BRIGHT).bold()
                    } else if is_cursor {
                        Style::default().fg(FG_PRIMARY)
                    } else {
                        Style::default().fg(FG_SECONDARY)
                    };

                    let shortcut = scan_type_shortcuts.get(i).unwrap_or(&"");
                    let shortcut_style = Style::default().fg(FG_DIM);

                    let line_style = if is_cursor {
                        Style::default().bg(FG_DIM)
                    } else {
                        Style::default()
                    };

                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{} ", marker), marker_style),
                        Span::styled(format!("{:10}", st.name()), name_style),
                        Span::styled(format!(" {} ", st.description()), Style::default().fg(FG_HINT)),
                        Span::styled(format!("[{}]", shortcut), shortcut_style),
                    ]).style(line_style))
                })
                .collect();

            let list = List::new(scan_types).block(Block::default().title("Scan Types").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Icmp => {
            // ICMP type/code options
            let icmp_types = [
                ("Echo Request", 8, 0),
                ("Echo Reply", 0, 0),
                ("Dest Unreachable", 3, 0),
                ("Time Exceeded", 11, 0),
                ("Timestamp", 13, 0),
            ];
            let items: Vec<ListItem> = icmp_types.iter().enumerate().map(|(i, (name, t, c))| {
                let is_selected = app.icmp_type == *t && app.icmp_code == *c;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(format!("{} (t={},c={})", name, t, c), style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("ICMP Type").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Dns => {
            // DNS query type options
            let dns_types = [
                ("A (IPv4)", 1),
                ("AAAA (IPv6)", 28),
                ("MX (Mail)", 15),
                ("TXT (Text)", 16),
                ("NS (Nameserver)", 2),
                ("CNAME", 5),
            ];
            let items: Vec<ListItem> = dns_types.iter().enumerate().map(|(i, (name, qtype))| {
                let is_selected = app.dns_query_type == *qtype;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("DNS Query Type").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Http | Protocol::Https => {
            // HTTP method options
            let methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"];
            let items: Vec<ListItem> = methods.iter().enumerate().map(|(i, method)| {
                let is_selected = app.http_method == *method;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*method, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("HTTP Method").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Ntp | Protocol::Raw => {
            // Show packet templates for quick selection with scrolling
            let templates = PacketTemplate::all();
            let visible_lines = inner.height.saturating_sub(1) as usize; // -1 for title

            // Calculate scroll offset to keep cursor visible
            let scroll_offset = if app.scan_type_index >= visible_lines {
                app.scan_type_index.saturating_sub(visible_lines - 1)
            } else {
                0
            };

            let items: Vec<ListItem> = templates.iter().enumerate()
                .skip(scroll_offset)
                .take(visible_lines)
                .map(|(i, tmpl)| {
                    let is_cursor = is_active && i == app.scan_type_index;
                    let style = if is_cursor {
                        Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                    } else {
                        Style::default().fg(FG_SECONDARY)
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{:10}", tmpl.name()), style),
                        Span::styled(format!(" [{}]", tmpl.shortcut()), Style::default().fg(FG_DIM)),
                    ]))
                }).collect();

            let title = if scroll_offset > 0 || templates.len() > visible_lines {
                format!("Templates ({}/{})", app.scan_type_index + 1, templates.len())
            } else {
                "Templates".to_string()
            };

            let list = List::new(items).block(Block::default().title(title).title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Snmp => {
            let versions = [("v1", 1u8), ("v2c", 2), ("v3", 3)];
            let items: Vec<ListItem> = versions.iter().enumerate().map(|(i, (name, ver))| {
                let is_selected = app.snmp_version == *ver;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(format!("SNMP {}", name), style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Version").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Ssdp => {
            let targets = [("ssdp:all", 0u8), ("upnp:rootdevice", 1), ("Custom ST", 2)];
            let items: Vec<ListItem> = targets.iter().enumerate().map(|(i, (name, idx))| {
                let is_selected = app.ssdp_target == *idx;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Search Target").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Smb => {
            let versions = [("SMB1 (NT LM 0.12)", 1u8), ("SMB2", 2), ("SMB3", 3)];
            let items: Vec<ListItem> = versions.iter().enumerate().map(|(i, (name, ver))| {
                let is_selected = app.smb_version == *ver;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("SMB Version").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Ldap => {
            let scopes = [("Base (single entry)", 0u8), ("One Level", 1), ("Subtree (recursive)", 2)];
            let items: Vec<ListItem> = scopes.iter().enumerate().map(|(i, (name, scope))| {
                let is_selected = app.ldap_scope == *scope;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Search Scope").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::NetBios => {
            let types = [("Name Query", 0u8), ("Node Status (nbstat)", 1)];
            let items: Vec<ListItem> = types.iter().enumerate().map(|(i, (name, t))| {
                let is_selected = app.netbios_type == *t;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Query Type").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Dhcp => {
            let types = [("Discover", 1u8), ("Request", 3), ("Release", 7)];
            let items: Vec<ListItem> = types.iter().enumerate().map(|(i, (name, t))| {
                let is_selected = app.dhcp_type == *t;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(format!("DHCP {}", name), style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Message Type").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Kerberos => {
            let types = [("AS-REQ (Auth)", 10u8), ("TGS-REQ (Service)", 12)];
            let items: Vec<ListItem> = types.iter().enumerate().map(|(i, (name, t))| {
                let is_selected = app.kerberos_type == *t;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Request Type").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
        Protocol::Arp => {
            let ops = [("ARP Request (who-has)", 1u8), ("ARP Reply (is-at)", 2)];
            let items: Vec<ListItem> = ops.iter().enumerate().map(|(i, (name, op))| {
                let is_selected = app.arp_operation == *op;
                let is_cursor = is_active && i == app.scan_type_index;
                let marker = if is_selected { "●" } else { "○" };
                let style = if is_selected {
                    Style::default().fg(ACCENT_BRIGHT).bold()
                } else if is_cursor {
                    Style::default().fg(FG_PRIMARY).bg(FG_DIM)
                } else {
                    Style::default().fg(FG_SECONDARY)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", marker), style),
                    Span::styled(*name, style),
                ]))
            }).collect();

            let list = List::new(items).block(Block::default().title("Operation").title_style(
                Style::default().fg(FG_SECONDARY).add_modifier(Modifier::DIM),
            ));
            frame.render_widget(list, inner);
        }
    }
}

/// Render TCP flag selection pane
fn render_flag_selection(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::FlagSelection;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    let block = Block::default()
        .title(" TCP Flags ")
        .title_style(Style::default().fg(if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR))
        .padding(Padding::horizontal(1));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Flag items
    let flags: Vec<ListItem> = TcpFlag::all()
        .iter()
        .enumerate()
        .map(|(i, flag)| {
            let is_selected = app.selected_flags.contains(flag);
            let is_cursor = is_active && i == app.flag_list_index;

            let checkbox = if is_selected { "[x]" } else { "[ ]" };
            let flag_style = if is_selected {
                Style::default().fg(ACCENT_BRIGHT).bold()
            } else {
                Style::default().fg(FG_SECONDARY)
            };

            let line_style = if is_cursor {
                Style::default().bg(FG_DIM)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(checkbox, flag_style),
                Span::styled(" ", Style::default()),
                Span::styled(flag.name(), flag_style),
                Span::styled(" - ", Style::default().fg(FG_HINT)),
                Span::styled(flag.description(), Style::default().fg(FG_HINT)),
            ]).style(line_style))
        })
        .collect();

    let list = List::new(flags);
    frame.render_widget(list, inner);
}

/// Render target configuration pane (protocol-aware)
fn render_target_config(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::TargetConfig;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    let block = Block::default()
        .title(" Target ")
        .title_style(Style::default().fg(if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR))
        .padding(Padding::horizontal(1));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Target info display
    let host_display = if app.target.host.is_empty() {
        "<none>".to_string()
    } else {
        app.target.host.clone()
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Host:   ", Style::default().fg(FG_PRIMARY).bold()),
            Span::styled(
                &host_display,
                Style::default().fg(if app.target.host.is_empty() {
                    FG_DIM
                } else {
                    ACCENT
                }),
            ),
        ]),
    ];

    // Protocol-specific fields
    match app.selected_protocol {
        Protocol::Tcp | Protocol::Udp | Protocol::Http | Protocol::Https => {
            // Show port for TCP/UDP/HTTP with service name lookup
            let port_display = if app.target.ports.is_empty() {
                "<none>".to_string()
            } else if app.target.ports.len() == 1 {
                let port = app.target.ports[0];
                let service = get_service_name(port);
                if service != "Unknown" {
                    format!("{} ({})", port, service)
                } else {
                    port.to_string()
                }
            } else {
                format!("{} ports", app.target.ports.len())
            };
            let port_color = if app.target.ports.is_empty() { FG_DIM } else { ACCENT };
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled(port_display, Style::default().fg(port_color)),
            ]));
        }
        Protocol::Icmp => {
            // ICMP: show type/code instead of port
            lines.push(Line::from(vec![
                Span::styled("Type:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled(
                    format!("{} ({})", icmp_type_name(app.icmp_type), app.icmp_type),
                    Style::default().fg(ACCENT),
                ),
            ]));
        }
        Protocol::Dns => {
            // DNS: show port and query type
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("53", Style::default().fg(ACCENT)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Query:  ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled(dns_type_name(app.dns_query_type), Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Ntp => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("123", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Snmp => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("161", Style::default().fg(ACCENT)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Comm:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled(&app.snmp_community, Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Ssdp => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("1900", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Smb => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("445", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Ldap => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("389", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::NetBios => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("137", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Dhcp => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("67/68", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Kerberos => {
            lines.push(Line::from(vec![
                Span::styled("Port:   ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("88", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Arp => {
            lines.push(Line::from(vec![
                Span::styled("Layer:  ", Style::default().fg(FG_PRIMARY).bold()),
                Span::styled("L2 (Ethernet)", Style::default().fg(ACCENT)),
            ]));
        }
        Protocol::Raw => {}
    }

    // HTTP-specific
    if matches!(app.selected_protocol, Protocol::Http | Protocol::Https) {
        lines.push(Line::from(vec![
            Span::styled("Method: ", Style::default().fg(FG_PRIMARY).bold()),
            Span::styled(&app.http_method, Style::default().fg(ACCENT)),
        ]));
    }

    // Packet count
    lines.push(Line::from(vec![
        Span::styled("Count:  ", Style::default().fg(FG_PRIMARY).bold()),
        Span::styled(app.packet_count.to_string(), Style::default().fg(ACCENT)),
        Span::styled(" pkt", Style::default().fg(FG_DIM)),
    ]));

    // Help hint
    lines.push(Line::from(Span::styled("", Style::default())));
    lines.push(Line::from(vec![
        Span::styled("'i' edit | ':flood'", Style::default().fg(FG_HINT)),
    ]));

    // Show input buffer when in insert mode
    if app.input_mode == InputMode::Insert && is_active {
        lines.push(Line::from(Span::styled("", Style::default())));
        lines.push(Line::from(vec![
            Span::styled("Input: ", Style::default().fg(ACCENT)),
            Span::styled(&app.input_buffer, Style::default().fg(FG_PRIMARY)),
            Span::styled("█", Style::default().fg(ACCENT_BRIGHT)),
        ]));
    }

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

/// Get ICMP type name
fn icmp_type_name(t: u8) -> &'static str {
    match t {
        0 => "Echo Reply",
        3 => "Dest Unreach",
        8 => "Echo Req",
        11 => "Time Exceed",
        _ => "Other",
    }
}

/// Get DNS type name
fn dns_type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "Other",
    }
}

/// Render response log pane
fn render_response_log(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::ResponseLog;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    // Use config's network timeout in title for context
    let timeout_ms = app.config.network.default_timeout_ms;
    let block = Block::default()
        .title(format!(" Responses ({}) [{}ms] ", app.logs.len(), timeout_ms))
        .title_style(Style::default().fg(if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Log entries with scroll support using log_scroll
    let log_items: Vec<ListItem> = app
        .logs
        .iter()
        .skip(app.log_scroll)
        .map(|entry| {
            let level_style = match entry.level {
                LogLevel::Info => Style::default().fg(INFO),
                LogLevel::Success => Style::default().fg(SUCCESS),
                LogLevel::Warning => Style::default().fg(WARNING),
                LogLevel::Error => Style::default().fg(ERROR),
                LogLevel::Debug => Style::default().fg(FG_SECONDARY),
            };

            let time = entry.timestamp.format("%H:%M:%S").to_string();

            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", time), Style::default().fg(FG_DIM)),
                Span::styled(format!("{} ", entry.level.symbol()), level_style),
                Span::styled(&entry.message, Style::default().fg(FG_PRIMARY)),
            ]))
        })
        .collect();

    let list = List::new(log_items);
    frame.render_widget(list, inner);
}

/// Render packet capture pane
fn render_packet_capture(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::PacketCapture;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    let block = Block::default()
        .title(format!(" Packet Capture ({}) ", app.captured_packets.len()))
        .title_style(Style::default().fg(if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.captured_packets.is_empty() {
        let empty = Paragraph::new(Line::from(vec![Span::styled(
            "No packets captured yet. Press 's' to send packets.",
            Style::default().fg(FG_DIM),
        )]))
        .alignment(Alignment::Center);
        frame.render_widget(empty, inner);
        return;
    }

    // Header row
    let header = Row::new(vec![
        Cell::from("ID").style(Style::default().fg(FG_SECONDARY).bold()),
        Cell::from("Dir").style(Style::default().fg(FG_SECONDARY).bold()),
        Cell::from("Proto").style(Style::default().fg(FG_SECONDARY).bold()),
        Cell::from("Source").style(Style::default().fg(FG_SECONDARY).bold()),
        Cell::from("Dest").style(Style::default().fg(FG_SECONDARY).bold()),
        Cell::from("Flags").style(Style::default().fg(FG_SECONDARY).bold()),
        Cell::from("Status").style(Style::default().fg(FG_SECONDARY).bold()),
    ])
    .height(1);

    // Data rows
    let rows: Vec<Row> = app
        .captured_packets
        .iter()
        .skip(app.capture_scroll)
        .map(|pkt| {
            let dir_style = match pkt.direction {
                PacketDirection::Sent => Style::default().fg(ACCENT),
                PacketDirection::Received => Style::default().fg(SUCCESS),
            };

            let status_style = if pkt.status.contains("Open") || pkt.status.contains("OK") {
                Style::default().fg(SUCCESS)
            } else if pkt.status.contains("Closed") || pkt.status.contains("Refused") {
                Style::default().fg(WARNING)
            } else if pkt.status.contains("Error") || pkt.status.contains("Timeout") {
                Style::default().fg(ERROR)
            } else {
                Style::default().fg(FG_PRIMARY)
            };

            let source = format!(
                "{}:{}",
                pkt.source_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "?".to_string()),
                pkt.source_port.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string())
            );

            let dest = format!(
                "{}:{}",
                pkt.dest_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "?".to_string()),
                pkt.dest_port.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string())
            );

            let flags_str = if pkt.flags.is_empty() {
                if pkt.flags_raw != 0 {
                    format!("0x{:02X}", pkt.flags_raw)
                } else {
                    "-".to_string()
                }
            } else {
                format_flags(&pkt.flags)
            };

            Row::new(vec![
                Cell::from(format!("{:04}", pkt.id)).style(Style::default().fg(FG_DIM)),
                Cell::from(pkt.direction.to_string()).style(dir_style),
                Cell::from(pkt.protocol.to_string()).style(Style::default().fg(ACCENT)),
                Cell::from(source).style(Style::default().fg(FG_PRIMARY)),
                Cell::from(dest).style(Style::default().fg(FG_PRIMARY)),
                Cell::from(flags_str).style(Style::default().fg(ACCENT_BRIGHT)),
                Cell::from(&*pkt.status).style(status_style),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),   // ID
            Constraint::Length(3),   // Dir
            Constraint::Length(6),   // Proto
            Constraint::Length(16),  // Source
            Constraint::Length(16),  // Dest
            Constraint::Length(12),  // Flags
            Constraint::Min(10),     // Status
        ],
    )
    .header(header)
    .style(Style::default().fg(FG_PRIMARY))
    .highlight_style(Style::default().bg(FG_DIM));

    frame.render_widget(table, inner);
}

/// Render HTTP stream pane
#[allow(dead_code)]
fn render_http_stream(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::HttpStream;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    let block = Block::default()
        .title(format!(" HTTP Stream ({}) ", app.http_stream.len()))
        .title_style(Style::default().fg(if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.http_stream.is_empty() {
        let empty = Paragraph::new(Line::from(vec![Span::styled(
            "No HTTP traffic captured",
            Style::default().fg(FG_DIM),
        )]))
        .alignment(Alignment::Center);
        frame.render_widget(empty, inner);
        return;
    }

    // HTTP stream entries with scroll support
    let items: Vec<ListItem> = app
        .http_stream
        .iter()
        .skip(app.http_scroll)
        .map(|entry| {
            let direction_style = match entry.direction {
                HttpDirection::Request => Style::default().fg(ACCENT),
                HttpDirection::Response => Style::default().fg(SUCCESS),
            };

            let direction_arrow = match entry.direction {
                HttpDirection::Request => "→",
                HttpDirection::Response => "←",
            };

            let content = match entry.direction {
                HttpDirection::Request => {
                    format!(
                        "{} {}",
                        entry.method.as_deref().unwrap_or("???"),
                        entry.url.as_deref().unwrap_or("/")
                    )
                }
                HttpDirection::Response => {
                    format!("HTTP {}", entry.status_code.unwrap_or(0))
                }
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    entry.timestamp.format("%H:%M:%S ").to_string(),
                    Style::default().fg(FG_DIM),
                ),
                Span::styled(format!("{} ", direction_arrow), direction_style),
                Span::styled(content, Style::default().fg(FG_PRIMARY)),
            ]))
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, inner);
}

/// Render statistics pane
fn render_statistics(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == ActivePane::Statistics;
    let border_color = if is_active { BORDER_ACTIVE } else { BORDER_INACTIVE };

    // Show flood indicator in title when active
    let title = if app.flood_mode {
        " Statistics [FLOOD] "
    } else {
        " Statistics "
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(if app.flood_mode { WARNING } else if is_active { ACCENT } else { FG_PRIMARY }))
        .borders(Borders::ALL)
        .border_type(if is_active { BorderType::Double } else { BorderType::Rounded })
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_COLOR));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Create stats table - use try_read to avoid blocking in async context
    let stats = app.stats.try_read()
        .map(|s| s.clone())
        .unwrap_or_default();

    // Build stats lines
    let mut lines: Vec<Line> = Vec::new();

    // Regular packet stats
    lines.push(Line::from(vec![
        Span::styled("Sent     ", Style::default().fg(FG_SECONDARY)),
        Span::styled(": ", Style::default().fg(FG_DIM)),
        Span::styled(stats.packets_sent.to_string(), Style::default().fg(FG_PRIMARY)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Received ", Style::default().fg(FG_SECONDARY)),
        Span::styled(": ", Style::default().fg(FG_DIM)),
        Span::styled(stats.packets_received.to_string(), Style::default().fg(SUCCESS)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Failed   ", Style::default().fg(FG_SECONDARY)),
        Span::styled(": ", Style::default().fg(FG_DIM)),
        Span::styled(stats.packets_failed.to_string(), Style::default().fg(if stats.packets_failed > 0 { ERROR } else { FG_PRIMARY })),
    ]));

    // Flood mode stats
    if app.flood_mode {
        let (flood_count, flood_duration, flood_pps) = app.get_flood_stats();
        lines.push(Line::from(vec![
            Span::styled("Flood    ", Style::default().fg(WARNING)),
            Span::styled(": ", Style::default().fg(FG_DIM)),
            Span::styled(format_count(flood_count), Style::default().fg(WARNING).add_modifier(Modifier::BOLD)),
            Span::styled(" pkts", Style::default().fg(FG_DIM)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Rate     ", Style::default().fg(WARNING)),
            Span::styled(": ", Style::default().fg(FG_DIM)),
            Span::styled(format!("{:.0}", flood_pps), Style::default().fg(ACCENT_BRIGHT).add_modifier(Modifier::BOLD)),
            Span::styled(" pps  ", Style::default().fg(FG_DIM)),
            Span::styled(format!("{:.1}s", flood_duration), Style::default().fg(FG_SECONDARY)),
        ]));
    } else {
        // Show port stats when not flooding
        lines.push(Line::from(vec![
            Span::styled("Open     ", Style::default().fg(FG_SECONDARY)),
            Span::styled(": ", Style::default().fg(FG_DIM)),
            Span::styled(stats.open_ports.to_string(), Style::default().fg(SUCCESS)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Closed   ", Style::default().fg(FG_SECONDARY)),
            Span::styled(": ", Style::default().fg(FG_DIM)),
            Span::styled(stats.closed_ports.to_string(), Style::default().fg(WARNING)),
        ]));
    }

    // RTT stats
    lines.push(Line::from(vec![
        Span::styled("Avg RTT  ", Style::default().fg(FG_SECONDARY)),
        Span::styled(": ", Style::default().fg(FG_DIM)),
        Span::styled(format!("{:.2} ms", stats.avg_rtt_ms), Style::default().fg(INFO)),
    ]));

    // Success rate as text (cleaner than progress bar)
    let total = stats.packets_sent.max(1) as f64;
    let success_rate = stats.packets_received as f64 / total;
    let rate_color = if success_rate > 0.8 { SUCCESS } else if success_rate > 0.5 { WARNING } else { ERROR };
    let rate_pct = format!("{:3.0}%", success_rate * 100.0);

    lines.push(Line::from(vec![
        Span::styled("Rate     ", Style::default().fg(FG_SECONDARY)),
        Span::styled(": ", Style::default().fg(FG_DIM)),
        Span::styled(&rate_pct, Style::default().fg(rate_color).add_modifier(Modifier::BOLD)),
    ]));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

/// Format large numbers with K/M suffixes for compact display
fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Render status bar
fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60),
            Constraint::Percentage(40),
        ])
        .split(area);

    // Status message or help hint
    let status_content = if let Some((msg, level)) = &app.status_message {
        let color = match level {
            LogLevel::Info => INFO,
            LogLevel::Success => SUCCESS,
            LogLevel::Warning => WARNING,
            LogLevel::Error => ERROR,
            LogLevel::Debug => FG_SECONDARY,
        };
        Line::from(vec![Span::styled(msg, Style::default().fg(color))])
    } else {
        Line::from(vec![
            Span::styled("Press ", Style::default().fg(FG_DIM)),
            Span::styled("?", Style::default().fg(ACCENT_BRIGHT).bold()),
            Span::styled(" for help | ", Style::default().fg(FG_DIM)),
            Span::styled("Tab", Style::default().fg(ACCENT_BRIGHT).bold()),
            Span::styled(" to switch panes | ", Style::default().fg(FG_DIM)),
            Span::styled("s", Style::default().fg(ACCENT_BRIGHT).bold()),
            Span::styled(" to send", Style::default().fg(FG_DIM)),
        ])
    };

    let status = Paragraph::new(status_content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_INACTIVE))
            .style(Style::default().bg(BG_COLOR)),
    );
    frame.render_widget(status, chunks[0]);

    // Current flags and pane info
    let flags_str = format_flags(&app.selected_flags);
    let info = Paragraph::new(Line::from(vec![
        Span::styled("Flags: ", Style::default().fg(FG_DIM)),
        Span::styled(&flags_str, Style::default().fg(ACCENT_BRIGHT).bold()),
        Span::styled(" | ", Style::default().fg(FG_DIM)),
        Span::styled(
            format!("[{}]", app.active_pane.name()),
            Style::default().fg(ACCENT),
        ),
    ]))
    .alignment(Alignment::Right)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(BORDER_INACTIVE))
            .style(Style::default().bg(BG_COLOR)),
    );
    frame.render_widget(info, chunks[1]);
}

/// Render command line at the bottom
fn render_command_line(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let popup_area = Rect {
        x: 0,
        y: area.height.saturating_sub(3),
        width: area.width,
        height: 3,
    };

    let command_line = Paragraph::new(Line::from(vec![
        Span::styled(":", Style::default().fg(ACCENT_BRIGHT).bold()),
        Span::styled(&app.command_buffer, Style::default().fg(FG_PRIMARY)),
        Span::styled("█", Style::default().fg(ACCENT_BRIGHT)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(ACCENT))
            .style(Style::default().bg(BG_COLOR)),
    );

    frame.render_widget(Clear, popup_area);
    frame.render_widget(command_line, popup_area);
}

/// Render search line
fn render_search_line(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let popup_area = Rect {
        x: 0,
        y: area.height.saturating_sub(3),
        width: area.width,
        height: 3,
    };

    let search_line = Paragraph::new(Line::from(vec![
        Span::styled("/", Style::default().fg(ACCENT_BRIGHT).bold()),
        Span::styled(&app.search_buffer, Style::default().fg(FG_PRIMARY)),
        Span::styled("█", Style::default().fg(ACCENT_BRIGHT)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(ACCENT))
            .style(Style::default().bg(BG_COLOR)),
    );

    frame.render_widget(Clear, popup_area);
    frame.render_widget(search_line, popup_area);
}
