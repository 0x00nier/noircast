//! Packet metadata editor popup
//!
//! Provides a protocol-aware popup for editing packet fields.

use crate::app::{App, PacketEditorField};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

// Color scheme matching the rest of the app
const BG_COLOR: Color = Color::Rgb(0, 0, 0);
const FG_PRIMARY: Color = Color::White;
const FG_SECONDARY: Color = Color::Rgb(128, 128, 128);
const FG_DIM: Color = Color::Rgb(80, 80, 80);
const ACCENT: Color = Color::Rgb(80, 200, 100);
const ACCENT_BRIGHT: Color = Color::Rgb(100, 255, 120);
const WARNING: Color = Color::Rgb(200, 180, 80);

/// Render the packet editor popup
pub fn render_packet_editor(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Get protocol-specific fields
    let fields = PacketEditorField::fields_for_protocol(app.selected_protocol);
    let field_count = fields.len();

    // Calculate popup size based on field count
    let popup_width = (area.width * 60 / 100).min(70).max(50);
    let popup_height = ((field_count as u16 + 6).max(10)).min(area.height * 70 / 100);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block with protocol in title
    let title = if app.packet_editor.editing {
        format!(" {} Packet - Editing {} ", app.selected_protocol, app.packet_editor.current_field.label())
    } else {
        format!(" {} Packet Editor ", app.selected_protocol)
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(ACCENT_BRIGHT).bold())
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .style(Style::default().bg(BG_COLOR))
        .padding(Padding::uniform(1));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Split inner area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),    // Fields
            Constraint::Length(1), // Spacer
            Constraint::Length(2), // Help text
        ])
        .split(inner);

    // Render protocol-specific fields
    render_fields(frame, app, chunks[0], &fields);

    // Render help text
    render_help_text(frame, app, chunks[2]);
}

/// Get display value for a field
fn get_field_value(app: &App, field: &PacketEditorField) -> String {
    match field {
        PacketEditorField::SourcePort => app.packet_editor.source_port.to_string(),
        PacketEditorField::DestPort => app.packet_editor.dest_port.to_string(),
        PacketEditorField::Ttl => app.packet_editor.ttl.to_string(),
        PacketEditorField::Payload => {
            if app.packet_editor.payload_hex.is_empty() {
                "(empty)".to_string()
            } else {
                format_hex_preview(&app.packet_editor.payload_hex, 20)
            }
        }
        PacketEditorField::SeqNum => app.packet_editor.seq_num.to_string(),
        PacketEditorField::AckNum => app.packet_editor.ack_num.to_string(),
        PacketEditorField::WindowSize => app.packet_editor.window_size.to_string(),
        PacketEditorField::IcmpType => format!("{} ({})", app.packet_editor.icmp_type, icmp_type_name(app.packet_editor.icmp_type)),
        PacketEditorField::IcmpCode => app.packet_editor.icmp_code.to_string(),
        PacketEditorField::IcmpId => app.packet_editor.icmp_id.to_string(),
        PacketEditorField::IcmpSeq => app.packet_editor.icmp_seq.to_string(),
        PacketEditorField::DnsQueryType => format!("{} ({})", app.packet_editor.dns_query_type, dns_type_name(app.packet_editor.dns_query_type)),
        PacketEditorField::DnsDomain => if app.packet_editor.dns_domain.is_empty() { "(target host)".to_string() } else { app.packet_editor.dns_domain.clone() },
        PacketEditorField::HttpMethod => app.packet_editor.http_method.clone(),
        PacketEditorField::HttpPath => app.packet_editor.http_path.clone(),
        PacketEditorField::HttpHeaders => if app.packet_editor.http_headers.is_empty() { "(default)".to_string() } else { format!("{} bytes", app.packet_editor.http_headers.len()) },
        PacketEditorField::SnmpVersion => format!("v{}", if app.packet_editor.snmp_version == 2 { "2c".to_string() } else { app.packet_editor.snmp_version.to_string() }),
        PacketEditorField::SnmpCommunity => app.packet_editor.snmp_community.clone(),
        PacketEditorField::SsdpTarget => app.packet_editor.ssdp_target.clone(),
        PacketEditorField::SmbVersion => format!("SMB{}", app.packet_editor.smb_version),
        PacketEditorField::LdapScope => format!("{} ({})", app.packet_editor.ldap_scope, ldap_scope_name(app.packet_editor.ldap_scope)),
        PacketEditorField::LdapBaseDn => if app.packet_editor.ldap_base_dn.is_empty() { "(empty)".to_string() } else { app.packet_editor.ldap_base_dn.clone() },
        PacketEditorField::NetBiosName => if app.packet_editor.netbios_name.is_empty() { "(broadcast)".to_string() } else { app.packet_editor.netbios_name.clone() },
        PacketEditorField::DhcpType => format!("{} ({})", app.packet_editor.dhcp_type, dhcp_type_name(app.packet_editor.dhcp_type)),
        PacketEditorField::KerberosRealm => if app.packet_editor.kerberos_realm.is_empty() { "(required)".to_string() } else { app.packet_editor.kerberos_realm.clone() },
        PacketEditorField::KerberosUser => if app.packet_editor.kerberos_user.is_empty() { "(required)".to_string() } else { app.packet_editor.kerberos_user.clone() },
        PacketEditorField::ArpOperation => format!("{} ({})", app.packet_editor.arp_operation, if app.packet_editor.arp_operation == 1 { "Request" } else { "Reply" }),
        PacketEditorField::ArpTargetIp => if app.packet_editor.arp_target_ip.is_empty() { "(target host)".to_string() } else { app.packet_editor.arp_target_ip.clone() },
    }
}

/// Render the editable fields (protocol-aware)
fn render_fields(frame: &mut Frame, app: &App, area: Rect, fields: &[PacketEditorField]) {
    let rows: Vec<Row> = fields.iter().map(|field| {
        let is_selected = *field == app.packet_editor.current_field;
        let is_editing = is_selected && app.packet_editor.editing;

        let label_style = if is_selected {
            Style::default().fg(ACCENT_BRIGHT).bold()
        } else {
            Style::default().fg(FG_SECONDARY)
        };

        let value = if is_editing {
            format!("{}▌", app.packet_editor.field_buffer)
        } else {
            get_field_value(app, field)
        };

        let value_style = if is_editing {
            Style::default().fg(WARNING).add_modifier(Modifier::BOLD)
        } else if is_selected {
            Style::default().fg(ACCENT_BRIGHT)
        } else {
            Style::default().fg(FG_PRIMARY)
        };

        let indicator = if is_selected { "▶ " } else { "  " };
        let indicator_style = if is_selected {
            Style::default().fg(ACCENT_BRIGHT)
        } else {
            Style::default().fg(BG_COLOR)
        };

        Row::new(vec![
            Span::styled(indicator, indicator_style),
            Span::styled(format!("{:14}", field.label()), label_style),
            Span::styled(value, value_style),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Length(15),
            Constraint::Min(20),
        ],
    )
    .column_spacing(1);

    frame.render_widget(table, area);
}

fn icmp_type_name(t: u8) -> &'static str {
    match t {
        0 => "Echo Reply",
        3 => "Dest Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        13 => "Timestamp",
        _ => "Other",
    }
}

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

fn ldap_scope_name(s: u8) -> &'static str {
    match s {
        0 => "Base",
        1 => "One Level",
        2 => "Subtree",
        _ => "Unknown",
    }
}

fn dhcp_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        _ => "Other",
    }
}

/// Render help text at the bottom
fn render_help_text(frame: &mut Frame, app: &App, area: Rect) {
    let help_text = if app.packet_editor.editing {
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(ACCENT)),
            Span::styled(" save  ", Style::default().fg(FG_DIM)),
            Span::styled("Esc", Style::default().fg(ACCENT)),
            Span::styled(" cancel", Style::default().fg(FG_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled("j/k", Style::default().fg(ACCENT)),
            Span::styled(" navigate  ", Style::default().fg(FG_DIM)),
            Span::styled("Enter/i", Style::default().fg(ACCENT)),
            Span::styled(" edit  ", Style::default().fg(FG_DIM)),
            Span::styled("r", Style::default().fg(ACCENT)),
            Span::styled(" randomize  ", Style::default().fg(FG_DIM)),
            Span::styled("Esc/q", Style::default().fg(ACCENT)),
            Span::styled(" close", Style::default().fg(FG_DIM)),
        ])
    };

    let paragraph = Paragraph::new(help_text).alignment(Alignment::Center);
    frame.render_widget(paragraph, area);
}

/// Format hex string with ellipsis for preview
fn format_hex_preview(hex: &str, max_len: usize) -> String {
    if hex.len() <= max_len {
        // Add spaces between byte pairs for readability
        hex.chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        let truncated: String = hex.chars().take(max_len).collect();
        let formatted = truncated.chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");
        format!("{}...", formatted)
    }
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
    fn test_format_hex_preview_short() {
        let hex = "48656c6c6f";
        let result = format_hex_preview(hex, 20);
        assert_eq!(result, "48 65 6c 6c 6f");
    }

    #[test]
    fn test_format_hex_preview_truncated() {
        let hex = "48656c6c6f576f726c64";
        let result = format_hex_preview(hex, 8);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_centered_rect() {
        let area = Rect { x: 0, y: 0, width: 100, height: 50 };
        let centered = centered_rect(40, 20, area);
        assert_eq!(centered.x, 30);
        assert_eq!(centered.y, 15);
        assert_eq!(centered.width, 40);
        assert_eq!(centered.height, 20);
    }
}
