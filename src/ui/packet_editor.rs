//! Packet metadata editor popup
//!
//! Provides a protocol-aware popup for editing packet fields with search/filter.

use crate::app::{App, PacketEditorField};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Row, Table},
    Frame,
};

/// Filter fields by search query (matches label)
pub fn filter_fields(fields: &[PacketEditorField], query: &str) -> Vec<PacketEditorField> {
    if query.is_empty() {
        return fields.to_vec();
    }
    let query_lower = query.to_lowercase();
    fields
        .iter()
        .filter(|f| {
            let label = f.label().to_lowercase();
            label.contains(&query_lower)
        })
        .cloned()
        .collect()
}

/// Render the packet editor popup
pub fn render_packet_editor(frame: &mut Frame, app: &App) {
    let colors = app.current_theme.colors();
    let area = frame.area();

    // Get protocol-specific fields with context (e.g., POST shows body/cookies)
    let all_fields = PacketEditorField::fields_for_protocol_context(
        app.selected_protocol,
        &app.packet_editor.http_method,
    );
    // Apply filter if active
    let fields = filter_fields(&all_fields, &app.packet_editor_filter);
    let field_count = fields.len();

    // Calculate popup size based on field count
    let popup_width = (area.width * 60 / 100).min(70).max(50);
    let popup_height = ((field_count as u16 + 6).max(10)).min(area.height * 70 / 100);

    let popup_area = centered_rect(popup_width, popup_height, area);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create main block with protocol in title, show filter if active
    let title = if app.packet_editor.editing {
        format!(" {} Packet - Editing {} ", app.selected_protocol, app.packet_editor.current_field.label())
    } else if !app.packet_editor_filter.is_empty() {
        format!(" {} Packet Editor [{}] ", app.selected_protocol, app.packet_editor_filter)
    } else {
        format!(" {} Packet Editor ", app.selected_protocol)
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
        // IP Header fields
        PacketEditorField::SourceIp => if app.packet_editor.source_ip.is_empty() { "(auto)".to_string() } else { app.packet_editor.source_ip.clone() },
        PacketEditorField::IpId => app.packet_editor.ip_id.to_string(),
        PacketEditorField::IpFlags => format!("0x{:02X} ({})", app.packet_editor.ip_flags, ip_flags_name(app.packet_editor.ip_flags)),
        PacketEditorField::FragmentOffset => app.packet_editor.fragment_offset.to_string(),
        PacketEditorField::Tos => format!("{} (DSCP {})", app.packet_editor.tos, app.packet_editor.tos >> 2),
        PacketEditorField::Ttl => app.packet_editor.ttl.to_string(),
        // Transport fields
        PacketEditorField::SourcePort => app.packet_editor.source_port.to_string(),
        PacketEditorField::DestPort => app.packet_editor.dest_port.to_string(),
        PacketEditorField::Payload => {
            if app.packet_editor.payload_hex.is_empty() {
                "(empty)".to_string()
            } else {
                format_hex_preview(&app.packet_editor.payload_hex, 20)
            }
        }
        // TCP fields
        PacketEditorField::TcpFlags => format_tcp_flags(app.packet_editor.tcp_flags),
        PacketEditorField::SeqNum => app.packet_editor.seq_num.to_string(),
        PacketEditorField::AckNum => app.packet_editor.ack_num.to_string(),
        PacketEditorField::WindowSize => app.packet_editor.window_size.to_string(),
        PacketEditorField::UrgentPtr => app.packet_editor.urgent_ptr.to_string(),
        // TCP Options fields
        PacketEditorField::TcpMss => if app.packet_editor.tcp_mss == 0 { "off".to_string() } else { format!("{} bytes", app.packet_editor.tcp_mss) },
        PacketEditorField::TcpWindowScale => if app.packet_editor.tcp_window_scale == 255 { "off".to_string() } else { format!("{} (x{})", app.packet_editor.tcp_window_scale, 1 << app.packet_editor.tcp_window_scale) },
        PacketEditorField::TcpSackPermitted => if app.packet_editor.tcp_sack_permitted { "yes".to_string() } else { "no".to_string() },
        PacketEditorField::TcpTimestampsEnabled => if app.packet_editor.tcp_timestamps_enabled { "yes".to_string() } else { "no".to_string() },
        PacketEditorField::TcpTsVal => app.packet_editor.tcp_tsval.to_string(),
        PacketEditorField::TcpTsEcr => app.packet_editor.tcp_tsecr.to_string(),
        // ICMP fields
        PacketEditorField::IcmpType => format!("{} ({})", app.packet_editor.icmp_type, icmp_type_name(app.packet_editor.icmp_type)),
        PacketEditorField::IcmpCode => app.packet_editor.icmp_code.to_string(),
        PacketEditorField::IcmpId => app.packet_editor.icmp_id.to_string(),
        PacketEditorField::IcmpSeq => app.packet_editor.icmp_seq.to_string(),
        // DNS fields
        PacketEditorField::DnsQueryType => format!("{} ({})", app.packet_editor.dns_query_type, dns_type_name(app.packet_editor.dns_query_type)),
        PacketEditorField::DnsDomain => if app.packet_editor.dns_domain.is_empty() { "(target host)".to_string() } else { app.packet_editor.dns_domain.clone() },
        // HTTP fields
        PacketEditorField::HttpMethod => app.packet_editor.http_method.clone(),
        PacketEditorField::HttpPath => app.packet_editor.http_path.clone(),
        PacketEditorField::HttpHeaders => if app.packet_editor.http_headers.is_empty() { "(default)".to_string() } else { format!("{} bytes", app.packet_editor.http_headers.len()) },
        // SNMP fields
        PacketEditorField::SnmpVersion => format!("v{}", if app.packet_editor.snmp_version == 2 { "2c".to_string() } else { app.packet_editor.snmp_version.to_string() }),
        PacketEditorField::SnmpCommunity => app.packet_editor.snmp_community.clone(),
        // SSDP fields
        PacketEditorField::SsdpTarget => app.packet_editor.ssdp_target.clone(),
        // SMB fields
        PacketEditorField::SmbVersion => format!("SMB{}", app.packet_editor.smb_version),
        // LDAP fields
        PacketEditorField::LdapScope => format!("{} ({})", app.packet_editor.ldap_scope, ldap_scope_name(app.packet_editor.ldap_scope)),
        PacketEditorField::LdapBaseDn => if app.packet_editor.ldap_base_dn.is_empty() { "(empty)".to_string() } else { app.packet_editor.ldap_base_dn.clone() },
        // NetBIOS fields
        PacketEditorField::NetBiosName => if app.packet_editor.netbios_name.is_empty() { "(broadcast)".to_string() } else { app.packet_editor.netbios_name.clone() },
        // DHCP fields
        PacketEditorField::DhcpType => format!("{} ({})", app.packet_editor.dhcp_type, dhcp_type_name(app.packet_editor.dhcp_type)),
        PacketEditorField::DhcpClientMac => if app.packet_editor.dhcp_client_mac.is_empty() { "(auto)".to_string() } else { app.packet_editor.dhcp_client_mac.clone() },
        // Kerberos fields
        PacketEditorField::KerberosRealm => if app.packet_editor.kerberos_realm.is_empty() { "(required)".to_string() } else { app.packet_editor.kerberos_realm.clone() },
        PacketEditorField::KerberosUser => if app.packet_editor.kerberos_user.is_empty() { "(required)".to_string() } else { app.packet_editor.kerberos_user.clone() },
        // ARP fields
        PacketEditorField::ArpOperation => format!("{} ({})", app.packet_editor.arp_operation, if app.packet_editor.arp_operation == 1 { "Request" } else { "Reply" }),
        PacketEditorField::ArpSenderMac => if app.packet_editor.arp_sender_mac.is_empty() { "(auto)".to_string() } else { app.packet_editor.arp_sender_mac.clone() },
        PacketEditorField::ArpSenderIp => if app.packet_editor.arp_sender_ip.is_empty() { "(auto)".to_string() } else { app.packet_editor.arp_sender_ip.clone() },
        PacketEditorField::ArpTargetMac => if app.packet_editor.arp_target_mac.is_empty() { "FF:FF:FF:FF:FF:FF".to_string() } else { app.packet_editor.arp_target_mac.clone() },
        PacketEditorField::ArpTargetIp => if app.packet_editor.arp_target_ip.is_empty() { "(target host)".to_string() } else { app.packet_editor.arp_target_ip.clone() },
        // HTTP extended fields
        PacketEditorField::HttpBody => if app.packet_editor.http_body.is_empty() { "(empty)".to_string() } else { format!("{} bytes", app.packet_editor.http_body.len()) },
        PacketEditorField::HttpCookies => if app.packet_editor.http_cookies.is_empty() { "(none)".to_string() } else { app.packet_editor.http_cookies.clone() },
        PacketEditorField::HttpContentType => if app.packet_editor.http_content_type.is_empty() { "application/json".to_string() } else { app.packet_editor.http_content_type.clone() },
    }
}

/// Format IP flags as human-readable string
fn ip_flags_name(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x02 != 0 { parts.push("DF"); }
    if flags & 0x01 != 0 { parts.push("MF"); }
    if parts.is_empty() { "none".to_string() } else { parts.join(",") }
}

/// Format TCP flags as human-readable string
fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 { parts.push("FIN"); }
    if flags & 0x02 != 0 { parts.push("SYN"); }
    if flags & 0x04 != 0 { parts.push("RST"); }
    if flags & 0x08 != 0 { parts.push("PSH"); }
    if flags & 0x10 != 0 { parts.push("ACK"); }
    if flags & 0x20 != 0 { parts.push("URG"); }
    if flags & 0x40 != 0 { parts.push("ECE"); }
    if flags & 0x80 != 0 { parts.push("CWR"); }
    if parts.is_empty() { "NONE".to_string() } else { parts.join(",") }
}

/// Render the editable fields (protocol-aware)
fn render_fields(frame: &mut Frame, app: &App, area: Rect, fields: &[PacketEditorField]) {
    let colors = app.current_theme.colors();
    // Check raw socket capability (cached)
    let has_raw_socket = crate::network::raw_socket::get_cached_availability().unwrap_or(false);

    let rows: Vec<Row> = fields.iter().map(|field| {
        let is_selected = *field == app.packet_editor.current_field;
        let is_editing = is_selected && app.packet_editor.editing;
        let requires_raw = field.requires_raw_socket();
        let raw_unavailable = requires_raw && !has_raw_socket;

        // Dim fields that require raw sockets when not available
        let label_style = if is_selected {
            Style::default().fg(colors.accent_bright).bold()
        } else if raw_unavailable {
            Style::default().fg(colors.fg_secondary).add_modifier(Modifier::DIM)
        } else {
            Style::default().fg(colors.fg_secondary)
        };

        let value = if is_editing {
            format!("{}|", app.packet_editor.field_buffer)
        } else {
            get_field_value(app, field)
        };

        let value_style = if is_editing {
            Style::default().fg(colors.warning).add_modifier(Modifier::BOLD)
        } else if is_selected {
            if raw_unavailable {
                Style::default().fg(colors.warning)
            } else {
                Style::default().fg(colors.accent_bright)
            }
        } else if raw_unavailable {
            Style::default().fg(colors.fg_secondary).add_modifier(Modifier::DIM)
        } else {
            Style::default().fg(colors.fg_primary)
        };

        // Show lock indicator for raw socket fields when not available
        let indicator = if is_selected {
            if raw_unavailable { "! " } else { "> " }
        } else if raw_unavailable {
            "# "
        } else {
            "  "
        };
        let indicator_style = if is_selected {
            if raw_unavailable {
                Style::default().fg(colors.warning)
            } else {
                Style::default().fg(colors.accent_bright)
            }
        } else if raw_unavailable {
            Style::default().fg(colors.fg_secondary).add_modifier(Modifier::DIM)
        } else {
            Style::default().fg(colors.bg)
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
    let colors = app.current_theme.colors();
    let has_raw_socket = crate::network::raw_socket::get_cached_availability().unwrap_or(false);
    let current_requires_raw = app.packet_editor.current_field.requires_raw_socket();
    let show_raw_warning = current_requires_raw && !has_raw_socket;

    let help_text = if app.packet_editor.editing {
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(colors.accent)),
            Span::styled(" save  ", Style::default().fg(colors.fg_dim)),
            Span::styled("Esc", Style::default().fg(colors.accent)),
            Span::styled(" cancel", Style::default().fg(colors.fg_dim)),
        ])
    } else if show_raw_warning {
        // Show raw socket warning with command
        Line::from(vec![
            Span::styled("! ", Style::default().fg(colors.warning)),
            Span::styled("Requires CAP_NET_RAW: ", Style::default().fg(colors.warning)),
            Span::styled("sudo setcap cap_net_raw+ep ", Style::default().fg(colors.accent)),
            Span::styled("<binary>", Style::default().fg(colors.accent).add_modifier(Modifier::DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled("j/k", Style::default().fg(colors.accent)),
            Span::styled(" navigate  ", Style::default().fg(colors.fg_dim)),
            Span::styled("Enter/i", Style::default().fg(colors.accent)),
            Span::styled(" edit  ", Style::default().fg(colors.fg_dim)),
            Span::styled("Type", Style::default().fg(colors.accent)),
            Span::styled(" filter  ", Style::default().fg(colors.fg_dim)),
            Span::styled("Esc/q", Style::default().fg(colors.accent)),
            Span::styled(" close", Style::default().fg(colors.fg_dim)),
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
    use crate::config::Protocol;

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

    #[test]
    fn test_filter_fields_empty_query() {
        let fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        let filtered = filter_fields(&fields, "");
        assert_eq!(filtered.len(), fields.len());
    }

    #[test]
    fn test_filter_fields_by_label() {
        let fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);

        // Filter for "port" should match Source Port and Dest Port
        let port_fields = filter_fields(&fields, "port");
        assert!(port_fields.contains(&PacketEditorField::SourcePort));
        assert!(port_fields.contains(&PacketEditorField::DestPort));
        assert!(!port_fields.contains(&PacketEditorField::Ttl));

        // Filter for "tcp" should match TCP Flags
        let tcp_fields = filter_fields(&fields, "tcp");
        assert!(tcp_fields.contains(&PacketEditorField::TcpFlags));

        // Filter for "seq" should match Sequence #
        let seq_fields = filter_fields(&fields, "seq");
        assert!(seq_fields.contains(&PacketEditorField::SeqNum));
    }

    #[test]
    fn test_filter_fields_case_insensitive() {
        let fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);

        let upper = filter_fields(&fields, "TTL");
        let lower = filter_fields(&fields, "ttl");
        let mixed = filter_fields(&fields, "TtL");

        assert_eq!(upper.len(), lower.len());
        assert_eq!(lower.len(), mixed.len());
        assert!(upper.contains(&PacketEditorField::Ttl));
    }

    #[test]
    fn test_filter_fields_no_match() {
        let fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        let filtered = filter_fields(&fields, "zzzznonexistent");
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_fields_icmp() {
        let fields = PacketEditorField::fields_for_protocol(Protocol::Icmp);

        // Filter for "icmp" should match all ICMP-specific fields
        let icmp_filtered = filter_fields(&fields, "icmp");
        assert!(icmp_filtered.contains(&PacketEditorField::IcmpType));
        assert!(icmp_filtered.contains(&PacketEditorField::IcmpCode));
        assert!(icmp_filtered.contains(&PacketEditorField::IcmpId));
        assert!(icmp_filtered.contains(&PacketEditorField::IcmpSeq));
    }

    #[test]
    fn test_filter_fields_http() {
        let fields = PacketEditorField::fields_for_protocol(Protocol::Http);

        // Filter for "method" should match HTTP Method
        let method_fields = filter_fields(&fields, "method");
        assert!(method_fields.contains(&PacketEditorField::HttpMethod));

        // Filter for "path" should match HTTP Path
        let path_fields = filter_fields(&fields, "path");
        assert!(path_fields.contains(&PacketEditorField::HttpPath));
    }
}
