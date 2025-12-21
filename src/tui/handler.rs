//! Event handlers for keyboard and mouse input
//!
//! Implements vim-like navigation and command handling

use crate::app::{ActivePane, App, HttpDirection, HttpStreamEntry, InputMode, PacketDirection, PacketEditorField, TargetField};
use crate::config::{PacketTemplate, Protocol, ScanType, TcpFlag};
use crate::network::protocols::{DnsQuery, DnsType, NtpPacket, get_service_name};
use crate::network::http::{HttpRequest, HttpResponse, HttpMethod, HttpStreamParser, status_description, format_headers};
use crate::network::packet::{PacketBuilder, parse_tcp_flags};
use crate::network::sender::common_ports;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

/// Handle keyboard events
pub async fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Global keys that work in any mode
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.quit();
            return;
        }
        _ => {}
    }

    // Protocol picker popup takes priority when visible
    if app.show_protocol_picker {
        handle_protocol_picker_keys(app, key);
        return;
    }

    // Packet editor popup takes priority when visible
    if app.show_packet_editor {
        handle_packet_editor_keys(app, key);
        return;
    }

    // Mode-specific handling
    match app.input_mode {
        InputMode::Normal => handle_normal_mode(app, key).await,
        InputMode::Insert => handle_insert_mode(app, key),
        InputMode::Command => handle_command_mode(app, key).await,
        InputMode::Help => handle_help_mode(app, key),
        InputMode::Search => handle_search_mode(app, key),
    }
}

/// Handle keys in the packet editor popup
fn handle_packet_editor_keys(app: &mut App, key: KeyEvent) {
    if app.packet_editor.editing {
        // Editing a field
        match key.code {
            KeyCode::Esc => {
                // Cancel editing
                app.packet_editor.editing = false;
                app.packet_editor.field_buffer.clear();
            }
            KeyCode::Enter => {
                // Apply the value
                if app.packet_editor.apply_buffer() {
                    app.log_success(format!("{} updated", app.packet_editor.current_field.label()));
                } else {
                    app.log_error(format!("Invalid value for {}", app.packet_editor.current_field.label()));
                }
                app.packet_editor.editing = false;
                app.packet_editor.field_buffer.clear();
            }
            KeyCode::Backspace => {
                app.packet_editor.field_buffer.pop();
            }
            KeyCode::Char(c) => {
                match app.packet_editor.current_field {
                    // Hex-only fields
                    PacketEditorField::Payload => {
                        if c.is_ascii_hexdigit() {
                            app.packet_editor.field_buffer.push(c.to_ascii_uppercase());
                        }
                    }
                    // Numeric fields
                    PacketEditorField::SourcePort | PacketEditorField::DestPort |
                    PacketEditorField::Ttl | PacketEditorField::SeqNum |
                    PacketEditorField::AckNum | PacketEditorField::WindowSize |
                    PacketEditorField::IcmpType | PacketEditorField::IcmpCode |
                    PacketEditorField::IcmpId | PacketEditorField::IcmpSeq |
                    PacketEditorField::DnsQueryType | PacketEditorField::SnmpVersion |
                    PacketEditorField::SmbVersion | PacketEditorField::LdapScope |
                    PacketEditorField::DhcpType | PacketEditorField::ArpOperation => {
                        if c.is_ascii_digit() {
                            app.packet_editor.field_buffer.push(c);
                        }
                    }
                    // Text fields (allow most printable characters)
                    _ => {
                        if c.is_ascii_graphic() || c == ' ' {
                            app.packet_editor.field_buffer.push(c);
                        }
                    }
                }
            }
            _ => {}
        }
    } else {
        // Navigation mode
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.show_packet_editor = false;
                app.log_debug("Packet editor closed");
            }
            KeyCode::Char('j') | KeyCode::Down => {
                app.packet_editor.current_field = app.packet_editor.current_field.next_for_protocol(app.selected_protocol);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                app.packet_editor.current_field = app.packet_editor.current_field.prev_for_protocol(app.selected_protocol);
            }
            KeyCode::Enter | KeyCode::Char('i') => {
                // Start editing current field
                app.packet_editor.editing = true;
                app.packet_editor.field_buffer = app.packet_editor.get_current_value();
            }
            KeyCode::Char('r') => {
                // Randomize current field
                match app.packet_editor.current_field {
                    PacketEditorField::SourcePort => {
                        app.packet_editor.source_port = rand::random::<u16>() | 0x8000;
                        app.log_info(format!("Source port randomized: {}", app.packet_editor.source_port));
                    }
                    PacketEditorField::SeqNum => {
                        app.packet_editor.seq_num = rand::random();
                        app.log_info(format!("Sequence number randomized: {}", app.packet_editor.seq_num));
                    }
                    PacketEditorField::AckNum => {
                        app.packet_editor.ack_num = rand::random();
                        app.log_info(format!("Ack number randomized: {}", app.packet_editor.ack_num));
                    }
                    PacketEditorField::IcmpId => {
                        app.packet_editor.icmp_id = rand::random();
                        app.log_info(format!("ICMP ID randomized: {}", app.packet_editor.icmp_id));
                    }
                    PacketEditorField::IcmpSeq => {
                        app.packet_editor.icmp_seq = rand::random::<u16>() & 0x7FFF;
                        app.log_info(format!("ICMP Seq randomized: {}", app.packet_editor.icmp_seq));
                    }
                    _ => {
                        app.log_warning("This field cannot be randomized");
                    }
                }
            }
            KeyCode::Char('c') => {
                // Clear payload
                if app.packet_editor.current_field == PacketEditorField::Payload {
                    app.packet_editor.payload_hex.clear();
                    app.log_info("Payload cleared");
                }
            }
            _ => {}
        }
    }
}

/// Get filtered protocols for the picker
fn get_filtered_protocols(filter: &str) -> Vec<Protocol> {
    let all = vec![
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Http,
        Protocol::Https,
        Protocol::Dns,
        Protocol::Ntp,
        Protocol::Snmp,
        Protocol::Ssdp,
        Protocol::Smb,
        Protocol::Ldap,
        Protocol::NetBios,
        Protocol::Dhcp,
        Protocol::Kerberos,
        Protocol::Arp,
        Protocol::Raw,
    ];

    if filter.is_empty() {
        return all;
    }

    let filter_lower = filter.to_lowercase();
    all.into_iter()
        .filter(|p| format!("{}", p).to_lowercase().contains(&filter_lower))
        .collect()
}

/// Handle keys in the protocol picker popup
fn handle_protocol_picker_keys(app: &mut App, key: KeyEvent) {
    let protocols = get_filtered_protocols(&app.protocol_picker_filter);

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.show_protocol_picker = false;
            app.protocol_picker_filter.clear();
            app.protocol_picker_index = 0;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if !protocols.is_empty() {
                app.protocol_picker_index = (app.protocol_picker_index + 1) % protocols.len();
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if !protocols.is_empty() {
                app.protocol_picker_index = app.protocol_picker_index
                    .checked_sub(1)
                    .unwrap_or(protocols.len().saturating_sub(1));
            }
        }
        KeyCode::Enter => {
            if let Some(proto) = protocols.get(app.protocol_picker_index) {
                app.set_protocol(*proto);
                app.show_protocol_picker = false;
                app.protocol_picker_filter.clear();
                app.protocol_picker_index = 0;
            }
        }
        KeyCode::Backspace => {
            app.protocol_picker_filter.pop();
            // Reset index if filter changes
            app.protocol_picker_index = 0;
        }
        KeyCode::Char(c) if c.is_alphanumeric() => {
            app.protocol_picker_filter.push(c);
            // Reset index when filter changes
            app.protocol_picker_index = 0;
        }
        _ => {}
    }
}

/// Handle normal mode key events (vim-like)
async fn handle_normal_mode(app: &mut App, key: KeyEvent) {
    // Handle key sequences (like 'gg')
    if !app.pending_keys.is_empty() {
        if let KeyCode::Char(c) = key.code {
            app.add_pending_key(c);
            if let Some(action) = match_key_sequence(app) {
                execute_action(app, &action).await;
                app.clear_pending_keys();
            }
            return;
        }
    }

    // Handle Ctrl+hjkl for pane navigation first
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('h') => {
                app.active_pane = app.active_pane.prev();
                app.log_debug(format!("Pane: {}", app.active_pane.name()));
                return;
            }
            KeyCode::Char('j') => {
                // Move to pane below (conceptually: left side to right side bottom)
                app.active_pane = match app.active_pane {
                    ActivePane::PacketConfig => ActivePane::FlagSelection,
                    ActivePane::FlagSelection => ActivePane::TargetConfig,
                    ActivePane::TargetConfig => ActivePane::ResponseLog,
                    ActivePane::ResponseLog => ActivePane::PacketCapture,
                    ActivePane::PacketCapture => ActivePane::Statistics,
                    ActivePane::HttpStream => ActivePane::Statistics,
                    ActivePane::Statistics => ActivePane::PacketConfig,
                };
                app.log_debug(format!("Pane: {}", app.active_pane.name()));
                return;
            }
            KeyCode::Char('k') => {
                // Move to pane above
                app.active_pane = match app.active_pane {
                    ActivePane::PacketConfig => ActivePane::Statistics,
                    ActivePane::FlagSelection => ActivePane::PacketConfig,
                    ActivePane::TargetConfig => ActivePane::FlagSelection,
                    ActivePane::ResponseLog => ActivePane::TargetConfig,
                    ActivePane::PacketCapture => ActivePane::ResponseLog,
                    ActivePane::HttpStream => ActivePane::PacketCapture,
                    ActivePane::Statistics => ActivePane::PacketCapture,
                };
                app.log_debug(format!("Pane: {}", app.active_pane.name()));
                return;
            }
            KeyCode::Char('l') => {
                app.active_pane = app.active_pane.next();
                app.log_debug(format!("Pane: {}", app.active_pane.name()));
                return;
            }
            _ => {}
        }
    }

    match key.code {
        // Movement keys
        KeyCode::Char('h') | KeyCode::Left => handle_left(app),
        KeyCode::Char('j') | KeyCode::Down => app.move_down(),
        KeyCode::Char('k') | KeyCode::Up => app.move_up(),
        KeyCode::Char('l') | KeyCode::Right => handle_right(app),

        // Start key sequence for 'gg'
        KeyCode::Char('g') => {
            app.add_pending_key('g');
        }

        // Go to bottom
        KeyCode::Char('G') => {
            handle_go_bottom(app);
        }

        // Half page scroll
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.page_down();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.page_up();
        }

        // Pane navigation
        KeyCode::Tab => {
            app.active_pane = app.active_pane.next();
            app.log_debug(format!("Switched to {} pane", app.active_pane.name()));
        }
        KeyCode::BackTab => {
            app.active_pane = app.active_pane.prev();
            app.log_debug(format!("Switched to {} pane", app.active_pane.name()));
        }

        // Selection / Toggle
        KeyCode::Enter => {
            handle_select(app);
        }
        // Space starts a key sequence for session commands (Space+n, Space+], etc.)
        KeyCode::Char(' ') => {
            app.add_pending_key(' ');
        }

        // Mode switches
        KeyCode::Char('i') => {
            app.input_mode = InputMode::Insert;
            // Jump directly to TargetConfig pane when entering insert mode
            app.active_pane = ActivePane::TargetConfig;
            app.input_buffer.clear();
            app.cursor_position = 0;
        }
        KeyCode::Char(':') => {
            app.input_mode = InputMode::Command;
            app.command_buffer.clear();
        }
        KeyCode::Char('/') => {
            app.input_mode = InputMode::Search;
            app.search_buffer.clear();
        }
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
            if app.show_help {
                app.input_mode = InputMode::Help;
            }
        }

        // Quick actions
        KeyCode::Char('s') => {
            // Send packet
            handle_send(app).await;
        }
        KeyCode::Char('r') => {
            // Retry last failed
            handle_retry(app).await;
        }
        KeyCode::Char('c') => {
            // Clear logs
            app.logs.clear();
            app.log_info("Logs cleared");
        }
        KeyCode::Char('e') => {
            // Open packet editor with protocol-specific fields
            app.packet_editor.reset_to_protocol(app.selected_protocol);
            app.show_packet_editor = true;
        }
        KeyCode::Char('P') => {
            // Open protocol picker
            app.show_protocol_picker = true;
        }

        // Protocol selection (number keys)
        KeyCode::Char('1') => app.set_protocol(Protocol::Tcp),
        KeyCode::Char('2') => app.set_protocol(Protocol::Udp),
        KeyCode::Char('3') => app.set_protocol(Protocol::Icmp),
        KeyCode::Char('4') => app.set_protocol(Protocol::Http),
        KeyCode::Char('5') => app.set_protocol(Protocol::Https),
        KeyCode::Char('6') => app.set_protocol(Protocol::Dns),
        KeyCode::Char('7') => app.set_protocol(Protocol::Ntp),

        // Scan type shortcuts
        KeyCode::F(1) => app.set_scan_type(ScanType::SynScan),
        KeyCode::F(2) => app.set_scan_type(ScanType::ConnectScan),
        KeyCode::F(3) => app.set_scan_type(ScanType::FinScan),
        KeyCode::F(4) => app.set_scan_type(ScanType::NullScan),
        KeyCode::F(5) => app.set_scan_type(ScanType::XmasScan),
        KeyCode::F(6) => app.set_scan_type(ScanType::AckScan),
        KeyCode::F(7) => app.set_scan_type(ScanType::UdpScan),

        // Quit
        KeyCode::Char('q') => {
            if !app.show_help {
                app.quit();
            } else {
                app.show_help = false;
                app.input_mode = InputMode::Normal;
            }
        }
        KeyCode::Esc => {
            if app.show_help {
                app.show_help = false;
            }
            app.input_mode = InputMode::Normal;
            app.clear_pending_keys();
        }

        _ => {}
    }
}

/// Handle insert mode key events
fn handle_insert_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            // Apply the input to the appropriate field
            apply_input(app);
        }
        KeyCode::Enter => {
            apply_input(app);
            app.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            if app.cursor_position > 0 {
                app.input_buffer.remove(app.cursor_position - 1);
                app.cursor_position -= 1;
            }
        }
        KeyCode::Delete => {
            if app.cursor_position < app.input_buffer.len() {
                app.input_buffer.remove(app.cursor_position);
            }
        }
        KeyCode::Left => {
            if app.cursor_position > 0 {
                app.cursor_position -= 1;
            }
        }
        KeyCode::Right => {
            if app.cursor_position < app.input_buffer.len() {
                app.cursor_position += 1;
            }
        }
        KeyCode::Home => {
            app.cursor_position = 0;
        }
        KeyCode::End => {
            app.cursor_position = app.input_buffer.len();
        }
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Delete word
            while app.cursor_position > 0
                && app
                    .input_buffer
                    .chars()
                    .nth(app.cursor_position - 1)
                    .map(|c| c.is_whitespace())
                    .unwrap_or(false)
            {
                app.input_buffer.remove(app.cursor_position - 1);
                app.cursor_position -= 1;
            }
            while app.cursor_position > 0
                && app
                    .input_buffer
                    .chars()
                    .nth(app.cursor_position - 1)
                    .map(|c| !c.is_whitespace())
                    .unwrap_or(false)
            {
                app.input_buffer.remove(app.cursor_position - 1);
                app.cursor_position -= 1;
            }
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Clear line
            app.input_buffer.clear();
            app.cursor_position = 0;
        }
        KeyCode::Char(c) => {
            app.input_buffer.insert(app.cursor_position, c);
            app.cursor_position += 1;
        }
        KeyCode::Tab => {
            // Switch target field
            app.target_input_field = match app.target_input_field {
                TargetField::Host => TargetField::Port,
                TargetField::Port => TargetField::Host,
            };
            // Load current value into buffer
            app.input_buffer = match app.target_input_field {
                TargetField::Host => app.target.host.clone(),
                TargetField::Port => app
                    .target
                    .ports
                    .first()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
            };
            app.cursor_position = app.input_buffer.len();
        }
        _ => {}
    }
}

/// Handle command mode key events
async fn handle_command_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            app.command_buffer.clear();
        }
        KeyCode::Enter => {
            let command = app.command_buffer.clone();
            app.command_buffer.clear();
            app.input_mode = InputMode::Normal;
            execute_command(app, &command).await;
        }
        KeyCode::Backspace => {
            app.command_buffer.pop();
        }
        KeyCode::Char(c) => {
            app.command_buffer.push(c);
        }
        KeyCode::Tab => {
            // Simple command completion
            complete_command(app);
        }
        _ => {}
    }
}

/// Handle help mode key events
fn handle_help_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
            app.show_help = false;
            app.input_mode = InputMode::Normal;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            // Scroll help down
        }
        KeyCode::Char('k') | KeyCode::Up => {
            // Scroll help up
        }
        _ => {}
    }
}

/// Handle search mode key events
fn handle_search_mode(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.input_mode = InputMode::Normal;
            app.search_buffer.clear();
        }
        KeyCode::Enter => {
            // Execute search
            app.input_mode = InputMode::Normal;
            if !app.search_buffer.is_empty() {
                app.log_info(format!("Searching for: {}", app.search_buffer));
            }
        }
        KeyCode::Backspace => {
            app.search_buffer.pop();
        }
        KeyCode::Char(c) => {
            app.search_buffer.push(c);
        }
        _ => {}
    }
}

/// Handle mouse events
pub fn handle_mouse_event(app: &mut App, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // Handle click - could be used for pane selection
            tracing::debug!("Mouse click at ({}, {})", mouse.column, mouse.row);
        }
        MouseEventKind::ScrollUp => {
            app.move_up();
        }
        MouseEventKind::ScrollDown => {
            app.move_down();
        }
        _ => {}
    }
}

/// Match key sequences like 'gg' or ' n' (Space+n)
fn match_key_sequence(app: &App) -> Option<String> {
    let keys: String = app.pending_keys.iter().collect();

    match keys.as_str() {
        "gg" => Some("go_top".to_string()),
        " n" => Some("new_session".to_string()),
        " ]" => Some("next_session".to_string()),
        " [" => Some("prev_session".to_string()),
        " x" => Some("close_session".to_string()),
        _ => None,
    }
}

/// Execute an action from a key sequence
async fn execute_action(app: &mut App, action: &str) {
    match action {
        "go_top" => handle_go_top(app),
        "new_session" => app.create_new_session(),
        "next_session" => app.next_session(),
        "prev_session" => app.prev_session(),
        "close_session" => app.close_session(),
        _ => {}
    }
}

/// Handle left movement
fn handle_left(app: &mut App) {
    app.active_pane = app.active_pane.prev();
}

/// Handle right movement
fn handle_right(app: &mut App) {
    app.active_pane = app.active_pane.next();
}

/// Handle go to top
fn handle_go_top(app: &mut App) {
    match app.active_pane {
        ActivePane::FlagSelection => app.flag_list_index = 0,
        ActivePane::PacketConfig => {
            app.protocol_index = 0;
            app.scan_type_index = 0;
        }
        ActivePane::ResponseLog => app.log_scroll = 0,
        ActivePane::HttpStream => app.http_scroll = 0,
        _ => {}
    }
}

/// Handle go to bottom
fn handle_go_bottom(app: &mut App) {
    match app.active_pane {
        ActivePane::FlagSelection => {
            app.flag_list_index = TcpFlag::all().len().saturating_sub(1);
        }
        ActivePane::PacketConfig => {
            app.scan_type_index = ScanType::all().len().saturating_sub(1);
        }
        ActivePane::ResponseLog => {
            app.log_scroll = app.logs.len().saturating_sub(1);
        }
        ActivePane::HttpStream => {
            app.http_scroll = app.http_stream.len().saturating_sub(1);
        }
        _ => {}
    }
}

/// Handle selection in current pane
fn handle_select(app: &mut App) {
    match app.active_pane {
        ActivePane::FlagSelection => {
            let flags = TcpFlag::all();
            if let Some(flag) = flags.get(app.flag_list_index) {
                app.toggle_flag(*flag);
                app.log_debug(format!("Toggled flag: {}", flag));
            }
        }
        ActivePane::PacketConfig => {
            // Handle selection based on current protocol
            match app.selected_protocol {
                Protocol::Tcp | Protocol::Udp => {
                    // Use filtered scan types to get correct item
                    let filtered = app.get_filtered_scan_types();
                    if let Some(scan_type) = filtered.get(app.scan_type_index) {
                        app.set_scan_type(*scan_type);
                        app.log_info(format!("Selected scan type: {}", scan_type.name()));
                    }
                }
                Protocol::Icmp => {
                    // ICMP type selection
                    let icmp_types = [(8u8, 0u8), (0, 0), (3, 0), (11, 0), (13, 0)];
                    if let Some((t, c)) = icmp_types.get(app.scan_type_index) {
                        app.icmp_type = *t;
                        app.icmp_code = *c;
                        app.log_info(format!("Selected ICMP type={} code={}", t, c));
                    }
                }
                Protocol::Dns => {
                    // DNS query type selection
                    let dns_types = [1u16, 28, 15, 16, 2, 5]; // A, AAAA, MX, TXT, NS, CNAME
                    if let Some(qtype) = dns_types.get(app.scan_type_index) {
                        app.dns_query_type = *qtype;
                        app.log_info(format!("Selected DNS query type: {}", qtype));
                    }
                }
                Protocol::Http | Protocol::Https => {
                    // HTTP method selection
                    let methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"];
                    if let Some(method) = methods.get(app.scan_type_index) {
                        app.http_method = method.to_string();
                        app.log_info(format!("Selected HTTP method: {}", method));
                    }
                }
                Protocol::Snmp => {
                    let versions = [1u8, 2, 3];
                    if let Some(ver) = versions.get(app.scan_type_index) {
                        app.snmp_version = *ver;
                        let name = match ver { 1 => "v1", 2 => "v2c", 3 => "v3", _ => "?" };
                        app.log_info(format!("Selected SNMP {}", name));
                    }
                }
                Protocol::Ssdp => {
                    let targets = [0u8, 1, 2];
                    if let Some(t) = targets.get(app.scan_type_index) {
                        app.ssdp_target = *t;
                        let name = match t { 0 => "ssdp:all", 1 => "upnp:rootdevice", _ => "custom" };
                        app.log_info(format!("Selected SSDP target: {}", name));
                    }
                }
                Protocol::Smb => {
                    let versions = [1u8, 2, 3];
                    if let Some(ver) = versions.get(app.scan_type_index) {
                        app.smb_version = *ver;
                        app.log_info(format!("Selected SMB{}", ver));
                    }
                }
                Protocol::Ldap => {
                    let scopes = [0u8, 1, 2];
                    if let Some(scope) = scopes.get(app.scan_type_index) {
                        app.ldap_scope = *scope;
                        let name = match scope { 0 => "Base", 1 => "One Level", _ => "Subtree" };
                        app.log_info(format!("Selected LDAP scope: {}", name));
                    }
                }
                Protocol::NetBios => {
                    let types = [0u8, 1];
                    if let Some(t) = types.get(app.scan_type_index) {
                        app.netbios_type = *t;
                        let name = match t { 0 => "Name Query", _ => "Node Status" };
                        app.log_info(format!("Selected NetBIOS: {}", name));
                    }
                }
                Protocol::Dhcp => {
                    let types = [1u8, 3, 7];
                    if let Some(t) = types.get(app.scan_type_index) {
                        app.dhcp_type = *t;
                        let name = match t { 1 => "Discover", 3 => "Request", _ => "Release" };
                        app.log_info(format!("Selected DHCP {}", name));
                    }
                }
                Protocol::Kerberos => {
                    let types = [10u8, 12];
                    if let Some(t) = types.get(app.scan_type_index) {
                        app.kerberos_type = *t;
                        let name = match t { 10 => "AS-REQ", _ => "TGS-REQ" };
                        app.log_info(format!("Selected Kerberos {}", name));
                    }
                }
                Protocol::Arp => {
                    let ops = [1u8, 2];
                    if let Some(op) = ops.get(app.scan_type_index) {
                        app.arp_operation = *op;
                        let name = match op { 1 => "Request", _ => "Reply" };
                        app.log_info(format!("Selected ARP {}", name));
                    }
                }
                Protocol::Ntp | Protocol::Raw => {
                    // Template selection - just log, templates are used elsewhere
                    let templates = PacketTemplate::all();
                    if let Some(tmpl) = templates.get(app.scan_type_index) {
                        app.log_info(format!("Selected template: {}", tmpl.name()));
                    }
                }
            }
        }
        _ => {}
    }
}

/// Handle send packet action
async fn handle_send(app: &mut App) {
    if app.target.host.is_empty() {
        app.log_error("No target specified. Use 'i' to enter target.");
        return;
    }

    tracing::info!(
        target = %app.target.host,
        protocol = %app.selected_protocol,
        scan_type = %app.selected_scan_type,
        packet_count = app.packet_count,
        "Initiating packet send"
    );

    let packet_count = app.packet_count;

    // Log with protocol-specific info
    let proto_info = match app.selected_protocol {
        Protocol::Icmp => format!("ICMP type={} code={} id={} seq={}",
            app.icmp_type, app.icmp_code, app.icmp_id, app.icmp_seq),
        Protocol::Dns => format!("DNS query={} domain={}",
            app.dns_query_type, if app.dns_domain.is_empty() { &app.target.host } else { &app.dns_domain }),
        Protocol::Http | Protocol::Https => format!("{} {}", app.http_method, app.http_path),
        _ => format!("{} flags=0x{:02X}", app.selected_scan_type, app.flags_bitmask()),
    };

    app.log_info(format!(
        "Sending {} x {} {} packets to {}:{} ({})",
        packet_count,
        app.selected_scan_type,
        app.selected_protocol,
        app.target.host,
        app.target.ports.first().unwrap_or(&80),
        proto_info
    ));

    // Clone what we need to avoid borrow issues
    let sender = app.packet_sender.clone();
    let host = app.target.host.clone();
    let ports = app.target.ports.clone();
    let scan_type = app.selected_scan_type;
    let flags = app.selected_flags.clone();
    let protocol = app.selected_protocol;

    if let Some(sender) = sender {
        // Resolve host
        match crate::network::sender::PacketSender::resolve_host(&host).await {
            Ok(ip) => {
                app.target.ip = Some(ip);

                // Create and execute job
                let job = app.create_job();
                app.log_info(format!("Created job: {}", job.id));

                // Handle HTTP/HTTPS specially - send actual HTTP requests
                if matches!(protocol, Protocol::Http | Protocol::Https) {
                    let port = *ports.first().unwrap_or(&80);
                    let http_method = app.http_method.clone();
                    let http_path = app.http_path.clone();
                    // Note: HTTPS not yet implemented - uses plain TCP
                    let _use_https = matches!(protocol, Protocol::Https);

                    for iteration in 0..packet_count {
                        if packet_count > 1 {
                            app.log_debug(format!("HTTP request {}/{}", iteration + 1, packet_count));
                        }

                        // Record outgoing HTTP request
                        app.capture_packet(
                            PacketDirection::Sent,
                            protocol,
                            None,
                            None,
                            Some(ip),
                            Some(port),
                            vec![],
                            0,
                            None,
                            None,
                            http_method.as_bytes(),
                            None,
                            format!("{} {} HTTP request", http_method, http_path),
                        );

                        // Build HTTP headers with Host
                        let mut headers = HashMap::new();
                        headers.insert("Host".to_string(), host.clone());
                        headers.insert("User-Agent".to_string(), "NoirCast/0.1.0".to_string());
                        headers.insert("Accept".to_string(), "*/*".to_string());
                        headers.insert("Connection".to_string(), "close".to_string());

                        // Send actual HTTP request
                        match sender.send_http_request(
                            ip,
                            port,
                            &http_method,
                            &http_path,
                            &headers,
                            None, // No body for GET/HEAD requests
                        ).await {
                            Ok((response_bytes, duration)) => {
                                let rtt = duration.as_secs_f64() * 1000.0;

                                // Parse HTTP response
                                let (status_code, status_text) = if let Ok(resp_str) = std::str::from_utf8(&response_bytes) {
                                    // Parse first line for status
                                    if let Some(first_line) = resp_str.lines().next() {
                                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                                        if parts.len() >= 2 {
                                            let code = parts[1].parse::<u16>().unwrap_or(0);
                                            let text = parts.get(2..).map(|p| p.join(" ")).unwrap_or_default();
                                            (code, text)
                                        } else {
                                            (0, String::new())
                                        }
                                    } else {
                                        (0, String::new())
                                    }
                                } else {
                                    (0, String::new())
                                };

                                // Record response in capture
                                let status_str = if status_code > 0 {
                                    format!("HTTP {} {}", status_code, status_text)
                                } else {
                                    "Response received".to_string()
                                };
                                app.capture_packet(
                                    PacketDirection::Received,
                                    protocol,
                                    Some(ip),
                                    Some(port),
                                    None,
                                    None,
                                    vec![],
                                    0,
                                    None,
                                    None,
                                    &response_bytes[..response_bytes.len().min(100)],
                                    Some(rtt),
                                    status_str.clone(),
                                );

                                app.log_success(format!(
                                    "HTTP {} {} -> {} {} ({:.2}ms, {} bytes)",
                                    http_method, http_path, status_code, status_text, rtt, response_bytes.len()
                                ));

                                // Add HTTP stream entry for response
                                let entry = HttpStreamEntry {
                                    timestamp: chrono::Utc::now(),
                                    direction: HttpDirection::Response,
                                    method: None,
                                    url: None,
                                    status_code: Some(status_code),
                                    headers: HashMap::new(),
                                    body: String::from_utf8(response_bytes.clone()).ok(),
                                    raw: response_bytes,
                                };
                                app.add_http_entry(entry);
                            }
                            Err(e) => {
                                app.log_error(format!("HTTP request failed: {}", e));
                                app.capture_packet(
                                    PacketDirection::Received,
                                    protocol,
                                    Some(ip),
                                    Some(port),
                                    None,
                                    None,
                                    vec![],
                                    0,
                                    None,
                                    None,
                                    &[],
                                    None,
                                    format!("Error: {}", e),
                                );
                            }
                        }
                    }

                    // Add HTTP stream entry for request
                    let entry = HttpStreamEntry {
                        timestamp: chrono::Utc::now(),
                        direction: HttpDirection::Request,
                        method: Some(http_method),
                        url: Some(format!("{}:{}{}", host, port, http_path)),
                        status_code: None,
                        headers: HashMap::new(),
                        body: None,
                        raw: vec![],
                    };
                    app.add_http_entry(entry);
                } else if matches!(protocol, Protocol::Icmp) {
                    // ICMP protocol: use send_icmp_batch
                    let icmp_type = app.icmp_type;
                    let icmp_code = app.icmp_code;
                    let icmp_id = app.icmp_id;
                    let icmp_seq = app.icmp_seq;

                    app.capture_packet(
                        PacketDirection::Sent,
                        protocol,
                        None,
                        None,
                        Some(ip),
                        None,
                        vec![],
                        0,
                        None,
                        None,
                        &[icmp_type, icmp_code],
                        None,
                        format!("ICMP type={} code={} id={} seq={}", icmp_type, icmp_code, icmp_id, icmp_seq),
                    );

                    // Send ICMP to the target (packet_count times)
                    let targets: Vec<IpAddr> = (0..packet_count).map(|_| ip).collect();
                    let responses = sender.send_icmp_batch(&targets, icmp_type, icmp_code, icmp_id, icmp_seq).await;

                    for response in responses {
                        let status_str = format!("{}", response.status);
                        app.capture_packet(
                            PacketDirection::Received,
                            protocol,
                            Some(response.target_ip),
                            None,
                            None,
                            None,
                            vec![],
                            0,
                            None,
                            None,
                            &[],
                            response.rtt_ms,
                            status_str.clone(),
                        );

                        app.log_info(format!(
                            "ICMP {}: {} (RTT: {:?}ms)",
                            response.target_ip,
                            response.status,
                            response.rtt_ms.map(|r| format!("{:.2}", r))
                        ));
                        app.add_response(response).await;
                    }

                    app.log_success(format!("Sent {} ICMP packets to {}", packet_count, host));
                } else if matches!(protocol, Protocol::Dns) {
                    // DNS protocol: use send_dns_batch
                    let dns_query_type = app.dns_query_type;
                    let domain = if app.dns_domain.is_empty() {
                        app.target.host.clone()
                    } else {
                        app.dns_domain.clone()
                    };

                    app.capture_packet(
                        PacketDirection::Sent,
                        protocol,
                        None,
                        None,
                        Some(ip),
                        Some(53),
                        vec![],
                        0,
                        None,
                        None,
                        domain.as_bytes(),
                        None,
                        format!("DNS query type={} domain={}", dns_query_type, domain),
                    );

                    let responses = sender.send_dns_batch(ip, &domain, dns_query_type, packet_count).await;

                    for response in responses {
                        let status_str = format!("{}", response.status);
                        app.capture_packet(
                            PacketDirection::Received,
                            protocol,
                            Some(response.target_ip),
                            Some(53),
                            None,
                            None,
                            vec![],
                            0,
                            None,
                            None,
                            response.raw_response.as_ref().map(|r| r.as_slice()).unwrap_or(&[]),
                            response.rtt_ms,
                            status_str.clone(),
                        );

                        app.log_info(format!(
                            "DNS {}: {} (RTT: {:?}ms)",
                            response.target_ip,
                            response.status,
                            response.rtt_ms.map(|r| format!("{:.2}", r))
                        ));
                        app.add_response(response).await;
                    }

                    app.log_success(format!("Sent {} DNS queries to {}", packet_count, host));
                } else if matches!(protocol, Protocol::Ntp) {
                    // NTP protocol: use send_ntp_batch
                    app.capture_packet(
                        PacketDirection::Sent,
                        protocol,
                        None,
                        None,
                        Some(ip),
                        Some(123),
                        vec![],
                        0,
                        None,
                        None,
                        &[0x1b], // NTP client mode
                        None,
                        "NTP request".to_string(),
                    );

                    let targets: Vec<IpAddr> = (0..packet_count).map(|_| ip).collect();
                    let responses = sender.send_ntp_batch(&targets).await;

                    for response in responses {
                        let status_str = format!("{}", response.status);
                        app.capture_packet(
                            PacketDirection::Received,
                            protocol,
                            Some(response.target_ip),
                            Some(123),
                            None,
                            None,
                            vec![],
                            0,
                            None,
                            None,
                            response.raw_response.as_ref().map(|r| r.as_slice()).unwrap_or(&[]),
                            response.rtt_ms,
                            status_str.clone(),
                        );

                        app.log_info(format!(
                            "NTP {}: {} (RTT: {:?}ms)",
                            response.target_ip,
                            response.status,
                            response.rtt_ms.map(|r| format!("{:.2}", r))
                        ));
                        app.add_response(response).await;
                    }

                    app.log_success(format!("Sent {} NTP requests to {}", packet_count, host));
                } else {
                    // TCP/UDP protocols: use send_batch for scanning
                    for iteration in 0..packet_count {
                        if packet_count > 1 {
                            app.log_debug(format!("Packet batch {}/{}", iteration + 1, packet_count));
                        }

                        // Record outgoing packets in capture
                        for &port in &ports {
                            app.capture_packet(
                                PacketDirection::Sent,
                                protocol,
                                None, // source IP (local)
                                None, // source port (ephemeral)
                                Some(IpAddr::V4(match ip {
                                    IpAddr::V4(v4) => v4,
                                    IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
                                })),
                                Some(port),
                                flags.clone(),
                                scan_type.flags_bitmask(),
                                None, // seq_num
                                None, // ack_num
                                &[],  // no payload for scan
                                None, // rtt not known yet
                                format!("{} scan #{}", scan_type, iteration + 1),
                            );
                        }

                        // Send packets
                        let responses = sender
                            .send_batch(ip, &ports, scan_type, &flags)
                            .await;

                        for response in responses {
                            // Record response in capture
                            let status_str = format!("{}", response.status);
                            app.capture_packet(
                                PacketDirection::Received,
                                protocol,
                                Some(response.target_ip),
                                Some(response.target_port),
                                None, // dest IP (us)
                                None, // dest port (our ephemeral)
                                response.flags_received.clone().unwrap_or_default(),
                                0,
                                None,
                                None,
                                &[],
                                response.rtt_ms,
                                status_str.clone(),
                            );

                            // Only log individual responses in debug mode or for last batch
                            if packet_count == 1 || iteration == packet_count - 1 {
                                app.log_info(format!(
                                    "Port {}: {} (RTT: {:?}ms)",
                                    response.target_port,
                                    response.status,
                                    response.rtt_ms.map(|r| format!("{:.2}", r))
                                ));
                            }
                            app.add_response(response).await;
                        }
                    }

                    // Summary for multiple packets
                    if packet_count > 1 {
                        app.log_success(format!(
                            "Completed: {} packets x {} ports = {} total",
                            packet_count,
                            ports.len(),
                            packet_count * ports.len()
                        ));
                    }
                }

                // Set temporary status
                app.set_status(
                    format!("Sent {} packets to {}", packet_count * ports.len(), host),
                    crate::app::LogLevel::Success,
                );
            }
            Err(e) => {
                app.log_error(format!("Failed to resolve host: {}", e));
            }
        }
    } else {
        app.log_error("Packet sender not initialized");
    }
}

/// Handle retry action
async fn handle_retry(app: &mut App) {
    // Find last failed job and retry
    if let Some(job) = app.jobs.iter().rev().find(|j| {
        j.status == crate::app::JobStatus::Failed
            || j.responses.iter().any(|r| {
                r.status == crate::network::packet::ResponseStatus::NoResponse
                    || r.status == crate::network::packet::ResponseStatus::Error
            })
    }) {
        app.log_info(format!("Retrying job: {}", job.id));
        // Re-send with same parameters
        handle_send(app).await;
    } else {
        app.log_warning("No failed jobs to retry");
    }
}

/// Apply input from insert mode
fn apply_input(app: &mut App) {
    if app.input_buffer.is_empty() {
        return;
    }

    match app.active_pane {
        ActivePane::TargetConfig => {
            match app.target_input_field {
                TargetField::Host => {
                    app.target.host = app.input_buffer.clone();
                    app.log_info(format!("Target host set to: {}", app.target.host));
                }
                TargetField::Port => {
                    if let Ok(ports) =
                        crate::network::sender::parse_port_range(&app.input_buffer)
                    {
                        app.target.ports = ports;
                        app.log_info(format!("Target ports set to: {:?}", app.target.ports));
                    } else {
                        app.log_error("Invalid port range");
                    }
                }
            }
        }
        ActivePane::PacketConfig => {
            // Could be used for custom payload input
            if let Ok(count) = app.input_buffer.parse::<usize>() {
                app.packet_count = count;
                app.log_info(format!("Packet count set to: {}", count));
            }
        }
        _ => {
            // Try to parse as target
            let input = app.input_buffer.clone();
            let _ = app.parse_target(&input);
        }
    }

    app.input_buffer.clear();
    app.cursor_position = 0;
}

/// Execute a command from command mode
async fn execute_command(app: &mut App, command: &str) {
    let parts: Vec<&str> = command.trim().split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    tracing::debug!(command = %command, "Executing command");

    match parts[0] {
        "q" | "quit" | "exit" => {
            app.quit();
        }
        "w" | "write" => {
            app.log_info("Configuration saved (placeholder)");
        }
        "wq" => {
            app.log_info("Configuration saved");
            app.quit();
        }
        "target" | "t" => {
            if parts.len() > 1 {
                let target = parts[1..].join(" ");
                let _ = app.parse_target(&target);
                app.log_success(format!("Target set to: {}", app.target.host));
            }
        }
        "port" | "p" => {
            if parts.len() > 1 {
                if let Ok(ports) = crate::network::sender::parse_port_range(parts[1]) {
                    app.target.ports = ports.clone();
                    app.log_success(format!("Ports set: {} port(s)", ports.len()));
                }
            }
        }
        "scan" => {
            if parts.len() > 1 {
                match parts[1].to_lowercase().as_str() {
                    "syn" => app.set_scan_type(ScanType::SynScan),
                    "connect" => app.set_scan_type(ScanType::ConnectScan),
                    "fin" => app.set_scan_type(ScanType::FinScan),
                    "null" => app.set_scan_type(ScanType::NullScan),
                    "xmas" => app.set_scan_type(ScanType::XmasScan),
                    "ack" => app.set_scan_type(ScanType::AckScan),
                    "udp" => app.set_scan_type(ScanType::UdpScan),
                    _ => app.log_error(format!("Unknown scan type: {}", parts[1])),
                }
            }
        }
        "send" | "s" => {
            handle_send(app).await;
        }
        "clear" | "cls" => {
            app.logs.clear();
            app.clear_captures();
            app.log_success("Logs and captures cleared");
        }
        "count" | "n" => {
            if parts.len() > 1 {
                if let Ok(count) = parts[1].parse::<usize>() {
                    app.packet_count = count.max(1); // At least 1 packet
                    app.log_success(format!("Packet count set to: {}", app.packet_count));
                } else {
                    app.log_error("Invalid count. Usage: :count <number>");
                }
            } else {
                app.log_info(format!("Current packet count: {}", app.packet_count));
            }
        }
        "stats" => {
            if let Some(sender) = &app.packet_sender {
                let stats = sender.get_stats().await;
                app.log_info(format!(
                    "Stats: sent={}, recv={}, failed={}, success_rate={:.1}%",
                    stats.packets_sent,
                    stats.packets_received,
                    stats.packets_failed,
                    stats.success_rate()
                ));
            }
        }
        "help" | "h" => {
            app.show_help = true;
            app.input_mode = InputMode::Help;
        }
        "packet" | "edit" | "pe" => {
            app.show_packet_editor = true;
            app.log_info("Packet editor opened");
        }
        "payload" => {
            if parts.len() > 1 {
                // Set payload from hex string
                let hex_str: String = parts[1..].join("").chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if hex_str.len() % 2 == 0 {
                    app.packet_editor.payload_hex = hex_str.to_uppercase();
                    let byte_count = app.packet_editor.payload_hex.len() / 2;
                    app.log_success(format!("Payload set: {} bytes", byte_count));
                } else {
                    app.log_error("Invalid hex payload: must have even number of hex characters");
                }
            } else {
                // Show current payload
                if let Some(bytes) = app.packet_editor.to_payload_bytes() {
                    app.log_info(format!("Payload: {} bytes - {:02X?}", bytes.len(), bytes));
                } else {
                    app.log_info("No payload configured");
                }
            }
        }
        "srcport" | "sp" => {
            if parts.len() > 1 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    app.packet_editor.source_port = port;
                    app.log_success(format!("Source port set to: {}", port));
                } else {
                    app.log_error("Invalid port number");
                }
            } else {
                app.log_info(format!("Source port: {}", app.packet_editor.source_port));
            }
        }
        "dstport" | "dp" => {
            if parts.len() > 1 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    app.packet_editor.dest_port = port;
                    app.log_success(format!("Dest port set to: {}", port));
                } else {
                    app.log_error("Invalid port number");
                }
            } else {
                app.log_info(format!("Dest port: {}", app.packet_editor.dest_port));
            }
        }
        "ttl" => {
            if parts.len() > 1 {
                if let Ok(ttl) = parts[1].parse::<u8>() {
                    app.packet_editor.ttl = ttl;
                    app.log_success(format!("TTL set to: {}", ttl));
                } else {
                    app.log_error("Invalid TTL (0-255)");
                }
            } else {
                app.log_info(format!("TTL: {}", app.packet_editor.ttl));
            }
        }
        "seq" | "seqnum" => {
            if parts.len() > 1 {
                if let Ok(seq) = parts[1].parse::<u32>() {
                    app.packet_editor.seq_num = seq;
                    app.log_success(format!("Sequence number set to: {}", seq));
                } else {
                    app.log_error("Invalid sequence number");
                }
            } else {
                app.log_info(format!("Sequence number: {}", app.packet_editor.seq_num));
            }
        }
        "ack" | "acknum" => {
            if parts.len() > 1 {
                if let Ok(ack) = parts[1].parse::<u32>() {
                    app.packet_editor.ack_num = ack;
                    app.log_success(format!("Ack number set to: {}", ack));
                } else {
                    app.log_error("Invalid ack number");
                }
            } else {
                app.log_info(format!("Ack number: {}", app.packet_editor.ack_num));
            }
        }
        "window" | "win" => {
            if parts.len() > 1 {
                if let Ok(win) = parts[1].parse::<u16>() {
                    app.packet_editor.window_size = win;
                    app.log_success(format!("Window size set to: {}", win));
                } else {
                    app.log_error("Invalid window size");
                }
            } else {
                app.log_info(format!("Window size: {}", app.packet_editor.window_size));
            }
        }
        "randseq" => {
            app.packet_editor.seq_num = rand::random();
            app.log_info(format!("Randomized sequence number: {}", app.packet_editor.seq_num));
        }
        "randport" => {
            app.packet_editor.source_port = rand::random::<u16>() | 0x8000;
            app.log_info(format!("Randomized source port: {}", app.packet_editor.source_port));
        }
        "debug" => {
            app.args.debug = !app.args.debug;
            app.log_info(format!("Debug mode: {}", app.args.debug));
        }
        "ports" => {
            // Set common ports using common_ports module
            if parts.len() > 1 {
                match parts[1] {
                    "top20" => {
                        app.target.ports = common_ports::TOP_20.to_vec();
                        app.log_success(format!("Set {} common ports (top 20)", common_ports::TOP_20.len()));
                    }
                    "top100" => {
                        app.target.ports = common_ports::TOP_100.to_vec();
                        app.log_success(format!("Set {} common ports (top 100)", common_ports::TOP_100.len()));
                    }
                    "all" => {
                        app.target.ports = common_ports::all();
                        app.log_success(format!("Set {} common ports (all)", common_ports::all().len()));
                    }
                    "priv" | "privileged" => {
                        app.target.ports = common_ports::privileged();
                        app.log_success(format!("Set {} privileged ports", common_ports::privileged().len()));
                    }
                    _ => {
                        app.log_error("Usage: :ports top20|top100|all|priv");
                    }
                }
            } else {
                app.log_info("Usage: :ports top20|top100|all|priv");
            }
        }
        "template" | "tmpl" => {
            // Use a packet template
            if parts.len() > 1 {
                let templates = PacketTemplate::all();
                if let Some(tmpl) = templates.iter().find(|t| t.shortcut().eq_ignore_ascii_case(parts[1]) || t.name().eq_ignore_ascii_case(parts[1])) {
                    app.selected_protocol = tmpl.protocol();
                    app.target.ports = vec![tmpl.default_port()];
                    app.selected_flags = tmpl.tcp_flags();
                    app.custom_payload = Some(tmpl.payload(&app.target.host));
                    app.log_success(format!("Applied template: {} (port {}, {} flags)",
                        tmpl.name(), tmpl.default_port(), tmpl.tcp_flags().len()));
                } else {
                    let names: Vec<_> = templates.iter().map(|t| t.shortcut()).collect();
                    app.log_error(format!("Unknown template. Available: {}", names.join(", ")));
                }
            } else {
                let templates = PacketTemplate::all();
                let names: Vec<_> = templates.iter().map(|t| format!("{}[{}]", t.name(), t.shortcut())).collect();
                app.log_info(format!("Templates: {}", names.join(", ")));
            }
        }
        "dns" => {
            // Send DNS query using DnsQuery builder with various shorthand methods
            if app.target.host.is_empty() {
                app.log_error("No target specified");
                return;
            }
            let domain = if app.dns_domain.is_empty() { &app.target.host } else { &app.dns_domain };

            // Use DnsQuery shorthand methods based on query type
            let (query, type_name) = match app.dns_query_type {
                1 => (DnsQuery::a_query(domain), "A"),
                28 => (DnsQuery::aaaa_query(domain), "AAAA"),
                15 => (DnsQuery::mx_query(domain), "MX"),
                16 => (DnsQuery::txt_query(domain), "TXT"),
                2 => (DnsQuery::new().transaction_id(0x1234).add_question(domain, DnsType::Ns), "NS"),
                5 => (DnsQuery::new().transaction_id(0x1234).add_question(domain, DnsType::Cname), "CNAME"),
                6 => (DnsQuery::new().transaction_id(0x1234).add_question(domain, DnsType::Soa), "SOA"),
                12 => (DnsQuery::new().transaction_id(0x1234).add_question(domain, DnsType::Ptr), "PTR"),
                33 => (DnsQuery::new().transaction_id(0x1234).add_question(domain, DnsType::Srv), "SRV"),
                255 => (DnsQuery::new().transaction_id(0x1234).add_question(domain, DnsType::Any), "ANY"),
                _ => (DnsQuery::a_query(domain), "A"),
            };
            let payload = query.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built DNS {} query for '{}' ({} bytes)", type_name, domain, payload.len()));
        }
        "dnsinfo" => {
            // Show DNS question details using DnsQuestion struct
            use crate::network::protocols::DnsQuestion;
            let domain = if parts.len() > 1 { parts[1] } else { "example.com" };
            let qtype = if parts.len() > 2 {
                match parts[2].to_uppercase().as_str() {
                    "A" => DnsType::A,
                    "AAAA" => DnsType::Aaaa,
                    "MX" => DnsType::Mx,
                    "TXT" => DnsType::Txt,
                    "NS" => DnsType::Ns,
                    "CNAME" => DnsType::Cname,
                    "SOA" => DnsType::Soa,
                    "PTR" => DnsType::Ptr,
                    "SRV" => DnsType::Srv,
                    _ => DnsType::A,
                }
            } else { DnsType::A };
            let question = DnsQuestion { name: domain.to_string(), qtype, qclass: 1 };
            app.log_info(format!("DNS Question: name={} type={:?} class={}", question.name, question.qtype, question.qclass));
        }
        "ntp" => {
            // Build NTP packet
            let ntp = NtpPacket::new();
            let payload = ntp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built NTP request packet ({} bytes)", payload.len()));
        }
        "http" => {
            // Build HTTP request using HttpRequest builder
            if app.target.host.is_empty() {
                app.log_error("No target specified");
                return;
            }
            let method = HttpMethod::all().iter()
                .find(|m| m.as_str().eq_ignore_ascii_case(&app.http_method))
                .copied()
                .unwrap_or(HttpMethod::Get);
            let req = match method {
                HttpMethod::Get => HttpRequest::get(&app.http_path),
                HttpMethod::Post => HttpRequest::post(&app.http_path),
                HttpMethod::Head => HttpRequest::head(&app.http_path),
                _ => HttpRequest::new(method.as_str(), &app.http_path),
            }.header("Host", &app.target.host);
            let payload = req.build();
            app.custom_payload = Some(payload.clone());
            let service = get_service_name(app.target.ports.first().copied().unwrap_or(80));
            app.log_info(format!("Built {} {} request for {}:{} ({}) - {} bytes",
                method, app.http_path, app.target.host, app.target.ports.first().unwrap_or(&80), service, payload.len()));
        }
        "response" => {
            // Parse mock HTTP response for testing
            let mock_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>";
            if let Ok(resp) = HttpResponse::parse(mock_response) {
                let desc_text = status_description(resp.status_code);
                let headers = format_headers(&resp.headers);
                app.log_debug(format!("Status description: {}", desc_text));
                // Use more HttpResponse fields
                let is_ok = if resp.is_success() { "SUCCESS" }
                    else if resp.is_redirect() { "REDIRECT" }
                    else if resp.is_client_error() { "CLIENT_ERROR" }
                    else if resp.is_server_error() { "SERVER_ERROR" } else { "UNKNOWN" };
                let content_type = resp.content_type().map(|s| s.as_str()).unwrap_or("none");
                let content_len = resp.content_length().unwrap_or(0);
                let body_len = resp.body.as_ref().map(|b| b.len()).unwrap_or(0);
                app.log_info(format!("Parsed: {} {} {} ({}) type={} len={}/{} headers={}",
                    resp.version, resp.status_code, resp.status_text, is_ok, content_type, content_len, body_len, headers.len()));
                app.log_debug(format!("Display: {}", resp.format_display()));
            }
        }
        "snmp" => {
            // Build SNMP GET request using SnmpGetRequest
            use crate::network::protocols::SnmpGetRequest;
            let snmp = SnmpGetRequest::new("public")
                .add_oid("1.3.6.1.2.1.1.1.0")  // sysDescr
                .add_oid("1.3.6.1.2.1.1.3.0"); // sysUpTime
            let payload = snmp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built SNMP GET request ({} bytes)", payload.len()));
        }
        "ssdp" => {
            // Build SSDP M-SEARCH request using SsdpRequest
            use crate::network::protocols::SsdpRequest;
            let ssdp = SsdpRequest::m_search()
                .search_target("ssdp:all")
                .mx(3);
            let payload = ssdp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built SSDP M-SEARCH request ({} bytes)", payload.len()));
        }
        "service" => {
            // Show service info for ports
            use crate::network::protocols::get_service_by_port;
            if parts.len() > 1 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    if let Some(info) = get_service_by_port(port) {
                        app.log_info(format!("Port {}: {} ({}) - {}", port, info.name, info.protocol, info.description));
                    } else {
                        app.log_info(format!("Port {}: Unknown service", port));
                    }
                }
            } else {
                app.log_info("Usage: :service <port>");
            }
        }
        "services" => {
            // List all common services from COMMON_SERVICES
            use crate::network::protocols::{COMMON_SERVICES, ServiceInfo};
            let filter = if parts.len() > 1 { Some(parts[1].to_lowercase()) } else { None };
            let matches: Vec<&ServiceInfo> = COMMON_SERVICES.iter()
                .filter(|s| {
                    filter.as_ref().map_or(true, |f| {
                        s.name.to_lowercase().contains(f) ||
                        s.description.to_lowercase().contains(f)
                    })
                })
                .collect();
            if matches.is_empty() {
                app.log_info("No matching services found");
            } else {
                app.log_info(format!("Common services ({} total, {} shown):", COMMON_SERVICES.len(), matches.len()));
                for s in matches.iter().take(20) {
                    app.log_info(format!("  {:5} {:12} {:8} {}", s.port, s.name, s.protocol, s.description));
                }
                if matches.len() > 20 {
                    app.log_info(format!("  ... and {} more (use :services <filter> to narrow)", matches.len() - 20));
                }
            }
        }
        "rawsyn" => {
            // Build raw SYN packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            match PacketBuilder::syn_packet(src_ip, dst_ip, 12345, 80) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built raw SYN packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "rawxmas" => {
            // Build XMAS packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            match PacketBuilder::xmas_packet(src_ip, dst_ip, 12345, 80) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built raw XMAS packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "rawnull" => {
            // Build NULL packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            match PacketBuilder::null_packet(src_ip, dst_ip, 12345, 80) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built raw NULL packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "rawfin" => {
            // Build FIN packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            match PacketBuilder::fin_packet(src_ip, dst_ip, 12345, 80) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built raw FIN packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "rawack" => {
            // Build ACK packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            match PacketBuilder::ack_packet(src_ip, dst_ip, 12345, 80, 1000) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built raw ACK packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "ping" => {
            // Build ICMP ping packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            match PacketBuilder::ping_packet(src_ip, dst_ip) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built ICMP ping packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "rawudp" => {
            // Build UDP packet using PacketBuilder
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            let payload = b"Hello UDP".to_vec();
            match PacketBuilder::udp_packet(src_ip, dst_ip, 12345, 53, payload) {
                Ok(packet) => {
                    app.custom_payload = Some(packet.clone());
                    app.log_success(format!("Built raw UDP packet ({} bytes)", packet.len()));
                }
                Err(e) => app.log_error(format!("Failed to build packet: {}", e)),
            }
        }
        "parseflags" => {
            // Parse TCP flags bitmask using parse_tcp_flags
            if parts.len() > 1 {
                if let Ok(flags_raw) = parts[1].parse::<u16>() {
                    let flags = parse_tcp_flags(flags_raw);
                    let names: Vec<_> = flags.iter().map(|f| format!("{}", f)).collect();
                    app.log_info(format!("Flags 0x{:04X}: {}", flags_raw, names.join("|")));
                }
            } else {
                app.log_info("Usage: :parseflags <bitmask>");
            }
        }
        "httpstream" => {
            // Test HttpStreamParser - uses entries(), clear(), pending_request methods
            let mut parser = HttpStreamParser::new();
            let test_data = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
            if let Some(entry) = parser.parse_data(test_data, chrono::Utc::now()) {
                app.add_http_entry(entry);
                // entries() returns the parsed entries
                let count = parser.entries().len();
                app.log_success(format!("Parsed HTTP stream entry, total: {}", count));

                // Test pending_request() - get the last parsed request
                if let Some(pending) = parser.pending_request() {
                    app.log_info(format!("Pending request: {} {}", pending.method, pending.path));
                }
                // Test take_pending_request() - consume the pending request
                if let Some(taken) = parser.take_pending_request() {
                    app.log_info(format!("Took pending request: {} {}", taken.method, taken.path));
                }
            }
            // clear() resets the parser state including pending_request
            parser.clear();
        }
        "httpbody" => {
            // Build HTTP POST request with body
            if app.target.host.is_empty() {
                app.log_error("No target specified");
                return;
            }
            let body = b"{\"test\": true}".to_vec();
            let req = HttpRequest::post(&app.http_path)
                .header("Host", &app.target.host)
                .header("Content-Type", "application/json")
                .body(body);
            let payload = req.build();
            app.custom_payload = Some(payload.clone());
            app.log_success(format!("Built HTTP POST with body ({} bytes)", payload.len()));
        }
        "tcpbuilder" => {
            // Use TcpPacketBuilder with all methods
            use crate::network::packet::TcpPacketBuilder;
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            let packet = PacketBuilder::tcp()
                .source_ip(src_ip)
                .dest_ip(dst_ip)
                .source_port(12345)
                .dest_port(80)
                .syn()
                .ack()
                .fin()
                .rst()
                .psh()
                .urg()
                .seq_num(1000)
                .ack_num(2000)
                .window(65535)
                .ttl(64)
                .payload(vec![0x41, 0x42, 0x43]);
            let _ = TcpPacketBuilder::new(); // use the struct directly
            // Also test flags methods
            let packet2 = PacketBuilder::tcp()
                .source_ip(src_ip)
                .dest_ip(dst_ip)
                .source_port(12345)
                .dest_port(80)
                .flags(&[TcpFlag::Syn, TcpFlag::Ack])
                .flags_raw(0x12)
                .xmas()
                .null();
            match packet.build() {
                Ok(data) => {
                    // Also test build_segment
                    let _ = packet2.build_segment();
                    app.custom_payload = Some(data.clone());
                    app.log_success(format!("Built TCP packet ({} bytes)", data.len()));
                }
                Err(e) => app.log_error(format!("Failed: {}", e)),
            }
        }
        "udpbuilder" => {
            // Use UdpPacketBuilder with all methods
            use crate::network::packet::UdpPacketBuilder;
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            let packet = PacketBuilder::udp()
                .source_ip(src_ip)
                .dest_ip(dst_ip)
                .source_port(12345)
                .dest_port(53)
                .ttl(64)
                .payload(vec![0x41, 0x42, 0x43]);
            let _ = UdpPacketBuilder::new(); // use the struct directly
            match packet.build() {
                Ok(data) => {
                    app.custom_payload = Some(data.clone());
                    app.log_success(format!("Built UDP packet ({} bytes)", data.len()));
                }
                Err(e) => app.log_error(format!("Failed: {}", e)),
            }
        }
        "icmpbuilder" => {
            // Use IcmpPacketBuilder with all methods
            use crate::network::packet::IcmpPacketBuilder;
            let src_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
            let packet = PacketBuilder::icmp()
                .source_ip(src_ip)
                .dest_ip(dst_ip)
                .echo_request()
                .echo_reply()
                .icmp_type(8)
                .icmp_code(0)
                .identifier(1234)
                .sequence(1)
                .ttl(64)
                .payload(vec![0x41, 0x42, 0x43]);
            let _ = IcmpPacketBuilder::new(); // use the struct directly
            match packet.build() {
                Ok(data) => {
                    app.custom_payload = Some(data.clone());
                    app.log_success(format!("Built ICMP packet ({} bytes)", data.len()));
                }
                Err(e) => app.log_error(format!("Failed: {}", e)),
            }
        }
        "retrystats" => {
            // Test retry tracking using PacketStats
            use crate::network::packet::PacketStats;
            let mut stats = PacketStats::default();
            stats.record_sent(100);
            stats.record_received(50, 10.0);
            stats.record_failed();
            stats.record_retry();
            app.log_info(format!("Stats: sent={} recv={} failed={} retries={}",
                stats.packets_sent, stats.packets_received, stats.packets_failed, stats.retries));
        }
        "httpconnect" => {
            // Use HTTP CONNECT and TRACE methods
            let req_trace = HttpRequest::new(HttpMethod::Trace.as_str(), "/");
            let req_connect = HttpRequest::new(HttpMethod::Connect.as_str(), "example.com:443");
            app.log_info(format!("TRACE: {} bytes, CONNECT: {} bytes",
                req_trace.build().len(), req_connect.build().len()));
        }
        "sendertest" => {
            // Test SenderError, SenderConfig fields, and PacketSender methods
            use crate::network::sender::{SenderError, SenderConfig};
            use crate::network::packet::{PacketError, PacketResponse, ResponseStatus};

            // Use SenderError variants
            let _err1 = SenderError::SocketCreation("test".to_string());
            let _err2 = SenderError::SendFailed("test".to_string());
            let _err3 = SenderError::Timeout;
            let _err4 = SenderError::ConnectionRefused;
            let _err5 = SenderError::NetworkUnreachable;
            let _err6 = SenderError::HostUnreachable;
            let _err7 = SenderError::DnsResolution("test".to_string());
            let _err8 = SenderError::InvalidTarget("test".to_string());

            // Use SenderConfig fields
            let config = SenderConfig {
                worker_threads: 4,
                batch_size: 100,
                timeout_ms: 3000,
                max_retries: 3,
                retry_delay_ms: 100,
            };
            app.log_info(format!("Config: workers={} retries={} retry_delay={}ms",
                config.worker_threads, config.max_retries, config.retry_delay_ms));

            // Use PacketError variants
            let _pe1 = PacketError::InvalidSize { expected: 20, actual: 10 };
            let _pe2 = PacketError::InvalidAddress { address: "test".to_string(), reason: "invalid format".to_string() };
            let _pe3 = PacketError::UnsupportedProtocol("SCTP".to_string());
            let _pe4 = PacketError::ChecksumError { packet_type: "TCP".to_string() };

            // Use PacketResponse fields
            let resp = PacketResponse {
                id: uuid::Uuid::new_v4(),
                target_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                target_port: 80,
                protocol: Protocol::Tcp,
                status: ResponseStatus::Open,
                rtt_ms: Some(10.5),
                flags_received: None,
                raw_response: Some(vec![0x41, 0x42]),
                timestamp: chrono::Utc::now(),
                error: Some("test error".to_string()),
            };

            // Use ResponseStatus::Unfiltered
            let _unfiltered = ResponseStatus::Unfiltered;

            app.log_info(format!("Response: id={} proto={} raw={:?} ts={} err={:?}",
                resp.id, resp.protocol, resp.raw_response.as_ref().map(|r| r.len()), resp.timestamp, resp.error));
        }
        "sendermethods" => {
            // Test PacketSender methods that aren't used elsewhere
            if let Some(sender) = &app.packet_sender {
                // active_jobs method
                let _jobs = sender.active_jobs();

                // reset_stats method
                let _ = tokio::spawn({
                    let sender = sender.clone();
                    async move {
                        sender.reset_stats().await;
                    }
                });

                // Test send_http_request (takes headers and body)
                let target = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
                let _ = tokio::spawn({
                    let sender = sender.clone();
                    async move {
                        let headers = HashMap::new();
                        let _ = sender.send_http_request(target, 80, "GET", "/", &headers, None).await;
                    }
                });

                // Test send_with_retry (takes 4 args, max_retries is internal)
                let _ = tokio::spawn({
                    let sender = sender.clone();
                    async move {
                        let _ = sender.send_with_retry(target, 80, ScanType::SynScan, &[TcpFlag::Syn]).await;
                    }
                });

                app.log_info("Tested PacketSender methods");
            } else {
                app.log_error("No sender available");
            }
        }
        "sendersetup" => {
            // Test set_response_channel by creating a channel and sender
            use tokio::sync::mpsc;
            use crate::network::sender::PacketSender;
            let (tx, _rx) = mpsc::channel::<crate::network::packet::PacketResponse>(100);

            // Create a new sender to test the set_response_channel method
            match PacketSender::new(4, 100, 1000).await {
                Ok(mut sender) => {
                    sender.set_response_channel(tx);
                    app.log_info("Response channel configured on test sender");
                }
                Err(e) => {
                    app.log_error(format!("Failed to create sender: {}", e));
                }
            }
        }
        "packetpreset" => {
            // Use PacketPreset from config
            use crate::config::PacketPreset;
            let preset = PacketPreset {
                name: "Test".to_string(),
                protocol: Protocol::Tcp,
                flags: vec![TcpFlag::Syn],
                payload: None,
                description: "Test preset".to_string(),
            };
            app.log_info(format!("Preset: {} ({}) - {}", preset.name, preset.protocol, preset.description));
        }
        "flood" => {
            // Flood mode like hping3 --flood
            if app.target.host.is_empty() {
                app.log_error("No target specified. Set target first with :target <host>");
                return;
            }
            if app.target.ports.is_empty() {
                app.log_error("No ports specified. Set port first with :port <port>");
                return;
            }
            if app.flood_mode {
                app.stop_flood();
            } else {
                // Resolve the host IP first
                match crate::network::sender::PacketSender::resolve_host(&app.target.host).await {
                    Ok(ip) => {
                        app.target.ip = Some(ip);
                        // Parse optional worker count: :flood [workers]
                        if parts.len() > 1 {
                            if let Ok(workers) = parts[1].parse::<usize>() {
                                app.flood_workers = workers.max(1).min(64); // 1-64 workers
                            }
                        }
                        app.start_flood();
                    }
                    Err(e) => {
                        app.log_error(format!("Failed to resolve host: {}", e));
                    }
                }
            }
        }
        "stop" => {
            if app.flood_mode {
                app.stop_flood();
            } else {
                app.log_info("Nothing to stop");
            }
        }
        "smb" => {
            // Build SMB Negotiate request using SmbNegotiatePacket
            use crate::network::protocols::SmbNegotiatePacket;
            let smb = SmbNegotiatePacket::new();
            let payload = smb.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built SMB Negotiate request ({} bytes) - supports NT LM 0.12, SMB 2.002, SMB 2.???", payload.len()));
        }
        "smb1" => {
            // Build SMB1-only Negotiate request
            use crate::network::protocols::SmbNegotiatePacket;
            let smb = SmbNegotiatePacket::smb1_only();
            let payload = smb.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built SMB1 Negotiate request ({} bytes) - NT LM 0.12 only", payload.len()));
        }
        "smb2" => {
            // Build SMB2-only Negotiate request
            use crate::network::protocols::SmbNegotiatePacket;
            let smb = SmbNegotiatePacket::smb2_only();
            let payload = smb.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built SMB2 Negotiate request ({} bytes) - SMB 2.x only", payload.len()));
        }
        "ldap" => {
            // Build LDAP search request using LdapSearchRequest
            use crate::network::protocols::{LdapSearchRequest, LdapScope};
            let base_dn = if parts.len() > 1 { parts[1] } else { "" };
            let ldap = LdapSearchRequest::new(base_dn)
                .scope(LdapScope::WholeSubtree)
                .filter("(objectClass=*)")
                .attributes(vec!["cn", "objectClass"]);
            let payload = ldap.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built LDAP Search request ({} bytes) base={}", payload.len(), base_dn));
        }
        "ldaprootdse" => {
            // Build LDAP RootDSE query
            use crate::network::protocols::LdapSearchRequest;
            let ldap = LdapSearchRequest::rootdse_query();
            let payload = ldap.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built LDAP RootDSE query ({} bytes)", payload.len()));
        }
        "ldapbase" => {
            // Build LDAP search with BaseObject/SingleLevel scope
            use crate::network::protocols::{LdapSearchRequest, LdapScope};
            let base_dn = if parts.len() > 1 { parts[1] } else { "dc=example,dc=com" };
            let scope_str = if parts.len() > 2 { parts[2] } else { "single" };
            let scope = match scope_str.to_lowercase().as_str() {
                "base" => LdapScope::BaseObject,
                "single" | "one" => LdapScope::SingleLevel,
                _ => LdapScope::WholeSubtree,
            };
            let msg_id: u32 = rand::random::<u16>() as u32;
            let ldap = LdapSearchRequest::new(base_dn)
                .message_id(msg_id)
                .scope(scope)
                .filter("(objectClass=*)");
            let payload = ldap.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built LDAP Search ({} bytes) base={} scope={:?} msg_id={}",
                payload.len(), base_dn, scope, msg_id));
        }
        "netbios" => {
            // Build NetBIOS Name Service query using NetBiosNsPacket
            use crate::network::protocols::NetBiosNsPacket;
            let name = if parts.len() > 1 { parts[1] } else { "*" };
            let netbios = NetBiosNsPacket::name_query(name);
            let payload = netbios.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built NetBIOS Name Query ({} bytes) for '{}'", payload.len(), name));
        }
        "nbstat" => {
            // Build NetBIOS Node Status query
            use crate::network::protocols::NetBiosNsPacket;
            let name = if parts.len() > 1 { parts[1] } else { "*" };
            let netbios = NetBiosNsPacket::node_status_query(name);
            let payload = netbios.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built NetBIOS Node Status query ({} bytes) for '{}'", payload.len(), name));
        }
        "dhcp" => {
            // Build DHCP Discover packet using DhcpDiscoverPacket
            use crate::network::protocols::DhcpDiscoverPacket;
            // Use a random MAC address for discovery
            let mac: [u8; 6] = [0x00, 0x11, 0x22, rand::random(), rand::random(), rand::random()];
            let hostname = if parts.len() > 1 { Some(parts[1].to_string()) } else { None };
            let mut dhcp = DhcpDiscoverPacket::new(mac);
            if let Some(ref h) = hostname {
                dhcp = dhcp.with_hostname(h);
            }
            let payload = dhcp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built DHCP Discover ({} bytes) MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}{}",
                payload.len(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                hostname.map(|h| format!(" hostname={}", h)).unwrap_or_default()));
        }
        "kerberos" => {
            // Build Kerberos AS-REQ using KerberosAsReq
            use crate::network::protocols::KerberosAsReq;
            if parts.len() < 3 {
                app.log_info("Usage: :kerberos <realm> <username>");
                return;
            }
            let realm = parts[1];
            let username = parts[2];
            let krb = KerberosAsReq::new(realm, username);
            let payload = krb.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built Kerberos AS-REQ ({} bytes) realm={} user={}", payload.len(), realm, username));
        }
        "arp" => {
            // Build ARP request using ArpPacket
            use crate::network::protocols::ArpPacket;
            // Parse target IP from args or use target host
            let target_ip_str = if parts.len() > 1 { parts[1] } else { &app.target.host };
            let target_ip: [u8; 4] = match target_ip_str.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => ip.octets(),
                Err(_) => {
                    app.log_error(format!("Invalid IPv4 address: {}", target_ip_str));
                    return;
                }
            };
            // Use a sample source MAC and IP (would need interface detection for real use)
            let sender_mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
            let sender_ip: [u8; 4] = [192, 168, 1, 100];
            let arp = ArpPacket::new_request(sender_mac, sender_ip, target_ip);
            let payload = arp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built ARP Request ({} bytes) for {}", payload.len(), target_ip_str));
        }
        "arpreply" => {
            // Build ARP reply using ArpPacket::new_reply
            use crate::network::protocols::ArpPacket;
            let target_ip_str = if parts.len() > 1 { parts[1] } else { "192.168.1.1" };
            let target_ip: [u8; 4] = match target_ip_str.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => ip.octets(),
                Err(_) => {
                    app.log_error(format!("Invalid IPv4 address: {}", target_ip_str));
                    return;
                }
            };
            let sender_mac: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
            let sender_ip: [u8; 4] = [192, 168, 1, 100];
            let target_mac: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let arp = ArpPacket::new_reply(sender_mac, sender_ip, target_mac, target_ip);
            let payload = arp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built ARP Reply ({} bytes) for {}", payload.len(), target_ip_str));
        }
        "dhcpxid" => {
            // Build DHCP Discover with specific transaction ID
            use crate::network::protocols::DhcpDiscoverPacket;
            let xid: u32 = if parts.len() > 1 {
                parts[1].parse().unwrap_or_else(|_| rand::random())
            } else {
                rand::random()
            };
            let mac: [u8; 6] = [0x00, 0x11, 0x22, rand::random(), rand::random(), rand::random()];
            let dhcp = DhcpDiscoverPacket::new(mac)
                .with_transaction_id(xid);
            let payload = dhcp.build();
            app.custom_payload = Some(payload.clone());
            app.log_info(format!("Built DHCP Discover ({} bytes) XID=0x{:08X}", payload.len(), xid));
        }
        _ => {
            app.log_error(format!("Unknown command: {}", command));
        }
    }
}

/// Simple command completion
fn complete_command(app: &mut App) {
    let commands = [
        "quit", "exit", "write", "target", "port", "scan", "send", "clear", "count", "stats",
        "help", "debug",
    ];

    let prefix = &app.command_buffer;
    if let Some(completion) = commands.iter().find(|c| c.starts_with(prefix)) {
        app.command_buffer = completion.to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;

    fn create_test_app() -> App {
        let args = Args {
            debug: false,
            log_file: std::path::PathBuf::from("test.log"),
            workers: 4,
            batch_size: 100,
            timeout: 1000,
            host: None,
            port: None,
        };
        App::new(args).unwrap()
    }

    #[test]
    fn test_handle_select_flag() {
        let mut app = create_test_app();
        app.active_pane = ActivePane::FlagSelection;
        app.flag_list_index = 0;
        app.selected_flags.clear();

        handle_select(&mut app);

        assert!(!app.selected_flags.is_empty());
    }

    #[test]
    fn test_go_top_and_bottom() {
        let mut app = create_test_app();
        app.active_pane = ActivePane::FlagSelection;
        app.flag_list_index = 5;

        handle_go_top(&mut app);
        assert_eq!(app.flag_list_index, 0);

        handle_go_bottom(&mut app);
        assert_eq!(app.flag_list_index, TcpFlag::all().len() - 1);
    }

    #[test]
    fn test_pane_navigation() {
        let mut app = create_test_app();
        let initial = app.active_pane;

        app.active_pane = app.active_pane.next();
        assert_ne!(app.active_pane, initial);

        app.active_pane = app.active_pane.prev();
        assert_eq!(app.active_pane, initial);
    }

    #[test]
    fn test_apply_input_host() {
        let mut app = create_test_app();
        app.active_pane = ActivePane::TargetConfig;
        app.target_input_field = TargetField::Host;
        app.input_buffer = "192.168.1.1".to_string();

        apply_input(&mut app);

        assert_eq!(app.target.host, "192.168.1.1");
    }
}
