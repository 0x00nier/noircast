//! Application state management for NoirCast

use crate::config::{Config, PacketTemplate, Protocol, ScanType, Target, TcpFlag};
use crate::network::packet::{PacketResponse, PacketStats};
use crate::network::sender::PacketSender;
use crate::cli::Args;
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Direction of captured packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Sent,
    Received,
}

impl std::fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketDirection::Sent => write!(f, "TX"),
            PacketDirection::Received => write!(f, "RX"),
        }
    }
}

/// Captured packet for display in capture pane
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are for detailed packet inspection (future feature)
pub struct CapturedPacket {
    pub id: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub direction: PacketDirection,
    pub protocol: Protocol,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub flags: Vec<TcpFlag>,
    pub flags_raw: u8,
    pub seq_num: Option<u32>,
    pub ack_num: Option<u32>,
    pub payload_size: usize,
    pub payload_preview: String,
    pub rtt_ms: Option<f64>,
    pub status: String,
}

/// Input mode for the TUI (vim-style)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    Insert,
    Command,
    Help,
    Search,
}

impl std::fmt::Display for InputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputMode::Normal => write!(f, "NORMAL"),
            InputMode::Insert => write!(f, "INSERT"),
            InputMode::Command => write!(f, "COMMAND"),
            InputMode::Help => write!(f, "HELP"),
            InputMode::Search => write!(f, "SEARCH"),
        }
    }
}

/// Active pane in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivePane {
    #[default]
    PacketConfig,
    FlagSelection,
    TargetConfig,
    ResponseLog,
    PacketCapture,
    HttpStream,
    Statistics,
}

impl ActivePane {
    pub fn next(&self) -> Self {
        match self {
            ActivePane::PacketConfig => ActivePane::FlagSelection,
            ActivePane::FlagSelection => ActivePane::TargetConfig,
            ActivePane::TargetConfig => ActivePane::ResponseLog,
            ActivePane::ResponseLog => ActivePane::PacketCapture,
            ActivePane::PacketCapture => ActivePane::HttpStream,
            ActivePane::HttpStream => ActivePane::Statistics,
            ActivePane::Statistics => ActivePane::PacketConfig,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ActivePane::PacketConfig => ActivePane::Statistics,
            ActivePane::FlagSelection => ActivePane::PacketConfig,
            ActivePane::TargetConfig => ActivePane::FlagSelection,
            ActivePane::ResponseLog => ActivePane::TargetConfig,
            ActivePane::PacketCapture => ActivePane::ResponseLog,
            ActivePane::HttpStream => ActivePane::PacketCapture,
            ActivePane::Statistics => ActivePane::HttpStream,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ActivePane::PacketConfig => "Packet Config",
            ActivePane::FlagSelection => "TCP Flags",
            ActivePane::TargetConfig => "Target",
            ActivePane::ResponseLog => "Responses",
            ActivePane::PacketCapture => "Packet Capture",
            ActivePane::HttpStream => "HTTP Stream",
            ActivePane::Statistics => "Statistics",
        }
    }
}

/// HTTP Stream entry for viewing
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields for HTTP stream inspection (future feature)
pub struct HttpStreamEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub direction: HttpDirection,
    pub method: Option<String>,
    pub url: Option<String>,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants for HTTP stream direction (future feature)
pub enum HttpDirection {
    Request,
    Response,
}

/// Log entry for response tracking
#[derive(Debug, Clone)]
#[allow(dead_code)] // details field for expandable log entries (future feature)
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
    Debug,
}

impl LogLevel {
    pub fn symbol(&self) -> &'static str {
        match self {
            LogLevel::Info => "ℹ",
            LogLevel::Success => "✓",
            LogLevel::Warning => "⚠",
            LogLevel::Error => "✗",
            LogLevel::Debug => "⚙",
        }
    }
}

/// Session state for multi-window support
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are used for session state management (future feature)
pub struct Session {
    pub id: usize,
    pub name: String,
    pub target: Target,
    pub protocol: Protocol,
    pub scan_type: ScanType,
    pub flags: Vec<TcpFlag>,
    pub captured_packets: VecDeque<CapturedPacket>,
    pub logs: VecDeque<LogEntry>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Session {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            name: format!("Session {}", id + 1),
            target: Target::default(),
            protocol: Protocol::Tcp,
            scan_type: ScanType::SynScan,
            flags: vec![TcpFlag::Syn],
            captured_packets: VecDeque::new(),
            logs: VecDeque::new(),
            created_at: chrono::Utc::now(),
        }
    }
}

/// Packet sending job
#[derive(Debug, Clone)]
#[allow(dead_code)] // Job tracking fields for async job management (future feature)
pub struct SendJob {
    pub id: uuid::Uuid,
    pub target: Target,
    pub protocol: Protocol,
    pub scan_type: ScanType,
    pub flags: Vec<TcpFlag>,
    pub packet_count: usize,
    pub status: JobStatus,
    pub responses: Vec<PacketResponse>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Job status variants for async job tracking (future feature)
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Pending => write!(f, "Pending"),
            JobStatus::Running => write!(f, "Running"),
            JobStatus::Completed => write!(f, "Completed"),
            JobStatus::Failed => write!(f, "Failed"),
            JobStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Packet editor field being edited - protocol-aware
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketEditorField {
    // Common fields
    #[default]
    SourcePort,
    DestPort,
    Ttl,
    Payload,

    // TCP-specific
    SeqNum,
    AckNum,
    WindowSize,

    // ICMP-specific
    IcmpType,
    IcmpCode,
    IcmpId,
    IcmpSeq,

    // DNS-specific
    DnsQueryType,
    DnsDomain,

    // HTTP-specific
    HttpMethod,
    HttpPath,
    HttpHeaders,

    // SNMP-specific
    SnmpVersion,
    SnmpCommunity,

    // SSDP-specific
    SsdpTarget,

    // SMB-specific
    SmbVersion,

    // LDAP-specific
    LdapScope,
    LdapBaseDn,

    // NetBIOS-specific
    NetBiosName,

    // DHCP-specific
    DhcpType,

    // Kerberos-specific
    KerberosRealm,
    KerberosUser,

    // ARP-specific
    ArpOperation,
    ArpTargetIp,
}

impl PacketEditorField {
    /// Get fields relevant for a specific protocol
    pub fn fields_for_protocol(protocol: Protocol) -> Vec<Self> {
        match protocol {
            Protocol::Tcp => vec![
                Self::SourcePort, Self::DestPort, Self::Ttl,
                Self::SeqNum, Self::AckNum, Self::WindowSize, Self::Payload,
            ],
            Protocol::Udp => vec![
                Self::SourcePort, Self::DestPort, Self::Ttl, Self::Payload,
            ],
            Protocol::Icmp => vec![
                Self::IcmpType, Self::IcmpCode, Self::IcmpId, Self::IcmpSeq,
                Self::Ttl, Self::Payload,
            ],
            Protocol::Dns => vec![
                Self::DnsQueryType, Self::DnsDomain, Self::DestPort, Self::Payload,
            ],
            Protocol::Http | Protocol::Https => vec![
                Self::HttpMethod, Self::HttpPath, Self::HttpHeaders, Self::DestPort,
            ],
            Protocol::Ntp => vec![
                Self::DestPort, Self::Payload,
            ],
            Protocol::Snmp => vec![
                Self::SnmpVersion, Self::SnmpCommunity, Self::DestPort,
            ],
            Protocol::Ssdp => vec![
                Self::SsdpTarget, Self::Payload,
            ],
            Protocol::Smb => vec![
                Self::SmbVersion, Self::DestPort,
            ],
            Protocol::Ldap => vec![
                Self::LdapScope, Self::LdapBaseDn, Self::DestPort,
            ],
            Protocol::NetBios => vec![
                Self::NetBiosName, Self::DestPort,
            ],
            Protocol::Dhcp => vec![
                Self::DhcpType,
            ],
            Protocol::Kerberos => vec![
                Self::KerberosRealm, Self::KerberosUser, Self::DestPort,
            ],
            Protocol::Arp => vec![
                Self::ArpOperation, Self::ArpTargetIp,
            ],
            Protocol::Raw => vec![
                Self::SourcePort, Self::DestPort, Self::Ttl, Self::Payload,
            ],
        }
    }

    /// Get next field for a given protocol context
    pub fn next_for_protocol(&self, protocol: Protocol) -> Self {
        let fields = Self::fields_for_protocol(protocol);
        if let Some(idx) = fields.iter().position(|f| f == self) {
            fields[(idx + 1) % fields.len()]
        } else {
            fields.first().copied().unwrap_or_default()
        }
    }

    /// Get previous field for a given protocol context
    pub fn prev_for_protocol(&self, protocol: Protocol) -> Self {
        let fields = Self::fields_for_protocol(protocol);
        if let Some(idx) = fields.iter().position(|f| f == self) {
            if idx == 0 {
                fields[fields.len() - 1]
            } else {
                fields[idx - 1]
            }
        } else {
            fields.first().copied().unwrap_or_default()
        }
    }

    /// Legacy next/prev for backwards compatibility (used in tests)
    #[cfg(test)]
    pub fn next(&self) -> Self {
        self.next_for_protocol(Protocol::Tcp)
    }

    #[cfg(test)]
    pub fn prev(&self) -> Self {
        self.prev_for_protocol(Protocol::Tcp)
    }

    pub fn label(&self) -> &'static str {
        match self {
            // Common
            PacketEditorField::SourcePort => "Source Port",
            PacketEditorField::DestPort => "Dest Port",
            PacketEditorField::Ttl => "TTL",
            PacketEditorField::Payload => "Payload (hex)",
            // TCP
            PacketEditorField::SeqNum => "Sequence #",
            PacketEditorField::AckNum => "Ack #",
            PacketEditorField::WindowSize => "Window Size",
            // ICMP
            PacketEditorField::IcmpType => "ICMP Type",
            PacketEditorField::IcmpCode => "ICMP Code",
            PacketEditorField::IcmpId => "ICMP ID",
            PacketEditorField::IcmpSeq => "ICMP Seq",
            // DNS
            PacketEditorField::DnsQueryType => "Query Type",
            PacketEditorField::DnsDomain => "Domain",
            // HTTP
            PacketEditorField::HttpMethod => "Method",
            PacketEditorField::HttpPath => "Path",
            PacketEditorField::HttpHeaders => "Headers",
            // SNMP
            PacketEditorField::SnmpVersion => "Version",
            PacketEditorField::SnmpCommunity => "Community",
            // SSDP
            PacketEditorField::SsdpTarget => "Search Target",
            // SMB
            PacketEditorField::SmbVersion => "SMB Version",
            // LDAP
            PacketEditorField::LdapScope => "Scope",
            PacketEditorField::LdapBaseDn => "Base DN",
            // NetBIOS
            PacketEditorField::NetBiosName => "Name",
            // DHCP
            PacketEditorField::DhcpType => "Message Type",
            // Kerberos
            PacketEditorField::KerberosRealm => "Realm",
            PacketEditorField::KerberosUser => "Username",
            // ARP
            PacketEditorField::ArpOperation => "Operation",
            PacketEditorField::ArpTargetIp => "Target IP",
        }
    }
}

/// State for the packet editor popup - protocol-aware
#[derive(Debug, Clone, Default)]
pub struct PacketEditorState {
    // Common fields
    pub source_port: u16,
    pub dest_port: u16,
    pub ttl: u8,
    pub payload_hex: String,

    // TCP-specific
    pub seq_num: u32,
    pub ack_num: u32,
    pub window_size: u16,

    // ICMP-specific
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,

    // DNS-specific
    pub dns_query_type: u16,
    pub dns_domain: String,

    // HTTP-specific
    pub http_method: String,
    pub http_path: String,
    pub http_headers: String,

    // SNMP-specific
    pub snmp_version: u8,
    pub snmp_community: String,

    // SSDP-specific
    pub ssdp_target: String,

    // SMB-specific
    pub smb_version: u8,

    // LDAP-specific
    pub ldap_scope: u8,
    pub ldap_base_dn: String,

    // NetBIOS-specific
    pub netbios_name: String,

    // DHCP-specific
    pub dhcp_type: u8,

    // Kerberos-specific
    pub kerberos_realm: String,
    pub kerberos_user: String,

    // ARP-specific
    pub arp_operation: u8,
    pub arp_target_ip: String,

    // Editor state
    pub current_field: PacketEditorField,
    pub field_buffer: String,
    pub editing: bool,
}

impl PacketEditorState {
    pub fn new() -> Self {
        Self {
            source_port: rand::random::<u16>() | 0x8000,
            dest_port: 80,
            ttl: 64,
            payload_hex: String::new(),
            seq_num: rand::random(),
            ack_num: 0,
            window_size: 65535,
            icmp_type: 8,
            icmp_code: 0,
            icmp_id: rand::random(),
            icmp_seq: 1,
            dns_query_type: 1,
            dns_domain: String::new(),
            http_method: "GET".to_string(),
            http_path: "/".to_string(),
            http_headers: String::new(),
            snmp_version: 2,
            snmp_community: "public".to_string(),
            ssdp_target: "ssdp:all".to_string(),
            smb_version: 2,
            ldap_scope: 2,
            ldap_base_dn: String::new(),
            netbios_name: String::new(),
            dhcp_type: 1,
            kerberos_realm: String::new(),
            kerberos_user: String::new(),
            arp_operation: 1,
            arp_target_ip: String::new(),
            current_field: PacketEditorField::default(),
            field_buffer: String::new(),
            editing: false,
        }
    }

    /// Reset field to first field for given protocol
    pub fn reset_to_protocol(&mut self, protocol: Protocol) {
        let fields = PacketEditorField::fields_for_protocol(protocol);
        self.current_field = fields.first().copied().unwrap_or_default();
    }

    pub fn get_current_value(&self) -> String {
        match self.current_field {
            PacketEditorField::SourcePort => self.source_port.to_string(),
            PacketEditorField::DestPort => self.dest_port.to_string(),
            PacketEditorField::Ttl => self.ttl.to_string(),
            PacketEditorField::Payload => self.payload_hex.clone(),
            PacketEditorField::SeqNum => self.seq_num.to_string(),
            PacketEditorField::AckNum => self.ack_num.to_string(),
            PacketEditorField::WindowSize => self.window_size.to_string(),
            PacketEditorField::IcmpType => self.icmp_type.to_string(),
            PacketEditorField::IcmpCode => self.icmp_code.to_string(),
            PacketEditorField::IcmpId => self.icmp_id.to_string(),
            PacketEditorField::IcmpSeq => self.icmp_seq.to_string(),
            PacketEditorField::DnsQueryType => self.dns_query_type.to_string(),
            PacketEditorField::DnsDomain => self.dns_domain.clone(),
            PacketEditorField::HttpMethod => self.http_method.clone(),
            PacketEditorField::HttpPath => self.http_path.clone(),
            PacketEditorField::HttpHeaders => self.http_headers.clone(),
            PacketEditorField::SnmpVersion => self.snmp_version.to_string(),
            PacketEditorField::SnmpCommunity => self.snmp_community.clone(),
            PacketEditorField::SsdpTarget => self.ssdp_target.clone(),
            PacketEditorField::SmbVersion => self.smb_version.to_string(),
            PacketEditorField::LdapScope => self.ldap_scope.to_string(),
            PacketEditorField::LdapBaseDn => self.ldap_base_dn.clone(),
            PacketEditorField::NetBiosName => self.netbios_name.clone(),
            PacketEditorField::DhcpType => self.dhcp_type.to_string(),
            PacketEditorField::KerberosRealm => self.kerberos_realm.clone(),
            PacketEditorField::KerberosUser => self.kerberos_user.clone(),
            PacketEditorField::ArpOperation => self.arp_operation.to_string(),
            PacketEditorField::ArpTargetIp => self.arp_target_ip.clone(),
        }
    }

    pub fn apply_buffer(&mut self) -> bool {
        let value = self.field_buffer.clone();
        match self.current_field {
            PacketEditorField::SourcePort => value.parse().map(|v| self.source_port = v).is_ok(),
            PacketEditorField::DestPort => value.parse().map(|v| self.dest_port = v).is_ok(),
            PacketEditorField::Ttl => value.parse().map(|v| self.ttl = v).is_ok(),
            PacketEditorField::Payload => {
                let cleaned: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if cleaned.len() % 2 == 0 {
                    self.payload_hex = cleaned;
                    true
                } else {
                    false
                }
            }
            PacketEditorField::SeqNum => value.parse().map(|v| self.seq_num = v).is_ok(),
            PacketEditorField::AckNum => value.parse().map(|v| self.ack_num = v).is_ok(),
            PacketEditorField::WindowSize => value.parse().map(|v| self.window_size = v).is_ok(),
            PacketEditorField::IcmpType => value.parse().map(|v| self.icmp_type = v).is_ok(),
            PacketEditorField::IcmpCode => value.parse().map(|v| self.icmp_code = v).is_ok(),
            PacketEditorField::IcmpId => value.parse().map(|v| self.icmp_id = v).is_ok(),
            PacketEditorField::IcmpSeq => value.parse().map(|v| self.icmp_seq = v).is_ok(),
            PacketEditorField::DnsQueryType => value.parse().map(|v| self.dns_query_type = v).is_ok(),
            PacketEditorField::DnsDomain => { self.dns_domain = value; true }
            PacketEditorField::HttpMethod => { self.http_method = value; true }
            PacketEditorField::HttpPath => { self.http_path = value; true }
            PacketEditorField::HttpHeaders => { self.http_headers = value; true }
            PacketEditorField::SnmpVersion => value.parse().map(|v| self.snmp_version = v).is_ok(),
            PacketEditorField::SnmpCommunity => { self.snmp_community = value; true }
            PacketEditorField::SsdpTarget => { self.ssdp_target = value; true }
            PacketEditorField::SmbVersion => value.parse().map(|v| self.smb_version = v).is_ok(),
            PacketEditorField::LdapScope => value.parse().map(|v| self.ldap_scope = v).is_ok(),
            PacketEditorField::LdapBaseDn => { self.ldap_base_dn = value; true }
            PacketEditorField::NetBiosName => { self.netbios_name = value; true }
            PacketEditorField::DhcpType => value.parse().map(|v| self.dhcp_type = v).is_ok(),
            PacketEditorField::KerberosRealm => { self.kerberos_realm = value; true }
            PacketEditorField::KerberosUser => { self.kerberos_user = value; true }
            PacketEditorField::ArpOperation => value.parse().map(|v| self.arp_operation = v).is_ok(),
            PacketEditorField::ArpTargetIp => { self.arp_target_ip = value; true }
        }
    }

    pub fn to_payload_bytes(&self) -> Option<Vec<u8>> {
        if self.payload_hex.is_empty() {
            return None;
        }
        hex::decode(&self.payload_hex).ok()
    }
}

/// Main application state
pub struct App {
    // Application state
    pub running: bool,
    pub config: Config,
    pub args: Args,

    // TUI state
    pub input_mode: InputMode,
    pub active_pane: ActivePane,
    pub command_buffer: String,
    pub search_buffer: String,
    pub input_buffer: String,
    pub cursor_position: usize,

    // Help system (which-key style)
    pub show_help: bool,
    pub help_filter: String,
    pub pending_keys: Vec<char>,
    pub key_timeout: std::time::Duration,
    pub last_key_time: std::time::Instant,

    // Packet editor popup
    pub show_packet_editor: bool,
    pub packet_editor: PacketEditorState,

    // Protocol picker popup
    pub show_protocol_picker: bool,
    pub protocol_picker_index: usize,
    pub protocol_picker_filter: String,

    // Packet configuration
    pub selected_protocol: Protocol,
    pub selected_scan_type: ScanType,
    pub selected_flags: Vec<TcpFlag>,
    pub custom_payload: Option<Vec<u8>>,
    pub packet_count: usize,

    // ICMP-specific options
    pub icmp_type: u8,      // 8 = Echo Request, 0 = Echo Reply, etc.
    pub icmp_code: u8,      // Usually 0
    pub icmp_id: u16,       // Identifier
    pub icmp_seq: u16,      // Sequence number

    // DNS-specific options
    pub dns_query_type: u16,     // A=1, AAAA=28, MX=15, etc.
    pub dns_domain: String,       // Domain to query

    // HTTP-specific options
    pub http_method: String,      // GET, POST, HEAD, etc.
    pub http_path: String,        // Request path

    // SNMP-specific options
    pub snmp_version: u8,         // 1, 2 (v2c), 3
    pub snmp_community: String,   // Community string (v1/v2c)

    // SSDP-specific options
    pub ssdp_target: u8,          // 0=ssdp:all, 1=upnp:rootdevice, 2=custom

    // SMB-specific options
    pub smb_version: u8,          // 1, 2, 3

    // LDAP-specific options
    pub ldap_scope: u8,           // 0=base, 1=one, 2=sub

    // NetBIOS-specific options
    pub netbios_type: u8,         // 0=name query, 1=node status

    // DHCP-specific options
    pub dhcp_type: u8,            // 1=Discover, 3=Request, 7=Release

    // Kerberos-specific options
    pub kerberos_type: u8,        // 10=AS-REQ, 12=TGS-REQ

    // ARP-specific options
    pub arp_operation: u8,        // 1=Request, 2=Reply

    // Target configuration
    pub target: Target,
    pub target_input_field: TargetField,

    // Selection indices for lists
    pub flag_list_index: usize,
    pub scan_type_index: usize,
    pub protocol_index: usize,
    pub log_scroll: usize,
    pub http_scroll: usize,

    // Network state
    pub packet_sender: Option<Arc<PacketSender>>,
    pub stats: Arc<RwLock<PacketStats>>,

    // Response tracking
    pub responses: Arc<RwLock<VecDeque<PacketResponse>>>,
    pub max_responses: usize,

    // Jobs
    pub jobs: Vec<SendJob>,
    pub current_job: Option<uuid::Uuid>,

    // Logs
    pub logs: VecDeque<LogEntry>,
    pub max_logs: usize,

    // HTTP Stream
    pub http_stream: VecDeque<HttpStreamEntry>,
    pub max_http_entries: usize,

    // Packet Capture
    pub captured_packets: VecDeque<CapturedPacket>,
    pub max_captured: usize,
    pub capture_scroll: usize,
    pub capture_selected: usize,
    pub next_capture_id: u64,

    // Status message
    pub status_message: Option<(String, LogLevel)>,
    pub status_time: std::time::Instant,

    // Flood mode (like hping3 --flood)
    pub flood_mode: bool,
    pub flood_count: u64,       // packets sent in flood mode
    pub flood_rate: u64,        // target packets per second (0 = unlimited)
    pub flood_start: Option<std::time::Instant>,

    // Multi-session support (Space+n to create new session)
    pub sessions: Vec<Session>,
    pub active_session: usize,
    pub next_session_id: usize,

    // Statistics scroll for Statistics pane
    pub stats_scroll: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetField {
    #[default]
    Host,
    Port,
}

impl App {
    pub fn new(args: Args) -> Result<Self> {
        let config = Config::default();

        Ok(Self {
            running: true,
            config,
            args,

            input_mode: InputMode::Normal,
            active_pane: ActivePane::PacketConfig,
            command_buffer: String::new(),
            search_buffer: String::new(),
            input_buffer: String::new(),
            cursor_position: 0,

            show_help: false,
            help_filter: String::new(),
            pending_keys: Vec::new(),
            key_timeout: std::time::Duration::from_millis(500),
            last_key_time: std::time::Instant::now(),

            show_packet_editor: false,
            packet_editor: PacketEditorState::new(),

            show_protocol_picker: false,
            protocol_picker_index: 0,
            protocol_picker_filter: String::new(),

            selected_protocol: Protocol::Tcp,
            selected_scan_type: ScanType::SynScan,
            selected_flags: vec![TcpFlag::Syn],
            custom_payload: None,
            packet_count: 1,

            // ICMP defaults
            icmp_type: 8,  // Echo Request
            icmp_code: 0,
            icmp_id: 1,
            icmp_seq: 1,

            // DNS defaults
            dns_query_type: 1,  // A record
            dns_domain: String::new(),

            // HTTP defaults
            http_method: "GET".to_string(),
            http_path: "/".to_string(),

            // SNMP defaults
            snmp_version: 2,  // v2c
            snmp_community: "public".to_string(),

            // SSDP defaults
            ssdp_target: 0,  // ssdp:all

            // SMB defaults
            smb_version: 2,  // SMB2

            // LDAP defaults
            ldap_scope: 2,  // subtree

            // NetBIOS defaults
            netbios_type: 0,  // name query

            // DHCP defaults
            dhcp_type: 1,  // Discover

            // Kerberos defaults
            kerberos_type: 10,  // AS-REQ

            // ARP defaults
            arp_operation: 1,  // Request

            target: Target::default(),
            target_input_field: TargetField::Host,

            flag_list_index: 0,
            scan_type_index: 0,
            protocol_index: 0,
            log_scroll: 0,
            http_scroll: 0,

            packet_sender: None,
            stats: Arc::new(RwLock::new(PacketStats::default())),

            responses: Arc::new(RwLock::new(VecDeque::new())),
            max_responses: 1000,

            jobs: Vec::new(),
            current_job: None,

            logs: VecDeque::new(),
            max_logs: 500,

            http_stream: VecDeque::new(),
            max_http_entries: 100,

            captured_packets: VecDeque::new(),
            max_captured: 500,
            capture_scroll: 0,
            capture_selected: 0,
            next_capture_id: 1,

            status_message: None,
            status_time: std::time::Instant::now(),

            flood_mode: false,
            flood_count: 0,
            flood_rate: 0,  // unlimited by default
            flood_start: None,

            // Session management
            sessions: vec![Session::new(0)],
            active_session: 0,
            next_session_id: 1,

            // Stats scroll
            stats_scroll: 0,
        })
    }

    /// Initialize the packet sender
    pub async fn init_sender(&mut self) -> Result<()> {
        let sender = PacketSender::new(
            self.args.workers,
            self.args.batch_size,
            self.args.timeout,
        ).await?;
        self.packet_sender = Some(Arc::new(sender));
        self.log_info("Packet sender initialized");
        Ok(())
    }

    /// Add a log entry
    pub fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        let entry = LogEntry {
            timestamp: chrono::Utc::now(),
            level,
            message: message.into(),
            details: None,
        };
        self.logs.push_back(entry);
        while self.logs.len() > self.max_logs {
            self.logs.pop_front();
        }
    }

    pub fn log_info(&mut self, message: impl Into<String>) {
        let msg = message.into();
        tracing::info!("{}", msg);
        self.log(LogLevel::Info, msg);
    }

    pub fn log_success(&mut self, message: impl Into<String>) {
        let msg = message.into();
        tracing::info!(status = "success", "{}", msg);
        self.log(LogLevel::Success, msg);
    }

    pub fn log_warning(&mut self, message: impl Into<String>) {
        let msg = message.into();
        tracing::warn!("{}", msg);
        self.log(LogLevel::Warning, msg);
    }

    pub fn log_error(&mut self, message: impl Into<String>) {
        let msg = message.into();
        tracing::error!("{}", msg);
        self.log(LogLevel::Error, msg);
    }

    pub fn log_debug(&mut self, message: impl Into<String>) {
        let msg = message.into();
        tracing::debug!("{}", msg);
        if self.args.debug {
            self.log(LogLevel::Debug, msg);
        }
    }

    /// Set status message
    pub fn set_status(&mut self, message: impl Into<String>, level: LogLevel) {
        self.status_message = Some((message.into(), level));
        self.status_time = std::time::Instant::now();
    }

    /// Clear status if expired
    pub fn clear_expired_status(&mut self) {
        if self.status_time.elapsed() > std::time::Duration::from_secs(5) {
            self.status_message = None;
        }
    }

    /// Toggle a TCP flag
    pub fn toggle_flag(&mut self, flag: TcpFlag) {
        if self.selected_flags.contains(&flag) {
            self.selected_flags.retain(|f| f != &flag);
        } else {
            self.selected_flags.push(flag);
        }
        self.selected_scan_type = ScanType::Custom;
    }

    /// Set scan type and update flags accordingly
    pub fn set_scan_type(&mut self, scan_type: ScanType) {
        self.selected_scan_type = scan_type;
        if scan_type != ScanType::Custom {
            self.selected_flags = scan_type.flags();
        }
    }

    /// Set protocol
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.selected_protocol = protocol;
        // Reset scan_type_index to prevent out-of-bounds when switching protocols
        self.scan_type_index = 0;
        self.log_info(format!("Protocol set to: {}", protocol));
    }

    /// Parse target from string (host:port or just host)
    pub fn parse_target(&mut self, input: &str) -> Result<()> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(());
        }

        if let Some((host, port_str)) = input.rsplit_once(':') {
            self.target.host = host.to_string();
            if let Ok(port) = port_str.parse::<u16>() {
                self.target.ports = vec![port];
            }
        } else {
            self.target.host = input.to_string();
        }

        // Try to parse the host (not original input) as IP address
        if let Ok(ip) = self.target.host.parse::<IpAddr>() {
            self.target.ip = Some(ip);
        }

        Ok(())
    }

    /// Get current flags as bitmask
    pub fn flags_bitmask(&self) -> u8 {
        self.selected_flags.iter().fold(0u8, |acc, f| acc | f.to_bit())
    }

    /// Get filtered scan types based on current protocol
    pub fn get_filtered_scan_types(&self) -> Vec<ScanType> {
        ScanType::all()
            .into_iter()
            .filter(|st| match self.selected_protocol {
                Protocol::Tcp => !matches!(st, ScanType::UdpScan),
                Protocol::Udp => matches!(st, ScanType::UdpScan),
                _ => true,
            })
            .collect()
    }

    /// Get count of filtered scan types for current protocol
    pub fn get_filtered_scan_types_count(&self) -> usize {
        match self.selected_protocol {
            Protocol::Tcp => ScanType::all().len() - 1, // Exclude UdpScan
            Protocol::Udp => 1, // Only UdpScan
            Protocol::Icmp => 5, // ICMP types
            Protocol::Dns => 6, // DNS query types
            Protocol::Http | Protocol::Https => 6, // HTTP methods
            Protocol::Ntp | Protocol::Raw => PacketTemplate::all().len(),
            Protocol::Snmp => 3, // v1, v2c, v3
            Protocol::Ssdp => 3, // ssdp:all, upnp:rootdevice, custom
            Protocol::Smb => 3, // SMB1, SMB2, SMB3
            Protocol::Ldap => 3, // base, one, sub
            Protocol::NetBios => 2, // name query, node status
            Protocol::Dhcp => 3, // Discover, Request, Release
            Protocol::Kerberos => 2, // AS-REQ, TGS-REQ
            Protocol::Arp => 2, // Request, Reply
        }
    }

    /// Create a new send job
    pub fn create_job(&mut self) -> SendJob {
        let job = SendJob {
            id: uuid::Uuid::new_v4(),
            target: self.target.clone(),
            protocol: self.selected_protocol,
            scan_type: self.selected_scan_type,
            flags: self.selected_flags.clone(),
            packet_count: self.packet_count,
            status: JobStatus::Pending,
            responses: Vec::new(),
            created_at: chrono::Utc::now(),
        };
        self.jobs.push(job.clone());
        self.current_job = Some(job.id);
        job
    }

    /// Add HTTP stream entry
    pub fn add_http_entry(&mut self, entry: HttpStreamEntry) {
        self.http_stream.push_back(entry);
        while self.http_stream.len() > self.max_http_entries {
            self.http_stream.pop_front();
        }
    }

    /// Add response
    pub async fn add_response(&self, response: PacketResponse) {
        let mut responses = self.responses.write().await;
        responses.push_back(response);
        while responses.len() > self.max_responses {
            responses.pop_front();
        }
    }

    /// Add captured packet for display
    pub fn capture_packet(
        &mut self,
        direction: PacketDirection,
        protocol: Protocol,
        source_ip: Option<IpAddr>,
        source_port: Option<u16>,
        dest_ip: Option<IpAddr>,
        dest_port: Option<u16>,
        flags: Vec<TcpFlag>,
        flags_raw: u8,
        seq_num: Option<u32>,
        ack_num: Option<u32>,
        payload: &[u8],
        rtt_ms: Option<f64>,
        status: impl Into<String>,
    ) {
        let payload_preview = if payload.is_empty() {
            String::new()
        } else {
            let preview_bytes = &payload[..payload.len().min(32)];
            // Try to show as ASCII if printable, otherwise hex
            if preview_bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                String::from_utf8_lossy(preview_bytes).to_string()
            } else {
                preview_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
        };

        let packet = CapturedPacket {
            id: self.next_capture_id,
            timestamp: chrono::Utc::now(),
            direction,
            protocol,
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            flags,
            flags_raw,
            seq_num,
            ack_num,
            payload_size: payload.len(),
            payload_preview,
            rtt_ms,
            status: status.into(),
        };

        self.next_capture_id += 1;
        self.captured_packets.push_back(packet);
        while self.captured_packets.len() > self.max_captured {
            self.captured_packets.pop_front();
        }
    }

    /// Clear all captured packets
    pub fn clear_captures(&mut self) {
        self.captured_packets.clear();
        self.capture_scroll = 0;
        self.capture_selected = 0;
    }

    /// Get all protocols as list
    #[allow(dead_code)]
    pub fn protocols() -> Vec<Protocol> {
        vec![
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Icmp,
            Protocol::Http,
            Protocol::Https,
            Protocol::Dns,
            Protocol::Ntp,
            Protocol::Raw,
        ]
    }

    /// Check if key sequence should show help
    pub fn should_show_key_help(&self) -> bool {
        !self.pending_keys.is_empty() &&
            self.last_key_time.elapsed() > std::time::Duration::from_millis(200)
    }

    /// Clear pending keys
    pub fn clear_pending_keys(&mut self) {
        self.pending_keys.clear();
    }

    /// Add pending key
    pub fn add_pending_key(&mut self, key: char) {
        self.pending_keys.push(key);
        self.last_key_time = std::time::Instant::now();
    }

    /// Move selection up in current pane
    pub fn move_up(&mut self) {
        self.move_up_by(1);
    }

    /// Move selection up by a specified amount
    pub fn move_up_by(&mut self, amount: usize) {
        match self.active_pane {
            ActivePane::FlagSelection => {
                self.flag_list_index = self.flag_list_index.saturating_sub(amount);
            }
            ActivePane::PacketConfig => {
                self.scan_type_index = self.scan_type_index.saturating_sub(amount);
            }
            ActivePane::ResponseLog => {
                self.log_scroll = self.log_scroll.saturating_sub(amount);
            }
            ActivePane::HttpStream => {
                self.http_scroll = self.http_scroll.saturating_sub(amount);
            }
            ActivePane::PacketCapture => {
                self.capture_scroll = self.capture_scroll.saturating_sub(amount);
            }
            ActivePane::Statistics => {
                self.stats_scroll = self.stats_scroll.saturating_sub(amount);
            }
            ActivePane::TargetConfig => {
                // No scrolling needed for target config
            }
        }
    }

    /// Move selection down in current pane
    pub fn move_down(&mut self) {
        self.move_down_by(1);
    }

    /// Move selection down by a specified amount
    pub fn move_down_by(&mut self, amount: usize) {
        match self.active_pane {
            ActivePane::FlagSelection => {
                let max = TcpFlag::all().len().saturating_sub(1);
                self.flag_list_index = (self.flag_list_index + amount).min(max);
            }
            ActivePane::PacketConfig => {
                let max_scan = self.get_filtered_scan_types_count().saturating_sub(1);
                self.scan_type_index = (self.scan_type_index + amount).min(max_scan);
            }
            ActivePane::ResponseLog => {
                let max = self.logs.len().saturating_sub(1);
                self.log_scroll = (self.log_scroll + amount).min(max);
            }
            ActivePane::HttpStream => {
                let max = self.http_stream.len().saturating_sub(1);
                self.http_scroll = (self.http_scroll + amount).min(max);
            }
            ActivePane::PacketCapture => {
                let max = self.captured_packets.len().saturating_sub(1);
                self.capture_scroll = (self.capture_scroll + amount).min(max);
            }
            ActivePane::Statistics => {
                // Stats has max 20 or so lines typically
                let max = 20usize;
                self.stats_scroll = (self.stats_scroll + amount).min(max);
            }
            ActivePane::TargetConfig => {
                // No scrolling needed for target config
            }
        }
    }

    /// Page down (half page)
    pub fn page_down(&mut self) {
        self.move_down_by(10);
    }

    /// Page up (half page)
    pub fn page_up(&mut self) {
        self.move_up_by(10);
    }

    /// Handle selection in current pane
    #[allow(dead_code)]
    pub fn select(&mut self) {
        match self.active_pane {
            ActivePane::FlagSelection => {
                let flags = TcpFlag::all();
                if let Some(flag) = flags.get(self.flag_list_index) {
                    self.toggle_flag(*flag);
                }
            }
            ActivePane::PacketConfig => {
                // Could toggle between protocol and scan type selection
            }
            _ => {}
        }
    }

    /// Start flood mode (like hping3 --flood)
    pub fn start_flood(&mut self) {
        self.flood_mode = true;
        self.flood_count = 0;
        self.flood_start = Some(std::time::Instant::now());
        self.log_warning("FLOOD MODE STARTED - Press 'q' to stop");
    }

    /// Stop flood mode
    pub fn stop_flood(&mut self) {
        if self.flood_mode {
            self.flood_mode = false;
            let duration = self.flood_start
                .map(|s| s.elapsed().as_secs_f64())
                .unwrap_or(0.0);
            let rate = if duration > 0.0 {
                self.flood_count as f64 / duration
            } else {
                0.0
            };
            self.log_success(format!(
                "FLOOD STOPPED: {} packets in {:.2}s ({:.0} pps)",
                self.flood_count, duration, rate
            ));
            self.flood_start = None;
        }
    }

    /// Increment flood counter
    #[allow(dead_code)]
    pub fn increment_flood_count(&mut self) {
        self.flood_count += 1;
    }

    /// Get flood stats for display
    pub fn get_flood_stats(&self) -> (u64, f64, f64) {
        let duration = self.flood_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        let rate = if duration > 0.0 {
            self.flood_count as f64 / duration
        } else {
            0.0
        };
        (self.flood_count, duration, rate)
    }

    /// Quit the application
    pub fn quit(&mut self) {
        if self.flood_mode {
            self.stop_flood();
        }
        self.running = false;
    }

    /// Create a new session
    pub fn create_new_session(&mut self) {
        let new_session = Session::new(self.next_session_id);
        self.next_session_id += 1;
        self.sessions.push(new_session);
        self.active_session = self.sessions.len() - 1;
        self.log_success(format!("Created new session: Session {}", self.active_session + 1));
    }

    /// Switch to next session
    pub fn next_session(&mut self) {
        if self.sessions.len() > 1 {
            self.active_session = (self.active_session + 1) % self.sessions.len();
            self.log_info(format!("Switched to: Session {}", self.active_session + 1));
        }
    }

    /// Switch to previous session
    pub fn prev_session(&mut self) {
        if self.sessions.len() > 1 {
            if self.active_session == 0 {
                self.active_session = self.sessions.len() - 1;
            } else {
                self.active_session -= 1;
            }
            self.log_info(format!("Switched to: Session {}", self.active_session + 1));
        }
    }

    /// Close current session (if more than one exists)
    pub fn close_session(&mut self) {
        if self.sessions.len() > 1 {
            let closed_id = self.active_session;
            self.sessions.remove(self.active_session);
            if self.active_session >= self.sessions.len() {
                self.active_session = self.sessions.len() - 1;
            }
            self.log_info(format!("Closed session {}, now on Session {}", closed_id + 1, self.active_session + 1));
        } else {
            self.log_warning("Cannot close last session");
        }
    }

    /// Get current session count
    #[allow(dead_code)]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get current session name
    #[allow(dead_code)]
    pub fn current_session_name(&self) -> &str {
        self.sessions.get(self.active_session)
            .map(|s| s.name.as_str())
            .unwrap_or("Session 1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args() -> Args {
        Args {
            debug: false,
            log_file: std::path::PathBuf::from("test.log"),
            workers: 4,
            batch_size: 100,
            timeout: 1000,
            host: None,
            port: None,
        }
    }

    #[test]
    fn test_app_creation() {
        let args = create_test_args();
        let app = App::new(args).unwrap();
        assert!(app.running);
        assert_eq!(app.input_mode, InputMode::Normal);
    }

    #[test]
    fn test_flag_toggle() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.selected_flags.clear();
        app.toggle_flag(TcpFlag::Syn);
        assert!(app.selected_flags.contains(&TcpFlag::Syn));

        app.toggle_flag(TcpFlag::Syn);
        assert!(!app.selected_flags.contains(&TcpFlag::Syn));
    }

    #[test]
    fn test_scan_type_flags() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.set_scan_type(ScanType::XmasScan);
        assert!(app.selected_flags.contains(&TcpFlag::Fin));
        assert!(app.selected_flags.contains(&TcpFlag::Psh));
        assert!(app.selected_flags.contains(&TcpFlag::Urg));
    }

    #[test]
    fn test_flags_bitmask() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.selected_flags = vec![TcpFlag::Syn, TcpFlag::Ack];
        let bitmask = app.flags_bitmask();
        assert_eq!(bitmask, 0x02 | 0x10); // SYN | ACK
    }

    #[test]
    fn test_pane_navigation() {
        assert_eq!(ActivePane::PacketConfig.next(), ActivePane::FlagSelection);
        assert_eq!(ActivePane::Statistics.next(), ActivePane::PacketConfig);
        assert_eq!(ActivePane::PacketConfig.prev(), ActivePane::Statistics);
    }

    #[test]
    fn test_parse_target() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.parse_target("192.168.1.1:80").unwrap();
        assert_eq!(app.target.host, "192.168.1.1");
        assert_eq!(app.target.ports, vec![80]);
    }

    #[test]
    fn test_logging() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        app.log_info("Test message");
        assert_eq!(app.logs.len(), 1);
        assert_eq!(app.logs[0].level, LogLevel::Info);
    }

    #[test]
    fn test_packet_editor_state_new() {
        let state = PacketEditorState::new();
        assert_eq!(state.ttl, 64);
        assert_eq!(state.dest_port, 80);
        assert_eq!(state.window_size, 65535);
        assert!(state.payload_hex.is_empty());
        assert!(!state.editing);
    }

    #[test]
    fn test_packet_editor_field_navigation() {
        assert_eq!(PacketEditorField::SourcePort.next(), PacketEditorField::DestPort);
        assert_eq!(PacketEditorField::Payload.next(), PacketEditorField::SourcePort);
        assert_eq!(PacketEditorField::SourcePort.prev(), PacketEditorField::Payload);
    }

    #[test]
    fn test_packet_editor_apply_buffer() {
        let mut state = PacketEditorState::new();

        // Test valid port number
        state.current_field = PacketEditorField::DestPort;
        state.field_buffer = "443".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.dest_port, 443);

        // Test valid TTL
        state.current_field = PacketEditorField::Ttl;
        state.field_buffer = "128".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.ttl, 128);

        // Test valid hex payload
        state.current_field = PacketEditorField::Payload;
        state.field_buffer = "48656C6C6F".to_string(); // "Hello"
        assert!(state.apply_buffer());
        assert_eq!(state.payload_hex, "48656C6C6F");

        // Test invalid hex payload (odd length)
        state.field_buffer = "48656".to_string();
        assert!(!state.apply_buffer());
    }

    #[test]
    fn test_packet_editor_to_payload_bytes() {
        let mut state = PacketEditorState::new();

        // Empty payload returns None
        assert!(state.to_payload_bytes().is_none());

        // Valid hex payload returns bytes
        state.payload_hex = "48656C6C6F".to_string(); // "Hello"
        let bytes = state.to_payload_bytes().unwrap();
        assert_eq!(bytes, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert_eq!(String::from_utf8(bytes).unwrap(), "Hello");
    }

    #[test]
    fn test_packet_editor_fields_for_protocol() {
        // TCP should have 7 fields
        let tcp_fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        assert_eq!(tcp_fields.len(), 7);
        assert!(tcp_fields.contains(&PacketEditorField::SeqNum));
        assert!(tcp_fields.contains(&PacketEditorField::WindowSize));

        // UDP should have fewer fields (no TCP-specific ones)
        let udp_fields = PacketEditorField::fields_for_protocol(Protocol::Udp);
        assert_eq!(udp_fields.len(), 4);
        assert!(!udp_fields.contains(&PacketEditorField::SeqNum));

        // ICMP should have ICMP-specific fields
        let icmp_fields = PacketEditorField::fields_for_protocol(Protocol::Icmp);
        assert!(icmp_fields.contains(&PacketEditorField::IcmpType));
        assert!(icmp_fields.contains(&PacketEditorField::IcmpCode));

        // HTTP should have HTTP-specific fields
        let http_fields = PacketEditorField::fields_for_protocol(Protocol::Http);
        assert!(http_fields.contains(&PacketEditorField::HttpMethod));
        assert!(http_fields.contains(&PacketEditorField::HttpPath));

        // DNS should have DNS-specific fields
        let dns_fields = PacketEditorField::fields_for_protocol(Protocol::Dns);
        assert!(dns_fields.contains(&PacketEditorField::DnsQueryType));
        assert!(dns_fields.contains(&PacketEditorField::DnsDomain));
    }

    #[test]
    fn test_packet_editor_protocol_navigation() {
        // Test navigation within TCP protocol
        let first = PacketEditorField::fields_for_protocol(Protocol::Tcp)[0];
        let second = first.next_for_protocol(Protocol::Tcp);
        assert_ne!(first, second);

        // Navigation should wrap around
        let tcp_fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        let last = tcp_fields[tcp_fields.len() - 1];
        let wrapped = last.next_for_protocol(Protocol::Tcp);
        assert_eq!(wrapped, tcp_fields[0]);

        // Test prev navigation
        let first = tcp_fields[0];
        let prev_from_first = first.prev_for_protocol(Protocol::Tcp);
        assert_eq!(prev_from_first, tcp_fields[tcp_fields.len() - 1]);
    }

    #[test]
    fn test_packet_editor_reset_to_protocol() {
        let mut state = PacketEditorState::new();

        // Set current field to something for TCP
        state.current_field = PacketEditorField::SeqNum;

        // Reset to ICMP should set first ICMP field
        state.reset_to_protocol(Protocol::Icmp);
        let icmp_first = PacketEditorField::fields_for_protocol(Protocol::Icmp)[0];
        assert_eq!(state.current_field, icmp_first);

        // Reset to HTTP should set first HTTP field
        state.reset_to_protocol(Protocol::Http);
        let http_first = PacketEditorField::fields_for_protocol(Protocol::Http)[0];
        assert_eq!(state.current_field, http_first);
    }

    #[test]
    fn test_packet_editor_protocol_specific_values() {
        let mut state = PacketEditorState::new();

        // Test ICMP fields
        state.current_field = PacketEditorField::IcmpType;
        state.field_buffer = "8".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.icmp_type, 8);

        // Test DNS fields
        state.current_field = PacketEditorField::DnsDomain;
        state.field_buffer = "example.com".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.dns_domain, "example.com");

        // Test HTTP fields
        state.current_field = PacketEditorField::HttpMethod;
        state.field_buffer = "POST".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.http_method, "POST");

        // Test SNMP fields
        state.current_field = PacketEditorField::SnmpCommunity;
        state.field_buffer = "private".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.snmp_community, "private");
    }

    #[test]
    fn test_protocol_config_counts() {
        let args = create_test_args();
        let mut app = App::new(args).unwrap();

        // TCP should have 8 scan types (9 total minus UDP)
        app.selected_protocol = Protocol::Tcp;
        assert_eq!(app.get_filtered_scan_types_count(), 8);

        // UDP should have 1 scan type
        app.selected_protocol = Protocol::Udp;
        assert_eq!(app.get_filtered_scan_types_count(), 1);

        // ICMP should have 5 types
        app.selected_protocol = Protocol::Icmp;
        assert_eq!(app.get_filtered_scan_types_count(), 5);

        // DNS should have 6 query types
        app.selected_protocol = Protocol::Dns;
        assert_eq!(app.get_filtered_scan_types_count(), 6);

        // SNMP should have 3 versions
        app.selected_protocol = Protocol::Snmp;
        assert_eq!(app.get_filtered_scan_types_count(), 3);

        // ARP should have 2 operations
        app.selected_protocol = Protocol::Arp;
        assert_eq!(app.get_filtered_scan_types_count(), 2);
    }

    #[test]
    fn test_packet_editor_field_labels() {
        // All fields should have non-empty labels
        let all_fields = [
            PacketEditorField::SourcePort, PacketEditorField::DestPort,
            PacketEditorField::Ttl, PacketEditorField::Payload,
            PacketEditorField::SeqNum, PacketEditorField::AckNum,
            PacketEditorField::WindowSize, PacketEditorField::IcmpType,
            PacketEditorField::IcmpCode, PacketEditorField::IcmpId,
            PacketEditorField::IcmpSeq, PacketEditorField::DnsQueryType,
            PacketEditorField::DnsDomain, PacketEditorField::HttpMethod,
            PacketEditorField::HttpPath, PacketEditorField::HttpHeaders,
        ];

        for field in &all_fields {
            assert!(!field.label().is_empty(), "Field {:?} has empty label", field);
        }
    }
}
