//! Application state management for NoirCast

use crate::config::{Config, PacketTemplate, Protocol, ScanType, Target, TcpFlag};
use crate::network::packet::{PacketResponse, PacketStats};
use crate::network::sender::PacketSender;
use crate::cli::Args;
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
            LogLevel::Info => "[i]",
            LogLevel::Success => "[+]",
            LogLevel::Warning => "[!]",
            LogLevel::Error => "[x]",
            LogLevel::Debug => "[*]",
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
    // IP Header fields (Layer 3)
    #[default]
    SourceIp,
    IpId,
    IpFlags,
    FragmentOffset,
    Tos,
    Ttl,

    // Common transport fields
    SourcePort,
    DestPort,
    Payload,

    // TCP-specific (Layer 4)
    TcpFlags,
    SeqNum,
    AckNum,
    WindowSize,
    UrgentPtr,

    // TCP Options (RFC 793/7323)
    TcpMss,              // Maximum Segment Size (0 = not included)
    TcpWindowScale,      // Window Scale shift (255 = not included, 0-14 = shift)
    TcpSackPermitted,    // SACK Permitted option (yes/no)
    TcpTimestampsEnabled, // Timestamps option enabled (yes/no)
    TcpTsVal,            // Timestamp Value
    TcpTsEcr,            // Timestamp Echo Reply

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
    HttpBody,        // Request body (shown for POST, PUT, PATCH)
    HttpCookies,     // Cookie header (key=value pairs)
    HttpContentType, // Content-Type header (shown for POST, PUT, PATCH)

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
    DhcpClientMac,

    // Kerberos-specific
    KerberosRealm,
    KerberosUser,

    // ARP-specific (Layer 2)
    ArpOperation,
    ArpSenderMac,
    ArpSenderIp,
    ArpTargetMac,
    ArpTargetIp,
}

impl PacketEditorField {
    /// Full IP header fields (Layer 3) - requires CAP_NET_RAW to actually modify
    const IP_FIELDS: &'static [Self] = &[
        Self::SourceIp, Self::Ttl, Self::Tos, Self::IpId, Self::IpFlags, Self::FragmentOffset,
    ];

    /// Full TCP header fields - requires raw sockets to modify on established connections
    const TCP_FIELDS: &'static [Self] = &[
        Self::SourcePort, Self::DestPort, Self::TcpFlags,
        Self::SeqNum, Self::AckNum, Self::WindowSize, Self::UrgentPtr,
    ];

    /// TCP Options fields (RFC 793/7323)
    const TCP_OPTIONS_FIELDS: &'static [Self] = &[
        Self::TcpMss, Self::TcpWindowScale, Self::TcpSackPermitted,
        Self::TcpTimestampsEnabled, Self::TcpTsVal, Self::TcpTsEcr,
    ];

    /// UDP header fields
    const UDP_FIELDS: &'static [Self] = &[
        Self::SourcePort, Self::DestPort,
    ];

    /// Get fields relevant for a specific protocol.
    /// All IP-based protocols get full IP header fields.
    /// TCP-based protocols also get TCP header fields.
    /// Only ARP (Layer 2) doesn't have IP fields.
    pub fn fields_for_protocol(protocol: Protocol) -> Vec<Self> {
        match protocol {
            // === RAW TCP ===
            Protocol::Tcp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::TCP_FIELDS);
                f.extend_from_slice(Self::TCP_OPTIONS_FIELDS);
                f.push(Self::Payload);
                f
            }

            // === RAW UDP ===
            Protocol::Udp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.push(Self::Payload);
                f
            }

            // === ICMP ===
            Protocol::Icmp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(&[Self::IcmpType, Self::IcmpCode, Self::IcmpId, Self::IcmpSeq, Self::Payload]);
                f
            }

            // === TCP-BASED APPLICATION PROTOCOLS ===
            Protocol::Http | Protocol::Https => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::TCP_FIELDS);
                f.extend_from_slice(Self::TCP_OPTIONS_FIELDS);
                f.extend_from_slice(&[Self::HttpMethod, Self::HttpPath, Self::HttpHeaders]);
                f
            }

            Protocol::Smb => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::TCP_FIELDS);
                f.extend_from_slice(Self::TCP_OPTIONS_FIELDS);
                f.push(Self::SmbVersion);
                f
            }

            Protocol::Ldap => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::TCP_FIELDS);
                f.extend_from_slice(Self::TCP_OPTIONS_FIELDS);
                f.extend_from_slice(&[Self::LdapScope, Self::LdapBaseDn]);
                f
            }

            Protocol::Kerberos => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::TCP_FIELDS);
                f.extend_from_slice(Self::TCP_OPTIONS_FIELDS);
                f.extend_from_slice(&[Self::KerberosRealm, Self::KerberosUser]);
                f
            }

            // === UDP-BASED APPLICATION PROTOCOLS ===
            Protocol::Dns => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.extend_from_slice(&[Self::DnsQueryType, Self::DnsDomain, Self::Payload]);
                f
            }

            Protocol::Ntp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.push(Self::Payload);
                f
            }

            Protocol::Snmp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.extend_from_slice(&[Self::SnmpVersion, Self::SnmpCommunity]);
                f
            }

            Protocol::Ssdp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.extend_from_slice(&[Self::SsdpTarget, Self::Payload]);
                f
            }

            Protocol::NetBios => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.push(Self::NetBiosName);
                f
            }

            Protocol::Dhcp => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::UDP_FIELDS);
                f.extend_from_slice(&[Self::DhcpType, Self::DhcpClientMac]);
                f
            }

            // === LAYER 2 (no IP header) ===
            Protocol::Arp => vec![
                Self::ArpOperation,
                Self::ArpSenderMac, Self::ArpSenderIp,
                Self::ArpTargetMac, Self::ArpTargetIp,
            ],

            // === RAW MODE ===
            Protocol::Raw => {
                let mut f = Self::IP_FIELDS.to_vec();
                f.extend_from_slice(Self::TCP_FIELDS);
                f.push(Self::Payload);
                f
            }
        }
    }

    /// Get fields for protocol with context-dependent additions.
    /// For HTTP, adds body/cookies/content-type when method is POST, PUT, or PATCH.
    pub fn fields_for_protocol_context(protocol: Protocol, http_method: &str) -> Vec<Self> {
        let mut fields = Self::fields_for_protocol(protocol);

        // Add context-dependent HTTP fields
        if matches!(protocol, Protocol::Http | Protocol::Https) {
            let method_upper = http_method.to_uppercase();
            if method_upper == "POST" || method_upper == "PUT" || method_upper == "PATCH" {
                // Insert body-related fields after HttpHeaders
                if let Some(pos) = fields.iter().position(|f| *f == Self::HttpHeaders) {
                    // Insert after HttpHeaders: ContentType, Cookies, Body
                    fields.insert(pos + 1, Self::HttpContentType);
                    fields.insert(pos + 2, Self::HttpCookies);
                    fields.insert(pos + 3, Self::HttpBody);
                } else {
                    // Fallback: append at end
                    fields.push(Self::HttpContentType);
                    fields.push(Self::HttpCookies);
                    fields.push(Self::HttpBody);
                }
            }
        }

        fields
    }

    /// Get next field for a given protocol context with HTTP method awareness
    #[allow(dead_code)]
    pub fn next_for_context(&self, protocol: Protocol, http_method: &str) -> Self {
        let fields = Self::fields_for_protocol_context(protocol, http_method);
        if let Some(idx) = fields.iter().position(|f| f == self) {
            fields[(idx + 1) % fields.len()]
        } else {
            fields.first().copied().unwrap_or_default()
        }
    }

    /// Get previous field for a given protocol context with HTTP method awareness
    #[allow(dead_code)]
    pub fn prev_for_context(&self, protocol: Protocol, http_method: &str) -> Self {
        let fields = Self::fields_for_protocol_context(protocol, http_method);
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

    /// Check if this field requires raw socket privileges (CAP_NET_RAW) to actually work.
    /// These fields can be edited in the UI but won't take effect without elevated privileges.
    pub fn requires_raw_socket(&self) -> bool {
        matches!(self,
            // IP header modifications require raw sockets
            PacketEditorField::SourceIp |
            PacketEditorField::IpId |
            PacketEditorField::IpFlags |
            PacketEditorField::FragmentOffset |
            PacketEditorField::Tos |
            // TCP flags on established connections require raw sockets
            PacketEditorField::TcpFlags |
            PacketEditorField::SeqNum |
            PacketEditorField::AckNum |
            PacketEditorField::UrgentPtr |
            // ARP requires raw L2 access
            PacketEditorField::ArpSenderMac |
            PacketEditorField::ArpSenderIp
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            // IP Header
            PacketEditorField::SourceIp => "Source IP",
            PacketEditorField::IpId => "IP ID",
            PacketEditorField::IpFlags => "IP Flags",
            PacketEditorField::FragmentOffset => "Frag Offset",
            PacketEditorField::Tos => "TOS/DSCP",
            PacketEditorField::Ttl => "TTL",
            // Transport Common
            PacketEditorField::SourcePort => "Source Port",
            PacketEditorField::DestPort => "Dest Port",
            PacketEditorField::Payload => "Payload (hex)",
            // TCP
            PacketEditorField::TcpFlags => "TCP Flags",
            PacketEditorField::SeqNum => "Sequence #",
            PacketEditorField::AckNum => "Ack #",
            PacketEditorField::WindowSize => "Window Size",
            PacketEditorField::UrgentPtr => "Urgent Ptr",
            // TCP Options
            PacketEditorField::TcpMss => "MSS",
            PacketEditorField::TcpWindowScale => "Win Scale",
            PacketEditorField::TcpSackPermitted => "SACK Perm",
            PacketEditorField::TcpTimestampsEnabled => "Timestamps",
            PacketEditorField::TcpTsVal => "TS Value",
            PacketEditorField::TcpTsEcr => "TS Echo",
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
            PacketEditorField::HttpBody => "Body",
            PacketEditorField::HttpCookies => "Cookies",
            PacketEditorField::HttpContentType => "Content-Type",
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
            PacketEditorField::DhcpClientMac => "Client MAC",
            // Kerberos
            PacketEditorField::KerberosRealm => "Realm",
            PacketEditorField::KerberosUser => "Username",
            // ARP
            PacketEditorField::ArpOperation => "Operation",
            PacketEditorField::ArpSenderMac => "Sender MAC",
            PacketEditorField::ArpSenderIp => "Sender IP",
            PacketEditorField::ArpTargetMac => "Target MAC",
            PacketEditorField::ArpTargetIp => "Target IP",
        }
    }
}

/// State for the packet editor popup - protocol-aware
///
/// This struct holds all editable packet fields across different protocols,
/// from Layer 2 (Ethernet/ARP) through Layer 4 (TCP/UDP) and application protocols.
///
/// ## IP Header Fields (Layer 3)
/// These fields require CAP_NET_RAW capability on Linux or Administrator on Windows
/// to actually be sent with custom values.
///
/// ## TCP Flags Reference
/// TCP flags control connection state. Common combinations:
/// - SYN (0x02): Initiate connection (SYN scan)
/// - SYN,ACK (0x12): Server acknowledging SYN
/// - ACK (0x10): Acknowledge received data
/// - FIN (0x01): Graceful connection close
/// - RST (0x04): Abruptly terminate connection
/// - PSH (0x08): Push data immediately to application
/// - URG (0x20): Urgent data present (see urgent_ptr)
/// - FIN,PSH,URG (0x29): XMAS scan - all flags set
#[derive(Debug, Clone, Default)]
pub struct PacketEditorState {
    // =========================================================================
    // IP HEADER FIELDS (Layer 3) - RFC 791
    // =========================================================================

    /// Source IP address for IP spoofing.
    /// Empty string = use the system's real IP address.
    /// Requires raw socket privileges (CAP_NET_RAW on Linux).
    /// Example: "192.168.1.100" or "10.0.0.1"
    pub source_ip: String,

    /// IP Identification field (16-bit).
    /// Used to identify fragments of an original datagram.
    /// Usually randomized per packet. Range: 0-65535.
    pub ip_id: u16,

    /// IP Flags (3-bit field, stored in low bits of this u8).
    /// - Bit 0 (0x01): MF (More Fragments) - more fragments follow
    /// - Bit 1 (0x02): DF (Don't Fragment) - packet should not be fragmented
    /// - Bit 2: Reserved, must be 0
    /// Common values: 0x02 (DF set, normal), 0x00 (allow fragmentation)
    pub ip_flags: u8,

    /// Fragment Offset (13-bit, in 8-byte units).
    /// Position of this fragment in the original datagram.
    /// 0 = first fragment or unfragmented packet.
    /// Max value: 8191 (represents offset of 65528 bytes).
    pub fragment_offset: u16,

    /// Type of Service / Differentiated Services Code Point (DSCP).
    /// 8-bit field controlling packet priority and handling:
    /// - Bits 0-1: ECN (Explicit Congestion Notification)
    /// - Bits 2-7: DSCP (6 bits, value 0-63)
    /// Common values:
    /// - 0x00: Default/Best Effort
    /// - 0x28 (40): Expedited Forwarding (EF) - low latency
    /// - 0x60 (96): Network Control - highest priority
    /// DSCP value = tos >> 2
    pub tos: u8,

    // =========================================================================
    // COMMON TRANSPORT FIELDS (Layer 4)
    // =========================================================================

    /// Source port number (16-bit, 0-65535).
    /// For client connections, typically ephemeral port (>= 32768).
    pub source_port: u16,

    /// Destination port number (16-bit, 0-65535).
    /// Common ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 53 (DNS).
    pub dest_port: u16,

    /// Time To Live (8-bit, 0-255).
    /// Decremented by each router; packet dropped when TTL=0.
    /// Used for traceroute. Common defaults:
    /// - Linux: 64
    /// - Windows: 128
    /// - Cisco/network devices: 255
    pub ttl: u8,

    /// Raw payload data in hexadecimal format.
    /// Must have even number of hex digits (each byte = 2 hex chars).
    /// Example: "48656C6C6F" = "Hello" in ASCII.
    pub payload_hex: String,

    // =========================================================================
    // TCP-SPECIFIC FIELDS (Layer 4) - RFC 793
    // =========================================================================

    /// TCP Flags bitmask (6 main flags + 2 congestion flags).
    /// - 0x01: FIN - No more data from sender
    /// - 0x02: SYN - Synchronize sequence numbers (connection init)
    /// - 0x04: RST - Reset the connection
    /// - 0x08: PSH - Push function (deliver data immediately)
    /// - 0x10: ACK - Acknowledgment field is significant
    /// - 0x20: URG - Urgent pointer field is significant
    /// - 0x40: ECE - ECN-Echo (congestion experienced)
    /// - 0x80: CWR - Congestion Window Reduced
    /// Can be set as: "SYN", "SYN,ACK", "FIN,PSH,URG", or numeric "18"
    pub tcp_flags: u8,

    /// TCP Sequence Number (32-bit).
    /// First byte of data in this segment. Randomly initialized.
    /// Wraps around after 4GB of data transferred.
    pub seq_num: u32,

    /// TCP Acknowledgment Number (32-bit).
    /// Next sequence number the sender expects to receive.
    /// Only valid when ACK flag is set.
    pub ack_num: u32,

    /// TCP Window Size (16-bit).
    /// Flow control: bytes sender can receive before acknowledgment.
    /// Modern systems use window scaling for larger values.
    /// Default 65535 = maximum without scaling.
    pub window_size: u16,

    /// TCP Urgent Pointer (16-bit).
    /// Offset from sequence number to urgent data boundary.
    /// Only valid when URG flag is set. Rarely used today.
    pub urgent_ptr: u16,

    // =========================================================================
    // TCP OPTIONS (RFC 793/7323)
    // =========================================================================

    /// TCP Maximum Segment Size option (Kind=2).
    /// 0 = option not included, otherwise the MSS value in bytes.
    /// Common values: 1460 (Ethernet), 1360 (with options), 536 (minimum).
    pub tcp_mss: u16,

    /// TCP Window Scale option (Kind=3).
    /// 255 = option not included, 0-14 = window scale shift count.
    /// Allows advertised window sizes up to 1GB (shift=14).
    pub tcp_window_scale: u8,

    /// TCP SACK Permitted option (Kind=4).
    /// When true, includes the SACK Permitted option in SYN packets.
    /// Enables selective acknowledgment for better loss recovery.
    pub tcp_sack_permitted: bool,

    /// TCP Timestamps option enabled (Kind=8).
    /// When true, includes TSval and TSecr in the packet.
    /// Used for RTT measurement and PAWS (Protection Against Wrapped Sequences).
    pub tcp_timestamps_enabled: bool,

    /// TCP Timestamp Value (TSval).
    /// Sender's current timestamp, typically milliseconds since some epoch.
    /// Only used when tcp_timestamps_enabled is true.
    pub tcp_tsval: u32,

    /// TCP Timestamp Echo Reply (TSecr).
    /// Echoed timestamp from last received segment.
    /// Set to 0 in SYN packets, otherwise echoes peer's TSval.
    pub tcp_tsecr: u32,

    // =========================================================================
    // ICMP-SPECIFIC FIELDS - RFC 792
    // =========================================================================

    /// ICMP Type (8-bit). Common types:
    /// - 0: Echo Reply (ping response)
    /// - 3: Destination Unreachable
    /// - 8: Echo Request (ping)
    /// - 11: Time Exceeded (traceroute)
    /// - 13: Timestamp Request
    pub icmp_type: u8,

    /// ICMP Code (8-bit). Subtype of ICMP message.
    /// For Type 3 (Unreachable): 0=Net, 1=Host, 3=Port unreachable
    /// For Echo Request/Reply: always 0.
    pub icmp_code: u8,

    /// ICMP Identifier (16-bit).
    /// Used to match Echo Requests with Replies.
    /// Usually set to process ID or random value.
    pub icmp_id: u16,

    /// ICMP Sequence Number (16-bit).
    /// Incremented for each Echo Request sent.
    /// Helps identify lost or reordered packets.
    pub icmp_seq: u16,

    // =========================================================================
    // DNS-SPECIFIC FIELDS - RFC 1035
    // =========================================================================

    /// DNS Query Type. Common types:
    /// - 1: A (IPv4 address)
    /// - 2: NS (Name Server)
    /// - 5: CNAME (Canonical Name)
    /// - 6: SOA (Start of Authority)
    /// - 15: MX (Mail Exchange)
    /// - 16: TXT (Text record)
    /// - 28: AAAA (IPv6 address)
    /// - 255: ANY (all records)
    pub dns_query_type: u16,

    /// Domain name to query. Example: "example.com"
    pub dns_domain: String,

    // =========================================================================
    // HTTP-SPECIFIC FIELDS
    // =========================================================================

    /// HTTP Method: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
    pub http_method: String,

    /// HTTP Request Path. Example: "/api/v1/users" or "/"
    pub http_path: String,

    /// Additional HTTP Headers (one per line, "Name: Value" format).
    /// Example: "Authorization: Bearer token123"
    pub http_headers: String,

    /// HTTP Request body (for POST, PUT, PATCH methods)
    pub http_body: String,

    /// HTTP Cookies (key=value pairs, semicolon separated)
    pub http_cookies: String,

    /// HTTP Content-Type header (e.g., "application/json", "text/html")
    pub http_content_type: String,

    // =========================================================================
    // SNMP-SPECIFIC FIELDS - RFC 1157/3416
    // =========================================================================

    /// SNMP Version: 1, 2 (v2c), or 3
    /// v1/v2c use community strings, v3 uses authentication.
    pub snmp_version: u8,

    /// SNMP Community String (v1/v2c authentication).
    /// Default: "public" for read, "private" for write.
    pub snmp_community: String,

    // =========================================================================
    // SSDP-SPECIFIC FIELDS (UPnP Discovery)
    // =========================================================================

    /// SSDP Search Target (ST header). Examples:
    /// - "ssdp:all" - discover all devices
    /// - "upnp:rootdevice" - root devices only
    /// - "urn:schemas-upnp-org:device:MediaServer:1"
    pub ssdp_target: String,

    // =========================================================================
    // SMB-SPECIFIC FIELDS
    // =========================================================================

    /// SMB Protocol Version: 1, 2, or 3
    pub smb_version: u8,

    // =========================================================================
    // LDAP-SPECIFIC FIELDS - RFC 4511
    // =========================================================================

    /// LDAP Search Scope:
    /// - 0: Base (only the base object)
    /// - 1: One Level (immediate children only)
    /// - 2: Subtree (base and all descendants)
    pub ldap_scope: u8,

    /// LDAP Base DN (Distinguished Name).
    /// Example: "dc=example,dc=com" or "ou=users,dc=corp,dc=local"
    pub ldap_base_dn: String,

    // =========================================================================
    // NETBIOS-SPECIFIC FIELDS - RFC 1002
    // =========================================================================

    /// NetBIOS Name to query (15 chars max, padded with spaces).
    /// Empty = wildcard query (*) for all names.
    pub netbios_name: String,

    // =========================================================================
    // DHCP-SPECIFIC FIELDS - RFC 2131
    // =========================================================================

    /// DHCP Message Type:
    /// - 1: DISCOVER - client looking for servers
    /// - 2: OFFER - server response to discover
    /// - 3: REQUEST - client requesting offered address
    /// - 4: DECLINE - client declining offer
    /// - 5: ACK - server confirming lease
    /// - 6: NAK - server denying request
    /// - 7: RELEASE - client releasing address
    /// - 8: INFORM - client requesting config only
    pub dhcp_type: u8,

    /// Client MAC address for DHCP. Format: "AA:BB:CC:DD:EE:FF"
    /// Empty = use system's actual MAC address.
    pub dhcp_client_mac: String,

    // =========================================================================
    // KERBEROS-SPECIFIC FIELDS - RFC 4120
    // =========================================================================

    /// Kerberos Realm (uppercase domain). Example: "EXAMPLE.COM"
    pub kerberos_realm: String,

    /// Kerberos Principal (username). Example: "admin"
    pub kerberos_user: String,

    // =========================================================================
    // ARP-SPECIFIC FIELDS (Layer 2) - RFC 826
    // =========================================================================

    /// ARP Operation:
    /// - 1: Request (who has IP X? tell IP Y)
    /// - 2: Reply (IP X is at MAC Z)
    pub arp_operation: u8,

    /// ARP Sender Hardware Address (MAC).
    /// Format: "AA:BB:CC:DD:EE:FF". Empty = use system MAC.
    pub arp_sender_mac: String,

    /// ARP Sender Protocol Address (IP).
    /// Format: "192.168.1.1". Empty = use system IP.
    pub arp_sender_ip: String,

    /// ARP Target Hardware Address (MAC).
    /// For requests: typically "00:00:00:00:00:00" (unknown).
    /// Empty = broadcast "FF:FF:FF:FF:FF:FF".
    pub arp_target_mac: String,

    /// ARP Target Protocol Address (IP).
    /// The IP address being queried/announced.
    pub arp_target_ip: String,

    // =========================================================================
    // EDITOR STATE
    // =========================================================================

    /// Currently selected field in the editor
    pub current_field: PacketEditorField,

    /// Text buffer for the field being edited
    pub field_buffer: String,

    /// Whether the user is actively editing a field
    pub editing: bool,
}

impl PacketEditorState {
    pub fn new() -> Self {
        Self {
            // IP Header defaults
            source_ip: String::new(),                   // Empty = use real IP
            ip_id: rand::random(),                      // Random IP ID
            ip_flags: 0x02,                             // DF (Don't Fragment) set by default
            fragment_offset: 0,
            tos: 0,                                     // Default TOS
            ttl: 64,

            // Transport defaults
            source_port: rand::random::<u16>() | 0x8000,
            dest_port: 80,
            payload_hex: String::new(),

            // TCP defaults
            tcp_flags: 0x02,                            // SYN flag by default
            seq_num: rand::random(),
            ack_num: 0,
            window_size: 65535,
            urgent_ptr: 0,

            // TCP Options defaults (common SYN options)
            tcp_mss: 1460,                              // Standard Ethernet MSS
            tcp_window_scale: 7,                        // Window scale shift (common value)
            tcp_sack_permitted: true,                   // SACK enabled by default
            tcp_timestamps_enabled: true,               // Timestamps enabled
            tcp_tsval: 0,                               // Will be set when sending
            tcp_tsecr: 0,                               // Echo reply (0 for SYN)

            // ICMP defaults
            icmp_type: 8,                               // Echo Request
            icmp_code: 0,
            icmp_id: rand::random(),
            icmp_seq: 1,

            // DNS defaults
            dns_query_type: 1,                          // A record
            dns_domain: String::new(),

            // HTTP defaults
            http_method: "GET".to_string(),
            http_path: "/".to_string(),
            http_headers: String::new(),
            http_body: String::new(),
            http_cookies: String::new(),
            http_content_type: "application/json".to_string(),

            // SNMP defaults
            snmp_version: 2,                            // v2c
            snmp_community: "public".to_string(),

            // SSDP defaults
            ssdp_target: "ssdp:all".to_string(),

            // SMB defaults
            smb_version: 2,

            // LDAP defaults
            ldap_scope: 2,                              // Subtree
            ldap_base_dn: String::new(),

            // NetBIOS defaults
            netbios_name: String::new(),

            // DHCP defaults
            dhcp_type: 1,                               // Discover
            dhcp_client_mac: String::new(),

            // Kerberos defaults
            kerberos_realm: String::new(),
            kerberos_user: String::new(),

            // ARP defaults
            arp_operation: 1,                           // Request
            arp_sender_mac: String::new(),
            arp_sender_ip: String::new(),
            arp_target_mac: String::new(),
            arp_target_ip: String::new(),

            // Editor state
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
            // IP Header fields
            PacketEditorField::SourceIp => if self.source_ip.is_empty() { "(auto)".to_string() } else { self.source_ip.clone() },
            PacketEditorField::IpId => self.ip_id.to_string(),
            PacketEditorField::IpFlags => format!("0x{:02X}", self.ip_flags),
            PacketEditorField::FragmentOffset => self.fragment_offset.to_string(),
            PacketEditorField::Tos => self.tos.to_string(),
            PacketEditorField::Ttl => self.ttl.to_string(),
            // Transport fields
            PacketEditorField::SourcePort => self.source_port.to_string(),
            PacketEditorField::DestPort => self.dest_port.to_string(),
            PacketEditorField::Payload => self.payload_hex.clone(),
            // TCP fields
            PacketEditorField::TcpFlags => Self::format_tcp_flags(self.tcp_flags),
            PacketEditorField::SeqNum => self.seq_num.to_string(),
            PacketEditorField::AckNum => self.ack_num.to_string(),
            PacketEditorField::WindowSize => self.window_size.to_string(),
            PacketEditorField::UrgentPtr => self.urgent_ptr.to_string(),
            // TCP Options fields
            PacketEditorField::TcpMss => if self.tcp_mss == 0 { "off".to_string() } else { self.tcp_mss.to_string() },
            PacketEditorField::TcpWindowScale => if self.tcp_window_scale == 255 { "off".to_string() } else { self.tcp_window_scale.to_string() },
            PacketEditorField::TcpSackPermitted => if self.tcp_sack_permitted { "yes".to_string() } else { "no".to_string() },
            PacketEditorField::TcpTimestampsEnabled => if self.tcp_timestamps_enabled { "yes".to_string() } else { "no".to_string() },
            PacketEditorField::TcpTsVal => self.tcp_tsval.to_string(),
            PacketEditorField::TcpTsEcr => self.tcp_tsecr.to_string(),
            // ICMP fields
            PacketEditorField::IcmpType => self.icmp_type.to_string(),
            PacketEditorField::IcmpCode => self.icmp_code.to_string(),
            PacketEditorField::IcmpId => self.icmp_id.to_string(),
            PacketEditorField::IcmpSeq => self.icmp_seq.to_string(),
            // DNS fields
            PacketEditorField::DnsQueryType => self.dns_query_type.to_string(),
            PacketEditorField::DnsDomain => self.dns_domain.clone(),
            // HTTP fields
            PacketEditorField::HttpMethod => self.http_method.clone(),
            PacketEditorField::HttpPath => self.http_path.clone(),
            PacketEditorField::HttpHeaders => self.http_headers.clone(),
            // SNMP fields
            PacketEditorField::SnmpVersion => self.snmp_version.to_string(),
            PacketEditorField::SnmpCommunity => self.snmp_community.clone(),
            // SSDP fields
            PacketEditorField::SsdpTarget => self.ssdp_target.clone(),
            // SMB fields
            PacketEditorField::SmbVersion => self.smb_version.to_string(),
            // LDAP fields
            PacketEditorField::LdapScope => self.ldap_scope.to_string(),
            PacketEditorField::LdapBaseDn => self.ldap_base_dn.clone(),
            // NetBIOS fields
            PacketEditorField::NetBiosName => self.netbios_name.clone(),
            // DHCP fields
            PacketEditorField::DhcpType => self.dhcp_type.to_string(),
            PacketEditorField::DhcpClientMac => if self.dhcp_client_mac.is_empty() { "(auto)".to_string() } else { self.dhcp_client_mac.clone() },
            // Kerberos fields
            PacketEditorField::KerberosRealm => self.kerberos_realm.clone(),
            PacketEditorField::KerberosUser => self.kerberos_user.clone(),
            // ARP fields
            PacketEditorField::ArpOperation => self.arp_operation.to_string(),
            PacketEditorField::ArpSenderMac => if self.arp_sender_mac.is_empty() { "(auto)".to_string() } else { self.arp_sender_mac.clone() },
            PacketEditorField::ArpSenderIp => if self.arp_sender_ip.is_empty() { "(auto)".to_string() } else { self.arp_sender_ip.clone() },
            PacketEditorField::ArpTargetMac => if self.arp_target_mac.is_empty() { "FF:FF:FF:FF:FF:FF".to_string() } else { self.arp_target_mac.clone() },
            PacketEditorField::ArpTargetIp => self.arp_target_ip.clone(),
            // HTTP extended fields (context-dependent)
            PacketEditorField::HttpBody => self.http_body.clone(),
            PacketEditorField::HttpCookies => self.http_cookies.clone(),
            PacketEditorField::HttpContentType => self.http_content_type.clone(),
        }
    }

    /// Format TCP flags as a human-readable string (e.g., "SYN,ACK")
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

    /// Parse TCP flags from string format (e.g., "SYN,ACK" or "SA" or "18")
    fn parse_tcp_flags(s: &str) -> Option<u8> {
        // Try parsing as number first
        if let Ok(v) = s.parse::<u8>() {
            return Some(v);
        }
        // Parse as comma-separated or single-letter flags
        let s = s.to_uppercase();
        let mut flags: u8 = 0;
        for part in s.split(|c: char| c == ',' || c == '|' || c == ' ') {
            let part = part.trim();
            match part {
                "FIN" | "F" => flags |= 0x01,
                "SYN" | "S" => flags |= 0x02,
                "RST" | "R" => flags |= 0x04,
                "PSH" | "P" => flags |= 0x08,
                "ACK" | "A" => flags |= 0x10,
                "URG" | "U" => flags |= 0x20,
                "ECE" | "E" => flags |= 0x40,
                "CWR" | "C" | "W" => flags |= 0x80,
                "" => {}
                _ => return None,
            }
        }
        Some(flags)
    }

    pub fn apply_buffer(&mut self) -> bool {
        let value = self.field_buffer.clone();
        match self.current_field {
            // IP Header fields
            PacketEditorField::SourceIp => { self.source_ip = value; true }
            PacketEditorField::IpId => value.parse().map(|v| self.ip_id = v).is_ok(),
            PacketEditorField::IpFlags => {
                // Parse hex (0x02) or decimal (2)
                let v = if value.starts_with("0x") || value.starts_with("0X") {
                    u8::from_str_radix(&value[2..], 16).ok()
                } else {
                    value.parse().ok()
                };
                v.map(|f| self.ip_flags = f).is_some()
            }
            PacketEditorField::FragmentOffset => value.parse().map(|v| self.fragment_offset = v).is_ok(),
            PacketEditorField::Tos => value.parse().map(|v| self.tos = v).is_ok(),
            PacketEditorField::Ttl => value.parse().map(|v| self.ttl = v).is_ok(),
            // Transport fields
            PacketEditorField::SourcePort => value.parse().map(|v| self.source_port = v).is_ok(),
            PacketEditorField::DestPort => value.parse().map(|v| self.dest_port = v).is_ok(),
            PacketEditorField::Payload => {
                let cleaned: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if cleaned.len() % 2 == 0 {
                    self.payload_hex = cleaned;
                    true
                } else {
                    false
                }
            }
            // TCP fields
            PacketEditorField::TcpFlags => Self::parse_tcp_flags(&value).map(|v| self.tcp_flags = v).is_some(),
            PacketEditorField::SeqNum => value.parse().map(|v| self.seq_num = v).is_ok(),
            PacketEditorField::AckNum => value.parse().map(|v| self.ack_num = v).is_ok(),
            PacketEditorField::WindowSize => value.parse().map(|v| self.window_size = v).is_ok(),
            PacketEditorField::UrgentPtr => value.parse().map(|v| self.urgent_ptr = v).is_ok(),
            // TCP Options fields
            PacketEditorField::TcpMss => {
                let lower = value.to_lowercase();
                if lower == "off" || lower == "0" || lower.is_empty() {
                    self.tcp_mss = 0;
                    true
                } else {
                    value.parse().map(|v| self.tcp_mss = v).is_ok()
                }
            }
            PacketEditorField::TcpWindowScale => {
                let lower = value.to_lowercase();
                if lower == "off" || lower.is_empty() {
                    self.tcp_window_scale = 255;
                    true
                } else {
                    value.parse::<u8>().map(|v| {
                        if v <= 14 {
                            self.tcp_window_scale = v;
                        } else {
                            self.tcp_window_scale = 255; // Invalid, disable
                        }
                    }).is_ok()
                }
            }
            PacketEditorField::TcpSackPermitted => {
                let lower = value.to_lowercase();
                self.tcp_sack_permitted = matches!(lower.as_str(), "yes" | "y" | "1" | "true" | "on");
                true
            }
            PacketEditorField::TcpTimestampsEnabled => {
                let lower = value.to_lowercase();
                self.tcp_timestamps_enabled = matches!(lower.as_str(), "yes" | "y" | "1" | "true" | "on");
                true
            }
            PacketEditorField::TcpTsVal => value.parse().map(|v| self.tcp_tsval = v).is_ok(),
            PacketEditorField::TcpTsEcr => value.parse().map(|v| self.tcp_tsecr = v).is_ok(),
            // ICMP fields
            PacketEditorField::IcmpType => value.parse().map(|v| self.icmp_type = v).is_ok(),
            PacketEditorField::IcmpCode => value.parse().map(|v| self.icmp_code = v).is_ok(),
            PacketEditorField::IcmpId => value.parse().map(|v| self.icmp_id = v).is_ok(),
            PacketEditorField::IcmpSeq => value.parse().map(|v| self.icmp_seq = v).is_ok(),
            // DNS fields
            PacketEditorField::DnsQueryType => value.parse().map(|v| self.dns_query_type = v).is_ok(),
            PacketEditorField::DnsDomain => { self.dns_domain = value; true }
            // HTTP fields
            PacketEditorField::HttpMethod => { self.http_method = value; true }
            PacketEditorField::HttpPath => { self.http_path = value; true }
            PacketEditorField::HttpHeaders => { self.http_headers = value; true }
            // SNMP fields
            PacketEditorField::SnmpVersion => value.parse().map(|v| self.snmp_version = v).is_ok(),
            PacketEditorField::SnmpCommunity => { self.snmp_community = value; true }
            // SSDP fields
            PacketEditorField::SsdpTarget => { self.ssdp_target = value; true }
            // SMB fields
            PacketEditorField::SmbVersion => value.parse().map(|v| self.smb_version = v).is_ok(),
            // LDAP fields
            PacketEditorField::LdapScope => value.parse().map(|v| self.ldap_scope = v).is_ok(),
            PacketEditorField::LdapBaseDn => { self.ldap_base_dn = value; true }
            // NetBIOS fields
            PacketEditorField::NetBiosName => { self.netbios_name = value; true }
            // DHCP fields
            PacketEditorField::DhcpType => value.parse().map(|v| self.dhcp_type = v).is_ok(),
            PacketEditorField::DhcpClientMac => { self.dhcp_client_mac = value; true }
            // Kerberos fields
            PacketEditorField::KerberosRealm => { self.kerberos_realm = value; true }
            PacketEditorField::KerberosUser => { self.kerberos_user = value; true }
            // ARP fields
            PacketEditorField::ArpOperation => value.parse().map(|v| self.arp_operation = v).is_ok(),
            PacketEditorField::ArpSenderMac => { self.arp_sender_mac = value; true }
            PacketEditorField::ArpSenderIp => { self.arp_sender_ip = value; true }
            PacketEditorField::ArpTargetMac => { self.arp_target_mac = value; true }
            PacketEditorField::ArpTargetIp => { self.arp_target_ip = value; true }
            // HTTP extended fields
            PacketEditorField::HttpBody => { self.http_body = value; true }
            PacketEditorField::HttpCookies => { self.http_cookies = value; true }
            PacketEditorField::HttpContentType => { self.http_content_type = value; true }
        }
    }

    pub fn to_payload_bytes(&self) -> Option<Vec<u8>> {
        if self.payload_hex.is_empty() {
            return None;
        }
        hex::decode(&self.payload_hex).ok()
    }
}

// =============================================================================
// REPEATER (BurpSuite-like packet replay)
// =============================================================================

/// Protocol-specific request data for the repeater
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RepeaterRequest {
    /// HTTP request
    Http {
        method: String,
        path: String,
        headers: std::collections::HashMap<String, String>,
        body: Option<Vec<u8>>,
    },
    /// Raw TCP packet
    Tcp {
        flags: u8,
        seq_num: u32,
        ack_num: u32,
        window_size: u16,
        payload: Vec<u8>,
    },
    /// Raw UDP packet
    Udp {
        payload: Vec<u8>,
    },
    /// DNS query
    Dns {
        query_type: u16,
        domain: String,
    },
    /// ICMP packet
    Icmp {
        icmp_type: u8,
        icmp_code: u8,
        id: u16,
        seq: u16,
    },
    /// Raw bytes (any protocol)
    Raw {
        data: Vec<u8>,
    },
}

impl RepeaterRequest {
    /// Get the protocol name for this request
    pub fn protocol_name(&self) -> &'static str {
        match self {
            RepeaterRequest::Http { .. } => "HTTP",
            RepeaterRequest::Tcp { .. } => "TCP",
            RepeaterRequest::Udp { .. } => "UDP",
            RepeaterRequest::Dns { .. } => "DNS",
            RepeaterRequest::Icmp { .. } => "ICMP",
            RepeaterRequest::Raw { .. } => "RAW",
        }
    }

    /// Get a short summary of the request
    pub fn summary(&self) -> String {
        match self {
            RepeaterRequest::Http { method, path, .. } => format!("{} {}", method, path),
            RepeaterRequest::Tcp { flags, .. } => {
                let flag_names = format_tcp_flags_brief(*flags);
                format!("TCP {}", flag_names)
            }
            RepeaterRequest::Udp { payload } => format!("UDP {} bytes", payload.len()),
            RepeaterRequest::Dns { query_type, domain } => format!("DNS {} {}", query_type, domain),
            RepeaterRequest::Icmp { icmp_type, icmp_code, .. } => format!("ICMP {}/{}", icmp_type, icmp_code),
            RepeaterRequest::Raw { data } => format!("RAW {} bytes", data.len()),
        }
    }
}

/// Format TCP flags briefly for display
fn format_tcp_flags_brief(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x02 != 0 { parts.push("S"); }
    if flags & 0x10 != 0 { parts.push("A"); }
    if flags & 0x01 != 0 { parts.push("F"); }
    if flags & 0x04 != 0 { parts.push("R"); }
    if flags & 0x08 != 0 { parts.push("P"); }
    if flags & 0x20 != 0 { parts.push("U"); }
    if parts.is_empty() { "---".to_string() } else { parts.join("") }
}

/// Response status for repeater entries
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ResponseStatus {
    /// Response received successfully
    Success,
    /// Request timed out
    Timeout,
    /// Connection refused
    ConnectionRefused,
    /// Network unreachable
    NetworkUnreachable,
    /// Other error with message
    Error(String),
}

/// Parsed response data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ParsedResponse {
    /// HTTP response
    Http {
        status_code: u16,
        status_text: String,
        headers: std::collections::HashMap<String, String>,
        body: Option<Vec<u8>>,
    },
    /// DNS response
    Dns {
        answers: Vec<String>,
    },
    /// Raw response (TCP, UDP, etc.)
    Raw {
        data: Vec<u8>,
    },
}

/// Response from a repeater request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepeaterResponse {
    /// When the response was received
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
    /// Response status
    pub status: ResponseStatus,
    /// Raw response data
    pub raw_data: Vec<u8>,
    /// Parsed response (if applicable)
    pub parsed: Option<ParsedResponse>,
}

/// A single repeater entry (request + optional response)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepeaterEntry {
    /// Unique identifier
    pub id: uuid::Uuid,
    /// User-assigned name or auto-generated
    pub name: String,
    /// When the entry was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Protocol used
    pub protocol: Protocol,
    /// Target host (IP or hostname)
    pub target_host: String,
    /// Target port
    pub target_port: u16,
    /// Request data
    pub request: RepeaterRequest,
    /// Response (if received)
    pub response: Option<RepeaterResponse>,
    /// Number of times this request has been sent
    pub send_count: u32,
}

impl RepeaterEntry {
    /// Create a new repeater entry
    pub fn new(
        name: String,
        protocol: Protocol,
        target_host: String,
        target_port: u16,
        request: RepeaterRequest,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name,
            timestamp: chrono::Utc::now(),
            protocol,
            target_host,
            target_port,
            request,
            response: None,
            send_count: 0,
        }
    }

    /// Get a display string for the entry
    pub fn display_name(&self) -> String {
        if self.name.is_empty() {
            format!("{} {}:{}", self.request.protocol_name(), self.target_host, self.target_port)
        } else {
            self.name.clone()
        }
    }

    /// Get short summary for list view
    pub fn short_summary(&self) -> String {
        format!("{} → {}:{}", self.request.summary(), self.target_host, self.target_port)
    }
}

/// Which pane is focused in the Repeater view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RepeaterPane {
    /// Entry list on the left
    #[default]
    List,
    /// Request view in the middle
    Request,
    /// Response view on the right
    Response,
}

/// Repeater persistence functions
impl RepeaterEntry {
    /// Get the default repeater file path
    pub fn default_file_path() -> std::path::PathBuf {
        let config_dir = if cfg!(windows) {
            std::env::var("APPDATA")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
        } else {
            std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".config"))
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
        };
        config_dir.join("noircast").join("repeater.json")
    }

    /// Save repeater entries to a file
    pub fn save_entries(entries: &[RepeaterEntry], path: Option<&std::path::Path>) -> anyhow::Result<()> {
        let path = path.map(|p| p.to_path_buf()).unwrap_or_else(Self::default_file_path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(entries)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Load repeater entries from a file
    pub fn load_entries(path: Option<&std::path::Path>) -> anyhow::Result<Vec<RepeaterEntry>> {
        let path = path.map(|p| p.to_path_buf()).unwrap_or_else(Self::default_file_path);

        if !path.exists() {
            return Ok(Vec::new());
        }

        let json = std::fs::read_to_string(&path)?;
        let entries: Vec<RepeaterEntry> = serde_json::from_str(&json)?;
        Ok(entries)
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
    /// Filter for packet editor field search
    pub packet_editor_filter: String,

    // Protocol picker popup
    pub show_protocol_picker: bool,
    pub protocol_picker_index: usize,
    pub protocol_picker_filter: String,

    // Template picker popup
    pub show_template_picker: bool,
    pub template_picker_index: usize,
    pub template_picker_filter: String,

    // Theme picker popup
    pub show_theme_picker: bool,
    pub theme_picker_index: usize,
    pub theme_picker_filter: String,
    pub current_theme: crate::ui::theme::ThemeType,

    // Repeater (BurpSuite-like packet replay)
    pub show_repeater: bool,
    pub repeater_entries: Vec<RepeaterEntry>,
    pub repeater_selected: usize,
    pub repeater_pane_focus: RepeaterPane,

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
    pub http_body: String,        // Request body (POST, PUT, PATCH)
    pub http_cookies: String,     // Cookies (key=value pairs)
    pub http_content_type: String, // Content-Type header

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
    pub flood_count: Arc<AtomicU64>,  // atomic counter for multithreaded flood
    pub flood_start: Option<std::time::Instant>,
    pub flood_stop: Arc<AtomicBool>,  // signal to stop flood workers
    pub flood_workers: usize,         // number of concurrent flood workers

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
            packet_editor_filter: String::new(),

            show_protocol_picker: false,
            protocol_picker_index: 0,
            protocol_picker_filter: String::new(),

            show_template_picker: false,
            template_picker_index: 0,
            template_picker_filter: String::new(),

            show_theme_picker: false,
            theme_picker_index: 0,
            theme_picker_filter: String::new(),
            current_theme: crate::ui::theme::ThemeType::default(),

            // Repeater - load saved entries
            show_repeater: false,
            repeater_entries: RepeaterEntry::load_entries(None).unwrap_or_default(),
            repeater_selected: 0,
            repeater_pane_focus: RepeaterPane::default(),

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
            http_body: String::new(),
            http_cookies: String::new(),
            http_content_type: "application/json".to_string(),

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
            flood_count: Arc::new(AtomicU64::new(0)),
            flood_start: None,
            flood_stop: Arc::new(AtomicBool::new(false)),
            flood_workers: 8,  // default 8 concurrent workers

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
        let mut sender = PacketSender::new(
            self.args.workers,
            self.args.batch_size,
            self.args.timeout,
        ).await?;
        // Share the stats Arc so sender updates are visible in the UI
        sender.set_stats(self.stats.clone());
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

    /// Add current packet configuration to the repeater
    pub fn add_current_to_repeater(&mut self) {
        // Determine target host and port
        let target_host = if self.target.host.is_empty() {
            "localhost".to_string()
        } else {
            self.target.host.clone()
        };
        let target_port = self.target.ports.first().copied().unwrap_or(80);

        // Create protocol-specific request
        let request = match self.selected_protocol {
            Protocol::Http | Protocol::Https => {
                let mut headers = std::collections::HashMap::new();
                headers.insert("Host".to_string(), format!("{}:{}", target_host, target_port));
                headers.insert("User-Agent".to_string(), "NoirCast/0.1.0".to_string());
                RepeaterRequest::Http {
                    method: self.http_method.clone(),
                    path: self.http_path.clone(),
                    headers,
                    body: self.custom_payload.clone(),
                }
            }
            Protocol::Tcp => {
                RepeaterRequest::Tcp {
                    flags: self.flags_bitmask(),
                    seq_num: self.packet_editor.seq_num,
                    ack_num: self.packet_editor.ack_num,
                    window_size: self.packet_editor.window_size,
                    payload: self.custom_payload.clone().unwrap_or_default(),
                }
            }
            Protocol::Udp | Protocol::Ntp | Protocol::Snmp | Protocol::Ssdp | Protocol::NetBios | Protocol::Dhcp => {
                RepeaterRequest::Udp {
                    payload: self.custom_payload.clone().unwrap_or_default(),
                }
            }
            Protocol::Dns => {
                RepeaterRequest::Dns {
                    query_type: self.dns_query_type,
                    domain: if self.dns_domain.is_empty() {
                        target_host.clone()
                    } else {
                        self.dns_domain.clone()
                    },
                }
            }
            Protocol::Icmp => {
                RepeaterRequest::Icmp {
                    icmp_type: self.icmp_type,
                    icmp_code: self.icmp_code,
                    id: self.icmp_id,
                    seq: self.icmp_seq,
                }
            }
            Protocol::Raw | Protocol::Smb | Protocol::Ldap | Protocol::Kerberos | Protocol::Arp => {
                RepeaterRequest::Raw {
                    data: self.custom_payload.clone().unwrap_or_default(),
                }
            }
        };

        let entry = RepeaterEntry::new(
            String::new(), // Auto-generate name
            self.selected_protocol,
            target_host,
            target_port,
            request,
        );

        self.repeater_entries.push(entry);

        // Auto-save entries
        if let Err(e) = RepeaterEntry::save_entries(&self.repeater_entries, None) {
            self.log_warning(format!("Failed to save repeater entries: {}", e));
        }
    }

    /// Apply packet editor changes to main App state.
    /// Called when closing the packet editor to preserve user's edits.
    pub fn apply_packet_editor_changes(&mut self) {
        let editor = &self.packet_editor;

        // HTTP fields
        self.http_method = editor.http_method.clone();
        self.http_path = editor.http_path.clone();
        self.http_body = editor.http_body.clone();
        self.http_cookies = editor.http_cookies.clone();
        self.http_content_type = editor.http_content_type.clone();

        // DNS fields
        self.dns_query_type = editor.dns_query_type;
        self.dns_domain = editor.dns_domain.clone();

        // ICMP fields
        self.icmp_type = editor.icmp_type;
        self.icmp_code = editor.icmp_code;
        self.icmp_id = editor.icmp_id;
        self.icmp_seq = editor.icmp_seq;

        // SNMP fields
        self.snmp_version = editor.snmp_version;
        self.snmp_community = editor.snmp_community.clone();

        // SMB fields
        self.smb_version = editor.smb_version;

        // LDAP fields
        self.ldap_scope = editor.ldap_scope;

        // DHCP fields
        self.dhcp_type = editor.dhcp_type;

        // Note: Kerberos editor has realm/user strings, App has kerberos_type u8
        // These don't directly map, so kerberos is edited via command mode

        // ARP fields
        self.arp_operation = editor.arp_operation;

        // Target port if specified
        if editor.dest_port > 0 {
            self.target.ports = vec![editor.dest_port];
        }

        self.log_debug("Packet editor changes applied");
    }

    /// Apply a packet template to the current configuration
    pub fn apply_template(&mut self, template: PacketTemplate) {
        // Set protocol
        self.selected_protocol = template.protocol();

        // Set default port if not custom
        if template != PacketTemplate::Custom {
            let port = template.default_port();
            if port > 0 {
                self.target.ports = vec![port];
            }
        }

        // Set TCP flags
        self.selected_flags = template.tcp_flags();

        // Set protocol-specific fields
        match template {
            PacketTemplate::HttpGet => {
                self.http_method = "GET".to_string();
                self.http_path = "/".to_string();
            }
            PacketTemplate::HttpHead => {
                self.http_method = "HEAD".to_string();
                self.http_path = "/".to_string();
            }
            PacketTemplate::HttpPost => {
                self.http_method = "POST".to_string();
                self.http_path = "/".to_string();
            }
            PacketTemplate::HttpOptions => {
                self.http_method = "OPTIONS".to_string();
                self.http_path = "*".to_string();
            }
            PacketTemplate::DnsQueryA => {
                self.dns_query_type = 1;
            }
            PacketTemplate::DnsQueryAAAA => {
                self.dns_query_type = 28;
            }
            PacketTemplate::DnsQueryMX => {
                self.dns_query_type = 15;
            }
            PacketTemplate::DnsQueryTXT => {
                self.dns_query_type = 16;
            }
            PacketTemplate::IcmpPing => {
                self.icmp_type = 8; // Echo Request
                self.icmp_code = 0;
            }
            _ => {}
        }

        // Sync packet editor with new values
        self.packet_editor.http_method = self.http_method.clone();
        self.packet_editor.http_path = self.http_path.clone();
        self.packet_editor.dns_query_type = self.dns_query_type;
        self.packet_editor.icmp_type = self.icmp_type;
        self.packet_editor.icmp_code = self.icmp_code;
        if !self.target.ports.is_empty() {
            self.packet_editor.dest_port = self.target.ports[0];
        }

        self.log_success(format!("Applied template: {}", template.name()));
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
        self.flood_count.store(0, Ordering::SeqCst);
        self.flood_stop.store(false, Ordering::SeqCst);
        self.flood_start = Some(std::time::Instant::now());
        self.log_warning(format!("FLOOD MODE STARTED ({} workers) - Press 'q' to stop", self.flood_workers));
    }

    /// Stop flood mode
    pub fn stop_flood(&mut self) {
        if self.flood_mode {
            self.flood_stop.store(true, Ordering::SeqCst);
            self.flood_mode = false;
            let count = self.flood_count.load(Ordering::SeqCst);
            let duration = self.flood_start
                .map(|s| s.elapsed().as_secs_f64())
                .unwrap_or(0.0);
            let rate = if duration > 0.0 {
                count as f64 / duration
            } else {
                0.0
            };
            self.log_success(format!(
                "FLOOD STOPPED: {} packets in {:.2}s ({:.0} pps)",
                count, duration, rate
            ));
            self.flood_start = None;
        }
    }

    /// Get flood stats for display
    pub fn get_flood_stats(&self) -> (u64, f64, f64) {
        let count = self.flood_count.load(Ordering::Relaxed);
        let duration = self.flood_start
            .map(|s| s.elapsed().as_secs_f64())
            .unwrap_or(0.0);
        let rate = if duration > 0.0 {
            count as f64 / duration
        } else {
            0.0
        };
        (count, duration, rate)
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
        // Test navigation uses protocol-specific fields
        // For TCP: SourceIp is first, then IpId, etc.
        let tcp_fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        assert_eq!(tcp_fields[0].next_for_context(Protocol::Tcp, "GET"), tcp_fields[1]);
        assert_eq!(tcp_fields[1].prev_for_context(Protocol::Tcp, "GET"), tcp_fields[0]);

        // Last field should wrap to first
        let last = tcp_fields.last().unwrap();
        assert_eq!(last.next_for_context(Protocol::Tcp, "GET"), tcp_fields[0]);
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
        // TCP should have IP header + TCP fields
        let tcp_fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        assert!(tcp_fields.len() >= 10);  // IP fields + TCP fields
        assert!(tcp_fields.contains(&PacketEditorField::SourceIp));  // IP header
        assert!(tcp_fields.contains(&PacketEditorField::TcpFlags));  // TCP flags
        assert!(tcp_fields.contains(&PacketEditorField::SeqNum));
        assert!(tcp_fields.contains(&PacketEditorField::WindowSize));

        // UDP should have IP header + UDP fields
        let udp_fields = PacketEditorField::fields_for_protocol(Protocol::Udp);
        assert!(udp_fields.len() >= 6);
        assert!(udp_fields.contains(&PacketEditorField::SourceIp));
        assert!(!udp_fields.contains(&PacketEditorField::SeqNum));  // No TCP fields

        // ICMP should have ICMP-specific fields
        let icmp_fields = PacketEditorField::fields_for_protocol(Protocol::Icmp);
        assert!(icmp_fields.contains(&PacketEditorField::SourceIp));
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

        // ARP should have L2 fields
        let arp_fields = PacketEditorField::fields_for_protocol(Protocol::Arp);
        assert!(arp_fields.contains(&PacketEditorField::ArpOperation));
        assert!(arp_fields.contains(&PacketEditorField::ArpSenderMac));
        assert!(arp_fields.contains(&PacketEditorField::ArpTargetMac));
    }

    #[test]
    fn test_packet_editor_protocol_navigation() {
        // Test navigation within TCP protocol
        let first = PacketEditorField::fields_for_protocol(Protocol::Tcp)[0];
        let second = first.next_for_context(Protocol::Tcp, "GET");
        assert_ne!(first, second);

        // Navigation should wrap around
        let tcp_fields = PacketEditorField::fields_for_protocol(Protocol::Tcp);
        let last = tcp_fields[tcp_fields.len() - 1];
        let wrapped = last.next_for_context(Protocol::Tcp, "GET");
        assert_eq!(wrapped, tcp_fields[0]);

        // Test prev navigation
        let first = tcp_fields[0];
        let prev_from_first = first.prev_for_context(Protocol::Tcp, "GET");
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
            PacketEditorField::SourceIp, PacketEditorField::IpId,
            PacketEditorField::IpFlags, PacketEditorField::Tos,
            PacketEditorField::SourcePort, PacketEditorField::DestPort,
            PacketEditorField::Ttl, PacketEditorField::Payload,
            PacketEditorField::TcpFlags, PacketEditorField::SeqNum,
            PacketEditorField::AckNum, PacketEditorField::WindowSize,
            PacketEditorField::IcmpType, PacketEditorField::IcmpCode,
            PacketEditorField::IcmpId, PacketEditorField::IcmpSeq,
            PacketEditorField::DnsQueryType, PacketEditorField::DnsDomain,
            PacketEditorField::HttpMethod, PacketEditorField::HttpPath,
            PacketEditorField::HttpHeaders, PacketEditorField::ArpOperation,
            PacketEditorField::ArpSenderMac, PacketEditorField::ArpTargetMac,
        ];

        for field in &all_fields {
            assert!(!field.label().is_empty(), "Field {:?} has empty label", field);
        }
    }

    #[test]
    fn test_tcp_flags_parsing() {
        // Test parsing TCP flags from various formats

        // Numeric format
        assert_eq!(PacketEditorState::parse_tcp_flags("2"), Some(0x02)); // SYN
        assert_eq!(PacketEditorState::parse_tcp_flags("18"), Some(0x12)); // SYN+ACK

        // Full name format
        assert_eq!(PacketEditorState::parse_tcp_flags("SYN"), Some(0x02));
        assert_eq!(PacketEditorState::parse_tcp_flags("SYN,ACK"), Some(0x12));
        assert_eq!(PacketEditorState::parse_tcp_flags("FIN,PSH,URG"), Some(0x29));

        // Single letter format
        assert_eq!(PacketEditorState::parse_tcp_flags("S"), Some(0x02));
        assert_eq!(PacketEditorState::parse_tcp_flags("S,A"), Some(0x12));

        // All flags
        let all_flags = PacketEditorState::parse_tcp_flags("FIN,SYN,RST,PSH,ACK,URG,ECE,CWR");
        assert_eq!(all_flags, Some(0xFF));

        // Invalid input
        assert_eq!(PacketEditorState::parse_tcp_flags("INVALID"), None);
    }

    #[test]
    fn test_tcp_flags_formatting() {
        assert_eq!(PacketEditorState::format_tcp_flags(0x00), "NONE");
        assert_eq!(PacketEditorState::format_tcp_flags(0x02), "SYN");
        assert_eq!(PacketEditorState::format_tcp_flags(0x12), "SYN,ACK");
        assert_eq!(PacketEditorState::format_tcp_flags(0x29), "FIN,PSH,URG");
    }

    #[test]
    fn test_ip_header_fields() {
        let mut state = PacketEditorState::new();

        // Test IP ID field
        state.current_field = PacketEditorField::IpId;
        state.field_buffer = "12345".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.ip_id, 12345);

        // Test IP Flags field (hex format)
        state.current_field = PacketEditorField::IpFlags;
        state.field_buffer = "0x02".to_string(); // DF flag
        assert!(state.apply_buffer());
        assert_eq!(state.ip_flags, 0x02);

        // Test IP Flags field (decimal format)
        state.field_buffer = "3".to_string(); // DF + MF
        assert!(state.apply_buffer());
        assert_eq!(state.ip_flags, 3);

        // Test TOS/DSCP field
        state.current_field = PacketEditorField::Tos;
        state.field_buffer = "32".to_string(); // DSCP 8
        assert!(state.apply_buffer());
        assert_eq!(state.tos, 32);

        // Test Fragment Offset
        state.current_field = PacketEditorField::FragmentOffset;
        state.field_buffer = "185".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.fragment_offset, 185);

        // Test Source IP
        state.current_field = PacketEditorField::SourceIp;
        state.field_buffer = "192.168.1.100".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.source_ip, "192.168.1.100");
    }

    #[test]
    fn test_tcp_flags_apply_buffer() {
        let mut state = PacketEditorState::new();

        // Test TCP flags with name format
        state.current_field = PacketEditorField::TcpFlags;
        state.field_buffer = "SYN,ACK".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.tcp_flags, 0x12);

        // Test TCP flags with numeric format
        state.field_buffer = "2".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.tcp_flags, 0x02);

        // Test urgent pointer
        state.current_field = PacketEditorField::UrgentPtr;
        state.field_buffer = "100".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.urgent_ptr, 100);
    }

    #[test]
    fn test_arp_fields() {
        let mut state = PacketEditorState::new();

        // Test ARP Operation
        state.current_field = PacketEditorField::ArpOperation;
        state.field_buffer = "2".to_string(); // Reply
        assert!(state.apply_buffer());
        assert_eq!(state.arp_operation, 2);

        // Test Sender MAC
        state.current_field = PacketEditorField::ArpSenderMac;
        state.field_buffer = "AA:BB:CC:DD:EE:FF".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.arp_sender_mac, "AA:BB:CC:DD:EE:FF");

        // Test Sender IP
        state.current_field = PacketEditorField::ArpSenderIp;
        state.field_buffer = "192.168.1.1".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.arp_sender_ip, "192.168.1.1");

        // Test Target MAC
        state.current_field = PacketEditorField::ArpTargetMac;
        state.field_buffer = "00:00:00:00:00:00".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.arp_target_mac, "00:00:00:00:00:00");
    }

    #[test]
    fn test_dhcp_fields() {
        let mut state = PacketEditorState::new();

        // Test DHCP type
        state.current_field = PacketEditorField::DhcpType;
        state.field_buffer = "2".to_string(); // Offer
        assert!(state.apply_buffer());
        assert_eq!(state.dhcp_type, 2);

        // Test Client MAC
        state.current_field = PacketEditorField::DhcpClientMac;
        state.field_buffer = "11:22:33:44:55:66".to_string();
        assert!(state.apply_buffer());
        assert_eq!(state.dhcp_client_mac, "11:22:33:44:55:66");
    }

    #[test]
    fn test_packet_editor_default_values() {
        let state = PacketEditorState::new();

        // IP Header defaults
        assert_eq!(state.ip_flags, 0x02);  // DF set by default
        assert_eq!(state.fragment_offset, 0);
        assert_eq!(state.tos, 0);
        assert_eq!(state.ttl, 64);
        assert!(state.source_ip.is_empty());  // Auto = empty

        // TCP defaults
        assert_eq!(state.tcp_flags, 0x02);  // SYN by default
        assert_eq!(state.window_size, 65535);
        assert_eq!(state.urgent_ptr, 0);

        // ARP defaults
        assert_eq!(state.arp_operation, 1);  // Request
        assert!(state.arp_sender_mac.is_empty());  // Auto
        assert!(state.arp_target_mac.is_empty());  // Broadcast default
    }

    #[test]
    fn test_get_current_value_auto_fields() {
        let state = PacketEditorState::new();

        // Empty source IP should show "(auto)"
        assert!(state.source_ip.is_empty());

        // Test TCP flags display
        let flags_display = PacketEditorState::format_tcp_flags(state.tcp_flags);
        assert_eq!(flags_display, "SYN");
    }

    // ==========================================================================
    // REPEATER TESTS
    // ==========================================================================

    #[test]
    fn test_repeater_entry_creation() {
        let request = RepeaterRequest::Http {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers: std::collections::HashMap::new(),
            body: None,
        };

        let entry = RepeaterEntry::new(
            "Test Entry".to_string(),
            Protocol::Http,
            "example.com".to_string(),
            80,
            request,
        );

        assert_eq!(entry.name, "Test Entry");
        assert_eq!(entry.protocol, Protocol::Http);
        assert_eq!(entry.target_host, "example.com");
        assert_eq!(entry.target_port, 80);
        assert!(entry.response.is_none());
        assert_eq!(entry.send_count, 0);
        assert!(!entry.id.is_nil());
    }

    #[test]
    fn test_repeater_request_protocol_name() {
        let http = RepeaterRequest::Http {
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: std::collections::HashMap::new(),
            body: Some(vec![1, 2, 3]),
        };
        assert_eq!(http.protocol_name(), "HTTP");

        let tcp = RepeaterRequest::Tcp {
            flags: 0x02,
            seq_num: 1000,
            ack_num: 0,
            window_size: 65535,
            payload: vec![],
        };
        assert_eq!(tcp.protocol_name(), "TCP");

        let dns = RepeaterRequest::Dns {
            query_type: 1,
            domain: "example.com".to_string(),
        };
        assert_eq!(dns.protocol_name(), "DNS");

        let icmp = RepeaterRequest::Icmp {
            icmp_type: 8,
            icmp_code: 0,
            id: 1234,
            seq: 1,
        };
        assert_eq!(icmp.protocol_name(), "ICMP");

        let raw = RepeaterRequest::Raw {
            data: vec![0xFF; 100],
        };
        assert_eq!(raw.protocol_name(), "RAW");
    }

    #[test]
    fn test_repeater_request_summary() {
        let http = RepeaterRequest::Http {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            headers: std::collections::HashMap::new(),
            body: None,
        };
        assert_eq!(http.summary(), "GET /api/users");

        let tcp = RepeaterRequest::Tcp {
            flags: 0x02, // SYN
            seq_num: 0,
            ack_num: 0,
            window_size: 65535,
            payload: vec![],
        };
        assert!(tcp.summary().contains("TCP"));
        assert!(tcp.summary().contains("S")); // SYN flag

        let dns = RepeaterRequest::Dns {
            query_type: 1,
            domain: "test.com".to_string(),
        };
        assert_eq!(dns.summary(), "DNS 1 test.com");

        let udp = RepeaterRequest::Udp {
            payload: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(udp.summary(), "UDP 5 bytes");

        let raw = RepeaterRequest::Raw {
            data: vec![0; 50],
        };
        assert_eq!(raw.summary(), "RAW 50 bytes");
    }

    #[test]
    fn test_repeater_response_status() {
        // Test all response status variants
        let success = ResponseStatus::Success;
        let timeout = ResponseStatus::Timeout;
        let error = ResponseStatus::Error("Connection refused".to_string());

        // Basic pattern matching should work
        match success {
            ResponseStatus::Success => {}
            _ => panic!("Expected Success"),
        }

        match timeout {
            ResponseStatus::Timeout => {}
            _ => panic!("Expected Timeout"),
        }

        match error {
            ResponseStatus::Error(msg) => assert!(msg.contains("refused")),
            _ => panic!("Expected Error"),
        }
    }

    #[test]
    fn test_repeater_tcp_flags_brief() {
        // SYN only
        let syn = format_tcp_flags_brief(0x02);
        assert!(syn.contains("S"));
        assert!(!syn.contains("A"));

        // SYN+ACK
        let synack = format_tcp_flags_brief(0x12);
        assert!(synack.contains("S"));
        assert!(synack.contains("A"));

        // FIN+ACK
        let finack = format_tcp_flags_brief(0x11);
        assert!(finack.contains("F"));
        assert!(finack.contains("A"));

        // RST
        let rst = format_tcp_flags_brief(0x04);
        assert!(rst.contains("R"));

        // PSH+ACK
        let pshack = format_tcp_flags_brief(0x18);
        assert!(pshack.contains("P"));
        assert!(pshack.contains("A"));
    }

    #[test]
    fn test_repeater_entry_increment_send_count() {
        let mut entry = RepeaterEntry::new(
            "Count Test".to_string(),
            Protocol::Tcp,
            "127.0.0.1".to_string(),
            22,
            RepeaterRequest::Tcp {
                flags: 0x02,
                seq_num: 0,
                ack_num: 0,
                window_size: 65535,
                payload: vec![],
            },
        );

        assert_eq!(entry.send_count, 0);
        entry.send_count += 1;
        assert_eq!(entry.send_count, 1);
        entry.send_count += 1;
        assert_eq!(entry.send_count, 2);
    }
}
