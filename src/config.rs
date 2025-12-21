//! Configuration management for NoirCast

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub tui: TuiConfig,
    pub keybindings: KeyBindings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            tui: TuiConfig::default(),
            keybindings: KeyBindings::default(),
        }
    }
}

/// Network-related configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub default_timeout_ms: u64,
    pub max_retries: u32,
    pub batch_size: usize,
    pub worker_threads: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: 3000,
            max_retries: 3,
            batch_size: 1000,
            worker_threads: 4,
        }
    }
}

/// TUI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuiConfig {
    pub show_help_on_start: bool,
    pub refresh_rate_ms: u64,
    pub colors: ColorScheme,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            show_help_on_start: false,
            refresh_rate_ms: 100,
            colors: ColorScheme::default(),
        }
    }
}

/// Color scheme for the TUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    pub background: String,
    pub foreground: String,
    pub highlight: String,
    pub success: String,
    pub error: String,
    pub warning: String,
    pub info: String,
    pub border: String,
    pub selection: String,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            background: "#1e1e2e".to_string(),
            foreground: "#cdd6f4".to_string(),
            highlight: "#89b4fa".to_string(),
            success: "#a6e3a1".to_string(),
            error: "#f38ba8".to_string(),
            warning: "#fab387".to_string(),
            info: "#89dceb".to_string(),
            border: "#6c7086".to_string(),
            selection: "#45475a".to_string(),
        }
    }
}

/// Vim-style keybindings configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBindings {
    pub global: HashMap<String, String>,
    pub normal: HashMap<String, String>,
    pub insert: HashMap<String, String>,
    pub command: HashMap<String, String>,
}

impl Default for KeyBindings {
    fn default() -> Self {
        let mut global = HashMap::new();
        global.insert("q".to_string(), "quit".to_string());
        global.insert("?".to_string(), "help".to_string());
        global.insert("Esc".to_string(), "cancel".to_string());

        let mut normal = HashMap::new();
        normal.insert("h".to_string(), "left".to_string());
        normal.insert("j".to_string(), "down".to_string());
        normal.insert("k".to_string(), "up".to_string());
        normal.insert("l".to_string(), "right".to_string());
        normal.insert("gg".to_string(), "top".to_string());
        normal.insert("G".to_string(), "bottom".to_string());
        normal.insert("Ctrl+d".to_string(), "half_page_down".to_string());
        normal.insert("Ctrl+u".to_string(), "half_page_up".to_string());
        normal.insert("i".to_string(), "insert_mode".to_string());
        normal.insert(":".to_string(), "command_mode".to_string());
        normal.insert("/".to_string(), "search".to_string());
        normal.insert("n".to_string(), "next_search".to_string());
        normal.insert("N".to_string(), "prev_search".to_string());
        normal.insert("Tab".to_string(), "next_pane".to_string());
        normal.insert("Shift+Tab".to_string(), "prev_pane".to_string());
        normal.insert("Enter".to_string(), "select".to_string());
        normal.insert("Space".to_string(), "toggle".to_string());

        let mut insert = HashMap::new();
        insert.insert("Esc".to_string(), "normal_mode".to_string());
        insert.insert("Enter".to_string(), "confirm".to_string());
        insert.insert("Backspace".to_string(), "delete_char".to_string());
        insert.insert("Ctrl+w".to_string(), "delete_word".to_string());
        insert.insert("Ctrl+u".to_string(), "clear_line".to_string());

        let mut command = HashMap::new();
        command.insert("Esc".to_string(), "normal_mode".to_string());
        command.insert("Enter".to_string(), "execute".to_string());
        command.insert("Tab".to_string(), "autocomplete".to_string());

        Self {
            global,
            normal,
            insert,
            command,
        }
    }
}

/// Packet preset configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketPreset {
    pub name: String,
    pub description: String,
    pub protocol: Protocol,
    pub flags: Vec<TcpFlag>,
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Http,
    Https,
    Dns,
    Ntp,
    Snmp,
    Ssdp,
    Smb,
    Ldap,
    NetBios,
    Dhcp,
    Kerberos,
    Arp,
    Raw,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Https => write!(f, "HTTPS"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Ntp => write!(f, "NTP"),
            Protocol::Snmp => write!(f, "SNMP"),
            Protocol::Ssdp => write!(f, "SSDP"),
            Protocol::Smb => write!(f, "SMB"),
            Protocol::Ldap => write!(f, "LDAP"),
            Protocol::NetBios => write!(f, "NetBIOS"),
            Protocol::Dhcp => write!(f, "DHCP"),
            Protocol::Kerberos => write!(f, "Kerberos"),
            Protocol::Arp => write!(f, "ARP"),
            Protocol::Raw => write!(f, "RAW"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpFlag {
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
    Urg,
    Ece,
    Cwr,
}

impl TcpFlag {
    pub fn all() -> Vec<TcpFlag> {
        vec![
            TcpFlag::Syn,
            TcpFlag::Ack,
            TcpFlag::Fin,
            TcpFlag::Rst,
            TcpFlag::Psh,
            TcpFlag::Urg,
            TcpFlag::Ece,
            TcpFlag::Cwr,
        ]
    }

    pub fn to_bit(&self) -> u8 {
        match self {
            TcpFlag::Fin => 0x01,
            TcpFlag::Syn => 0x02,
            TcpFlag::Rst => 0x04,
            TcpFlag::Psh => 0x08,
            TcpFlag::Ack => 0x10,
            TcpFlag::Urg => 0x20,
            TcpFlag::Ece => 0x40,
            TcpFlag::Cwr => 0x80,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            TcpFlag::Syn => "SYN",
            TcpFlag::Ack => "ACK",
            TcpFlag::Fin => "FIN",
            TcpFlag::Rst => "RST",
            TcpFlag::Psh => "PSH",
            TcpFlag::Urg => "URG",
            TcpFlag::Ece => "ECE",
            TcpFlag::Cwr => "CWR",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            TcpFlag::Syn => "Synchronize - Initiate connection",
            TcpFlag::Ack => "Acknowledge - Confirm receipt",
            TcpFlag::Fin => "Finish - Close connection gracefully",
            TcpFlag::Rst => "Reset - Abort connection immediately",
            TcpFlag::Psh => "Push - Send data immediately",
            TcpFlag::Urg => "Urgent - High priority data",
            TcpFlag::Ece => "ECN Echo - Congestion notification",
            TcpFlag::Cwr => "Congestion Window Reduced",
        }
    }
}

impl std::fmt::Display for TcpFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Scan type presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    SynScan,
    ConnectScan,
    FinScan,
    NullScan,
    XmasScan,
    AckScan,
    WindowScan,
    UdpScan,
    Custom,
}

impl ScanType {
    pub fn all() -> Vec<ScanType> {
        vec![
            ScanType::SynScan,
            ScanType::ConnectScan,
            ScanType::FinScan,
            ScanType::NullScan,
            ScanType::XmasScan,
            ScanType::AckScan,
            ScanType::WindowScan,
            ScanType::UdpScan,
            ScanType::Custom,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            ScanType::SynScan => "SYN Scan",
            ScanType::ConnectScan => "Connect Scan",
            ScanType::FinScan => "FIN Scan",
            ScanType::NullScan => "NULL Scan",
            ScanType::XmasScan => "X-Mas Scan",
            ScanType::AckScan => "ACK Scan",
            ScanType::WindowScan => "Window Scan",
            ScanType::UdpScan => "UDP Scan",
            ScanType::Custom => "Custom",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ScanType::SynScan => "Half-open scan, sends SYN packets only",
            ScanType::ConnectScan => "Full TCP connect, completes handshake",
            ScanType::FinScan => "Sends FIN to detect closed ports (RST response)",
            ScanType::NullScan => "No flags set, relies on RFC 793 behavior",
            ScanType::XmasScan => "FIN+PSH+URG flags, 'lit up like a Christmas tree'",
            ScanType::AckScan => "ACK flag only, detects firewall rules",
            ScanType::WindowScan => "Like ACK scan but examines window field",
            ScanType::UdpScan => "UDP packets, ICMP unreachable means closed",
            ScanType::Custom => "Custom flag combination",
        }
    }

    pub fn flags(&self) -> Vec<TcpFlag> {
        match self {
            ScanType::SynScan => vec![TcpFlag::Syn],
            ScanType::ConnectScan => vec![TcpFlag::Syn], // Full connect handled differently
            ScanType::FinScan => vec![TcpFlag::Fin],
            ScanType::NullScan => vec![],
            ScanType::XmasScan => vec![TcpFlag::Fin, TcpFlag::Psh, TcpFlag::Urg],
            ScanType::AckScan => vec![TcpFlag::Ack],
            ScanType::WindowScan => vec![TcpFlag::Ack],
            ScanType::UdpScan => vec![],
            ScanType::Custom => vec![],
        }
    }

    pub fn flags_bitmask(&self) -> u8 {
        self.flags().iter().fold(0u8, |acc, f| acc | f.to_bit())
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub ports: Vec<u16>,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            ip: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            ports: vec![80],
        }
    }
}

/// Packet templates for common protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketTemplate {
    // TCP Templates
    TcpSyn,
    TcpSynAck,
    TcpAck,
    TcpFin,
    TcpRst,
    TcpXmas,
    TcpNull,

    // HTTP Templates
    HttpGet,
    HttpHead,
    HttpPost,
    HttpOptions,

    // DNS Templates
    DnsQueryA,
    DnsQueryAAAA,
    DnsQueryMX,
    DnsQueryTXT,

    // Other Templates
    IcmpPing,
    NtpRequest,

    // Custom
    Custom,
}

impl PacketTemplate {
    pub fn all() -> Vec<PacketTemplate> {
        vec![
            PacketTemplate::TcpSyn,
            PacketTemplate::TcpSynAck,
            PacketTemplate::TcpAck,
            PacketTemplate::TcpFin,
            PacketTemplate::TcpRst,
            PacketTemplate::TcpXmas,
            PacketTemplate::TcpNull,
            PacketTemplate::HttpGet,
            PacketTemplate::HttpHead,
            PacketTemplate::HttpPost,
            PacketTemplate::HttpOptions,
            PacketTemplate::DnsQueryA,
            PacketTemplate::DnsQueryAAAA,
            PacketTemplate::DnsQueryMX,
            PacketTemplate::DnsQueryTXT,
            PacketTemplate::IcmpPing,
            PacketTemplate::NtpRequest,
            PacketTemplate::Custom,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            PacketTemplate::TcpSyn => "TCP SYN",
            PacketTemplate::TcpSynAck => "TCP SYN+ACK",
            PacketTemplate::TcpAck => "TCP ACK",
            PacketTemplate::TcpFin => "TCP FIN",
            PacketTemplate::TcpRst => "TCP RST",
            PacketTemplate::TcpXmas => "TCP X-Mas",
            PacketTemplate::TcpNull => "TCP NULL",
            PacketTemplate::HttpGet => "HTTP GET",
            PacketTemplate::HttpHead => "HTTP HEAD",
            PacketTemplate::HttpPost => "HTTP POST",
            PacketTemplate::HttpOptions => "HTTP OPTIONS",
            PacketTemplate::DnsQueryA => "DNS A Query",
            PacketTemplate::DnsQueryAAAA => "DNS AAAA Query",
            PacketTemplate::DnsQueryMX => "DNS MX Query",
            PacketTemplate::DnsQueryTXT => "DNS TXT Query",
            PacketTemplate::IcmpPing => "ICMP Ping",
            PacketTemplate::NtpRequest => "NTP Request",
            PacketTemplate::Custom => "Custom",
        }
    }

    pub fn shortcut(&self) -> &'static str {
        match self {
            PacketTemplate::TcpSyn => "F1",
            PacketTemplate::TcpSynAck => "F2",
            PacketTemplate::TcpAck => "F3",
            PacketTemplate::TcpFin => "F4",
            PacketTemplate::TcpRst => "F5",
            PacketTemplate::TcpXmas => "F6",
            PacketTemplate::TcpNull => "F7",
            PacketTemplate::HttpGet => "F8",
            PacketTemplate::HttpHead => "F9",
            PacketTemplate::HttpPost => "F10",
            PacketTemplate::HttpOptions => "-",
            PacketTemplate::DnsQueryA => "F11",
            PacketTemplate::DnsQueryAAAA => "-",
            PacketTemplate::DnsQueryMX => "-",
            PacketTemplate::DnsQueryTXT => "-",
            PacketTemplate::IcmpPing => "F12",
            PacketTemplate::NtpRequest => "-",
            PacketTemplate::Custom => "-",
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            PacketTemplate::TcpSyn
            | PacketTemplate::TcpSynAck
            | PacketTemplate::TcpAck
            | PacketTemplate::TcpFin
            | PacketTemplate::TcpRst
            | PacketTemplate::TcpXmas
            | PacketTemplate::TcpNull => Protocol::Tcp,
            PacketTemplate::HttpGet
            | PacketTemplate::HttpHead
            | PacketTemplate::HttpPost
            | PacketTemplate::HttpOptions => Protocol::Http,
            PacketTemplate::DnsQueryA
            | PacketTemplate::DnsQueryAAAA
            | PacketTemplate::DnsQueryMX
            | PacketTemplate::DnsQueryTXT => Protocol::Dns,
            PacketTemplate::IcmpPing => Protocol::Icmp,
            PacketTemplate::NtpRequest => Protocol::Ntp,
            PacketTemplate::Custom => Protocol::Raw,
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            PacketTemplate::TcpSyn
            | PacketTemplate::TcpSynAck
            | PacketTemplate::TcpAck
            | PacketTemplate::TcpFin
            | PacketTemplate::TcpRst
            | PacketTemplate::TcpXmas
            | PacketTemplate::TcpNull => 80,
            PacketTemplate::HttpGet
            | PacketTemplate::HttpHead
            | PacketTemplate::HttpPost
            | PacketTemplate::HttpOptions => 80,
            PacketTemplate::DnsQueryA
            | PacketTemplate::DnsQueryAAAA
            | PacketTemplate::DnsQueryMX
            | PacketTemplate::DnsQueryTXT => 53,
            PacketTemplate::IcmpPing => 0,
            PacketTemplate::NtpRequest => 123,
            PacketTemplate::Custom => 80,
        }
    }

    pub fn tcp_flags(&self) -> Vec<TcpFlag> {
        match self {
            PacketTemplate::TcpSyn => vec![TcpFlag::Syn],
            PacketTemplate::TcpSynAck => vec![TcpFlag::Syn, TcpFlag::Ack],
            PacketTemplate::TcpAck => vec![TcpFlag::Ack],
            PacketTemplate::TcpFin => vec![TcpFlag::Fin],
            PacketTemplate::TcpRst => vec![TcpFlag::Rst],
            PacketTemplate::TcpXmas => vec![TcpFlag::Fin, TcpFlag::Psh, TcpFlag::Urg],
            PacketTemplate::TcpNull => vec![],
            _ => vec![],
        }
    }

    /// Generate payload for this template
    pub fn payload(&self, host: &str) -> Vec<u8> {
        match self {
            PacketTemplate::HttpGet => {
                format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NoirCast/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                    host
                ).into_bytes()
            }
            PacketTemplate::HttpHead => {
                format!(
                    "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NoirCast/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                    host
                ).into_bytes()
            }
            PacketTemplate::HttpPost => {
                let body = "{}";
                format!(
                    "POST / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NoirCast/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    host, body.len(), body
                ).into_bytes()
            }
            PacketTemplate::HttpOptions => {
                format!(
                    "OPTIONS * HTTP/1.1\r\nHost: {}\r\nUser-Agent: NoirCast/1.0\r\nAccept: */*\r\n\r\n",
                    host
                ).into_bytes()
            }
            PacketTemplate::DnsQueryA => Self::build_dns_query(host, 1), // A record
            PacketTemplate::DnsQueryAAAA => Self::build_dns_query(host, 28), // AAAA record
            PacketTemplate::DnsQueryMX => Self::build_dns_query(host, 15), // MX record
            PacketTemplate::DnsQueryTXT => Self::build_dns_query(host, 16), // TXT record
            PacketTemplate::NtpRequest => Self::build_ntp_request(),
            _ => vec![],
        }
    }

    fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID (random)
        packet.extend_from_slice(&[0xAB, 0xCD]);
        // Flags: Standard query
        packet.extend_from_slice(&[0x01, 0x00]);
        // Questions: 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // Answer RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // Authority RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);
        // Additional RRs: 0
        packet.extend_from_slice(&[0x00, 0x00]);

        // QNAME (domain name)
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // End of domain name

        // QTYPE
        packet.extend_from_slice(&qtype.to_be_bytes());
        // QCLASS: IN (Internet)
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    fn build_ntp_request() -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        // LI=0, VN=4, Mode=3 (client)
        packet[0] = 0x23;
        packet
    }
}

impl std::fmt::Display for PacketTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
