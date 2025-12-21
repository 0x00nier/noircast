//! Async packet sender with multithreading support
//!
//! Implements high-performance packet sending using Tokio async runtime
//! with configurable batch sizes and worker threads, inspired by RustScan's
//! architecture.

use crate::config::{Protocol, ScanType, TcpFlag};
use crate::network::packet::{PacketResponse, PacketStats, ResponseStatus};
use crate::network::raw_socket::{self, RawSocketCapability};
use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum SenderError {
    #[error("Failed to create socket: {0}")]
    SocketCreation(String),

    #[error("Failed to send packet: {0}")]
    SendFailed(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Network unreachable")]
    NetworkUnreachable,

    #[error("Host unreachable")]
    HostUnreachable,

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("Invalid target: {0}")]
    InvalidTarget(String),
}

/// Configuration for packet sending
#[derive(Debug, Clone)]
pub struct SenderConfig {
    pub worker_threads: usize,
    pub batch_size: usize,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            worker_threads: 4,
            batch_size: 1000,
            timeout_ms: 3000,
            max_retries: 3,
            retry_delay_ms: 100,
        }
    }
}

/// High-performance packet sender using async I/O
pub struct PacketSender {
    config: SenderConfig,
    semaphore: Arc<Semaphore>,
    stats: Arc<RwLock<PacketStats>>,
    active_jobs: Arc<AtomicU64>,
    response_tx: Option<mpsc::Sender<PacketResponse>>,
    raw_socket_capability: RawSocketCapability,
    use_raw_sockets: AtomicBool,
}

impl PacketSender {
    /// Create a new packet sender with specified configuration
    pub async fn new(workers: usize, batch_size: usize, timeout_ms: u64) -> Result<Self> {
        let config = SenderConfig {
            worker_threads: workers,
            batch_size,
            timeout_ms,
            ..Default::default()
        };

        // Create semaphore to limit concurrent connections
        // This prevents overwhelming the OS with too many open sockets
        let semaphore = Arc::new(Semaphore::new(batch_size));

        // Check raw socket capability at startup
        let raw_socket_capability = raw_socket::check_raw_socket_capability();
        let use_raw_sockets = AtomicBool::new(raw_socket_capability.available);

        if raw_socket_capability.available {
            tracing::info!("Raw socket capability: {}", raw_socket_capability.explanation());
        } else {
            tracing::warn!("Raw socket capability: {}", raw_socket_capability.explanation());
        }

        Ok(Self {
            config,
            semaphore,
            stats: Arc::new(RwLock::new(PacketStats::default())),
            active_jobs: Arc::new(AtomicU64::new(0)),
            response_tx: None,
            raw_socket_capability,
            use_raw_sockets,
        })
    }

    /// Check if raw sockets are available
    #[allow(dead_code)]
    pub fn has_raw_socket_capability(&self) -> bool {
        self.raw_socket_capability.available
    }

    /// Get explanation of raw socket capability
    pub fn raw_socket_explanation(&self) -> String {
        self.raw_socket_capability.explanation()
    }

    /// Enable or disable raw socket usage (for testing/fallback)
    #[allow(dead_code)]
    pub fn set_use_raw_sockets(&self, enabled: bool) {
        self.use_raw_sockets.store(enabled, Ordering::SeqCst);
    }

    /// Check if raw sockets are currently being used
    pub fn is_using_raw_sockets(&self) -> bool {
        self.use_raw_sockets.load(Ordering::SeqCst) && self.raw_socket_capability.available
    }

    /// Set the response channel for receiving packet responses
    pub fn set_response_channel(&mut self, tx: mpsc::Sender<PacketResponse>) {
        self.response_tx = Some(tx);
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> PacketStats {
        self.stats.read().await.clone()
    }

    /// Set the stats Arc (for sharing with App)
    pub fn set_stats(&mut self, stats: Arc<RwLock<PacketStats>>) {
        self.stats = stats;
    }

    /// Get number of active jobs
    pub fn active_jobs(&self) -> u64 {
        self.active_jobs.load(Ordering::Relaxed)
    }

    /// Resolve hostname to IP address
    pub async fn resolve_host(host: &str) -> Result<IpAddr> {
        // First try to parse as IP address directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Use tokio's built-in DNS resolution
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:0", host))
            .await
            .context("DNS lookup failed")?
            .collect();

        addrs
            .first()
            .map(|addr| addr.ip())
            .ok_or_else(|| anyhow::anyhow!("No addresses found for host"))
    }

    /// Perform a TCP connect scan (full handshake)
    ///
    /// Note: This performs a full TCP 3-way handshake. For raw socket scans
    /// (SYN, FIN, NULL, XMAS, ACK, Window) that send custom TCP flags,
    /// elevated privileges (root/admin) are required.
    #[tracing::instrument(skip(self), fields(target = %target_ip, port_count = ports.len()))]
    pub async fn tcp_connect_scan(
        &self,
        target_ip: IpAddr,
        ports: &[u16],
    ) -> Vec<PacketResponse> {
        tracing::debug!("Starting TCP connect scan on {} ports", ports.len());
        let semaphore = self.semaphore.clone();
        let timeout_ms = self.config.timeout_ms;
        let response_tx = self.response_tx.clone();

        // Use buffered parallel execution for better performance
        let responses: Vec<PacketResponse> = stream::iter(ports.iter().cloned())
            .map(|port| {
                let semaphore = semaphore.clone();
                let response_tx = response_tx.clone();

                async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let start = Instant::now();
                    let socket_addr = SocketAddr::new(target_ip, port);

                    let response = match timeout(
                        Duration::from_millis(timeout_ms),
                        TcpStream::connect(socket_addr),
                    )
                    .await
                    {
                        Ok(Ok(_stream)) => {
                            let rtt = start.elapsed().as_secs_f64() * 1000.0;
                            PacketResponse {
                                id: uuid::Uuid::new_v4(),
                                target_ip,
                                target_port: port,
                                protocol: Protocol::Tcp,
                                status: ResponseStatus::Open,
                                flags_received: Some(vec![TcpFlag::Syn, TcpFlag::Ack]),
                                rtt_ms: Some(rtt),
                                raw_response: None,
                                timestamp: chrono::Utc::now(),
                                error: None,
                            }
                        }
                        Ok(Err(e)) => {
                            let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                ResponseStatus::Closed
                            } else {
                                ResponseStatus::Filtered
                            };
                            PacketResponse {
                                id: uuid::Uuid::new_v4(),
                                target_ip,
                                target_port: port,
                                protocol: Protocol::Tcp,
                                status,
                                flags_received: Some(vec![TcpFlag::Rst]),
                                rtt_ms: None,
                                raw_response: None,
                                timestamp: chrono::Utc::now(),
                                error: Some(e.to_string()),
                            }
                        }
                        Err(_) => PacketResponse {
                            id: uuid::Uuid::new_v4(),
                            target_ip,
                            target_port: port,
                            protocol: Protocol::Tcp,
                            status: ResponseStatus::Filtered,
                            flags_received: None,
                            rtt_ms: None,
                            raw_response: None,
                            timestamp: chrono::Utc::now(),
                            error: Some("Connection timeout".to_string()),
                        },
                    };

                    if let Some(tx) = &response_tx {
                        let _ = tx.send(response.clone()).await;
                    }
                    response
                }
            })
            .buffer_unordered(self.config.batch_size)
            .collect()
            .await;

        // Batch update stats after all operations complete (reduces lock contention)
        {
            let mut s = self.stats.write().await;
            for response in &responses {
                s.record_sent(40);
                match response.status {
                    ResponseStatus::Open => {
                        s.open_ports += 1;
                        if let Some(rtt) = response.rtt_ms {
                            s.record_received(0, rtt);
                        }
                    }
                    ResponseStatus::Closed => s.closed_ports += 1,
                    ResponseStatus::Filtered | ResponseStatus::OpenFiltered => s.filtered_ports += 1,
                    _ => {}
                }
            }
        }

        responses
    }

    /// Send a batch of packets concurrently
    pub async fn send_batch(
        &self,
        target_ip: IpAddr,
        ports: &[u16],
        scan_type: ScanType,
        flags: &[TcpFlag],
    ) -> Vec<PacketResponse> {
        match scan_type {
            ScanType::ConnectScan => self.tcp_connect_scan(target_ip, ports).await,
            ScanType::SynScan
            | ScanType::FinScan
            | ScanType::NullScan
            | ScanType::XmasScan
            | ScanType::AckScan
            | ScanType::WindowScan
            | ScanType::Custom => {
                // For raw socket scans, check if we have the capability
                if self.is_using_raw_sockets() {
                    self.raw_tcp_scan(target_ip, ports, flags).await
                } else {
                    // Provide detailed warning about missing capabilities
                    tracing::warn!(
                        "{}. Falling back to connect scan.",
                        self.raw_socket_explanation()
                    );
                    self.tcp_connect_scan(target_ip, ports).await
                }
            }
            ScanType::UdpScan => self.udp_scan(target_ip, ports).await,
        }
    }

    /// Perform raw TCP scan with custom flags (requires raw socket capability)
    async fn raw_tcp_scan(
        &self,
        target_ip: IpAddr,
        ports: &[u16],
        flags: &[TcpFlag],
    ) -> Vec<PacketResponse> {
        use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
        use std::net::Ipv4Addr;

        let target_v4 = match target_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                tracing::warn!("IPv6 raw TCP scan not yet supported, falling back to connect scan");
                return self.tcp_connect_scan(target_ip, ports).await;
            }
        };

        // Create transport channel
        let protocol = TransportChannelType::Layer4(
            TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)
        );

        let (mut tx, _rx) = match transport_channel(4096, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                tracing::error!("Failed to create raw TCP channel: {}. Falling back to connect scan.", e);
                return self.tcp_connect_scan(target_ip, ports).await;
            }
        };

        // Convert TcpFlag to pnet flags (pnet uses u8 for TCP flags)
        let tcp_flags: u8 = flags.iter().fold(0u8, |acc, f| {
            let flag_bit: u8 = match f {
                TcpFlag::Syn => TcpFlags::SYN as u8,
                TcpFlag::Ack => TcpFlags::ACK as u8,
                TcpFlag::Fin => TcpFlags::FIN as u8,
                TcpFlag::Rst => TcpFlags::RST as u8,
                TcpFlag::Psh => TcpFlags::PSH as u8,
                TcpFlag::Urg => TcpFlags::URG as u8,
                TcpFlag::Ece => TcpFlags::ECE as u8,
                TcpFlag::Cwr => TcpFlags::CWR as u8,
            };
            acc | flag_bit
        });

        let semaphore = self.semaphore.clone();
        let _timeout_ms = self.config.timeout_ms; // Will be used for receive in full implementation
        let response_tx = self.response_tx.clone();

        // For raw TCP, we send packets in sequence due to channel sharing
        // but we can still parallelize the receive portion
        let mut responses = Vec::with_capacity(ports.len());

        for &port in ports {
            let _permit = semaphore.acquire().await.ok();
            let start = Instant::now();

            // Build TCP packet
            let mut tcp_buffer = [0u8; 20];
            if let Some(mut tcp_packet) = MutableTcpPacket::new(&mut tcp_buffer) {
                tcp_packet.set_source(rand::random::<u16>().saturating_add(1024));
                tcp_packet.set_destination(port);
                tcp_packet.set_sequence(rand::random::<u32>());
                tcp_packet.set_acknowledgement(0);
                tcp_packet.set_data_offset(5);
                tcp_packet.set_flags(tcp_flags);
                tcp_packet.set_window(65535);
                tcp_packet.set_urgent_ptr(0);

                // Calculate checksum with pseudo-header
                let source_ip = Ipv4Addr::new(0, 0, 0, 0); // Will be filled by kernel
                let checksum = pnet::packet::tcp::ipv4_checksum(
                    &tcp_packet.to_immutable(),
                    &source_ip,
                    &target_v4,
                );
                tcp_packet.set_checksum(checksum);

                // Send the packet
                if let Err(e) = tx.send_to(tcp_packet.to_immutable(), target_ip) {
                    tracing::debug!("Failed to send raw TCP packet to {}:{}: {}", target_ip, port, e);
                }
            }

            // For SYN scan, we expect SYN-ACK (open) or RST (closed)
            let response = PacketResponse {
                id: uuid::Uuid::new_v4(),
                target_ip,
                target_port: port,
                protocol: Protocol::Tcp,
                status: ResponseStatus::OpenFiltered, // Will be updated if we get a response
                flags_received: None,
                rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                raw_response: None,
                timestamp: chrono::Utc::now(),
                error: None,
            };

            if let Some(ref tx) = response_tx {
                let _ = tx.send(response.clone()).await;
            }
            responses.push(response);
        }

        // Note: In a full implementation, we would receive and match responses
        // For now, we've sent the packets - a proper receiver would update statuses

        responses
    }

    /// Perform UDP scan with service-specific probes for better detection
    #[tracing::instrument(skip(self), fields(target = %target_ip, port_count = ports.len()))]
    pub async fn udp_scan(&self, target_ip: IpAddr, ports: &[u16]) -> Vec<PacketResponse> {
        tracing::debug!("Starting UDP scan on {} ports", ports.len());
        let semaphore = self.semaphore.clone();
        let timeout_ms = self.config.timeout_ms;
        let response_tx = self.response_tx.clone();

        // Use buffered parallel execution for better performance
        let responses: Vec<PacketResponse> = stream::iter(ports.iter().cloned())
            .map(|port| {
                let semaphore = semaphore.clone();
                let response_tx = response_tx.clone();

                async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let start = Instant::now();

                    let (status, raw_response) = match Self::send_udp_probe(target_ip, port, timeout_ms).await {
                        Ok((s, r)) => (s, r),
                        Err(_) => (ResponseStatus::Error, None),
                    };

                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    let response = PacketResponse {
                        id: uuid::Uuid::new_v4(),
                        target_ip,
                        target_port: port,
                        protocol: Protocol::Udp,
                        status,
                        flags_received: None,
                        rtt_ms: Some(rtt),
                        raw_response,
                        timestamp: chrono::Utc::now(),
                        error: None,
                    };

                    if let Some(tx) = &response_tx {
                        let _ = tx.send(response.clone()).await;
                    }
                    response
                }
            })
            .buffer_unordered(self.config.batch_size)
            .collect()
            .await;

        // Batch update stats (reduces lock contention)
        {
            let mut s = self.stats.write().await;
            for response in &responses {
                s.record_sent(28);
                match response.status {
                    ResponseStatus::Open => {
                        s.open_ports += 1;
                        if let Some(rtt) = response.rtt_ms {
                            s.record_received(0, rtt);
                        }
                    }
                    ResponseStatus::Closed => s.closed_ports += 1,
                    ResponseStatus::OpenFiltered | ResponseStatus::Filtered => s.filtered_ports += 1,
                    ResponseStatus::Error => s.packets_failed += 1,
                    _ => {}
                }
            }
        }

        responses
    }

    /// Get service-specific probe payload for UDP scanning (zero-copy)
    #[inline]
    pub fn get_udp_probe(port: u16) -> &'static [u8] {
        // Static probe payloads - no allocation on each call
        static DNS_PROBE: &[u8] = &[
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
            0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', // "version"
            0x04, b'b', b'i', b'n', b'd', // "bind"
            0x00, // Root
            0x00, 0x10, // Type: TXT
            0x00, 0x03, // Class: CH (Chaos)
        ];

        static NTP_PROBE: &[u8] = &[
            0x1b, 0x00, 0x00, 0x00, // LI/VN/Mode, Stratum, Poll, Precision
            0x00, 0x00, 0x00, 0x00, // Root Delay
            0x00, 0x00, 0x00, 0x00, // Root Dispersion
            0x00, 0x00, 0x00, 0x00, // Reference ID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reference Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originate Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Receive Timestamp
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transmit Timestamp
        ];

        static SNMP_PROBE: &[u8] = &[
            0x30, 0x26, // SEQUENCE
            0x02, 0x01, 0x00, // Version: 0 (v1)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // Community: "public"
            0xa0, 0x19, // GetRequest-PDU
            0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // Request ID
            0x02, 0x01, 0x00, // Error status
            0x02, 0x01, 0x00, // Error index
            0x30, 0x0b, // VarBindList
            0x30, 0x09, // VarBind
            0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1
            0x05, 0x00, // NULL
        ];

        static SSDP_PROBE: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

        static NETBIOS_PROBE: &[u8] = &[
            0x80, 0x94, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answers/Authority/Additional
            0x20, // Name length (encoded)
            b'C', b'K', b'A', b'A', b'A', b'A', b'A', b'A', // Encoded "*" wildcard
            b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            0x00, // Name terminator
            0x00, 0x21, // Type: NBSTAT
            0x00, 0x01, // Class: IN
        ];

        static SIP_PROBE: &[u8] = b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK\r\nMax-Forwards: 70\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm@nm>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContact: <sip:nm@nm>\r\nContent-Length: 0\r\n\r\n";

        static TFTP_PROBE: &[u8] = &[0x00, 0x01, b't', b'e', b's', b't', 0x00, b'o', b'c', b't', b'e', b't', 0x00];

        static EMPTY_PROBE: &[u8] = &[];

        match port {
            53 => DNS_PROBE,
            123 => NTP_PROBE,
            161 => SNMP_PROBE,
            1900 => SSDP_PROBE,
            137 => NETBIOS_PROBE,
            5060 => SIP_PROBE,
            69 => TFTP_PROBE,
            _ => EMPTY_PROBE,
        }
    }

    /// Send a UDP probe to a single port with service-specific payload
    async fn send_udp_probe(
        target_ip: IpAddr,
        port: u16,
        timeout_ms: u64,
    ) -> Result<(ResponseStatus, Option<Vec<u8>>)> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let target = SocketAddr::new(target_ip, port);

        // Get service-specific probe payload
        let probe = Self::get_udp_probe(port);
        socket.send_to(&probe, target).await?;

        // Try to receive response
        let mut buf = [0u8; 4096];
        match timeout(Duration::from_millis(timeout_ms), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if len > 0 {
                    Ok((ResponseStatus::Open, Some(buf[..len].to_vec())))
                } else {
                    Ok((ResponseStatus::OpenFiltered, None))
                }
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    Ok((ResponseStatus::Closed, None))
                } else {
                    Ok((ResponseStatus::Filtered, None))
                }
            }
            Err(_) => Ok((ResponseStatus::OpenFiltered, None)),
        }
    }

    /// Send HTTP request and get response
    #[tracing::instrument(skip(self, headers, body), fields(target = %target_ip, port, method, path))]
    pub async fn send_http_request(
        &self,
        target_ip: IpAddr,
        port: u16,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Duration)> {
        tracing::debug!("Sending HTTP {} request to {}:{}{}", method, target_ip, port, path);
        let start = Instant::now();
        let socket_addr = SocketAddr::new(target_ip, port);

        let stream = timeout(
            Duration::from_millis(self.config.timeout_ms),
            TcpStream::connect(socket_addr),
        )
        .await
        .context(format!("Connection to {}:{} timed out after {}ms", target_ip, port, self.config.timeout_ms))?
        .context(format!("Failed to connect to {}:{}", target_ip, port))?;

        // Build HTTP request
        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);

        for (key, value) in headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        if let Some(body_data) = body {
            request.push_str(&format!("Content-Length: {}\r\n", body_data.len()));
        }

        request.push_str("\r\n");

        // Send request
        stream.writable().await?;
        let request_bytes = if let Some(body_data) = body {
            let mut bytes = request.into_bytes();
            bytes.extend_from_slice(body_data);
            bytes
        } else {
            request.into_bytes()
        };

        use tokio::io::AsyncWriteExt;
        let mut stream = stream;
        stream.write_all(&request_bytes).await?;

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        let mut headers_complete = false;
        let mut expected_body_len: Option<usize> = None;
        let mut header_end_pos: usize = 0;

        use tokio::io::AsyncReadExt;
        loop {
            match timeout(Duration::from_millis(self.config.timeout_ms), stream.read(&mut buf)).await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => response.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break, // Timeout, assume we got all data
            }

            // Check if we've received complete HTTP headers
            if !headers_complete {
                if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    headers_complete = true;
                    header_end_pos = pos + 4;

                    // Try to extract Content-Length from headers
                    if let Ok(headers_str) = std::str::from_utf8(&response[..pos]) {
                        for line in headers_str.lines() {
                            if line.to_lowercase().starts_with("content-length:") {
                                if let Some(len_str) = line.split(':').nth(1) {
                                    expected_body_len = len_str.trim().parse().ok();
                                }
                            }
                        }
                    }
                }
            }

            // If we know the expected body length, check if we have it all
            if headers_complete {
                if let Some(body_len) = expected_body_len {
                    let current_body_len = response.len().saturating_sub(header_end_pos);
                    if current_body_len >= body_len {
                        break; // Got the full response
                    }
                }
            }
        }

        let duration = start.elapsed();
        {
            let mut s = self.stats.write().await;
            s.record_sent(request_bytes.len() as u64);
            s.record_received(response.len() as u64, duration.as_secs_f64() * 1000.0);
        }

        Ok((response, duration))
    }

    /// Perform a single packet send with retry logic
    pub async fn send_with_retry(
        &self,
        target_ip: IpAddr,
        port: u16,
        scan_type: ScanType,
        flags: &[TcpFlag],
    ) -> PacketResponse {
        let mut last_response = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                self.stats.write().await.record_retry();
                tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
            }

            let responses = self.send_batch(target_ip, &[port], scan_type, flags).await;

            if let Some(response) = responses.into_iter().next() {
                if response.status != ResponseStatus::NoResponse
                    && response.status != ResponseStatus::Error
                {
                    return response;
                }
                last_response = Some(response);
            }
        }

        last_response.unwrap_or_else(|| PacketResponse {
            id: uuid::Uuid::new_v4(),
            target_ip,
            target_port: port,
            protocol: Protocol::Tcp,
            status: ResponseStatus::NoResponse,
            flags_received: None,
            rtt_ms: None,
            raw_response: None,
            timestamp: chrono::Utc::now(),
            error: Some("Max retries exceeded".to_string()),
        })
    }

    /// Send ICMP echo requests (ping) to multiple targets with batch support
    #[tracing::instrument(skip(self), fields(target_count = targets.len(), icmp_type, icmp_code))]
    pub async fn send_icmp_batch(
        &self,
        targets: &[IpAddr],
        icmp_type: u8,
        icmp_code: u8,
        icmp_id: u16,
        start_seq: u16,
    ) -> Vec<PacketResponse> {
        tracing::debug!("Sending ICMP batch to {} targets (type={}, code={})", targets.len(), icmp_type, icmp_code);
        let semaphore = self.semaphore.clone();
        let timeout_ms = self.config.timeout_ms;
        let tx = self.response_tx.clone();

        // Use buffered parallel execution for better performance
        let responses: Vec<PacketResponse> = stream::iter(targets.iter().enumerate())
            .map(|(idx, &target_ip)| {
                let semaphore = semaphore.clone();
                let tx = tx.clone();
                let seq = start_seq.wrapping_add(idx as u16);

                async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let start = Instant::now();

                    let (status, received) = match Self::send_icmp_probe(target_ip, icmp_type, icmp_code, icmp_id, seq, timeout_ms).await {
                        Ok(true) => (ResponseStatus::Open, true),
                        Ok(false) => (ResponseStatus::NoResponse, false),
                        Err(_) => (ResponseStatus::Error, false),
                    };

                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    let response = PacketResponse {
                        id: uuid::Uuid::new_v4(),
                        target_ip,
                        target_port: 0,
                        protocol: Protocol::Icmp,
                        status,
                        flags_received: None,
                        rtt_ms: if received { Some(rtt) } else { None },
                        raw_response: None,
                        timestamp: chrono::Utc::now(),
                        error: None,
                    };

                    if let Some(ref tx) = tx {
                        let _ = tx.send(response.clone()).await;
                    }
                    response
                }
            })
            .buffer_unordered(self.config.batch_size)
            .collect()
            .await;

        // Batch update stats (reduces lock contention)
        {
            let mut s = self.stats.write().await;
            for response in &responses {
                s.record_sent(64);
                if response.status == ResponseStatus::Open {
                    if let Some(rtt) = response.rtt_ms {
                        s.record_received(64, rtt);
                    }
                } else if response.status == ResponseStatus::Error {
                    s.packets_failed += 1;
                }
            }
        }

        responses
    }

    /// Send a single ICMP probe using raw sockets when available
    async fn send_icmp_probe(
        target_ip: IpAddr,
        icmp_type: u8,
        icmp_code: u8,
        icmp_id: u16,
        icmp_seq: u16,
        timeout_ms: u64,
    ) -> Result<bool> {
        // Check if raw sockets are available (cached check)
        if raw_socket::get_cached_availability().unwrap_or(false) {
            // Use proper ICMP raw socket
            Self::send_icmp_probe_raw(target_ip, icmp_type, icmp_code, icmp_id, icmp_seq, timeout_ms).await
        } else {
            // Fallback to unprivileged method
            Self::send_icmp_probe_fallback(target_ip, icmp_id, icmp_seq, timeout_ms).await
        }
    }

    /// Send ICMP probe using raw socket (pnet)
    async fn send_icmp_probe_raw(
        target_ip: IpAddr,
        _icmp_type: u8,
        _icmp_code: u8,
        icmp_id: u16,
        icmp_seq: u16,
        timeout_ms: u64,
    ) -> Result<bool> {
        // Run the blocking pnet operation in a spawn_blocking task
        let result = tokio::task::spawn_blocking(move || {
            let payload = b"NoirCast ICMP Probe";
            raw_socket::send_icmp_echo_raw(
                target_ip,
                icmp_id,
                icmp_seq,
                payload,
                Duration::from_millis(timeout_ms),
            )
        }).await;

        match result {
            Ok(Ok(icmp_result)) => Ok(icmp_result.received),
            Ok(Err(e)) => {
                tracing::debug!("ICMP raw socket error: {}", e);
                Ok(false)
            }
            Err(e) => {
                tracing::debug!("ICMP task join error: {}", e);
                Ok(false)
            }
        }
    }

    /// Send ICMP probe using unprivileged UDP fallback
    async fn send_icmp_probe_fallback(
        target_ip: IpAddr,
        icmp_id: u16,
        icmp_seq: u16,
        timeout_ms: u64,
    ) -> Result<bool> {
        let result = raw_socket::send_icmp_fallback(target_ip, icmp_id, icmp_seq, timeout_ms).await;
        Ok(result.received)
    }

    /// Calculate ICMP checksum
    #[allow(dead_code)]
    fn icmp_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }

    /// Send DNS queries with batch support
    #[tracing::instrument(skip(self), fields(target = %target_ip, domain, query_type, count))]
    pub async fn send_dns_batch(
        &self,
        target_ip: IpAddr,
        domain: &str,
        query_type: u16,
        count: usize,
    ) -> Vec<PacketResponse> {
        tracing::debug!("Sending {} DNS queries for {} (type {})", count, domain, query_type);
        let semaphore = self.semaphore.clone();
        let timeout_ms = self.config.timeout_ms;
        let tx = self.response_tx.clone();
        let domain = domain.to_string();

        // Use buffered parallel execution for better performance
        let responses: Vec<PacketResponse> = stream::iter(0..count)
            .map(|_| {
                let semaphore = semaphore.clone();
                let tx = tx.clone();
                let domain = domain.clone();

                async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let start = Instant::now();

                    let (status, raw_response, error) = match Self::send_dns_query(target_ip, &domain, query_type, timeout_ms).await {
                        Ok(data) => (ResponseStatus::Open, Some(data), None),
                        Err(e) => (ResponseStatus::Error, None, Some(e.to_string())),
                    };

                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    let response = PacketResponse {
                        id: uuid::Uuid::new_v4(),
                        target_ip,
                        target_port: 53,
                        protocol: Protocol::Dns,
                        status,
                        flags_received: None,
                        rtt_ms: if status == ResponseStatus::Open { Some(rtt) } else { None },
                        raw_response,
                        timestamp: chrono::Utc::now(),
                        error,
                    };

                    if let Some(ref tx) = tx {
                        let _ = tx.send(response.clone()).await;
                    }
                    response
                }
            })
            .buffer_unordered(self.config.batch_size)
            .collect()
            .await;

        // Batch update stats (reduces lock contention)
        {
            let mut s = self.stats.write().await;
            for response in &responses {
                s.record_sent(64);
                if response.status == ResponseStatus::Open {
                    let resp_len = response.raw_response.as_ref().map(|r| r.len()).unwrap_or(0);
                    if let Some(rtt) = response.rtt_ms {
                        s.record_received(resp_len as u64, rtt);
                    }
                } else if response.status == ResponseStatus::Error {
                    s.packets_failed += 1;
                }
            }
        }

        responses
    }

    /// Send a single DNS query
    async fn send_dns_query(
        target_ip: IpAddr,
        domain: &str,
        query_type: u16,
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        use crate::network::protocols::{DnsQuery, DnsType};
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = SocketAddr::new(target_ip, 53);

        let dns_type = match query_type {
            1 => DnsType::A,
            2 => DnsType::Ns,
            5 => DnsType::Cname,
            15 => DnsType::Mx,
            16 => DnsType::Txt,
            28 => DnsType::Aaaa,
            _ => DnsType::A,
        };
        let query = DnsQuery::new().add_question(domain, dns_type);
        let packet = query.build();

        socket.send_to(&packet, target).await?;

        let mut buf = [0u8; 4096];
        match timeout(Duration::from_millis(timeout_ms), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Ok(buf[..len].to_vec()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("DNS query timeout")),
        }
    }

    /// Send NTP requests with batch support
    #[tracing::instrument(skip(self), fields(target_count = targets.len()))]
    pub async fn send_ntp_batch(
        &self,
        targets: &[IpAddr],
    ) -> Vec<PacketResponse> {
        tracing::debug!("Sending NTP requests to {} targets", targets.len());
        let semaphore = self.semaphore.clone();
        let timeout_ms = self.config.timeout_ms;
        let tx = self.response_tx.clone();

        // Use buffered parallel execution for better performance
        let responses: Vec<PacketResponse> = stream::iter(targets.iter().copied())
            .map(|target_ip| {
                let semaphore = semaphore.clone();
                let tx = tx.clone();

                async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let start = Instant::now();

                    let (status, raw_response, error) = match Self::send_ntp_request(target_ip, timeout_ms).await {
                        Ok(data) => (ResponseStatus::Open, Some(data), None),
                        Err(e) => (ResponseStatus::Error, None, Some(e.to_string())),
                    };

                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    let response = PacketResponse {
                        id: uuid::Uuid::new_v4(),
                        target_ip,
                        target_port: 123,
                        protocol: Protocol::Ntp,
                        status,
                        flags_received: None,
                        rtt_ms: if status == ResponseStatus::Open { Some(rtt) } else { None },
                        raw_response,
                        timestamp: chrono::Utc::now(),
                        error,
                    };

                    if let Some(ref tx) = tx {
                        let _ = tx.send(response.clone()).await;
                    }
                    response
                }
            })
            .buffer_unordered(self.config.batch_size)
            .collect()
            .await;

        // Batch update stats (reduces lock contention)
        {
            let mut s = self.stats.write().await;
            for response in &responses {
                s.record_sent(48);
                if response.status == ResponseStatus::Open {
                    let resp_len = response.raw_response.as_ref().map(|r| r.len()).unwrap_or(0);
                    if let Some(rtt) = response.rtt_ms {
                        s.record_received(resp_len as u64, rtt);
                    }
                } else if response.status == ResponseStatus::Error {
                    s.packets_failed += 1;
                }
            }
        }

        responses
    }

    /// Send a single NTP request
    async fn send_ntp_request(
        target_ip: IpAddr,
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        use crate::network::protocols::NtpPacket;
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = SocketAddr::new(target_ip, 123);

        let ntp = NtpPacket::new();
        let packet = ntp.build();

        socket.send_to(&packet, target).await?;

        let mut buf = [0u8; 128];
        match timeout(Duration::from_millis(timeout_ms), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => Ok(buf[..len].to_vec()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("NTP request timeout")),
        }
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        *self.stats.write().await = PacketStats::default();
    }
}

/// Port range utilities
pub fn parse_port_range(range: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in range.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                let start: u16 = bounds[0].parse()?;
                let end: u16 = bounds[1].parse()?;
                ports.extend(start..=end);
            }
        } else {
            ports.push(part.parse()?);
        }
    }

    Ok(ports)
}

/// Common port lists
pub mod common_ports {
    /// Top 100 most common ports
    pub const TOP_100: &[u16] = &[
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
        143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
        631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
        1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008,
        8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
    ];

    /// Top 20 most common ports
    pub const TOP_20: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5900, 8080,
    ];

    /// All privileged ports (1-1023)
    pub fn privileged() -> Vec<u16> {
        (1..=1023).collect()
    }

    /// All ports (1-65535)
    pub fn all() -> Vec<u16> {
        (1..=65535).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_packet_sender_creation() {
        let sender = PacketSender::new(4, 100, 1000).await.unwrap();
        assert_eq!(sender.config.worker_threads, 4);
        assert_eq!(sender.config.batch_size, 100);
    }

    #[test]
    fn test_parse_port_range() {
        let ports = parse_port_range("80,443,8080-8082").unwrap();
        assert_eq!(ports, vec![80, 443, 8080, 8081, 8082]);
    }

    #[test]
    fn test_parse_port_range_single() {
        let ports = parse_port_range("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_common_ports() {
        assert!(common_ports::TOP_100.contains(&80));
        assert!(common_ports::TOP_100.contains(&443));
        assert_eq!(common_ports::TOP_20.len(), 20);
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let ip = PacketSender::resolve_host("127.0.0.1").await.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let sender = PacketSender::new(4, 100, 1000).await.unwrap();
        {
            let mut stats = sender.stats.write().await;
            stats.record_sent(100);
            stats.record_received(50, 10.0);
        }

        let stats = sender.get_stats().await;
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
    }
}
