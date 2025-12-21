//! TUI module - Terminal User Interface for NoirCast
//!
//! Provides the main event loop, terminal setup, and rendering
//! using Ratatui and Crossterm.

pub mod event;
pub mod handler;

use crate::app::App;
use crate::ui;
use crate::config::ScanType;
use crate::network::sender::PacketSender;
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io::{stdout, Stdout};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Terminal type alias
type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initialize the terminal
fn init_terminal() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restore the terminal to its original state
fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// Main TUI run loop
pub async fn run(app: &mut App) -> Result<()> {
    // Initialize terminal
    let mut terminal = init_terminal()?;

    // Initialize packet sender
    if let Err(e) = app.init_sender().await {
        app.log_error(format!("Failed to initialize packet sender: {}", e));
    }

    app.log_info("NoirCast TUI initialized. Press '?' for help.");

    // Create event handler
    let mut events = event::EventHandler::new(Duration::from_millis(100));

    // Main loop
    let result = run_app(&mut terminal, app, &mut events).await;

    // Restore terminal on exit
    restore_terminal(&mut terminal)?;

    result
}

/// Run the application loop
async fn run_app(
    terminal: &mut Tui,
    app: &mut App,
    events: &mut event::EventHandler,
) -> Result<()> {
    while app.running {
        // Draw UI
        terminal.draw(|frame| {
            ui::render(frame, app);
        })?;

        // Handle flood mode - spawn workers if just started
        if app.flood_mode && !app.flood_stop.load(Ordering::Relaxed) {
            // Spawn flood workers if not already running (check if count is 0 means just started)
            if app.flood_count.load(Ordering::Relaxed) == 0 {
                if let Some(sender) = &app.packet_sender {
                    if let Some(ip) = app.target.ip {
                        spawn_flood_workers(
                            sender.clone(),
                            ip,
                            app.target.ports.clone(),
                            app.selected_protocol,
                            app.selected_scan_type,
                            app.flood_count.clone(),
                            app.flood_stop.clone(),
                            app.flood_workers,
                            app.target.host.clone(),
                            app.http_method.clone(),
                            app.http_path.clone(),
                        );
                    }
                }
            }
        }

        // Handle events (non-blocking in flood mode)
        match events.next().await? {
            event::Event::Tick => {
                // Update application state on tick
                app.clear_expired_status();

                // Check for pending key timeouts
                if !app.pending_keys.is_empty()
                    && app.last_key_time.elapsed() > app.key_timeout
                {
                    app.clear_pending_keys();
                }

                // Update flood stats display
                if app.flood_mode {
                    let (count, duration, rate) = app.get_flood_stats();
                    app.set_status(
                        format!("FLOODING: {} pkts | {:.1}s | {:.0} pps", count, duration, rate),
                        crate::app::LogLevel::Warning,
                    );
                }
            }
            event::Event::Key(key_event) => {
                // In flood mode, 'q' stops the flood
                if app.flood_mode {
                    match key_event.code {
                        crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => {
                            app.stop_flood();
                        }
                        _ => {}
                    }
                } else {
                    handler::handle_key_event(app, key_event).await;
                }
            }
            event::Event::Mouse(mouse_event) => {
                handler::handle_mouse_event(app, mouse_event);
            }
            event::Event::Resize(width, height) => {
                tracing::debug!("Terminal resized to {}x{}", width, height);
            }
        }
    }

    Ok(())
}

/// Spawn multiple flood worker tasks for high-speed packet flooding
fn spawn_flood_workers(
    _sender: Arc<PacketSender>,
    target_ip: IpAddr,
    ports: Vec<u16>,
    protocol: crate::config::Protocol,
    _scan_type: ScanType,
    counter: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
    num_workers: usize,
    host: String,
    http_method: String,
    http_path: String,
) {
    use tokio::net::TcpStream;
    use tokio::io::AsyncWriteExt;
    use std::net::SocketAddr;
    use crate::config::Protocol;
    use crate::network::protocols::*;

    // Increment counter to mark that workers have started
    counter.fetch_add(1, Ordering::SeqCst);

    for worker_id in 0..num_workers {
        let ports = ports.clone();
        let counter = counter.clone();
        let stop_flag = stop_flag.clone();
        let host = host.clone();
        let http_method = http_method.clone();
        let http_path = http_path.clone();

        tokio::spawn(async move {
            tracing::debug!("Flood worker {} started for {:?}", worker_id, protocol);

            // Each worker sends packets in a tight loop
            while !stop_flag.load(Ordering::Relaxed) {
                for &port in &ports {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    let addr = SocketAddr::new(target_ip, port);

                    match protocol {
                        Protocol::Http | Protocol::Https => {
                            // Send actual HTTP request
                            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                                Duration::from_millis(100),
                                TcpStream::connect(addr)
                            ).await {
                                let request = format!(
                                    "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NoirCast/0.1.0\r\nConnection: close\r\n\r\n",
                                    http_method, http_path, host
                                );
                                let _ = stream.write_all(request.as_bytes()).await;
                            }
                        }
                        Protocol::Tcp => {
                            // TCP connect flood
                            let _ = tokio::time::timeout(
                                Duration::from_millis(50),
                                TcpStream::connect(addr)
                            ).await;
                        }
                        Protocol::Udp => {
                            // UDP packet flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let _ = socket.send_to(&[0u8; 64], addr).await;
                            }
                        }
                        Protocol::Dns => {
                            // DNS query flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let query = DnsQuery::a_query(&host);
                                let _ = socket.send_to(&query.build(), addr).await;
                            }
                        }
                        Protocol::Ntp => {
                            // NTP request flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let ntp = NtpPacket::new();
                                let _ = socket.send_to(&ntp.build(), addr).await;
                            }
                        }
                        Protocol::Snmp => {
                            // SNMP request flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let snmp = SnmpGetRequest::new("public").add_oid("1.3.6.1.2.1.1.1.0");
                                let _ = socket.send_to(&snmp.build(), addr).await;
                            }
                        }
                        Protocol::Ssdp => {
                            // SSDP M-SEARCH flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let ssdp = SsdpRequest::m_search();
                                let _ = socket.send_to(&ssdp.build(), addr).await;
                            }
                        }
                        Protocol::NetBios => {
                            // NetBIOS name query flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let nb = NetBiosNsPacket::node_status_query("*");
                                let _ = socket.send_to(&nb.build(), addr).await;
                            }
                        }
                        Protocol::Dhcp => {
                            // DHCP discover flood
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let mac = [0x00, 0x11, 0x22, 0x33, 0x44, rand::random::<u8>()];
                                let dhcp = DhcpDiscoverPacket::new(mac);
                                let _ = socket.send_to(&dhcp.build(), addr).await;
                            }
                        }
                        Protocol::Smb => {
                            // SMB negotiate flood
                            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                                Duration::from_millis(100),
                                TcpStream::connect(addr)
                            ).await {
                                let smb = SmbNegotiatePacket::new();
                                let _ = stream.write_all(&smb.build()).await;
                            }
                        }
                        Protocol::Ldap => {
                            // LDAP search flood
                            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                                Duration::from_millis(100),
                                TcpStream::connect(addr)
                            ).await {
                                let ldap = LdapSearchRequest::rootdse_query();
                                let _ = stream.write_all(&ldap.build()).await;
                            }
                        }
                        Protocol::Kerberos => {
                            // Kerberos AS-REQ flood
                            if let Ok(Ok(mut stream)) = tokio::time::timeout(
                                Duration::from_millis(100),
                                TcpStream::connect(addr)
                            ).await {
                                let krb = KerberosAsReq::new("REALM", "user");
                                let _ = stream.write_all(&krb.build()).await;
                            }
                        }
                        Protocol::Icmp | Protocol::Arp => {
                            // ICMP and ARP require raw sockets - fall back to TCP connect
                            let _ = tokio::time::timeout(
                                Duration::from_millis(50),
                                TcpStream::connect(addr)
                            ).await;
                        }
                        Protocol::Raw => {
                            // Raw mode: send empty TCP connections
                            let _ = tokio::time::timeout(
                                Duration::from_millis(50),
                                TcpStream::connect(addr)
                            ).await;
                        }
                    }

                    // Increment counter for each packet sent
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }

            tracing::debug!("Flood worker {} stopped", worker_id);
        });
    }
}

#[cfg(test)]
mod tests {
    // TUI tests are integration tests that require a terminal
    // These are placeholder tests for the module structure
    #[test]
    fn test_module_exists() {
        // Module compiles successfully
        assert!(true);
    }
}
