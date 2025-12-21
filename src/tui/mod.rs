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
                            app.selected_scan_type,
                            app.flood_count.clone(),
                            app.flood_stop.clone(),
                            app.flood_workers,
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
    sender: Arc<PacketSender>,
    target_ip: IpAddr,
    ports: Vec<u16>,
    scan_type: ScanType,
    counter: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
    num_workers: usize,
) {
    use tokio::net::TcpStream;
    use std::net::SocketAddr;

    // Increment counter to mark that workers have started
    counter.fetch_add(1, Ordering::SeqCst);

    for worker_id in 0..num_workers {
        let _sender = sender.clone(); // Reserved for raw socket flood
        let ports = ports.clone();
        let counter = counter.clone();
        let stop_flag = stop_flag.clone();

        tokio::spawn(async move {
            tracing::debug!("Flood worker {} started", worker_id);

            // Each worker sends packets in a tight loop
            while !stop_flag.load(Ordering::Relaxed) {
                for &port in &ports {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    // Fire-and-forget connection attempt for maximum speed
                    match scan_type {
                        ScanType::ConnectScan => {
                            let addr = SocketAddr::new(target_ip, port);
                            // Non-blocking connect attempt - don't wait for result
                            let _ = tokio::time::timeout(
                                Duration::from_millis(50),
                                TcpStream::connect(addr)
                            ).await;
                        }
                        ScanType::UdpScan => {
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let addr = SocketAddr::new(target_ip, port);
                                let _ = socket.send_to(&[0u8; 1], addr).await;
                            }
                        }
                        _ => {
                            // For SYN/FIN/NULL/XMAS scans, use raw sockets if available
                            // Fall back to connect scan otherwise
                            let addr = SocketAddr::new(target_ip, port);
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
