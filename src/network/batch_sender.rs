//! High-performance batch sender with socket reuse and buffer pooling
//!
//! This module provides optimized packet sending with:
//! - Socket reuse to avoid repeated socket creation overhead
//! - Pre-allocated buffer pools to reduce memory allocations
//! - Batched async operations for maximum throughput
//! - Adaptive concurrency based on system resources

#![allow(dead_code)] // Module prepared for future optimization integration

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use parking_lot::Mutex;

/// Pre-allocated buffer for packet data
#[derive(Debug)]
pub struct PacketBuffer {
    data: Vec<u8>,
    len: usize,
}

impl PacketBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            len: 0,
        }
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.data.len());
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn buffer(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    pub fn reset(&mut self) {
        self.len = 0;
    }
}

/// Buffer pool for reusing packet buffers
pub struct BufferPool {
    buffers: Mutex<Vec<PacketBuffer>>,
    buffer_size: usize,
    stats: BufferPoolStats,
}

#[derive(Debug, Default)]
pub struct BufferPoolStats {
    pub acquired: AtomicU64,
    pub released: AtomicU64,
    pub created: AtomicU64,
}

impl BufferPool {
    pub fn new(initial_count: usize, buffer_size: usize) -> Self {
        let buffers: Vec<PacketBuffer> = (0..initial_count)
            .map(|_| PacketBuffer::new(buffer_size))
            .collect();

        Self {
            buffers: Mutex::new(buffers),
            buffer_size,
            stats: BufferPoolStats {
                created: AtomicU64::new(initial_count as u64),
                ..Default::default()
            },
        }
    }

    pub fn acquire(&self) -> PacketBuffer {
        self.stats.acquired.fetch_add(1, Ordering::Relaxed);

        let mut buffers = self.buffers.lock();
        buffers.pop().unwrap_or_else(|| {
            self.stats.created.fetch_add(1, Ordering::Relaxed);
            PacketBuffer::new(self.buffer_size)
        })
    }

    pub fn release(&self, mut buffer: PacketBuffer) {
        self.stats.released.fetch_add(1, Ordering::Relaxed);
        buffer.reset();
        self.buffers.lock().push(buffer);
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.stats.acquired.load(Ordering::Relaxed),
            self.stats.released.load(Ordering::Relaxed),
            self.stats.created.load(Ordering::Relaxed),
        )
    }
}

/// Socket pool for UDP socket reuse
pub struct UdpSocketPool {
    sockets: Mutex<Vec<Arc<UdpSocket>>>,
    max_sockets: usize,
    created: AtomicUsize,
}

impl UdpSocketPool {
    pub fn new(max_sockets: usize) -> Self {
        Self {
            sockets: Mutex::new(Vec::with_capacity(max_sockets)),
            max_sockets,
            created: AtomicUsize::new(0),
        }
    }

    pub async fn acquire(&self) -> anyhow::Result<Arc<UdpSocket>> {
        // Try to get from pool first
        {
            let mut sockets = self.sockets.lock();
            if let Some(socket) = sockets.pop() {
                return Ok(socket);
            }
        }

        // Create new socket if under limit
        if self.created.fetch_add(1, Ordering::Relaxed) < self.max_sockets {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            Ok(Arc::new(socket))
        } else {
            self.created.fetch_sub(1, Ordering::Relaxed);
            // Wait and try again
            tokio::time::sleep(Duration::from_micros(100)).await;
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            Ok(Arc::new(socket))
        }
    }

    pub fn release(&self, socket: Arc<UdpSocket>) {
        let mut sockets = self.sockets.lock();
        if sockets.len() < self.max_sockets {
            sockets.push(socket);
        }
        // Otherwise socket is dropped
    }
}

/// Result from a batch send operation
#[derive(Debug, Clone)]
pub struct BatchSendResult {
    pub sent: u64,
    pub received: u64,
    pub failed: u64,
    pub duration: Duration,
    pub avg_rtt_ms: f64,
}

impl BatchSendResult {
    pub fn packets_per_second(&self) -> f64 {
        if self.duration.as_secs_f64() > 0.0 {
            self.sent as f64 / self.duration.as_secs_f64()
        } else {
            0.0
        }
    }
}

/// High-performance batch sender with optimizations
pub struct BatchSender {
    buffer_pool: Arc<BufferPool>,
    socket_pool: Arc<UdpSocketPool>,
    semaphore: Arc<Semaphore>,
    concurrency: usize,
    timeout_ms: u64,
}

impl BatchSender {
    pub fn new(concurrency: usize, buffer_size: usize, timeout_ms: u64) -> Self {
        // Pre-allocate buffer pool with 2x concurrency buffers
        let buffer_pool = Arc::new(BufferPool::new(concurrency * 2, buffer_size));
        let socket_pool = Arc::new(UdpSocketPool::new(concurrency));
        let semaphore = Arc::new(Semaphore::new(concurrency));

        Self {
            buffer_pool,
            socket_pool,
            semaphore,
            concurrency,
            timeout_ms,
        }
    }

    /// Send DNS queries in optimized batches
    pub async fn send_dns_batch(
        &self,
        target_ip: IpAddr,
        domain: &str,
        query_type: u16,
        count: usize,
    ) -> anyhow::Result<BatchSendResult> {
        use futures::stream::{self, StreamExt};
        use crate::network::protocols::{DnsQuery, DnsType};

        let start = Instant::now();
        let target = SocketAddr::new(target_ip, 53);

        // Pre-build DNS query packet once
        let dns_type = match query_type {
            1 => DnsType::A,
            2 => DnsType::Ns,
            5 => DnsType::Cname,
            15 => DnsType::Mx,
            16 => DnsType::Txt,
            28 => DnsType::Aaaa,
            _ => DnsType::A,
        };
        let base_query = DnsQuery::new().add_question(domain, dns_type);
        let base_packet = base_query.build();

        let sent = AtomicU64::new(0);
        let received = AtomicU64::new(0);
        let failed = AtomicU64::new(0);
        let total_rtt = AtomicU64::new(0);

        // Process in parallel with controlled concurrency
        stream::iter(0..count)
            .map(|i| {
                let semaphore = self.semaphore.clone();
                let socket_pool = self.socket_pool.clone();
                let buffer_pool = self.buffer_pool.clone();
                let packet = base_packet.clone();
                let sent = &sent;
                let received = &received;
                let failed = &failed;
                let total_rtt = &total_rtt;
                let timeout_ms = self.timeout_ms;

                async move {
                    let _permit = semaphore.acquire().await.ok()?;
                    let socket = socket_pool.acquire().await.ok()?;
                    let send_start = Instant::now();

                    // Modify transaction ID for each query
                    let mut query_packet = packet.clone();
                    if query_packet.len() >= 2 {
                        let txid = (i as u16).wrapping_add(1);
                        query_packet[0] = (txid >> 8) as u8;
                        query_packet[1] = (txid & 0xff) as u8;
                    }

                    // Send
                    if socket.send_to(&query_packet, target).await.is_ok() {
                        sent.fetch_add(1, Ordering::Relaxed);

                        // Receive with timeout
                        let mut buf = buffer_pool.acquire();
                        buf.set_len(4096);

                        match tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
                            socket.recv_from(buf.as_mut_slice()),
                        ).await {
                            Ok(Ok((len, _))) if len > 0 => {
                                received.fetch_add(1, Ordering::Relaxed);
                                let rtt_us = send_start.elapsed().as_micros() as u64;
                                total_rtt.fetch_add(rtt_us, Ordering::Relaxed);
                            }
                            _ => {
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        buffer_pool.release(buf);
                    } else {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }

                    socket_pool.release(socket);
                    Some(())
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await;

        let sent_count = sent.load(Ordering::Relaxed);
        let received_count = received.load(Ordering::Relaxed);
        let failed_count = failed.load(Ordering::Relaxed);
        let total_rtt_us = total_rtt.load(Ordering::Relaxed);

        let avg_rtt = if received_count > 0 {
            (total_rtt_us as f64 / received_count as f64) / 1000.0
        } else {
            0.0
        };

        Ok(BatchSendResult {
            sent: sent_count,
            received: received_count,
            failed: failed_count,
            duration: start.elapsed(),
            avg_rtt_ms: avg_rtt,
        })
    }

    /// Send NTP queries in optimized batches
    pub async fn send_ntp_batch(
        &self,
        targets: &[IpAddr],
    ) -> anyhow::Result<BatchSendResult> {
        use futures::stream::{self, StreamExt};
        use crate::network::protocols::NtpPacket;

        let start = Instant::now();

        // Pre-build NTP packet once
        let ntp = NtpPacket::new();
        let ntp_packet = ntp.build();

        let sent = AtomicU64::new(0);
        let received = AtomicU64::new(0);
        let failed = AtomicU64::new(0);
        let total_rtt = AtomicU64::new(0);

        stream::iter(targets.iter().copied())
            .map(|target_ip| {
                let semaphore = self.semaphore.clone();
                let socket_pool = self.socket_pool.clone();
                let buffer_pool = self.buffer_pool.clone();
                let packet = ntp_packet.clone();
                let sent = &sent;
                let received = &received;
                let failed = &failed;
                let total_rtt = &total_rtt;
                let timeout_ms = self.timeout_ms;

                async move {
                    let _permit = semaphore.acquire().await.ok()?;
                    let socket = socket_pool.acquire().await.ok()?;
                    let target = SocketAddr::new(target_ip, 123);
                    let send_start = Instant::now();

                    if socket.send_to(&packet, target).await.is_ok() {
                        sent.fetch_add(1, Ordering::Relaxed);

                        let mut buf = buffer_pool.acquire();
                        buf.set_len(128);

                        match tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
                            socket.recv_from(buf.as_mut_slice()),
                        ).await {
                            Ok(Ok((len, _))) if len > 0 => {
                                received.fetch_add(1, Ordering::Relaxed);
                                let rtt_us = send_start.elapsed().as_micros() as u64;
                                total_rtt.fetch_add(rtt_us, Ordering::Relaxed);
                            }
                            _ => {
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        buffer_pool.release(buf);
                    } else {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }

                    socket_pool.release(socket);
                    Some(())
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await;

        let sent_count = sent.load(Ordering::Relaxed);
        let received_count = received.load(Ordering::Relaxed);
        let failed_count = failed.load(Ordering::Relaxed);
        let total_rtt_us = total_rtt.load(Ordering::Relaxed);

        let avg_rtt = if received_count > 0 {
            (total_rtt_us as f64 / received_count as f64) / 1000.0
        } else {
            0.0
        };

        Ok(BatchSendResult {
            sent: sent_count,
            received: received_count,
            failed: failed_count,
            duration: start.elapsed(),
            avg_rtt_ms: avg_rtt,
        })
    }

    /// Send UDP probes in optimized batches
    pub async fn send_udp_batch(
        &self,
        target_ip: IpAddr,
        ports: &[u16],
    ) -> anyhow::Result<BatchSendResult> {
        use futures::stream::{self, StreamExt};
        use crate::network::sender::PacketSender;

        let start = Instant::now();

        let sent = AtomicU64::new(0);
        let received = AtomicU64::new(0);
        let failed = AtomicU64::new(0);
        let total_rtt = AtomicU64::new(0);

        stream::iter(ports.iter().copied())
            .map(|port| {
                let semaphore = self.semaphore.clone();
                let socket_pool = self.socket_pool.clone();
                let buffer_pool = self.buffer_pool.clone();
                let sent = &sent;
                let received = &received;
                let failed = &failed;
                let total_rtt = &total_rtt;
                let timeout_ms = self.timeout_ms;

                async move {
                    let _permit = semaphore.acquire().await.ok()?;
                    let socket = socket_pool.acquire().await.ok()?;
                    let target = SocketAddr::new(target_ip, port);
                    let send_start = Instant::now();

                    // Get service-specific probe
                    let probe = PacketSender::get_udp_probe(port);

                    if socket.send_to(&probe, target).await.is_ok() {
                        sent.fetch_add(1, Ordering::Relaxed);

                        let mut buf = buffer_pool.acquire();
                        buf.set_len(4096);

                        match tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
                            socket.recv_from(buf.as_mut_slice()),
                        ).await {
                            Ok(Ok((len, _))) if len > 0 => {
                                received.fetch_add(1, Ordering::Relaxed);
                                let rtt_us = send_start.elapsed().as_micros() as u64;
                                total_rtt.fetch_add(rtt_us, Ordering::Relaxed);
                            }
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                                // Port is closed - still count as response
                                received.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        buffer_pool.release(buf);
                    } else {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }

                    socket_pool.release(socket);
                    Some(())
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await;

        let sent_count = sent.load(Ordering::Relaxed);
        let received_count = received.load(Ordering::Relaxed);
        let failed_count = failed.load(Ordering::Relaxed);
        let total_rtt_us = total_rtt.load(Ordering::Relaxed);

        let avg_rtt = if received_count > 0 {
            (total_rtt_us as f64 / received_count as f64) / 1000.0
        } else {
            0.0
        };

        Ok(BatchSendResult {
            sent: sent_count,
            received: received_count,
            failed: failed_count,
            duration: start.elapsed(),
            avg_rtt_ms: avg_rtt,
        })
    }

    /// Get buffer pool statistics
    pub fn buffer_stats(&self) -> (u64, u64, u64) {
        self.buffer_pool.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(10, 1024);
        let buf = pool.acquire();
        assert_eq!(buf.data.len(), 1024);
        pool.release(buf);

        let (acquired, released, created) = pool.stats();
        assert_eq!(acquired, 1);
        assert_eq!(released, 1);
        assert_eq!(created, 10); // Initial count
    }

    #[test]
    fn test_packet_buffer() {
        let mut buf = PacketBuffer::new(100);
        buf.buffer()[0..5].copy_from_slice(b"hello");
        buf.set_len(5);
        assert_eq!(buf.as_slice(), b"hello");
    }

    #[tokio::test]
    async fn test_udp_socket_pool() {
        let pool = UdpSocketPool::new(5);
        let socket = pool.acquire().await.unwrap();
        assert!(socket.local_addr().is_ok());
        pool.release(socket);
    }

    #[test]
    fn test_buffer_pool_exhaustion_and_creation() {
        // Start with small pool
        let pool = BufferPool::new(2, 512);

        // Acquire more than initial count
        let b1 = pool.acquire();
        let b2 = pool.acquire();
        let b3 = pool.acquire(); // Should create new buffer

        let (acquired, _, created) = pool.stats();
        assert_eq!(acquired, 3);
        assert_eq!(created, 3); // 2 initial + 1 new

        pool.release(b1);
        pool.release(b2);
        pool.release(b3);
    }

    #[test]
    fn test_packet_buffer_reset() {
        let mut buf = PacketBuffer::new(100);
        buf.buffer()[0..10].copy_from_slice(b"0123456789");
        buf.set_len(10);
        assert_eq!(buf.as_slice().len(), 10);

        buf.reset();
        assert_eq!(buf.as_slice().len(), 0);
    }

    #[test]
    fn test_packet_buffer_set_len_clamped() {
        let mut buf = PacketBuffer::new(50);
        buf.set_len(100); // Larger than capacity
        assert_eq!(buf.as_slice().len(), 50); // Clamped to capacity
    }

    #[test]
    fn test_packet_buffer_mut_slice() {
        let mut buf = PacketBuffer::new(100);
        buf.set_len(5);
        let slice = buf.as_mut_slice();
        slice[0] = 0xAA;
        slice[4] = 0xBB;
        assert_eq!(buf.as_slice()[0], 0xAA);
        assert_eq!(buf.as_slice()[4], 0xBB);
    }

    #[test]
    fn test_batch_send_result_pps() {
        let result = BatchSendResult {
            sent: 1000,
            received: 950,
            failed: 50,
            duration: Duration::from_secs(1),
            avg_rtt_ms: 5.0,
        };
        assert_eq!(result.packets_per_second(), 1000.0);

        // Test with fractional duration
        let result2 = BatchSendResult {
            sent: 500,
            received: 450,
            failed: 50,
            duration: Duration::from_millis(500),
            avg_rtt_ms: 2.5,
        };
        assert_eq!(result2.packets_per_second(), 1000.0);
    }

    #[test]
    fn test_batch_send_result_zero_duration() {
        let result = BatchSendResult {
            sent: 100,
            received: 100,
            failed: 0,
            duration: Duration::ZERO,
            avg_rtt_ms: 0.0,
        };
        assert_eq!(result.packets_per_second(), 0.0);
    }

    #[tokio::test]
    async fn test_udp_socket_pool_reuse() {
        let pool = UdpSocketPool::new(3);

        // Acquire and release a socket
        let socket1 = pool.acquire().await.unwrap();
        let addr1 = socket1.local_addr().unwrap();
        pool.release(socket1);

        // Re-acquire - should get same socket from pool
        let socket2 = pool.acquire().await.unwrap();
        let addr2 = socket2.local_addr().unwrap();

        // Same socket should have same local address
        assert_eq!(addr1, addr2);
    }

    #[tokio::test]
    async fn test_udp_socket_pool_multiple() {
        let pool = UdpSocketPool::new(5);

        // Acquire multiple sockets concurrently
        let s1 = pool.acquire().await.unwrap();
        let s2 = pool.acquire().await.unwrap();
        let s3 = pool.acquire().await.unwrap();

        // All should have different local addresses
        let a1 = s1.local_addr().unwrap();
        let a2 = s2.local_addr().unwrap();
        let a3 = s3.local_addr().unwrap();

        assert_ne!(a1, a2);
        assert_ne!(a2, a3);
        assert_ne!(a1, a3);

        pool.release(s1);
        pool.release(s2);
        pool.release(s3);
    }

    #[test]
    fn test_batch_sender_creation() {
        let sender = BatchSender::new(10, 4096, 1000);
        assert_eq!(sender.concurrency, 10);
        assert_eq!(sender.timeout_ms, 1000);
    }

    #[test]
    fn test_buffer_pool_stats_accuracy() {
        let pool = BufferPool::new(5, 256);

        // Multiple acquire/release cycles
        for _ in 0..10 {
            let buf = pool.acquire();
            pool.release(buf);
        }

        let (acquired, released, created) = pool.stats();
        assert_eq!(acquired, 10);
        assert_eq!(released, 10);
        assert_eq!(created, 5); // Only initial buffers created
    }

    #[test]
    fn test_packet_buffer_zero_length() {
        let buf = PacketBuffer::new(100);
        assert_eq!(buf.as_slice().len(), 0);
        assert_eq!(buf.len, 0);
    }

    #[test]
    fn test_batch_send_result_clone() {
        let result = BatchSendResult {
            sent: 100,
            received: 90,
            failed: 10,
            duration: Duration::from_millis(500),
            avg_rtt_ms: 3.5,
        };

        let cloned = result.clone();
        assert_eq!(result.sent, cloned.sent);
        assert_eq!(result.received, cloned.received);
        assert_eq!(result.failed, cloned.failed);
        assert_eq!(result.duration, cloned.duration);
        assert_eq!(result.avg_rtt_ms, cloned.avg_rtt_ms);
    }
}
