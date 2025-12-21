//! NTP protocol packet builder

/// Pre-built NTP client request packet (48 bytes)
/// LI=0, VN=3, Mode=3 (client), all timestamps zero
static NTP_CLIENT_PACKET: [u8; 48] = [
    0x1b, 0x00, 0x00, 0x00, // LI/VN/Mode, Stratum, Poll, Precision
    0x00, 0x00, 0x00, 0x00, // Root Delay
    0x00, 0x00, 0x00, 0x00, // Root Dispersion
    0x00, 0x00, 0x00, 0x00, // Reference ID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reference Timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originate Timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Receive Timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transmit Timestamp
];

/// NTP client request packet builder
pub struct NtpPacket;

impl NtpPacket {
    /// Create a new NTP client request packet
    #[inline]
    pub fn new() -> Self {
        Self
    }

    /// Build the NTP packet (uses pre-built static template)
    #[inline]
    pub fn build(&self) -> Vec<u8> {
        NTP_CLIENT_PACKET.to_vec()
    }
}

impl Default for NtpPacket {
    fn default() -> Self {
        Self::new()
    }
}
