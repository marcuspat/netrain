//! Legacy `Packet`-based API, kept for crate users. Live capture goes through
//! [`crate::pipeline`], which knows the link type and does not copy the data.

use crate::classify::classify_bytes;
use crate::decode::decode_guess;
use crate::{Packet, Protocol};

/// Parse raw packet data into a Packet struct.
///
/// Accepts an Ethernet frame or a raw IP packet. Addresses come from the
/// real IP header (IPv4 or IPv6); `length` is the IP total length when only
/// a truncated IPv4 header is available, otherwise the number of bytes given.
pub fn parse_packet(data: &[u8]) -> Result<Packet, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("Empty packet data".into());
    }

    let (src_ip, dst_ip, length) = match decode_guess(data) {
        Ok(d) => (d.src.to_string(), d.dst.to_string(), data.len()),
        Err(_) => {
            let unknown = || "0.0.0.0".to_string();
            match ipv4_total_length(data) {
                Some(total) => (unknown(), unknown(), total.max(data.len())),
                None => (unknown(), unknown(), data.len()),
            }
        }
    };

    Ok(Packet {
        data: data.to_vec(),
        length,
        timestamp: 0,
        src_ip,
        dst_ip,
    })
}

fn ipv4_total_length(data: &[u8]) -> Option<usize> {
    if data.len() >= 4 && data[0] >> 4 == 4 {
        Some(usize::from(u16::from_be_bytes([data[2], data[3]])))
    } else {
        None
    }
}

/// Extract protocol from packet
pub fn extract_protocol(packet: &Packet) -> Protocol {
    // IP header protocol field is at byte 9 (0-indexed)
    if packet.data.len() > 9 {
        match packet.data[9] {
            0x06 => Protocol::TCP,
            0x11 => Protocol::UDP,
            _ => Protocol::Unknown,
        }
    } else {
        Protocol::Unknown
    }
}

/// Check that the declared length is consistent with the captured bytes.
///
/// A packet is consistent when `length` equals the number of bytes held, or
/// equals the IPv4 total-length field (a capture truncated by the snap
/// length). Returns `false` instead of panicking on inconsistent input.
pub fn validate_packet(packet: &Packet) -> bool {
    if packet.data.is_empty() {
        return false;
    }
    packet.length == packet.data.len() || ipv4_total_length(&packet.data) == Some(packet.length)
}

/// Classify protocol based on packet content. Never panics.
pub fn classify_protocol(packet: &Packet) -> Protocol {
    classify_bytes(&packet.data)
}
