//! The single per-packet path shared by live capture, replay and tests:
//! decode with the capture's real link type, then classify.

use std::net::IpAddr;

use crate::classify::classify;
use crate::decode::{decode, DecodeError, Decoded, LinkType, Transport};
use crate::Protocol;

/// What the UI and statistics need to know about one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketEvent {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    /// IP protocol number (6 TCP, 17 UDP, ...).
    pub ip_proto: u8,
    /// Transport header summary (ports, TCP flags) for threat analysis.
    pub transport: Transport,
    /// Length on the wire, which is larger than the captured length when the
    /// snap length truncated the packet.
    pub wire_len: usize,
}

impl PacketEvent {
    pub fn from_decoded(decoded: &Decoded<'_>, wire_len: usize) -> Self {
        Self {
            src: decoded.src,
            dst: decoded.dst,
            src_port: decoded.src_port(),
            dst_port: decoded.dst_port(),
            protocol: classify(decoded),
            ip_proto: decoded.ip_proto,
            transport: decoded.transport,
            wire_len: wire_len.max(decoded.captured_len),
        }
    }

    /// One line for the packet log, e.g. `[12:00:01] HTTPS 10.0.0.2 -> 1.1.1.1 [60B]`.
    pub fn log_line(&self, timestamp: &str) -> String {
        format!(
            "[{}] {:<5} {} -> {} [{}B]",
            timestamp,
            self.protocol.label(),
            self.src,
            self.dst,
            self.wire_len
        )
    }
}

/// Decode and classify one captured packet.
pub fn observe<'a>(
    link: LinkType,
    data: &'a [u8],
    wire_len: usize,
) -> Result<(PacketEvent, Decoded<'a>), DecodeError> {
    let decoded = decode(link, data)?;
    Ok((PacketEvent::from_decoded(&decoded, wire_len), decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::testutil::{ethernet, ipv4, ipv6, tcp, udp};
    use crate::decode::TcpFlags;

    #[test]
    fn ethernet_frame_yields_real_addresses_ports_and_length() {
        let frame = ethernet(
            0x0800,
            &ipv4(
                6,
                [10, 0, 0, 2],
                [1, 1, 1, 1],
                &tcp(51000, 443, TcpFlags::SYN, b""),
            ),
        );
        let (event, decoded) = observe(LinkType::Ethernet, &frame, 1514).unwrap();
        assert_eq!(event.src.to_string(), "10.0.0.2");
        assert_eq!(event.dst.to_string(), "1.1.1.1");
        assert_eq!((event.src_port, event.dst_port), (Some(51000), Some(443)));
        assert_eq!(event.protocol, Protocol::HTTPS);
        assert_eq!(
            event.wire_len, 1514,
            "wire length, not the truncated capture length"
        );
        assert!(decoded.tcp_flags().unwrap().syn());
        assert_eq!(
            event.log_line("12:00:01"),
            "[12:00:01] HTTPS 10.0.0.2 -> 1.1.1.1 [1514B]"
        );
    }

    #[test]
    fn ipv6_is_a_first_class_citizen() {
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[15] = 1;
        let mut dst = [0u8; 16];
        dst[15] = 1;
        let frame = ethernet(
            0x86dd,
            &ipv6(
                17,
                src,
                dst,
                &udp(40000, 53, &crate::dns::query("example.com")),
            ),
        );
        let (event, decoded) = observe(LinkType::Ethernet, &frame, frame.len()).unwrap();
        assert_eq!(event.protocol, Protocol::DNS);
        assert_eq!(event.src.to_string(), "2001::1");
        assert_eq!(
            event.log_line("t"),
            format!("[t] DNS   2001::1 -> ::1 [{}B]", frame.len())
        );
        assert_eq!(
            crate::dns::question_name(decoded.payload).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn non_ip_and_garbage_are_errors_not_fake_packets() {
        assert!(observe(LinkType::Ethernet, &ethernet(0x0806, &[0; 28]), 42).is_err());
        assert!(observe(LinkType::Ethernet, &[], 0).is_err());
    }
}
