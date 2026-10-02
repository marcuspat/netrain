//! Protocol classification on top of [`crate::decode`].
//!
//! One rule set for every caller: payload signatures first (they are right
//! regardless of port), then well-known ports, then the bare transport.

use crate::decode::{Decoded, Transport};
use crate::Protocol;

const HTTP_PREFIXES: [&[u8]; 10] = [
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
    b"HTTP/",
];

/// Recognise an application protocol from the first bytes of a stream.
pub fn classify_payload(payload: &[u8]) -> Option<Protocol> {
    if payload.starts_with(b"SSH-") {
        return Some(Protocol::SSH);
    }
    if HTTP_PREFIXES.iter().any(|p| payload.starts_with(p)) {
        return Some(Protocol::HTTP);
    }
    if is_tls_record(payload) {
        return Some(Protocol::HTTPS);
    }
    None
}

/// A TLS record header: content type 20..=23, then version major 3.
///
/// A lone leading `0x16` byte is still accepted so that a truncated capture
/// of a handshake is recognised.
pub fn is_tls_record(payload: &[u8]) -> bool {
    match payload {
        [0x14..=0x17, 0x03, 0x00..=0x04, ..] => true,
        [0x16] => true,
        _ => false,
    }
}

/// Classify a decoded packet.
pub fn classify(decoded: &Decoded<'_>) -> Protocol {
    match decoded.transport {
        Transport::Tcp { src_port, dst_port, .. } => {
            if let Some(p) = classify_payload(decoded.payload) {
                return p;
            }
            match (src_port, dst_port) {
                (22, _) | (_, 22) => Protocol::SSH,
                (443, _) | (_, 443) => Protocol::HTTPS,
                (80, _) | (_, 80) => Protocol::HTTP,
                (53, _) | (_, 53) => Protocol::DNS,
                _ => Protocol::TCP,
            }
        }
        Transport::Udp { src_port, dst_port } => {
            if let Some(p) = udp_service(src_port).or_else(|| udp_service(dst_port)) {
                return p;
            }
            if (src_port == 443 || dst_port == 443) && crate::inspect::is_quic_initial(decoded.payload) {
                return Protocol::QUIC;
            }
            Protocol::UDP
        }
        Transport::Icmp { .. } | Transport::Icmpv6 { .. } => Protocol::ICMP,
        _ => Protocol::Unknown,
    }
}

/// Well-known UDP services by port.
fn udp_service(port: u16) -> Option<Protocol> {
    match port {
        53 => Some(Protocol::DNS),
        5353 => Some(Protocol::MDNS),
        123 => Some(Protocol::NTP),
        67 | 68 | 546 | 547 => Some(Protocol::DHCP),
        1900 => Some(Protocol::SSDP),
        _ => None,
    }
}

/// Classify a buffer of unknown framing (legacy `Packet`-based API).
///
/// Never panics. Callers historically passed three different things here -
/// a bare application payload, a raw IP packet, or an Ethernet frame - so
/// this tries each interpretation in turn. Live capture does not use this:
/// it knows the link type and calls [`classify`] directly.
pub fn classify_bytes(data: &[u8]) -> Protocol {
    if let Some(p) = classify_payload(data) {
        return p;
    }
    if let Ok(decoded) = crate::decode::decode_guess(data) {
        return classify(&decoded);
    }
    // A bare DNS message (no IP/UDP headers).
    if crate::dns::question_name(data).is_some() {
        return Protocol::DNS;
    }
    // Truncated IPv4 header: the protocol byte is still readable.
    if data.len() > 9 && data[0] >> 4 == 4 {
        return match data[9] {
            crate::decode::ip_proto::TCP => Protocol::TCP,
            crate::decode::ip_proto::UDP => Protocol::UDP,
            _ => Protocol::Unknown,
        };
    }
    Protocol::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::testutil::{ethernet, ipv4, ipv6, tcp, udp};
    use crate::decode::{decode, LinkType, TcpFlags};
    use proptest::prelude::*;

    const A: [u8; 4] = [10, 0, 0, 2];
    const B: [u8; 4] = [93, 184, 216, 34];

    fn class_tcp(sp: u16, dp: u16, payload: &[u8]) -> Protocol {
        let pkt = ethernet(0x0800, &ipv4(6, A, B, &tcp(sp, dp, TcpFlags::ACK, payload)));
        classify(&decode(LinkType::Ethernet, &pkt).unwrap())
    }

    #[test]
    fn payload_signature_beats_port() {
        assert_eq!(class_tcp(50000, 8080, b"GET /x HTTP/1.1\r\n"), Protocol::HTTP);
        assert_eq!(class_tcp(50000, 2222, b"SSH-2.0-OpenSSH_9.6\r\n"), Protocol::SSH);
        assert_eq!(class_tcp(50000, 8443, &[0x16, 0x03, 0x01, 0x02, 0x00]), Protocol::HTTPS);
        // plain HTTP spoken on 443 is HTTP, not HTTPS
        assert_eq!(class_tcp(50000, 443, b"HEAD / HTTP/1.1\r\n"), Protocol::HTTP);
    }

    #[test]
    fn ports_decide_when_there_is_no_payload() {
        assert_eq!(class_tcp(50000, 22, b""), Protocol::SSH);
        assert_eq!(class_tcp(443, 50000, b""), Protocol::HTTPS);
        assert_eq!(class_tcp(50000, 80, b""), Protocol::HTTP);
        assert_eq!(class_tcp(50000, 53, b""), Protocol::DNS);
        assert_eq!(class_tcp(50000, 5432, b""), Protocol::TCP);
    }

    #[test]
    fn tls_application_data_is_https_but_random_bytes_are_not() {
        assert_eq!(class_tcp(50000, 9999, &[0x17, 0x03, 0x03, 0x00, 0x20, 1, 2, 3]), Protocol::HTTPS);
        assert_eq!(class_tcp(50000, 9999, &[0x16, 0x99, 0x01]), Protocol::TCP);
    }

    #[test]
    fn udp_and_ipv6() {
        let pkt = ipv4(17, A, B, &udp(40000, 53, b"\0\0"));
        assert_eq!(classify(&decode(LinkType::RawIp, &pkt).unwrap()), Protocol::DNS);
        let pkt = ipv4(17, A, B, &udp(40000, 9999, b""));
        assert_eq!(classify(&decode(LinkType::RawIp, &pkt).unwrap()), Protocol::UDP);
        let pkt = ethernet(0x86dd, &ipv6(6, [1; 16], [2; 16], &tcp(50000, 443, TcpFlags::SYN, b"")));
        assert_eq!(classify(&decode(LinkType::Ethernet, &pkt).unwrap()), Protocol::HTTPS);
    }

    #[test]
    fn udp_services_icmp_and_quic_have_their_own_labels() {
        let udp_class = |sp: u16, dp: u16, payload: &[u8]| {
            let pkt = ipv4(17, A, B, &udp(sp, dp, payload));
            classify(&decode(LinkType::RawIp, &pkt).unwrap())
        };
        assert_eq!(udp_class(40000, 123, &[0x1b; 48]), Protocol::NTP);
        assert_eq!(udp_class(68, 67, b""), Protocol::DHCP);
        assert_eq!(udp_class(546, 547, b""), Protocol::DHCP);
        assert_eq!(udp_class(5353, 5353, b""), Protocol::MDNS);
        assert_eq!(udp_class(50000, 1900, b"M-SEARCH * HTTP/1.1\r\n"), Protocol::SSDP);
        // The reply comes *from* the service port.
        assert_eq!(udp_class(123, 40000, b""), Protocol::NTP);

        // QUIC connection setup on UDP 443; other UDP on 443 is just UDP.
        assert_eq!(udp_class(40000, 443, &[0xc3, 0, 0, 0, 1, 8, 1, 2, 3]), Protocol::QUIC);
        assert_eq!(udp_class(40000, 443, &[0x40, 1, 2, 3, 4, 5, 6, 7, 8]), Protocol::UDP);
        assert_eq!(udp_class(40000, 8443, &[0xc3, 0, 0, 0, 1, 8, 1, 2, 3]), Protocol::UDP);

        let pkt = ipv4(1, A, B, &[8, 0, 0, 0]);
        assert_eq!(classify(&decode(LinkType::RawIp, &pkt).unwrap()), Protocol::ICMP);
        let pkt = ipv6(58, [1; 16], [2; 16], &[135, 0, 0, 0]);
        assert_eq!(classify(&decode(LinkType::RawIp, &pkt).unwrap()), Protocol::ICMP);
        // GRE has no label of its own.
        let pkt = ipv4(47, A, B, &[0; 8]);
        assert_eq!(classify(&decode(LinkType::RawIp, &pkt).unwrap()), Protocol::Unknown);
    }

    #[test]
    fn classify_bytes_handles_every_legacy_shape() {
        assert_eq!(classify_bytes(&[]), Protocol::Unknown);
        assert_eq!(classify_bytes(b"GET / HTTP/1.1\r\n"), Protocol::HTTP);
        assert_eq!(classify_bytes(&[0x45, 0, 0, 0x3c, 0, 0, 0x40, 0, 0x40, 0x11]), Protocol::UDP);
        let raw = ipv4(6, A, B, &tcp(1, 22, 0x10, b""));
        assert_eq!(classify_bytes(&raw), Protocol::SSH);
        assert_eq!(classify_bytes(&ethernet(0x0800, &raw)), Protocol::SSH);
        assert_eq!(classify_bytes(&[0u8; 100]), Protocol::Unknown);
    }

    proptest! {
        #[test]
        fn classify_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = classify_bytes(&data);
        }
    }
}
