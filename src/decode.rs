//! Zero-copy, panic-free layered packet decoder.
//!
//! This is the single place that knows how bytes on the wire are laid out.
//! It walks link layer -> (VLAN tags) -> IPv4/IPv6 (-> extension headers) ->
//! TCP/UDP/ICMP and hands back borrowed views into the original buffer.
//!
//! Design rules:
//! * never index without a bounds check - every malformed or truncated input
//!   yields a [`DecodeError`], never a panic (see the property tests);
//! * never allocate - [`Decoded`] only borrows from the input;
//! * honour the real header lengths (IPv4 IHL, TCP data offset, IPv6
//!   extension chains) instead of assuming 20-byte headers.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Link-layer framing of a captured packet (a subset of pcap's DLT_* values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    /// DLT_EN10MB - Ethernet II, optionally with 802.1Q / 802.1ad tags.
    Ethernet,
    /// DLT_RAW / DLT_IPV4 / DLT_IPV6 - the buffer starts at the IP header.
    RawIp,
    /// DLT_NULL / DLT_LOOP - 4-byte address family header (BSD loopback).
    Null,
    /// DLT_LINUX_SLL - Linux "cooked" capture v1 (the `any` device).
    LinuxSll,
    /// DLT_LINUX_SLL2 - Linux "cooked" capture v2.
    LinuxSll2,
}

impl LinkType {
    /// Map a pcap datalink value (`pcap_datalink()`) to a [`LinkType`].
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            1 => Some(Self::Ethernet),
            0 | 108 => Some(Self::Null),
            12 | 14 | 101 | 228 | 229 => Some(Self::RawIp),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            _ => None,
        }
    }

    /// Best-effort guess for buffers of unknown origin (tests, legacy callers).
    ///
    /// Prefer [`LinkType::from_dlt`] with the capture's real datalink type:
    /// a guess can be wrong, e.g. an Ethernet frame whose destination MAC
    /// starts with `0x45` looks like an IPv4 header.
    pub fn guess(data: &[u8]) -> Self {
        if data.len() >= 14 {
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            if matches!(
                ethertype,
                ETHERTYPE_IPV4 | ETHERTYPE_IPV6 | ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_ARP
            ) {
                return Self::Ethernet;
            }
        }
        Self::RawIp
    }
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// IANA protocol numbers used by the decoder.
pub mod ip_proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// Which layer a decode failure happened in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Link,
    Network,
    Transport,
}

/// Why a buffer could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ends before the header of this layer does.
    Truncated(Layer),
    /// The link layer carries something other than IP (ARP, LLDP, ...).
    NotIp { ethertype: u16 },
    /// The IP version nibble is neither 4 nor 6.
    BadIpVersion(u8),
    /// A header length field is smaller than the minimum legal header.
    BadHeaderLength(Layer),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(l) => write!(f, "packet truncated in {l:?} layer"),
            Self::NotIp { ethertype } => write!(f, "not an IP packet (ethertype {ethertype:#06x})"),
            Self::BadIpVersion(v) => write!(f, "unsupported IP version {v}"),
            Self::BadHeaderLength(l) => write!(f, "invalid header length in {l:?} layer"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// TCP flag byte with named accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    pub fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }
    pub fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }
    pub fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }
    pub fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }
    /// A connection *attempt*: SYN set, ACK clear. A SYN-ACK is the reply
    /// from a server and must not be counted towards scans or SYN floods.
    pub fn is_connection_attempt(self) -> bool {
        self.syn() && !self.ack()
    }
    /// No flags at all - never legitimate, used by NULL scans.
    pub fn is_null(self) -> bool {
        self.0 & 0x3f == 0
    }
    /// FIN+PSH+URG without SYN/ACK/RST - the classic Xmas scan.
    pub fn is_xmas(self) -> bool {
        self.0 & 0x3f == Self::FIN | Self::PSH | Self::URG
    }
}

/// Decoded transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp { src_port: u16, dst_port: u16, flags: TcpFlags },
    Udp { src_port: u16, dst_port: u16 },
    Icmp { icmp_type: u8, code: u8 },
    Icmpv6 { icmp_type: u8, code: u8 },
    /// A non-first IP fragment: the transport header lives in another packet.
    Fragment,
    /// Any other IP protocol (GRE, ESP, SCTP, ...).
    Other,
}

/// A fully decoded packet. Borrows from the capture buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Final IP protocol number (after any IPv6 extension headers).
    pub ip_proto: u8,
    /// IPv4 TTL / IPv6 hop limit.
    pub ttl: u8,
    /// Outermost 802.1Q VLAN id, if the frame was tagged.
    pub vlan: Option<u16>,
    pub transport: Transport,
    /// Application payload (empty for fragments and unknown protocols).
    pub payload: &'a [u8],
    /// Number of captured bytes, including the link header.
    pub captured_len: usize,
}

impl Decoded<'_> {
    pub fn src_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp { src_port, .. } | Transport::Udp { src_port, .. } => Some(src_port),
            _ => None,
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp { dst_port, .. } | Transport::Udp { dst_port, .. } => Some(dst_port),
            _ => None,
        }
    }

    pub fn tcp_flags(&self) -> Option<TcpFlags> {
        match self.transport {
            Transport::Tcp { flags, .. } => Some(flags),
            _ => None,
        }
    }
}

#[inline]
fn be16(data: &[u8], at: usize, layer: Layer) -> Result<u16, DecodeError> {
    match data.get(at..at + 2) {
        Some(b) => Ok(u16::from_be_bytes([b[0], b[1]])),
        None => Err(DecodeError::Truncated(layer)),
    }
}

/// Decode a captured packet with a known link type.
pub fn decode(link: LinkType, data: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    let (ip_offset, vlan) = match link {
        LinkType::RawIp => (0, None),
        LinkType::Ethernet => strip_ethernet(data)?,
        LinkType::Null => {
            if data.len() < 4 {
                return Err(DecodeError::Truncated(Layer::Link));
            }
            (4, None)
        }
        LinkType::LinuxSll => {
            let ethertype = be16(data, 14, Layer::Link)?;
            if ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6 {
                return Err(DecodeError::NotIp { ethertype });
            }
            (16, None)
        }
        LinkType::LinuxSll2 => {
            let ethertype = be16(data, 0, Layer::Link)?;
            if data.len() < 20 {
                return Err(DecodeError::Truncated(Layer::Link));
            }
            if ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6 {
                return Err(DecodeError::NotIp { ethertype });
            }
            (20, None)
        }
    };

    let ip = data.get(ip_offset..).ok_or(DecodeError::Truncated(Layer::Link))?;
    let first = *ip.first().ok_or(DecodeError::Truncated(Layer::Network))?;
    let mut decoded = match first >> 4 {
        4 => decode_ipv4(ip)?,
        6 => decode_ipv6(ip)?,
        v => return Err(DecodeError::BadIpVersion(v)),
    };
    decoded.vlan = vlan;
    decoded.captured_len = data.len();
    Ok(decoded)
}

/// Decode a buffer whose link type is unknown, using [`LinkType::guess`].
pub fn decode_guess(data: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    decode(LinkType::guess(data), data)
}

/// Returns (offset of the IP header, outermost VLAN id).
fn strip_ethernet(data: &[u8]) -> Result<(usize, Option<u16>), DecodeError> {
    let mut offset = 12;
    let mut ethertype = be16(data, offset, Layer::Link)?;
    offset += 2;
    let mut vlan = None;
    // At most two tags (802.1ad QinQ); anything deeper is not real traffic.
    for _ in 0..2 {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        let tci = be16(data, offset, Layer::Link)?;
        if vlan.is_none() {
            vlan = Some(tci & 0x0fff);
        }
        ethertype = be16(data, offset + 2, Layer::Link)?;
        offset += 4;
    }
    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => Ok((offset, vlan)),
        other => Err(DecodeError::NotIp { ethertype: other }),
    }
}

fn decode_ipv4(ip: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    if ip.len() < 20 {
        return Err(DecodeError::Truncated(Layer::Network));
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 {
        return Err(DecodeError::BadHeaderLength(Layer::Network));
    }
    if ip.len() < ihl {
        return Err(DecodeError::Truncated(Layer::Network));
    }
    // Trust the IP total length to cut off Ethernet padding, but never read
    // past what was actually captured.
    let total_len = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let end = if total_len >= ihl { total_len.min(ip.len()) } else { ip.len() };
    let fragment_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    let proto = ip[9];
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));

    let (transport, payload) = if fragment_offset != 0 {
        (Transport::Fragment, &ip[end..end])
    } else {
        decode_transport(proto, &ip[ihl..end])?
    };

    Ok(Decoded { src, dst, ip_proto: proto, ttl: ip[8], vlan: None, transport, payload, captured_len: 0 })
}

fn decode_ipv6(ip: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    if ip.len() < 40 {
        return Err(DecodeError::Truncated(Layer::Network));
    }
    let payload_len = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
    let mut next = ip[6];
    let ttl = ip[7];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&ip[8..24]);
    dst.copy_from_slice(&ip[24..40]);

    // payload_len == 0 means a jumbogram; fall back to the captured length.
    let end = if payload_len == 0 { ip.len() } else { (40 + payload_len).min(ip.len()) };
    let mut offset = 40;
    let mut is_fragment = false;

    // Walk extension headers. Bounded so a crafted chain cannot spin us.
    for _ in 0..8 {
        match next {
            // hop-by-hop, routing, destination options
            0 | 43 | 60 => {
                let hdr = ip.get(offset..offset + 2).ok_or(DecodeError::Truncated(Layer::Network))?;
                next = hdr[0];
                offset += (usize::from(hdr[1]) + 1) * 8;
            }
            // fragment header: fixed 8 bytes
            44 => {
                let hdr = ip.get(offset..offset + 8).ok_or(DecodeError::Truncated(Layer::Network))?;
                next = hdr[0];
                if u16::from_be_bytes([hdr[2], hdr[3]]) >> 3 != 0 {
                    is_fragment = true;
                }
                offset += 8;
            }
            // authentication header: length in 4-byte units, minus 2
            51 => {
                let hdr = ip.get(offset..offset + 2).ok_or(DecodeError::Truncated(Layer::Network))?;
                next = hdr[0];
                offset += (usize::from(hdr[1]) + 2) * 4;
            }
            _ => break,
        }
        if offset > end {
            return Err(DecodeError::Truncated(Layer::Network));
        }
    }

    let (transport, payload) = if is_fragment {
        (Transport::Fragment, &ip[end..end])
    } else {
        decode_transport(next, &ip[offset..end])?
    };

    Ok(Decoded {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        ip_proto: next,
        ttl,
        vlan: None,
        transport,
        payload,
        captured_len: 0,
    })
}

fn decode_transport(proto: u8, seg: &[u8]) -> Result<(Transport, &[u8]), DecodeError> {
    match proto {
        ip_proto::TCP => {
            if seg.len() < 20 {
                return Err(DecodeError::Truncated(Layer::Transport));
            }
            let data_offset = usize::from(seg[12] >> 4) * 4;
            if data_offset < 20 {
                return Err(DecodeError::BadHeaderLength(Layer::Transport));
            }
            // Options may be cut off by the snap length; the fixed header is
            // still valid, so report an empty payload rather than failing.
            let payload = seg.get(data_offset..).unwrap_or(&[]);
            Ok((
                Transport::Tcp {
                    src_port: u16::from_be_bytes([seg[0], seg[1]]),
                    dst_port: u16::from_be_bytes([seg[2], seg[3]]),
                    flags: TcpFlags(seg[13]),
                },
                payload,
            ))
        }
        ip_proto::UDP => {
            if seg.len() < 8 {
                return Err(DecodeError::Truncated(Layer::Transport));
            }
            Ok((
                Transport::Udp {
                    src_port: u16::from_be_bytes([seg[0], seg[1]]),
                    dst_port: u16::from_be_bytes([seg[2], seg[3]]),
                },
                &seg[8..],
            ))
        }
        ip_proto::ICMP | ip_proto::ICMPV6 => {
            if seg.len() < 4 {
                return Err(DecodeError::Truncated(Layer::Transport));
            }
            let (icmp_type, code) = (seg[0], seg[1]);
            let transport = if proto == ip_proto::ICMP {
                Transport::Icmp { icmp_type, code }
            } else {
                Transport::Icmpv6 { icmp_type, code }
            };
            Ok((transport, &seg[4..]))
        }
        _ => Ok((Transport::Other, &seg[seg.len()..])),
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Builders for well-formed packets, shared by unit tests across modules.

    pub fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let total = (20 + l4.len()) as u16;
        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, proto, 0x00, 0x00]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    pub fn tcp(src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&src_port.to_be_bytes());
        s.extend_from_slice(&dst_port.to_be_bytes());
        s.extend_from_slice(&[0; 8]); // seq + ack
        s.push(0x50); // data offset 5
        s.push(flags);
        s.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, csum, urg
        s.extend_from_slice(payload);
        s
    }

    pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&src_port.to_be_bytes());
        s.extend_from_slice(&dst_port.to_be_bytes());
        s.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        s.extend_from_slice(&[0, 0]);
        s.extend_from_slice(payload);
        s
    }

    pub fn ethernet(ethertype: u16, inner: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(inner);
        f
    }

    pub fn ipv6(next: u8, src: [u8; 16], dst: [u8; 16], body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(body.len() as u16).to_be_bytes());
        p.push(next);
        p.push(64);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(body);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use proptest::prelude::*;

    const A: [u8; 4] = [192, 168, 1, 10];
    const B: [u8; 4] = [10, 0, 0, 1];

    #[test]
    fn raw_ipv4_tcp_syn() {
        let pkt = ipv4(6, A, B, &tcp(40000, 443, TcpFlags::SYN, b""));
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert_eq!(d.src, IpAddr::from(A));
        assert_eq!(d.dst, IpAddr::from(B));
        assert_eq!(d.dst_port(), Some(443));
        assert_eq!(d.src_port(), Some(40000));
        assert!(d.tcp_flags().unwrap().is_connection_attempt());
        assert_eq!(d.ttl, 64);
        assert!(d.payload.is_empty());
    }

    #[test]
    fn syn_ack_is_not_a_connection_attempt() {
        let flags = TcpFlags(TcpFlags::SYN | TcpFlags::ACK);
        assert!(flags.syn() && !flags.is_connection_attempt());
    }

    #[test]
    fn scan_flag_patterns() {
        assert!(TcpFlags(0).is_null());
        assert!(TcpFlags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG).is_xmas());
        assert!(!TcpFlags(TcpFlags::ACK).is_null());
    }

    #[test]
    fn ethernet_ipv4_udp_payload() {
        let pkt = ethernet(0x0800, &ipv4(17, A, B, &udp(5353, 53, b"hello")));
        let d = decode(LinkType::Ethernet, &pkt).unwrap();
        assert_eq!(d.transport, Transport::Udp { src_port: 5353, dst_port: 53 });
        assert_eq!(d.payload, b"hello");
        assert_eq!(d.captured_len, pkt.len());
        assert_eq!(d.vlan, None);
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        // Minimum Ethernet frames are zero-padded to 60 bytes.
        let mut pkt = ethernet(0x0800, &ipv4(17, A, B, &udp(1, 2, b"x")));
        pkt.resize(60, 0);
        let d = decode(LinkType::Ethernet, &pkt).unwrap();
        assert_eq!(d.payload, b"x");
    }

    #[test]
    fn vlan_and_qinq_tags() {
        let ip = ipv4(6, A, B, &tcp(1, 22, TcpFlags::ACK, b"SSH-2.0"));
        let mut tagged = vec![0u8; 12];
        tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x2a, 0x08, 0x00]);
        tagged.extend_from_slice(&ip);
        let d = decode(LinkType::Ethernet, &tagged).unwrap();
        assert_eq!(d.vlan, Some(42));
        assert_eq!(d.payload, b"SSH-2.0");

        let mut qinq = vec![0u8; 12];
        qinq.extend_from_slice(&[0x88, 0xa8, 0x00, 0x07, 0x81, 0x00, 0x00, 0x2a, 0x08, 0x00]);
        qinq.extend_from_slice(&ip);
        let d = decode(LinkType::Ethernet, &qinq).unwrap();
        assert_eq!(d.vlan, Some(7));
        assert_eq!(d.dst_port(), Some(22));
    }

    #[test]
    fn ipv4_options_shift_the_transport_header() {
        // IHL = 6 (24-byte header). A fixed "+20" parser reads the ports wrong.
        let l4 = tcp(1234, 80, TcpFlags::SYN, b"");
        let mut pkt = ipv4(6, A, B, &[]);
        pkt[0] = 0x46;
        pkt.extend_from_slice(&[1, 1, 1, 0]); // NOP NOP NOP EOL
        pkt.extend_from_slice(&l4);
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert_eq!(d.dst_port(), Some(80));
        assert!(d.tcp_flags().unwrap().syn());
    }

    #[test]
    fn tcp_options_shift_the_payload() {
        let mut seg = tcp(1, 80, TcpFlags::ACK, &[]);
        seg[12] = 0x80; // data offset 8 -> 12 bytes of options
        seg.extend_from_slice(&[1; 12]);
        seg.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let pkt = ipv4(6, A, B, &seg);
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert!(d.payload.starts_with(b"GET "));
    }

    #[test]
    fn ipv6_udp_and_extension_headers() {
        let mut src = [0u8; 16];
        src[15] = 1;
        let mut dst = [0u8; 16];
        dst[0] = 0xfe;
        dst[1] = 0x80;
        let pkt = ipv6(17, src, dst, &udp(546, 547, b"dhcp"));
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert_eq!(d.src, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(d.dst_port(), Some(547));
        assert_eq!(d.payload, b"dhcp");

        // hop-by-hop (8 bytes) in front of TCP
        let mut body = vec![6, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&tcp(1, 443, TcpFlags::SYN, b""));
        let pkt = ethernet(0x86dd, &ipv6(0, src, dst, &body));
        let d = decode(LinkType::Ethernet, &pkt).unwrap();
        assert_eq!(d.ip_proto, 6);
        assert_eq!(d.dst_port(), Some(443));
    }

    #[test]
    fn non_first_fragment_has_no_transport() {
        let mut pkt = ipv4(6, A, B, &[0xde, 0xad, 0xbe, 0xef]);
        pkt[6] = 0x00;
        pkt[7] = 0xb9; // fragment offset 185
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert_eq!(d.transport, Transport::Fragment);
        assert_eq!(d.dst_port(), None);
    }

    #[test]
    fn icmp_and_other_protocols() {
        let pkt = ipv4(1, A, B, &[8, 0, 0, 0, 1, 2]);
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert_eq!(d.transport, Transport::Icmp { icmp_type: 8, code: 0 });
        let pkt = ipv4(47, A, B, &[0; 8]);
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        assert_eq!(d.transport, Transport::Other);
    }

    #[test]
    fn linux_cooked_and_loopback_framing() {
        let ip = ipv4(17, A, B, &udp(1, 53, b""));
        let mut sll = vec![0u8; 14];
        sll.extend_from_slice(&[0x08, 0x00]);
        sll.extend_from_slice(&ip);
        assert_eq!(decode(LinkType::LinuxSll, &sll).unwrap().dst_port(), Some(53));

        let mut sll2 = vec![0x08, 0x00];
        sll2.extend_from_slice(&[0u8; 18]);
        sll2.extend_from_slice(&ip);
        assert_eq!(decode(LinkType::LinuxSll2, &sll2).unwrap().dst_port(), Some(53));

        let mut null = vec![2, 0, 0, 0];
        null.extend_from_slice(&ip);
        assert_eq!(decode(LinkType::Null, &null).unwrap().dst_port(), Some(53));
    }

    #[test]
    fn errors_are_specific() {
        assert_eq!(decode(LinkType::RawIp, &[]), Err(DecodeError::Truncated(Layer::Network)));
        assert_eq!(decode(LinkType::Ethernet, &[0; 5]), Err(DecodeError::Truncated(Layer::Link)));
        assert_eq!(
            decode(LinkType::Ethernet, &ethernet(0x0806, &[0; 28])),
            Err(DecodeError::NotIp { ethertype: 0x0806 })
        );
        assert_eq!(decode(LinkType::RawIp, &[0x15; 40]), Err(DecodeError::BadIpVersion(1)));
        let mut bad_ihl = ipv4(6, A, B, &tcp(1, 2, 0, b""));
        bad_ihl[0] = 0x42;
        assert_eq!(decode(LinkType::RawIp, &bad_ihl), Err(DecodeError::BadHeaderLength(Layer::Network)));
        let short_tcp = ipv4(6, A, B, &[0; 10]);
        assert_eq!(decode(LinkType::RawIp, &short_tcp), Err(DecodeError::Truncated(Layer::Transport)));
    }

    #[test]
    fn dlt_mapping_and_guess() {
        assert_eq!(LinkType::from_dlt(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_dlt(113), Some(LinkType::LinuxSll));
        assert_eq!(LinkType::from_dlt(276), Some(LinkType::LinuxSll2));
        assert_eq!(LinkType::from_dlt(0), Some(LinkType::Null));
        assert_eq!(LinkType::from_dlt(101), Some(LinkType::RawIp));
        assert_eq!(LinkType::from_dlt(9999), None);

        let ip = ipv4(6, A, B, &tcp(1, 2, 0, b""));
        assert_eq!(LinkType::guess(&ip), LinkType::RawIp);
        assert_eq!(LinkType::guess(&ethernet(0x0800, &ip)), LinkType::Ethernet);
    }

    proptest! {
        /// The decoder is fed attacker-controlled bytes off the wire: it must
        /// never panic, whatever the input and whatever the link type.
        #[test]
        fn never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            for link in [LinkType::Ethernet, LinkType::RawIp, LinkType::Null, LinkType::LinuxSll, LinkType::LinuxSll2] {
                let _ = decode(link, &data);
            }
            let _ = decode_guess(&data);
        }

        /// Same, but starting from a valid packet and corrupting it, which
        /// reaches much deeper into the parser than uniform random bytes.
        #[test]
        fn never_panics_on_mutated_packets(
            flips in proptest::collection::vec((0usize..80, any::<u8>()), 0..6),
            cut in 0usize..90,
            v6 in any::<bool>(),
        ) {
            let l4 = tcp(1234, 80, TcpFlags::SYN, b"GET / HTTP/1.1\r\n\r\n");
            let ip = if v6 { ipv6(6, [1; 16], [2; 16], &l4) } else { ipv4(6, A, B, &l4) };
            let mut pkt = ethernet(if v6 { 0x86dd } else { 0x0800 }, &ip);
            for (i, b) in flips {
                let len = pkt.len();
                pkt[i % len] = b;
            }
            pkt.truncate(cut.min(pkt.len()));
            if let Ok(d) = decode(LinkType::Ethernet, &pkt) {
                prop_assert!(d.payload.len() <= pkt.len());
            }
        }

        #[test]
        fn roundtrips_ports_and_addresses(
            src in any::<[u8; 4]>(), dst in any::<[u8; 4]>(),
            sp in any::<u16>(), dp in any::<u16>(), flags in any::<u8>(),
            payload in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let pkt = ethernet(0x0800, &ipv4(6, src, dst, &tcp(sp, dp, flags, &payload)));
            let d = decode(LinkType::Ethernet, &pkt).unwrap();
            prop_assert_eq!(d.src, IpAddr::from(src));
            prop_assert_eq!(d.dst, IpAddr::from(dst));
            prop_assert_eq!(d.transport, Transport::Tcp { src_port: sp, dst_port: dp, flags: TcpFlags(flags) });
            prop_assert_eq!(d.payload, &payload[..]);
        }
    }
}
