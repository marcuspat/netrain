//! Builders for well-formed synthetic packets.
//!
//! Used by the test suite, the fixture generator and anyone who wants to
//! feed the pipeline without a network. Nothing here touches a socket.


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

/// An IPv4/TCP packet inside an Ethernet frame.
pub fn eth_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    ethernet(0x0800, &ipv4(6, src, dst, &tcp(src_port, dst_port, flags, payload)))
}

/// An IPv4/UDP packet inside an Ethernet frame.
pub fn eth_udp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    ethernet(0x0800, &ipv4(17, src, dst, &udp(src_port, dst_port, payload)))
}

/// A DNS query message for `name` (A record, recursion desired).
pub fn dns_query(name: &str) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

/// Insert an 802.1Q tag with `vlan` into an Ethernet frame.
pub fn with_vlan(frame: &[u8], vlan: u16) -> Vec<u8> {
    let mut f = frame[..12].to_vec();
    f.extend_from_slice(&[0x81, 0x00]);
    f.extend_from_slice(&(vlan & 0x0fff).to_be_bytes());
    f.extend_from_slice(&frame[12..]);
    f
}
