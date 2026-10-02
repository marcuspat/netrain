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
pub fn eth_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4(6, src, dst, &tcp(src_port, dst_port, flags, payload)),
    )
}

/// An IPv4/UDP packet inside an Ethernet frame.
pub fn eth_udp(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    ethernet(
        0x0800,
        &ipv4(17, src, dst, &udp(src_port, dst_port, payload)),
    )
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
    // A frame too short to have addresses is returned unchanged.
    let Some((addresses, rest)) = frame.split_at_checked(12) else {
        return frame.to_vec();
    };
    let mut f = addresses.to_vec();
    f.extend_from_slice(&[0x81, 0x00]);
    f.extend_from_slice(&(vlan & 0x0fff).to_be_bytes());
    f.extend_from_slice(rest);
    f
}

/// A DNS response for `name` carrying one A/AAAA record per address. The
/// answer names use a compression pointer back to the question, as real
/// servers do.
pub fn dns_response(name: &str, addrs: &[std::net::IpAddr]) -> Vec<u8> {
    let mut m = dns_query(name);
    m[2] = 0x81; // response, recursion desired
    m[3] = 0x80; // recursion available
    m[6..8].copy_from_slice(&(addrs.len() as u16).to_be_bytes());
    for addr in addrs {
        m.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        match addr {
            std::net::IpAddr::V4(v4) => {
                m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                m.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                m.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                m.extend_from_slice(&v6.octets());
            }
        }
    }
    m
}

/// A TLS 1.2-style ClientHello record carrying `server_name` in the
/// server-name extension, preceded by one unrelated extension.
pub fn client_hello(server_name: &str) -> Vec<u8> {
    let name = server_name.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list length
    sni.push(0); // host_name
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);

    let mut extensions = vec![0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]; // ec_point_formats
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let mut body = vec![0x03, 0x03]; // client version
    body.extend_from_slice(&[0x5a; 32]); // random
    body.push(0); // session id length
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher suites
    body.extend_from_slice(&[0x01, 0x00]); // compression methods
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01, 0x00];
    handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
