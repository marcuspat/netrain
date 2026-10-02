//! Application-layer insight: which *name* a packet is about.
//!
//! Three places carry a hostname in clear text: the DNS question, the TLS
//! ClientHello's server-name extension, and the HTTP `Host` header. All of it
//! is attacker-controlled input, so every parser here is bounds-checked and
//! every name is validated before it can reach the terminal.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::decode::{Decoded, Transport};
use crate::dns;

/// Where a hostname was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    Dns,
    Sni,
    HttpHost,
}

impl NameSource {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Sni => "sni",
            Self::HttpHost => "host",
        }
    }
}

/// A validated hostname seen in a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insight {
    pub source: NameSource,
    pub name: String,
}

impl Insight {
    /// e.g. `sni=example.com`.
    pub fn label(&self) -> String {
        format!("{}={}", self.source.tag(), self.name)
    }
}

/// Accept only what a hostname may contain, lower-cased. Anything else -
/// control bytes, escape sequences, spaces, non-ASCII - is rejected so a
/// crafted packet cannot inject terminal control codes into the display.
pub fn sanitize_hostname(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let mut name = String::with_capacity(raw.len());
    for &b in raw {
        match b {
            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => name.push(char::from(b)),
            b'A'..=b'Z' => name.push(char::from(b.to_ascii_lowercase())),
            _ => return None,
        }
    }
    if name.starts_with('.') || name.contains("..") {
        return None;
    }
    Some(name)
}

fn be16(data: &[u8], at: usize) -> Option<usize> {
    let b = data.get(at..at + 2)?;
    Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
}

/// Server name from a TLS ClientHello (the start of a TLS connection).
///
/// Only the first record is examined; a ClientHello split across TCP
/// segments beyond the extension we need simply yields `None`.
pub fn tls_sni(payload: &[u8]) -> Option<String> {
    // Record header: type 22 (handshake), version, length.
    if payload.len() < 5 || payload[0] != 0x16 || payload[1] != 0x03 {
        return None;
    }
    let record = payload.get(5..)?;
    // Handshake header: type 1 (ClientHello), 24-bit length.
    if *record.first()? != 0x01 {
        return None;
    }
    let mut pos = 4; // handshake header
    pos += 2 + 32; // client version + random
    pos += 1 + usize::from(*record.get(pos)?); // session id
    pos += 2 + be16(record, pos)?; // cipher suites
    pos += 1 + usize::from(*record.get(pos)?); // compression methods
    let ext_total = be16(record, pos)?;
    pos += 2;
    let end = (pos + ext_total).min(record.len());

    // At most a bounded number of extensions; real hellos carry ~15.
    for _ in 0..64 {
        if pos + 4 > end {
            return None;
        }
        let ext_type = be16(record, pos)?;
        let ext_len = be16(record, pos + 2)?;
        let body = record.get(pos + 4..pos + 4 + ext_len)?;
        if ext_type == 0 {
            // server_name: list length, then entries of (type, length, name).
            let list_len = be16(body, 0)?;
            let list = body.get(2..2 + list_len)?;
            if *list.first()? != 0 {
                return None; // not a host_name entry
            }
            let name_len = be16(list, 1)?;
            return sanitize_hostname(list.get(3..3 + name_len)?);
        }
        pos += 4 + ext_len;
    }
    None
}

/// The `Host` header of an HTTP/1.x request, without any port.
pub fn http_host(payload: &[u8]) -> Option<String> {
    const METHODS: [&[u8]; 9] =
        [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    if !METHODS.iter().any(|m| payload.starts_with(m)) {
        return None;
    }
    // Headers only, and only a bounded prefix of them.
    let head = &payload[..payload.len().min(4096)];
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break; // end of headers
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let value = line[5..].trim_ascii();
            // Strip a port, but leave IPv6 literals ([::1]:80) alone - they
            // are not hostnames and are rejected by the sanitiser anyway.
            let host = match value.iter().rposition(|&b| b == b':') {
                Some(i) if value[i + 1..].iter().all(u8::is_ascii_digit) => &value[..i],
                _ => value,
            };
            return sanitize_hostname(host);
        }
    }
    None
}

/// QUIC long-header packet (connection setup): header-form and fixed bits
/// set, and a non-zero version. Short-header packets are indistinguishable
/// from random UDP and are not claimed.
pub fn is_quic_initial(payload: &[u8]) -> bool {
    payload.len() >= 7 && payload[0] & 0xc0 == 0xc0 && payload[1..5] != [0, 0, 0, 0]
}

/// The hostname a packet reveals, if any.
pub fn insight(decoded: &Decoded<'_>) -> Option<Insight> {
    let named = |source, name| Some(Insight { source, name });
    match decoded.transport {
        Transport::Udp { src_port, dst_port } => {
            // DNS and mDNS questions.
            if [53, 5353].contains(&src_port) || [53, 5353].contains(&dst_port) {
                return named(NameSource::Dns, dns::question_name(decoded.payload)?);
            }
            None
        }
        Transport::Tcp { .. } => {
            if let Some(name) = tls_sni(decoded.payload) {
                return named(NameSource::Sni, name);
            }
            if let Some(name) = http_host(decoded.payload) {
                return named(NameSource::HttpHost, name);
            }
            None
        }
        _ => None,
    }
}

/// Bounded map from address to the name it was last resolved from.
///
/// Filled from DNS answers seen on the wire, so the display can show
/// `93.184.216.34 (example.com)` without doing any lookups of its own -
/// a monitor that issued reverse lookups would generate the traffic it is
/// watching, and leak what it is watching to the resolver.
#[derive(Debug)]
pub struct NameCache {
    names: HashMap<IpAddr, (String, u64)>,
    capacity: usize,
    clock: u64,
}

impl Default for NameCache {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl NameCache {
    pub fn new(capacity: usize) -> Self {
        Self { names: HashMap::new(), capacity: capacity.max(1), clock: 0 }
    }

    pub fn insert(&mut self, ip: IpAddr, name: &str) {
        self.clock += 1;
        if !self.names.contains_key(&ip) && self.names.len() >= self.capacity {
            // Drop the least recently learned eighth in one pass.
            let mut ages: Vec<(u64, IpAddr)> = self.names.iter().map(|(ip, (_, t))| (*t, *ip)).collect();
            let remove = (self.capacity / 8).max(1).min(ages.len());
            ages.select_nth_unstable(remove - 1);
            for (_, old) in ages.into_iter().take(remove) {
                self.names.remove(&old);
            }
        }
        self.names.insert(ip, (name.to_string(), self.clock));
    }

    /// Learn every address in a DNS response.
    pub fn learn_from_dns(&mut self, message: &[u8]) -> usize {
        let Some((name, addrs)) = dns::answers(message) else {
            return 0;
        };
        for ip in &addrs {
            self.insert(*ip, &name);
        }
        addrs.len()
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&str> {
        self.names.get(ip).map(|(name, _)| name.as_str())
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// `1.2.3.4 (example.com)` when known, otherwise just the address.
    pub fn display(&self, ip: &IpAddr) -> String {
        match self.get(ip) {
            Some(name) => format!("{ip} ({name})"),
            None => ip.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode, LinkType, TcpFlags};
    use crate::synth::{client_hello, dns_query, dns_response, eth_tcp, eth_udp};
    use proptest::prelude::*;

    const C: [u8; 4] = [10, 0, 0, 2];
    const S: [u8; 4] = [93, 184, 216, 34];

    #[test]
    fn sni_from_a_client_hello() {
        assert_eq!(tls_sni(&client_hello("example.com")).as_deref(), Some("example.com"));
        assert_eq!(tls_sni(&client_hello("Sub.Example.ORG")).as_deref(), Some("sub.example.org"));
    }

    #[test]
    fn sni_rejects_other_records_and_truncation() {
        let hello = client_hello("example.com");
        assert_eq!(tls_sni(&[0x17, 0x03, 0x03, 0, 1, 0]), None, "application data");
        let mut server_hello = hello.clone();
        server_hello[5] = 0x02;
        assert_eq!(tls_sni(&server_hello), None);
        for cut in 0..hello.len() {
            // Never panics; a truncated hello just has no name.
            let _ = tls_sni(&hello[..cut]);
        }
        assert_eq!(tls_sni(&hello[..hello.len() - 3]), None);
    }

    #[test]
    fn names_that_could_attack_the_terminal_are_rejected() {
        assert_eq!(tls_sni(&client_hello("evil\x1b[2Jexample.com")), None);
        assert_eq!(sanitize_hostname(b"ok-host_1.example"), Some("ok-host_1.example".into()));
        assert_eq!(sanitize_hostname(b"has space.com"), None);
        assert_eq!(sanitize_hostname(b"caf\xc3\xa9.fr"), None);
        assert_eq!(sanitize_hostname(b""), None);
        assert_eq!(sanitize_hostname(b".leading"), None);
        assert_eq!(sanitize_hostname(b"a..b"), None);
        assert_eq!(sanitize_hostname(&[b'a'; 254]), None);
    }

    #[test]
    fn http_host_header() {
        let req = b"GET /index.html HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\nbody";
        assert_eq!(http_host(req).as_deref(), Some("example.com"));
        assert_eq!(http_host(b"POST / HTTP/1.1\r\nhost:api.test\r\n\r\n").as_deref(), Some("api.test"));
        // Not a request, no header, header only in the body, hostile value.
        assert_eq!(http_host(b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\n"), None);
        assert_eq!(http_host(b"GET / HTTP/1.0\r\n\r\n"), None);
        assert_eq!(http_host(b"GET / HTTP/1.1\r\n\r\nHost: smuggled.example\r\n"), None);
        assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: a\x1b[31m.com\r\n\r\n"), None);
        assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"), None);
    }

    #[test]
    fn quic_long_header() {
        assert!(is_quic_initial(&[0xc3, 0, 0, 0, 1, 8, 1, 2, 3]));
        assert!(!is_quic_initial(&[0x43, 0, 0, 0, 1, 8, 1, 2, 3]), "short header");
        assert!(!is_quic_initial(&[0xc3, 0, 0, 0, 0, 8, 1, 2, 3]), "version negotiation");
        assert!(!is_quic_initial(&[0xc3, 0, 0]));
    }

    #[test]
    fn insight_picks_the_right_parser_per_transport() {
        let pkt = eth_udp(C, [9, 9, 9, 9], 40000, 53, &dns_query("example.com"));
        let d = decode(LinkType::Ethernet, &pkt).unwrap();
        assert_eq!(insight(&d).unwrap().label(), "dns=example.com");

        let pkt = eth_tcp(C, S, 50000, 443, TcpFlags::ACK, &client_hello("example.com"));
        let d = decode(LinkType::Ethernet, &pkt).unwrap();
        assert_eq!(insight(&d).unwrap().label(), "sni=example.com");

        // TLS on a non-standard port is still recognised by content.
        let pkt = eth_tcp(C, S, 50000, 8443, TcpFlags::ACK, &client_hello("alt.example"));
        assert_eq!(insight(&decode(LinkType::Ethernet, &pkt).unwrap()).unwrap().label(), "sni=alt.example");

        let pkt = eth_tcp(C, S, 50000, 80, TcpFlags::ACK, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(insight(&decode(LinkType::Ethernet, &pkt).unwrap()).unwrap().label(), "host=example.com");

        let pkt = eth_tcp(C, S, 50000, 443, TcpFlags::SYN, b"");
        assert_eq!(insight(&decode(LinkType::Ethernet, &pkt).unwrap()), None);
        let pkt = eth_udp(C, S, 40000, 123, &dns_query("not-dns.example"));
        assert_eq!(insight(&decode(LinkType::Ethernet, &pkt).unwrap()), None, "port 123 is not DNS");
    }

    #[test]
    fn name_cache_learns_from_answers_and_stays_bounded() {
        let mut cache = NameCache::new(8);
        let resp = dns_response("example.com", &[IpAddr::from(S), "2606:2800::1".parse().unwrap()]);
        assert_eq!(cache.learn_from_dns(&resp), 2);
        assert_eq!(cache.get(&IpAddr::from(S)), Some("example.com"));
        assert_eq!(cache.display(&IpAddr::from(S)), "93.184.216.34 (example.com)");
        assert_eq!(cache.display(&IpAddr::from(C)), "10.0.0.2");
        assert_eq!(cache.learn_from_dns(&dns_query("example.com")), 0, "a query has no answers");
        assert_eq!(cache.learn_from_dns(b"junk"), 0);

        for i in 0..100u8 {
            cache.insert(IpAddr::from([10, 1, 1, i]), "x.example");
            assert!(cache.len() <= 8);
        }
        assert_eq!(cache.get(&IpAddr::from([10, 1, 1, 99])), Some("x.example"), "newest kept");
        assert_eq!(cache.get(&IpAddr::from(S)), None, "oldest evicted");
    }

    proptest! {
        #[test]
        fn parsers_never_panic_and_only_emit_safe_names(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            for name in [tls_sni(&data), http_host(&data)].into_iter().flatten() {
                prop_assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)));
            }
            let _ = is_quic_initial(&data);
        }

        #[test]
        fn mutated_client_hellos_never_panic(
            flips in proptest::collection::vec((0usize..200, any::<u8>()), 0..8),
            cut in 0usize..220,
        ) {
            let mut hello = client_hello("www.example.com");
            for (i, b) in flips {
                let len = hello.len();
                hello[i % len] = b;
            }
            hello.truncate(cut.min(hello.len()));
            if let Some(name) = tls_sni(&hello) {
                prop_assert!(sanitize_hostname(name.as_bytes()).is_some());
            }
        }
    }
}
