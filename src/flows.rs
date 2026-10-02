//! Flow table: who is talking to whom, how much, and in what state.
//!
//! A flow is a bidirectional 5-tuple. Both directions of a conversation map
//! to the same entry; the side that sent the first packet we saw is the
//! initiator. Everything is bounded: the table holds at most `max_flows`
//! flows and `max_hosts` hosts, evicting the least recently active.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::decode::Transport;
use crate::pipeline::PacketEvent;
use crate::Protocol;

/// One end of a flow.
pub type Endpoint = (IpAddr, u16);

/// Direction-independent identity of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub ip_proto: u8,
    /// The lower endpoint (by address, then port).
    pub low: Endpoint,
    /// The higher endpoint.
    pub high: Endpoint,
}

impl FlowKey {
    pub fn new(ip_proto: u8, a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            Self { ip_proto, low: a, high: b }
        } else {
            Self { ip_proto, low: b, high: a }
        }
    }
}

/// Coarse TCP connection state, inferred from the flags seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Not TCP, or TCP joined mid-stream.
    Active,
    /// SYN seen, no reply yet.
    Opening,
    /// Handshake completed.
    Established,
    /// A FIN was seen.
    Closing,
    /// Reset by either side.
    Reset,
}

impl FlowState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Opening => "opening",
            Self::Established => "open",
            Self::Closing => "closing",
            Self::Reset => "reset",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub key: FlowKey,
    /// The endpoint that sent the first packet we saw.
    pub initiator: Endpoint,
    pub responder: Endpoint,
    /// Most specific application protocol seen on the flow.
    pub protocol: Protocol,
    pub state: FlowState,
    /// Initiator -> responder.
    pub packets_out: u64,
    pub bytes_out: u64,
    /// Responder -> initiator.
    pub packets_in: u64,
    pub bytes_in: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl Flow {
    pub fn packets(&self) -> u64 {
        self.packets_out + self.packets_in
    }

    pub fn bytes(&self) -> u64 {
        self.bytes_out + self.bytes_in
    }

    /// e.g. `HTTPS 10.0.0.2:51000 -> 1.1.1.1:443 open 1.2 KB`.
    pub fn summary(&self) -> String {
        format!(
            "{} {} -> {} {} {}",
            self.protocol.label(),
            fmt_endpoint(self.initiator),
            fmt_endpoint(self.responder),
            self.state.label(),
            human_bytes(self.bytes())
        )
    }
}

fn fmt_endpoint((ip, port): Endpoint) -> String {
    match (ip, port) {
        (ip, 0) => ip.to_string(),
        (IpAddr::V6(ip), port) => format!("[{ip}]:{port}"),
        (ip, port) => format!("{ip}:{port}"),
    }
}

/// `1536` -> `1.5 KB`.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Per-host totals (sent + received).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: Instant,
}

#[derive(Debug, Clone)]
pub struct FlowConfig {
    pub max_flows: usize,
    pub max_hosts: usize,
    /// A flow with no packets for this long is forgotten.
    pub idle_timeout: Duration,
    /// Closed or reset flows are forgotten sooner.
    pub closed_timeout: Duration,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            max_flows: 8192,
            max_hosts: 4096,
            idle_timeout: Duration::from_secs(60),
            closed_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub struct FlowTable {
    config: FlowConfig,
    flows: HashMap<FlowKey, Flow>,
    hosts: HashMap<IpAddr, HostStats>,
    /// Flows ever created, including ones since evicted.
    total_flows: u64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(FlowConfig::default())
    }
}

/// How specific a protocol label is; a flow keeps the most specific one.
fn specificity(p: Protocol) -> u8 {
    match p {
        Protocol::Unknown => 0,
        Protocol::TCP | Protocol::UDP => 1,
        _ => 2,
    }
}

/// Remove the least recently active entries so that at most `keep` remain.
/// Evicting in batches keeps the cost amortised O(1) per packet even when a
/// flood creates a new entry with every packet.
fn evict_oldest<K: Copy + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    keep: usize,
    last_seen: impl Fn(&V) -> Instant,
) {
    if map.len() <= keep {
        return;
    }
    let mut ages: Vec<(Instant, K)> = map.iter().map(|(k, v)| (last_seen(v), *k)).collect();
    let remove = ages.len() - keep;
    ages.select_nth_unstable_by_key(remove - 1, |(t, _)| *t);
    for (_, key) in ages.into_iter().take(remove) {
        map.remove(&key);
    }
}

impl FlowTable {
    pub fn new(config: FlowConfig) -> Self {
        Self { config, flows: HashMap::new(), hosts: HashMap::new(), total_flows: 0 }
    }

    /// Account one packet observed at `now`.
    pub fn observe(&mut self, event: &PacketEvent, now: Instant) {
        let bytes = event.wire_len as u64;
        for ip in [event.src, event.dst] {
            if !self.hosts.contains_key(&ip) && self.hosts.len() >= self.config.max_hosts {
                // Drop the oldest eighth in one go.
                let keep = self.config.max_hosts - (self.config.max_hosts / 8).max(1);
                evict_oldest(&mut self.hosts, keep, |h| h.last_seen);
            }
            let host = self.hosts.entry(ip).or_insert(HostStats { packets: 0, bytes: 0, last_seen: now });
            host.packets += 1;
            host.bytes += bytes;
            host.last_seen = now;
        }

        let src = (event.src, event.src_port.unwrap_or(0));
        let dst = (event.dst, event.dst_port.unwrap_or(0));
        let key = FlowKey::new(event.ip_proto, src, dst);

        if !self.flows.contains_key(&key) && self.flows.len() >= self.config.max_flows {
            self.expire(now);
            if self.flows.len() >= self.config.max_flows {
                let keep = self.config.max_flows - (self.config.max_flows / 8).max(1);
                evict_oldest(&mut self.flows, keep, |f| f.last_seen);
            }
        }

        let total = &mut self.total_flows;
        let flow = self.flows.entry(key).or_insert_with(|| {
            *total += 1;
            Flow {
                key,
                initiator: src,
                responder: dst,
                protocol: event.protocol,
                state: FlowState::Active,
                packets_out: 0,
                bytes_out: 0,
                packets_in: 0,
                bytes_in: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        flow.last_seen = now;
        if src == flow.initiator {
            flow.packets_out += 1;
            flow.bytes_out += bytes;
        } else {
            flow.packets_in += 1;
            flow.bytes_in += bytes;
        }
        if specificity(event.protocol) > specificity(flow.protocol) {
            flow.protocol = event.protocol;
        }
        if let Transport::Tcp { flags, .. } = event.transport {
            flow.state = if flags.rst() {
                FlowState::Reset
            } else if flags.fin() {
                FlowState::Closing
            } else if flags.is_connection_attempt() {
                // A fresh SYN on a finished flow is a new connection reusing the ports.
                FlowState::Opening
            } else if flow.state == FlowState::Opening && flags.ack() {
                // SYN-ACK from the responder, or the final ACK of the handshake.
                if flags.syn() || src == flow.initiator {
                    FlowState::Established
                } else {
                    FlowState::Opening
                }
            } else {
                flow.state
            };
            // A SYN-ACK alone means the server answered; the handshake is
            // complete once the initiator ACKs, but for display "open" on
            // SYN-ACK is the useful signal.
        }
    }

    /// Forget idle and finished flows, and idle hosts.
    pub fn expire(&mut self, now: Instant) {
        let (idle, closed) = (self.config.idle_timeout, self.config.closed_timeout);
        self.flows.retain(|_, f| {
            let quiet = now.saturating_duration_since(f.last_seen);
            let limit = if matches!(f.state, FlowState::Closing | FlowState::Reset) { closed } else { idle };
            quiet <= limit
        });
        self.hosts.retain(|_, h| now.saturating_duration_since(h.last_seen) <= idle);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Flows ever seen, including those since expired or evicted.
    pub fn total_flows(&self) -> u64 {
        self.total_flows
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    /// The `n` flows carrying the most bytes. Ties are ordered deterministically.
    pub fn top_flows(&self, n: usize) -> Vec<&Flow> {
        let mut flows: Vec<&Flow> = self.flows.values().collect();
        flows.sort_by(|a, b| {
            b.bytes().cmp(&a.bytes()).then_with(|| (a.key.low, a.key.high).cmp(&(b.key.low, b.key.high)))
        });
        flows.truncate(n);
        flows
    }

    /// The `n` hosts that sent or received the most bytes.
    pub fn top_talkers(&self, n: usize) -> Vec<(IpAddr, HostStats)> {
        let mut hosts: Vec<(IpAddr, HostStats)> = self.hosts.iter().map(|(ip, s)| (*ip, *s)).collect();
        hosts.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then_with(|| a.0.cmp(&b.0)));
        hosts.truncate(n);
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{LinkType, TcpFlags};
    use crate::pipeline::observe;
    use crate::synth::{eth_tcp, eth_udp, ethernet, ipv4, ipv6, tcp};

    const C: [u8; 4] = [10, 0, 0, 2];
    const S: [u8; 4] = [93, 184, 216, 34];

    fn ev(frame: &[u8], wire_len: usize) -> PacketEvent {
        observe(LinkType::Ethernet, frame, wire_len).unwrap().0
    }

    fn feed(t: &mut FlowTable, frame: &[u8], wire_len: usize, at: Instant) {
        t.observe(&ev(frame, wire_len), at);
    }

    #[test]
    fn both_directions_are_one_flow_with_split_counters() {
        let t0 = Instant::now();
        let mut t = FlowTable::default();
        feed(&mut t, &eth_tcp(C, S, 51000, 443, TcpFlags::SYN, b""), 74, t0);
        feed(&mut t, &eth_tcp(S, C, 443, 51000, TcpFlags::SYN | TcpFlags::ACK, b""), 74, t0);
        feed(&mut t, &eth_tcp(C, S, 51000, 443, TcpFlags::ACK, b""), 66, t0);
        feed(&mut t, &eth_tcp(S, C, 443, 51000, TcpFlags::ACK, &[0x17, 3, 3, 0, 1, 0]), 1500, t0);

        assert_eq!(t.len(), 1);
        let f = t.top_flows(1)[0];
        assert_eq!(f.initiator, (C.into(), 51000));
        assert_eq!(f.responder, (S.into(), 443));
        assert_eq!((f.packets_out, f.bytes_out), (2, 140));
        assert_eq!((f.packets_in, f.bytes_in), (2, 1574));
        assert_eq!(f.protocol, Protocol::HTTPS);
        assert_eq!(f.state, FlowState::Established);
        assert_eq!(f.summary(), "HTTPS 10.0.0.2:51000 -> 93.184.216.34:443 open 1.7 KB");
    }

    #[test]
    fn tcp_state_follows_the_flags() {
        let t0 = Instant::now();
        let mut t = FlowTable::default();
        let key = FlowKey::new(6, (C.into(), 51000), (S.into(), 80));
        feed(&mut t, &eth_tcp(C, S, 51000, 80, TcpFlags::SYN, b""), 60, t0);
        assert_eq!(t.get(&key).unwrap().state, FlowState::Opening);
        feed(&mut t, &eth_tcp(S, C, 80, 51000, TcpFlags::SYN | TcpFlags::ACK, b""), 60, t0);
        assert_eq!(t.get(&key).unwrap().state, FlowState::Established);
        feed(&mut t, &eth_tcp(C, S, 51000, 80, TcpFlags::FIN | TcpFlags::ACK, b""), 60, t0);
        assert_eq!(t.get(&key).unwrap().state, FlowState::Closing);
        feed(&mut t, &eth_tcp(S, C, 80, 51000, TcpFlags::RST, b""), 60, t0);
        assert_eq!(t.get(&key).unwrap().state, FlowState::Reset);

        // Joined mid-stream: no handshake seen, so just "active".
        feed(&mut t, &eth_tcp(C, S, 52000, 80, TcpFlags::ACK, b"x"), 60, t0);
        let mid = FlowKey::new(6, (C.into(), 52000), (S.into(), 80));
        assert_eq!(t.get(&mid).unwrap().state, FlowState::Active);
        // An unanswered SYN stays "opening" however many retries arrive.
        feed(&mut t, &eth_tcp(C, S, 53000, 81, TcpFlags::SYN, b""), 60, t0);
        feed(&mut t, &eth_tcp(C, S, 53000, 81, TcpFlags::SYN, b""), 60, t0);
        let syn = FlowKey::new(6, (C.into(), 53000), (S.into(), 81));
        assert_eq!(t.get(&syn).unwrap().state, FlowState::Opening);
    }

    #[test]
    fn protocol_label_only_becomes_more_specific() {
        let t0 = Instant::now();
        let mut t = FlowTable::default();
        // Port 8080 with no payload is plain TCP; the request reveals HTTP;
        // later bare ACKs must not downgrade it.
        feed(&mut t, &eth_tcp(C, S, 51000, 8080, TcpFlags::SYN, b""), 60, t0);
        assert_eq!(t.top_flows(1)[0].protocol, Protocol::TCP);
        feed(&mut t, &eth_tcp(C, S, 51000, 8080, TcpFlags::ACK, b"GET / HTTP/1.1\r\n"), 90, t0);
        feed(&mut t, &eth_tcp(S, C, 8080, 51000, TcpFlags::ACK, b""), 60, t0);
        assert_eq!(t.top_flows(1)[0].protocol, Protocol::HTTP);
    }

    #[test]
    fn distinct_tuples_are_distinct_flows() {
        let t0 = Instant::now();
        let mut t = FlowTable::default();
        feed(&mut t, &eth_tcp(C, S, 51000, 443, TcpFlags::SYN, b""), 60, t0);
        feed(&mut t, &eth_tcp(C, S, 51001, 443, TcpFlags::SYN, b""), 60, t0); // other source port
        feed(&mut t, &eth_udp(C, S, 51000, 443, b"q"), 60, t0); // same ports, UDP
        feed(&mut t, &ethernet(0x0800, &ipv4(1, C, S, &[8, 0, 0, 0])), 60, t0); // ICMP, no ports
        let v6 = ethernet(0x86dd, &ipv6(6, [1; 16], [2; 16], &tcp(51000, 443, TcpFlags::SYN, b"")));
        feed(&mut t, &v6, 80, t0);
        assert_eq!(t.len(), 5);
        assert_eq!(t.total_flows(), 5);
        let icmp = t.top_flows(10).into_iter().find(|f| f.key.ip_proto == 1).unwrap();
        assert_eq!(icmp.summary(), "??? 10.0.0.2 -> 93.184.216.34 active 60 B");
        let six = t.top_flows(10).into_iter().find(|f| f.initiator.0.is_ipv6()).unwrap();
        assert!(six.summary().contains("[101:101:101:101:101:101:101:101]:51000"), "{}", six.summary());
    }

    #[test]
    fn top_talkers_and_flows_rank_by_bytes() {
        let t0 = Instant::now();
        let mut t = FlowTable::default();
        feed(&mut t, &eth_tcp(C, S, 51000, 443, TcpFlags::ACK, b""), 5000, t0);
        feed(&mut t, &eth_tcp([10, 0, 0, 3], S, 51000, 443, TcpFlags::ACK, b""), 100, t0);
        for _ in 0..50 {
            // Many small packets must not outrank one big transfer.
            feed(&mut t, &eth_udp([10, 0, 0, 4], [8, 8, 8, 8], 5353, 53, b""), 60, t0);
        }
        let talkers = t.top_talkers(3);
        let ips: Vec<String> = talkers.iter().map(|(ip, _)| ip.to_string()).collect();
        // The server took part in both TCP flows. The DNS pair tie at 3000
        // bytes each; ties are broken by address so the order is stable.
        assert_eq!(ips, ["93.184.216.34", "10.0.0.2", "8.8.8.8"]);
        assert_eq!(talkers[0].1.bytes, 5100);
        assert_eq!(talkers[0].1.packets, 2);
        let flows = t.top_flows(2);
        assert_eq!(flows[0].bytes(), 5000);
        assert_eq!(flows[1].bytes(), 3000);
        assert_eq!(t.top_flows(0).len(), 0);
    }

    #[test]
    fn idle_and_closed_flows_expire_on_their_own_timeouts() {
        let t0 = Instant::now();
        let mut t = FlowTable::default();
        feed(&mut t, &eth_tcp(C, S, 51000, 443, TcpFlags::ACK, b""), 60, t0);
        feed(&mut t, &eth_tcp(C, S, 51001, 443, TcpFlags::RST, b""), 60, t0);
        t.expire(t0 + Duration::from_secs(6));
        assert_eq!(t.len(), 1, "the reset flow goes after 5s");
        assert_eq!(t.host_count(), 2);
        t.expire(t0 + Duration::from_secs(61));
        assert!(t.is_empty());
        assert_eq!(t.host_count(), 0);
        assert_eq!(t.total_flows(), 2, "the lifetime count is kept");
    }

    #[test]
    fn tables_stay_bounded_under_a_flood_of_new_flows() {
        let t0 = Instant::now();
        let cfg = FlowConfig { max_flows: 64, max_hosts: 32, ..FlowConfig::default() };
        let mut t = FlowTable::new(cfg);
        // Keep one long-lived flow busy throughout.
        let keeper = eth_tcp(C, S, 51000, 443, TcpFlags::ACK, b"");
        for i in 0..5000u32 {
            let now = t0 + Duration::from_millis(u64::from(i));
            let b = i.to_be_bytes();
            let spoofed = eth_tcp([11, b[1], b[2], b[3]], S, 1000 + (i % 60000) as u16, 80, TcpFlags::SYN, b"");
            feed(&mut t, &spoofed, 60, now);
            feed(&mut t, &keeper, 60, now);
            assert!(t.len() <= 64 && t.host_count() <= 32);
        }
        let key = FlowKey::new(6, (C.into(), 51000), (S.into(), 443));
        assert_eq!(t.get(&key).unwrap().packets(), 5000, "the active flow is never evicted");
        assert_eq!(t.total_flows(), 5001);
    }

    #[test]
    fn human_readable_sizes() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_bytes(u64::MAX), "16777216.0 TB");
    }
}
