//! Threat engine: per-source sliding windows, bounded memory, expiring alerts.
//!
//! Every method takes the current time as an argument so behaviour is fully
//! deterministic under test - nothing in here calls `Instant::now()`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::decode::{Decoded, Transport};
use crate::{Severity, ThreatLevel};

/// What kind of behaviour an alert describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    /// One source probing many ports on one host.
    PortScan,
    /// One source probing the same port on many hosts.
    HostSweep,
    /// Packets with flag combinations no real TCP stack sends (NULL, Xmas, bare FIN).
    StealthScan,
    /// Many connection attempts to one host that it is not answering.
    SynFlood,
    /// Overall packet rate above the configured ceiling.
    TrafficSpike,
}

impl AlertKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::PortScan => "Port scan",
            Self::HostSweep => "Host sweep",
            Self::StealthScan => "Stealth scan",
            Self::SynFlood => "SYN flood",
            Self::TrafficSpike => "Traffic spike",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Self::TrafficSpike => Severity::Medium,
            _ => Severity::High,
        }
    }
}

/// A live detection. Alerts are refreshed while the behaviour continues and
/// expire `alert_ttl` after it stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    /// The host responsible (absent for target-centric alerts).
    pub source: Option<IpAddr>,
    /// The host on the receiving end, when there is a single one.
    pub target: Option<IpAddr>,
    /// Human-readable evidence, e.g. `25 ports in 60s`.
    pub detail: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl Alert {
    /// One line for the UI / log.
    pub fn summary(&self) -> String {
        match (self.source, self.target) {
            (Some(s), Some(t)) => format!("{} {} -> {} ({})", self.kind.label(), s, t, self.detail),
            (Some(s), None) => format!("{} from {} ({})", self.kind.label(), s, self.detail),
            (None, Some(t)) => format!("{} on {} ({})", self.kind.label(), t, self.detail),
            (None, None) => format!("{} ({})", self.kind.label(), self.detail),
        }
    }
}

/// Tunables. Defaults are conservative: quiet on a normal workstation.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Window for scan and sweep detection.
    pub scan_window: Duration,
    /// Distinct ports on one host that make a port scan.
    pub port_scan_threshold: usize,
    /// Distinct hosts on one port that make a sweep.
    pub host_sweep_threshold: usize,
    /// Abnormal-flag packets from one source that make a stealth scan.
    pub stealth_threshold: usize,
    /// Window for SYN flood detection.
    pub flood_window: Duration,
    /// Connection attempts to one host inside `flood_window`.
    pub syn_flood_threshold: usize,
    /// Overall packets per second that count as a spike.
    pub rate_threshold: f64,
    /// How long an alert stays active after it was last refreshed.
    pub alert_ttl: Duration,
    /// Hard cap on tracked hosts (sources and flood targets, each).
    pub max_tracked_hosts: usize,
    /// Hard cap on remembered connection attempts per source.
    pub max_attempts_per_source: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            scan_window: Duration::from_secs(60),
            port_scan_threshold: 20,
            host_sweep_threshold: 20,
            stealth_threshold: 5,
            flood_window: Duration::from_secs(10),
            syn_flood_threshold: 100,
            rate_threshold: 1000.0,
            alert_ttl: Duration::from_secs(30),
            max_tracked_hosts: 4096,
            max_attempts_per_source: 512,
        }
    }
}

#[derive(Debug)]
struct SourceState {
    /// (when, destination, destination port) of recent connection attempts.
    attempts: VecDeque<(Instant, IpAddr, u16)>,
    /// Times of recent abnormal-flag packets.
    stealth: VecDeque<Instant>,
    last_seen: Instant,
}

#[derive(Debug)]
struct TargetState {
    /// Times of inbound connection attempts.
    syns: VecDeque<Instant>,
    /// Times of SYN-ACKs this host sent back.
    syn_acks: VecDeque<Instant>,
    last_seen: Instant,
}

/// See the module documentation.
#[derive(Debug)]
pub struct ThreatEngine {
    config: EngineConfig,
    sources: HashMap<IpAddr, SourceState>,
    targets: HashMap<IpAddr, TargetState>,
    alerts: HashMap<(AlertKind, Option<IpAddr>, Option<IpAddr>), Alert>,
    /// Packet timestamps inside the last second, for the rate check.
    recent: VecDeque<Instant>,
}

impl Default for ThreatEngine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

fn prune(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while queue.front().is_some_and(|&t| now.saturating_duration_since(t) > window) {
        queue.pop_front();
    }
}

impl ThreatEngine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            sources: HashMap::new(),
            targets: HashMap::new(),
            alerts: HashMap::new(),
            recent: VecDeque::new(),
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Feed one decoded packet observed at `now`.
    pub fn observe(&mut self, decoded: &Decoded<'_>, now: Instant) {
        self.observe_rate(now);

        let Transport::Tcp { dst_port, flags, .. } = decoded.transport else {
            return;
        };

        if flags.is_connection_attempt() {
            self.observe_attempt(decoded.src, decoded.dst, dst_port, now);
            self.observe_syn(decoded.dst, now);
        } else if flags.syn() && flags.ack() {
            // The *sender* of a SYN-ACK is a host answering its SYNs.
            if let Some(target) = self.targets.get_mut(&decoded.src) {
                target.syn_acks.push_back(now);
                target.last_seen = now;
            }
        } else if flags.is_null() || flags.is_xmas() || flags.0 & 0x3f == crate::decode::TcpFlags::FIN {
            self.observe_stealth(decoded.src, now);
        }
    }

    fn observe_rate(&mut self, now: Instant) {
        self.recent.push_back(now);
        prune(&mut self.recent, now, Duration::from_secs(1));
        // The queue only needs to prove the threshold was crossed.
        let cap = (self.config.rate_threshold as usize).saturating_add(1).max(1);
        while self.recent.len() > cap {
            self.recent.pop_front();
        }
        if self.recent.len() as f64 > self.config.rate_threshold {
            let detail = format!("over {} packets/s", self.config.rate_threshold as u64);
            self.raise(AlertKind::TrafficSpike, None, None, detail, now);
        }
    }

    fn observe_attempt(&mut self, src: IpAddr, dst: IpAddr, port: u16, now: Instant) {
        Self::make_room(&mut self.sources, self.config.max_tracked_hosts, &src, |s| s.last_seen);
        let window = self.config.scan_window;
        let cap = self.config.max_attempts_per_source;
        let state = self.sources.entry(src).or_insert_with(|| SourceState {
            attempts: VecDeque::new(),
            stealth: VecDeque::new(),
            last_seen: now,
        });
        state.last_seen = now;
        state.attempts.push_back((now, dst, port));
        while state.attempts.front().is_some_and(|&(t, _, _)| now.saturating_duration_since(t) > window) {
            state.attempts.pop_front();
        }
        while state.attempts.len() > cap {
            state.attempts.pop_front();
        }

        // Vertical scan: many ports on the host just probed.
        let ports: HashSet<u16> = state.attempts.iter().filter(|a| a.1 == dst).map(|a| a.2).collect();
        // Horizontal sweep: many hosts on the port just probed.
        let hosts: HashSet<IpAddr> = state.attempts.iter().filter(|a| a.2 == port).map(|a| a.1).collect();
        let secs = window.as_secs();

        if ports.len() >= self.config.port_scan_threshold {
            let detail = format!("{} ports in {}s", ports.len(), secs);
            self.raise(AlertKind::PortScan, Some(src), Some(dst), detail, now);
        }
        if hosts.len() >= self.config.host_sweep_threshold {
            let detail = format!("{} hosts on port {} in {}s", hosts.len(), port, secs);
            self.raise(AlertKind::HostSweep, Some(src), None, detail, now);
        }
    }

    fn observe_syn(&mut self, dst: IpAddr, now: Instant) {
        Self::make_room(&mut self.targets, self.config.max_tracked_hosts, &dst, |t| t.last_seen);
        let window = self.config.flood_window;
        let threshold = self.config.syn_flood_threshold;
        let state = self.targets.entry(dst).or_insert_with(|| TargetState {
            syns: VecDeque::new(),
            syn_acks: VecDeque::new(),
            last_seen: now,
        });
        state.last_seen = now;
        state.syns.push_back(now);
        prune(&mut state.syns, now, window);
        prune(&mut state.syn_acks, now, window);
        // Bounded: beyond a few multiples of the threshold more history adds nothing.
        let cap = threshold.saturating_mul(4).max(16);
        while state.syns.len() > cap {
            state.syns.pop_front();
        }
        while state.syn_acks.len() > cap {
            state.syn_acks.pop_front();
        }

        // A busy server sees many SYNs too, but answers them. A flood is a
        // burst of attempts of which fewer than half were answered.
        let (syns, answered) = (state.syns.len(), state.syn_acks.len());
        if syns >= threshold && answered * 2 < syns {
            let detail = format!("{} SYNs, {} answered in {}s", syns, answered, window.as_secs());
            self.raise(AlertKind::SynFlood, None, Some(dst), detail, now);
        }
    }

    fn observe_stealth(&mut self, src: IpAddr, now: Instant) {
        Self::make_room(&mut self.sources, self.config.max_tracked_hosts, &src, |s| s.last_seen);
        let window = self.config.scan_window;
        let cap = self.config.stealth_threshold.saturating_mul(4).max(16);
        let state = self.sources.entry(src).or_insert_with(|| SourceState {
            attempts: VecDeque::new(),
            stealth: VecDeque::new(),
            last_seen: now,
        });
        state.last_seen = now;
        state.stealth.push_back(now);
        prune(&mut state.stealth, now, window);
        while state.stealth.len() > cap {
            state.stealth.pop_front();
        }
        if state.stealth.len() >= self.config.stealth_threshold {
            let detail = format!("{} NULL/FIN/Xmas probes", state.stealth.len());
            self.raise(AlertKind::StealthScan, Some(src), None, detail, now);
        }
    }

    /// Keep a host table within its cap by evicting the least recently seen
    /// entry. An attacker spoofing sources can therefore cost at most
    /// `max_tracked_hosts` entries, never unbounded memory.
    fn make_room<S>(map: &mut HashMap<IpAddr, S>, cap: usize, incoming: &IpAddr, last_seen: fn(&S) -> Instant) {
        if map.len() < cap || map.contains_key(incoming) {
            return;
        }
        if let Some(oldest) = map.iter().min_by_key(|(_, s)| last_seen(s)).map(|(ip, _)| *ip) {
            map.remove(&oldest);
        }
    }

    fn raise(
        &mut self,
        kind: AlertKind,
        source: Option<IpAddr>,
        target: Option<IpAddr>,
        detail: String,
        now: Instant,
    ) {
        // Alerts are keyed by who/what, so a continuing scan refreshes one
        // alert rather than producing thousands. Bounded like the host tables.
        if self.alerts.len() >= self.config.max_tracked_hosts {
            self.expire(now);
            if self.alerts.len() >= self.config.max_tracked_hosts {
                if let Some(k) = self.alerts.iter().min_by_key(|(_, a)| a.last_seen).map(|(k, _)| *k) {
                    self.alerts.remove(&k);
                }
            }
        }
        self.alerts
            .entry((kind, source, target))
            .and_modify(|a| {
                a.last_seen = now;
                a.detail.clone_from(&detail);
            })
            .or_insert(Alert { kind, source, target, detail, first_seen: now, last_seen: now });
    }

    /// Drop alerts and host state that have gone quiet.
    pub fn expire(&mut self, now: Instant) {
        let ttl = self.config.alert_ttl;
        self.alerts.retain(|_, a| now.saturating_duration_since(a.last_seen) <= ttl);
        let idle = self.config.scan_window.max(self.config.flood_window);
        self.sources.retain(|_, s| now.saturating_duration_since(s.last_seen) <= idle);
        self.targets.retain(|_, t| now.saturating_duration_since(t.last_seen) <= idle);
    }

    /// Alerts still active at `now`, most severe and most recent first.
    pub fn active_alerts(&self, now: Instant) -> Vec<&Alert> {
        let ttl = self.config.alert_ttl;
        let mut alerts: Vec<&Alert> =
            self.alerts.values().filter(|a| now.saturating_duration_since(a.last_seen) <= ttl).collect();
        alerts.sort_by(|a, b| {
            severity_rank(b.kind.severity())
                .cmp(&severity_rank(a.kind.severity()))
                .then(b.last_seen.cmp(&a.last_seen))
                .then(a.summary().cmp(&b.summary()))
        });
        alerts
    }

    /// Overall level: nothing active is Low; a traffic spike alone is Medium;
    /// one attack is High; a SYN flood, or several attacks at once, Critical.
    pub fn threat_level(&self, now: Instant) -> ThreatLevel {
        let active = self.active_alerts(now);
        let high = active.iter().filter(|a| a.kind.severity() == Severity::High).count();
        if active.iter().any(|a| a.kind == AlertKind::SynFlood) || high >= 2 {
            ThreatLevel::Critical
        } else if high == 1 {
            ThreatLevel::High
        } else if !active.is_empty() {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        }
    }

    /// Is `ip` the source of an active scan/sweep alert?
    pub fn is_scanning(&self, ip: IpAddr, now: Instant) -> bool {
        self.active_alerts(now).iter().any(|a| {
            a.source == Some(ip)
                && matches!(a.kind, AlertKind::PortScan | AlertKind::HostSweep | AlertKind::StealthScan)
        })
    }

    /// Number of hosts currently tracked (sources + flood targets).
    pub fn tracked_hosts(&self) -> usize {
        self.sources.len() + self.targets.len()
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::testutil::{ipv4, tcp, udp};
    use crate::decode::{decode, LinkType, TcpFlags};

    const VICTIM: [u8; 4] = [10, 0, 0, 1];
    const ATTACKER: [u8; 4] = [203, 0, 113, 7];

    fn feed(engine: &mut ThreatEngine, src: [u8; 4], dst: [u8; 4], port: u16, flags: u8, at: Instant) {
        let pkt = ipv4(6, src, dst, &tcp(40000, port, flags, b""));
        engine.observe(&decode(LinkType::RawIp, &pkt).unwrap(), at);
    }

    fn ip(a: [u8; 4]) -> IpAddr {
        IpAddr::from(a)
    }

    #[test]
    fn quiet_network_is_low() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for port in [80, 443, 22] {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        assert_eq!(e.threat_level(t0), ThreatLevel::Low);
        assert!(e.active_alerts(t0).is_empty());
    }

    #[test]
    fn vertical_port_scan_raises_one_alert_with_evidence() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for port in 1..=40u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0 + Duration::from_millis(u64::from(port)));
        }
        let now = t0 + Duration::from_secs(1);
        let alerts = e.active_alerts(now);
        assert_eq!(alerts.len(), 1, "a continuing scan refreshes one alert");
        assert_eq!(alerts[0].kind, AlertKind::PortScan);
        assert_eq!(alerts[0].source, Some(ip(ATTACKER)));
        assert_eq!(alerts[0].target, Some(ip(VICTIM)));
        assert_eq!(alerts[0].summary(), "Port scan 203.0.113.7 -> 10.0.0.1 (40 ports in 60s)");
        assert_eq!(e.threat_level(now), ThreatLevel::High);
        assert!(e.is_scanning(ip(ATTACKER), now));
        assert!(!e.is_scanning(ip(VICTIM), now));
    }

    #[test]
    fn slow_probing_outside_the_window_is_not_a_scan() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        // One new port every 10 seconds: never 20 distinct ports within 60s.
        for i in 0..40u16 {
            feed(&mut e, ATTACKER, VICTIM, 1000 + i, TcpFlags::SYN, t0 + Duration::from_secs(10 * u64::from(i)));
        }
        assert!(e.active_alerts(t0 + Duration::from_secs(400)).is_empty());
    }

    #[test]
    fn horizontal_sweep_across_hosts() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for host in 1..=25u8 {
            feed(&mut e, ATTACKER, [10, 0, 0, host], 22, TcpFlags::SYN, t0);
        }
        let alerts = e.active_alerts(t0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::HostSweep);
        assert_eq!(alerts[0].summary(), "Host sweep from 203.0.113.7 (25 hosts on port 22 in 60s)");
    }

    #[test]
    fn client_opening_many_connections_to_one_service_is_not_a_scan() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for _ in 0..80 {
            feed(&mut e, ATTACKER, VICTIM, 443, TcpFlags::SYN, t0);
        }
        assert!(e.active_alerts(t0).is_empty());
    }

    #[test]
    fn stealth_scans_are_detected() {
        let t0 = Instant::now();
        for flags in [0u8, TcpFlags::FIN, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG] {
            let mut e = ThreatEngine::default();
            for port in 1..=5u16 {
                feed(&mut e, ATTACKER, VICTIM, port, flags, t0);
            }
            assert_eq!(e.active_alerts(t0)[0].kind, AlertKind::StealthScan, "flags {flags:#04x}");
        }
        // FIN+ACK is an ordinary connection close.
        let mut e = ThreatEngine::default();
        for port in 1..=50u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::FIN | TcpFlags::ACK, t0);
        }
        assert!(e.active_alerts(t0).is_empty());
    }

    #[test]
    fn syn_flood_needs_unanswered_syns() {
        let t0 = Instant::now();

        // Spoofed sources hammering one port, nothing answered: flood.
        let mut e = ThreatEngine::default();
        for i in 0..150u32 {
            let src = [198, 51, (i / 256) as u8, (i % 256) as u8];
            feed(&mut e, src, VICTIM, 80, TcpFlags::SYN, t0 + Duration::from_millis(u64::from(i)));
        }
        let now = t0 + Duration::from_secs(1);
        let alerts = e.active_alerts(now);
        assert_eq!(alerts[0].kind, AlertKind::SynFlood);
        assert_eq!(alerts[0].target, Some(ip(VICTIM)));
        assert_eq!(e.threat_level(now), ThreatLevel::Critical);

        // The same load on a healthy server that answers every SYN: no alert.
        let mut e = ThreatEngine::default();
        for i in 0..150u32 {
            let src = [198, 51, (i / 256) as u8, (i % 256) as u8];
            let at = t0 + Duration::from_millis(u64::from(i));
            feed(&mut e, src, VICTIM, 80, TcpFlags::SYN, at);
            feed(&mut e, VICTIM, src, 40000, TcpFlags::SYN | TcpFlags::ACK, at);
        }
        assert!(e.active_alerts(now).is_empty(), "{:?}", e.active_alerts(now));
    }

    #[test]
    fn traffic_spike_is_medium_and_counts_all_protocols() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::new(EngineConfig { rate_threshold: 50.0, ..EngineConfig::default() });
        let pkt = ipv4(17, ATTACKER, VICTIM, &udp(1, 2, b""));
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        for i in 0..60 {
            e.observe(&d, t0 + Duration::from_millis(i));
        }
        assert_eq!(e.active_alerts(t0)[0].kind, AlertKind::TrafficSpike);
        assert_eq!(e.threat_level(t0), ThreatLevel::Medium);

        // 60 packets spread over a minute is not a spike.
        let mut e = ThreatEngine::new(EngineConfig { rate_threshold: 50.0, ..EngineConfig::default() });
        for i in 0..60 {
            e.observe(&d, t0 + Duration::from_secs(i));
        }
        assert!(e.active_alerts(t0 + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn alerts_expire_and_the_level_returns_to_low() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for port in 1..=30u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        assert_eq!(e.threat_level(t0 + Duration::from_secs(29)), ThreatLevel::High);
        let later = t0 + Duration::from_secs(31);
        assert_eq!(e.threat_level(later), ThreatLevel::Low);
        e.expire(t0 + Duration::from_secs(120));
        assert_eq!(e.tracked_hosts(), 0, "idle host state is released");
    }

    #[test]
    fn two_simultaneous_attacks_are_critical() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for port in 1..=30u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        for host in 1..=30u8 {
            feed(&mut e, [192, 0, 2, 9], [10, 0, 1, host], 3389, TcpFlags::SYN, t0);
        }
        assert_eq!(e.threat_level(t0), ThreatLevel::Critical);
        assert_eq!(e.active_alerts(t0).len(), 2);
    }

    #[test]
    fn memory_is_bounded_under_spoofed_source_flood() {
        let t0 = Instant::now();
        let cfg = EngineConfig { max_tracked_hosts: 64, max_attempts_per_source: 32, ..EngineConfig::default() };
        let mut e = ThreatEngine::new(cfg);
        // 20k distinct spoofed sources and 20k distinct targets.
        for i in 0..20_000u32 {
            let b = i.to_be_bytes();
            feed(&mut e, [11, b[1], b[2], b[3]], [12, b[1], b[2], b[3]], 80, TcpFlags::SYN, t0);
        }
        assert!(e.tracked_hosts() <= 128, "tracked {}", e.tracked_hosts());
        // One source hammering many ports keeps a bounded attempt history.
        for port in 0..5000u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        assert!(e.sources[&ip(ATTACKER)].attempts.len() <= 32);
        assert!(e.alerts.len() <= 64);
    }

    #[test]
    fn eviction_drops_the_least_recently_seen_host() {
        let t0 = Instant::now();
        let cfg = EngineConfig { max_tracked_hosts: 2, ..EngineConfig::default() };
        let mut e = ThreatEngine::new(cfg);
        feed(&mut e, [1, 1, 1, 1], VICTIM, 80, TcpFlags::SYN, t0);
        feed(&mut e, [2, 2, 2, 2], VICTIM, 80, TcpFlags::SYN, t0 + Duration::from_secs(1));
        feed(&mut e, [3, 3, 3, 3], VICTIM, 80, TcpFlags::SYN, t0 + Duration::from_secs(2));
        assert!(!e.sources.contains_key(&ip([1, 1, 1, 1])));
        assert!(e.sources.contains_key(&ip([2, 2, 2, 2])));
        assert!(e.sources.contains_key(&ip([3, 3, 3, 3])));
    }
}
