//! Threat engine: per-source sliding windows, bounded memory, expiring alerts.
//!
//! Every method takes the current time as an argument so behaviour is fully
//! deterministic under test - nothing in here calls `Instant::now()`.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::decode::{Decoded, Transport};
use crate::{Severity, ThreatLevel};

/// What kind of behaviour an alert describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
    /// How many attempts in the window went to each (destination, port).
    pairs: HashMap<(IpAddr, u16), u32>,
    /// Distinct ports probed per destination, kept in step with `pairs` so
    /// that a scan is recognised in O(1) per packet instead of rescanning
    /// the whole history.
    ports_per_host: HashMap<IpAddr, u32>,
    /// Distinct destinations probed per port.
    hosts_per_port: HashMap<u16, u32>,
    /// Times of recent abnormal-flag packets.
    stealth: VecDeque<Instant>,
    last_seen: Instant,
}

impl SourceState {
    fn new(now: Instant) -> Self {
        Self {
            attempts: VecDeque::new(),
            pairs: HashMap::new(),
            ports_per_host: HashMap::new(),
            hosts_per_port: HashMap::new(),
            stealth: VecDeque::new(),
            last_seen: now,
        }
    }

    fn push_attempt(&mut self, now: Instant, dst: IpAddr, port: u16) {
        self.attempts.push_back((now, dst, port));
        let count = self.pairs.entry((dst, port)).or_insert(0);
        *count += 1;
        if *count == 1 {
            *self.ports_per_host.entry(dst).or_insert(0) += 1;
            *self.hosts_per_port.entry(port).or_insert(0) += 1;
        }
    }

    fn pop_attempt(&mut self) {
        let Some((_, dst, port)) = self.attempts.pop_front() else {
            return;
        };
        fn decrement<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u32>, key: K) -> bool {
            match map.get_mut(&key) {
                Some(n) if *n > 1 => {
                    *n -= 1;
                    false
                }
                Some(_) => {
                    map.remove(&key);
                    true
                }
                None => false,
            }
        }
        // Only when the last attempt at this (host, port) leaves the window
        // do the distinct counts drop.
        if decrement(&mut self.pairs, (dst, port)) {
            decrement(&mut self.ports_per_host, dst);
            decrement(&mut self.hosts_per_port, port);
        }
    }
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
    revision: u64,
}

impl Default for ThreatEngine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

fn prune(queue: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while queue
        .front()
        .is_some_and(|&t| now.saturating_duration_since(t) > window)
    {
        queue.pop_front();
    }
}

impl ThreatEngine {
    pub fn new(config: EngineConfig) -> Self {
        let mut config = config;
        // gate r1: a zero capacity underflows make_room's eviction index on
        // the first observation (0 - 1 in debug, select_nth_unstable(usize::MAX)
        // in release). Clamp the same way NameCache does — a degenerate config
        // tracks one host, it never panics.
        config.max_tracked_hosts = config.max_tracked_hosts.max(1);
        Self {
            config,
            sources: HashMap::new(),
            targets: HashMap::new(),
            alerts: HashMap::new(),
            recent: VecDeque::new(),
            revision: 0,
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Feed one decoded packet observed at `now`.
    pub fn observe(&mut self, decoded: &Decoded<'_>, now: Instant) {
        self.observe_parts(decoded.src, decoded.dst, decoded.transport, now);
    }

    /// Feed one packet from its addresses and transport summary.
    pub fn observe_parts(&mut self, src: IpAddr, dst: IpAddr, transport: Transport, now: Instant) {
        self.observe_rate(now);

        let Transport::Tcp {
            dst_port, flags, ..
        } = transport
        else {
            return;
        };

        if flags.is_connection_attempt() {
            self.observe_attempt(src, dst, dst_port, now);
            self.observe_syn(dst, now);
        } else if flags.syn() && flags.ack() {
            // The *sender* of a SYN-ACK is a host answering its SYNs.
            if let Some(target) = self.targets.get_mut(&src) {
                target.syn_acks.push_back(now);
                target.last_seen = now;
            }
        } else if flags.is_null()
            || flags.is_xmas()
            || flags.0 & 0x3f == crate::decode::TcpFlags::FIN
        {
            self.observe_stealth(src, now);
        }
    }

    fn observe_rate(&mut self, now: Instant) {
        self.recent.push_back(now);
        prune(&mut self.recent, now, Duration::from_secs(1));
        // The queue only needs to prove the threshold was crossed. ceil, not
        // truncate: a fractional threshold (0.5/s) must still leave room for
        // one packet without instantly re-firing (gate r1).
        let cap = (self.config.rate_threshold.ceil() as usize)
            .saturating_add(1)
            .max(1);
        while self.recent.len() > cap {
            self.recent.pop_front();
        }
        if self.recent.len() as f64 > self.config.rate_threshold {
            // f64, not `as u64`: a 0.5 threshold used to read "over 0 packets/s"
            let limit = self.config.rate_threshold;
            self.raise(
                AlertKind::TrafficSpike,
                None,
                None,
                now,
                format_args!("over {limit} packets/s"),
            );
        }
    }

    fn observe_attempt(&mut self, src: IpAddr, dst: IpAddr, port: u16, now: Instant) {
        Self::make_room(
            &mut self.sources,
            self.config.max_tracked_hosts,
            &src,
            |s| s.last_seen,
        );
        let window = self.config.scan_window;
        let cap = self.config.max_attempts_per_source;
        let state = self
            .sources
            .entry(src)
            .or_insert_with(|| SourceState::new(now));
        state.last_seen = now;
        state.push_attempt(now, dst, port);
        while state
            .attempts
            .front()
            .is_some_and(|&(t, _, _)| now.saturating_duration_since(t) > window)
        {
            state.pop_attempt();
        }
        while state.attempts.len() > cap {
            state.pop_attempt();
        }

        // Vertical scan: many ports on the host just probed.
        let ports = state.ports_per_host.get(&dst).copied().unwrap_or(0) as usize;
        // Horizontal sweep: many hosts on the port just probed.
        let hosts = state.hosts_per_port.get(&port).copied().unwrap_or(0) as usize;
        let secs = window.as_secs();

        if ports >= self.config.port_scan_threshold {
            self.raise(
                AlertKind::PortScan,
                Some(src),
                Some(dst),
                now,
                format_args!("{ports} ports in {secs}s"),
            );
        }
        if hosts >= self.config.host_sweep_threshold {
            self.raise(
                AlertKind::HostSweep,
                Some(src),
                None,
                now,
                format_args!("{hosts} hosts on port {port} in {secs}s"),
            );
        }
    }

    fn observe_syn(&mut self, dst: IpAddr, now: Instant) {
        Self::make_room(
            &mut self.targets,
            self.config.max_tracked_hosts,
            &dst,
            |t| t.last_seen,
        );
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
            let secs = window.as_secs();
            self.raise(
                AlertKind::SynFlood,
                None,
                Some(dst),
                now,
                format_args!("{syns} SYNs, {answered} answered in {secs}s"),
            );
        }
    }

    fn observe_stealth(&mut self, src: IpAddr, now: Instant) {
        Self::make_room(
            &mut self.sources,
            self.config.max_tracked_hosts,
            &src,
            |s| s.last_seen,
        );
        let window = self.config.scan_window;
        let cap = self.config.stealth_threshold.saturating_mul(4).max(16);
        let state = self
            .sources
            .entry(src)
            .or_insert_with(|| SourceState::new(now));
        state.last_seen = now;
        state.stealth.push_back(now);
        prune(&mut state.stealth, now, window);
        while state.stealth.len() > cap {
            state.stealth.pop_front();
        }
        if state.stealth.len() >= self.config.stealth_threshold {
            let probes = state.stealth.len();
            self.raise(
                AlertKind::StealthScan,
                Some(src),
                None,
                now,
                format_args!("{probes} NULL/FIN/Xmas probes"),
            );
        }
    }

    /// Keep a host table within its cap by evicting the least recently seen
    /// entries. An attacker spoofing sources can therefore cost at most
    /// `max_tracked_hosts` entries, never unbounded memory. Eviction removes
    /// an eighth of the table at once: finding the single oldest entry on
    /// every packet of a spoofed flood made each packet cost a full scan.
    fn make_room<S>(
        map: &mut HashMap<IpAddr, S>,
        cap: usize,
        incoming: &IpAddr,
        last_seen: fn(&S) -> Instant,
    ) {
        if map.len() < cap || map.contains_key(incoming) {
            return;
        }
        let remove = (cap / 8).max(1).min(map.len());
        let mut ages: Vec<(Instant, IpAddr)> =
            map.iter().map(|(ip, s)| (last_seen(s), *ip)).collect();
        ages.select_nth_unstable(remove - 1);
        for (_, ip) in ages.into_iter().take(remove) {
            map.remove(&ip);
        }
    }

    fn raise(
        &mut self,
        kind: AlertKind,
        source: Option<IpAddr>,
        target: Option<IpAddr>,
        now: Instant,
        detail: std::fmt::Arguments<'_>,
    ) {
        use std::fmt::Write as _;
        let key = (kind, source, target);
        // The common case under attack: refresh an existing alert in place,
        // reusing its string rather than allocating a new one per packet.
        if let Some(alert) = self.alerts.get_mut(&key) {
            alert.last_seen = now;
            alert.detail.clear();
            let _ = alert.detail.write_fmt(detail);
            return;
        }
        // Alerts are keyed by who/what, so a continuing scan refreshes one
        // alert rather than producing thousands. Bounded like the host tables.
        if self.alerts.len() >= self.config.max_tracked_hosts {
            self.expire(now);
            if self.alerts.len() >= self.config.max_tracked_hosts {
                if let Some(k) = self
                    .alerts
                    .iter()
                    .min_by_key(|(_, a)| a.last_seen)
                    .map(|(k, _)| *k)
                {
                    self.alerts.remove(&k);
                }
            }
        }
        self.revision += 1;
        self.alerts.insert(
            key,
            Alert {
                kind,
                source,
                target,
                detail: detail.to_string(),
                first_seen: now,
                last_seen: now,
            },
        );
    }

    /// Changes whenever a new alert is raised. Lets callers skip re-reading
    /// the alert list while nothing new has happened.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Number of alerts currently held (including any not yet expired).
    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    /// Drop alerts and host state that have gone quiet.
    pub fn expire(&mut self, now: Instant) {
        let ttl = self.config.alert_ttl;
        self.alerts
            .retain(|_, a| now.saturating_duration_since(a.last_seen) <= ttl);
        let idle = self.config.scan_window.max(self.config.flood_window);
        self.sources
            .retain(|_, s| now.saturating_duration_since(s.last_seen) <= idle);
        self.targets
            .retain(|_, t| now.saturating_duration_since(t.last_seen) <= idle);
    }

    /// Alerts still active at `now`, most severe and most recent first.
    pub fn active_alerts(&self, now: Instant) -> Vec<&Alert> {
        let ttl = self.config.alert_ttl;
        let mut alerts: Vec<&Alert> = self
            .alerts
            .values()
            .filter(|a| now.saturating_duration_since(a.last_seen) <= ttl)
            .collect();
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
        let high = active
            .iter()
            .filter(|a| a.kind.severity() == Severity::High)
            .count();
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
                && matches!(
                    a.kind,
                    AlertKind::PortScan | AlertKind::HostSweep | AlertKind::StealthScan
                )
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

    fn feed(
        engine: &mut ThreatEngine,
        src: [u8; 4],
        dst: [u8; 4],
        port: u16,
        flags: u8,
        at: Instant,
    ) {
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
            feed(
                &mut e,
                ATTACKER,
                VICTIM,
                port,
                TcpFlags::SYN,
                t0 + Duration::from_millis(u64::from(port)),
            );
        }
        let now = t0 + Duration::from_secs(1);
        let alerts = e.active_alerts(now);
        assert_eq!(alerts.len(), 1, "a continuing scan refreshes one alert");
        assert_eq!(alerts[0].kind, AlertKind::PortScan);
        assert_eq!(alerts[0].source, Some(ip(ATTACKER)));
        assert_eq!(alerts[0].target, Some(ip(VICTIM)));
        assert_eq!(
            alerts[0].summary(),
            "Port scan 203.0.113.7 -> 10.0.0.1 (40 ports in 60s)"
        );
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
            feed(
                &mut e,
                ATTACKER,
                VICTIM,
                1000 + i,
                TcpFlags::SYN,
                t0 + Duration::from_secs(10 * u64::from(i)),
            );
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
        assert_eq!(
            alerts[0].summary(),
            "Host sweep from 203.0.113.7 (25 hosts on port 22 in 60s)"
        );
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
        for flags in [
            0u8,
            TcpFlags::FIN,
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        ] {
            let mut e = ThreatEngine::default();
            for port in 1..=5u16 {
                feed(&mut e, ATTACKER, VICTIM, port, flags, t0);
            }
            assert_eq!(
                e.active_alerts(t0)[0].kind,
                AlertKind::StealthScan,
                "flags {flags:#04x}"
            );
        }
        // FIN+ACK is an ordinary connection close.
        let mut e = ThreatEngine::default();
        for port in 1..=50u16 {
            feed(
                &mut e,
                ATTACKER,
                VICTIM,
                port,
                TcpFlags::FIN | TcpFlags::ACK,
                t0,
            );
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
            feed(
                &mut e,
                src,
                VICTIM,
                80,
                TcpFlags::SYN,
                t0 + Duration::from_millis(u64::from(i)),
            );
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
            feed(
                &mut e,
                VICTIM,
                src,
                40000,
                TcpFlags::SYN | TcpFlags::ACK,
                at,
            );
        }
        assert!(
            e.active_alerts(now).is_empty(),
            "{:?}",
            e.active_alerts(now)
        );
    }

    #[test]
    fn answering_server_is_not_flagged_while_the_target_table_churns() {
        // A healthy server keeps answering while thousands of other targets
        // push the table to its cap. Its state is the most recently used, so
        // eviction must never reset its SYN-ACK credit.
        let t0 = Instant::now();
        let cfg = EngineConfig {
            max_tracked_hosts: 16,
            ..EngineConfig::default()
        };
        let mut e = ThreatEngine::new(cfg);
        for i in 0..400u32 {
            let at = t0 + Duration::from_millis(u64::from(i) * 10);
            let client = [198, 51, (i / 250) as u8, (i % 250) as u8 + 1];
            feed(&mut e, client, VICTIM, 443, TcpFlags::SYN, at);
            feed(
                &mut e,
                VICTIM,
                client,
                40000,
                TcpFlags::SYN | TcpFlags::ACK,
                at,
            );
            // Churn: three other targets per round.
            for j in 0..3u32 {
                let b = (i * 3 + j).to_be_bytes();
                feed(&mut e, client, [172, 16, b[2], b[3]], 80, TcpFlags::SYN, at);
            }
        }
        let now = t0 + Duration::from_secs(4);
        assert!(
            !e.active_alerts(now)
                .iter()
                .any(|a| a.kind == AlertKind::SynFlood && a.target == Some(ip(VICTIM))),
            "{:?}",
            e.active_alerts(now)
        );
    }

    #[test]
    fn traffic_spike_is_medium_and_counts_all_protocols() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::new(EngineConfig {
            rate_threshold: 50.0,
            ..EngineConfig::default()
        });
        let pkt = ipv4(17, ATTACKER, VICTIM, &udp(1, 2, b""));
        let d = decode(LinkType::RawIp, &pkt).unwrap();
        for i in 0..60 {
            e.observe(&d, t0 + Duration::from_millis(i));
        }
        assert_eq!(e.active_alerts(t0)[0].kind, AlertKind::TrafficSpike);
        assert_eq!(e.threat_level(t0), ThreatLevel::Medium);

        // 60 packets spread over a minute is not a spike.
        let mut e = ThreatEngine::new(EngineConfig {
            rate_threshold: 50.0,
            ..EngineConfig::default()
        });
        for i in 0..60 {
            e.observe(&d, t0 + Duration::from_secs(i));
        }
        assert!(e.active_alerts(t0 + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn zero_max_tracked_hosts_is_clamped_never_panics() {
        // gate r1: a zero capacity must not underflow make_room's eviction
        // index on the first observation — it clamps to tracking one host
        let t0 = Instant::now();
        let mut e = ThreatEngine::new(EngineConfig {
            max_tracked_hosts: 0,
            ..EngineConfig::default()
        });
        feed(&mut e, ATTACKER, VICTIM, 22, TcpFlags::SYN, t0);
        feed(&mut e, [192, 0, 2, 77], VICTIM, 23, TcpFlags::SYN, t0);
        assert_eq!(e.tracked_hosts(), 1, "degenerate config tracks one host");
    }

    #[test]
    fn alerts_expire_and_the_level_returns_to_low() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for port in 1..=30u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        assert_eq!(
            e.threat_level(t0 + Duration::from_secs(29)),
            ThreatLevel::High
        );
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
            feed(
                &mut e,
                [192, 0, 2, 9],
                [10, 0, 1, host],
                3389,
                TcpFlags::SYN,
                t0,
            );
        }
        assert_eq!(e.threat_level(t0), ThreatLevel::Critical);
        assert_eq!(e.active_alerts(t0).len(), 2);
    }

    #[test]
    fn memory_is_bounded_under_spoofed_source_flood() {
        let t0 = Instant::now();
        let cfg = EngineConfig {
            max_tracked_hosts: 64,
            max_attempts_per_source: 32,
            ..EngineConfig::default()
        };
        let mut e = ThreatEngine::new(cfg);
        // 20k distinct spoofed sources and 20k distinct targets.
        for i in 0..20_000u32 {
            let b = i.to_be_bytes();
            feed(
                &mut e,
                [11, b[1], b[2], b[3]],
                [12, b[1], b[2], b[3]],
                80,
                TcpFlags::SYN,
                t0,
            );
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
    fn distinct_counts_stay_exact_as_attempts_leave_the_window() {
        // Regression guard for the incremental counters: repeated probes of
        // the same port must not inflate the count, and probes that age out
        // must stop counting.
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for round in 0..5u64 {
            for port in 1..=19u16 {
                feed(
                    &mut e,
                    ATTACKER,
                    VICTIM,
                    port,
                    TcpFlags::SYN,
                    t0 + Duration::from_secs(round),
                );
            }
        }
        assert!(
            e.active_alerts(t0 + Duration::from_secs(5)).is_empty(),
            "19 distinct ports, however often"
        );
        let state = &e.sources[&ip(ATTACKER)];
        assert_eq!(state.ports_per_host[&ip(VICTIM)], 19);
        assert_eq!(state.hosts_per_port[&1], 1);

        // 70s later the old probes have aged out; 19 new ports are again not a scan.
        let later = t0 + Duration::from_secs(70);
        for port in 100..119u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, later);
        }
        let state = &e.sources[&ip(ATTACKER)];
        assert_eq!(
            state.ports_per_host[&ip(VICTIM)],
            19,
            "old ports no longer counted"
        );
        assert_eq!(state.attempts.len(), 19);
        assert_eq!(state.pairs.len(), 19);
        assert!(e.active_alerts(later).is_empty());
        // One more distinct port tips it over.
        feed(&mut e, ATTACKER, VICTIM, 200, TcpFlags::SYN, later);
        assert_eq!(e.active_alerts(later)[0].detail, "20 ports in 60s");
    }

    #[test]
    fn revision_changes_only_when_a_new_alert_appears() {
        let t0 = Instant::now();
        let mut e = ThreatEngine::default();
        for port in 1..=19u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        assert_eq!(e.revision(), 0);
        feed(&mut e, ATTACKER, VICTIM, 20, TcpFlags::SYN, t0);
        assert_eq!(e.revision(), 1);
        // Stay under the SYN-flood threshold so only the scan is in play.
        for port in 21..=60u16 {
            feed(&mut e, ATTACKER, VICTIM, port, TcpFlags::SYN, t0);
        }
        assert_eq!(e.revision(), 1, "refreshing an alert is not a new alert");
        assert_eq!(
            e.active_alerts(t0)[0].detail,
            "60 ports in 60s",
            "evidence still updates"
        );
    }

    #[test]
    fn eviction_drops_the_least_recently_seen_host() {
        let t0 = Instant::now();
        let cfg = EngineConfig {
            max_tracked_hosts: 2,
            ..EngineConfig::default()
        };
        let mut e = ThreatEngine::new(cfg);
        feed(&mut e, [1, 1, 1, 1], VICTIM, 80, TcpFlags::SYN, t0);
        feed(
            &mut e,
            [2, 2, 2, 2],
            VICTIM,
            80,
            TcpFlags::SYN,
            t0 + Duration::from_secs(1),
        );
        feed(
            &mut e,
            [3, 3, 3, 3],
            VICTIM,
            80,
            TcpFlags::SYN,
            t0 + Duration::from_secs(2),
        );
        assert!(!e.sources.contains_key(&ip([1, 1, 1, 1])));
        assert!(e.sources.contains_key(&ip([2, 2, 2, 2])));
        assert!(e.sources.contains_key(&ip([3, 3, 3, 3])));
    }
}
