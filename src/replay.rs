//! Deterministic, headless analysis of a capture.
//!
//! Packets are run through exactly the pipeline the live UI uses, but the
//! clock is the capture's own timestamps rather than the wall clock, so the
//! same file always produces the same summary - on any machine, at any speed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, Instant};

use crate::alerts::{Alert, AlertKind, EngineConfig, ThreatEngine};
use crate::decode::LinkType;
use crate::flows::{human_bytes, FlowTable};
use crate::pcapfile::{PcapError, PcapReader};
use crate::pipeline::observe;
use crate::{Protocol, ThreatLevel};

/// What a capture contained.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplaySummary {
    /// Packets decoded and analysed.
    pub packets: u64,
    /// Packets that were not IP or were malformed.
    pub undecodable: u64,
    /// Bytes on the wire across decoded packets.
    pub bytes: u64,
    /// Packet count per protocol label, in alphabetical order.
    pub protocols: BTreeMap<&'static str, u64>,
    /// Every distinct alert raised, as `Alert::summary` minus the evidence
    /// counts (which grow as an attack continues).
    pub alerts: BTreeSet<String>,
    /// The highest threat level reached at any point.
    pub peak_level: Option<ThreatLevel>,
    /// Time between the first and last packet.
    pub duration: Duration,
    /// Hostnames seen in DNS questions, TLS SNI and HTTP Host headers.
    pub hostnames: BTreeSet<String>,
    /// Distinct flows (bidirectional 5-tuples) seen.
    pub flows: u64,
    /// The busiest hosts by bytes sent plus received: (address, bytes, packets).
    pub top_talkers: Vec<(std::net::IpAddr, u64, u64)>,
}

impl ReplaySummary {
    pub fn count(&self, protocol: Protocol) -> u64 {
        self.protocols.get(protocol.label()).copied().unwrap_or(0)
    }

    pub fn peak(&self) -> ThreatLevel {
        self.peak_level.unwrap_or(ThreatLevel::Low)
    }
}

impl fmt::Display for ReplaySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "packets:      {}", self.packets)?;
        writeln!(f, "undecodable:  {}", self.undecodable)?;
        writeln!(f, "bytes:        {}", self.bytes)?;
        writeln!(f, "duration:     {:.3}s", self.duration.as_secs_f64())?;
        writeln!(f, "flows:        {}", self.flows)?;
        writeln!(f, "peak threat:  {:?}", self.peak())?;
        writeln!(f, "protocols:")?;
        for (label, count) in &self.protocols {
            writeln!(f, "  {label:<6}{count}")?;
        }
        if !self.hostnames.is_empty() {
            writeln!(f, "hostnames:")?;
            for name in &self.hostnames {
                writeln!(f, "  {name}")?;
            }
        }
        if !self.top_talkers.is_empty() {
            writeln!(f, "top talkers:")?;
            for (ip, bytes, packets) in &self.top_talkers {
                writeln!(f, "  {ip} {} ({packets} pkts)", human_bytes(*bytes))?;
            }
        }
        if self.alerts.is_empty() {
            writeln!(f, "alerts:       none")?;
        } else {
            writeln!(f, "alerts:")?;
            for alert in &self.alerts {
                writeln!(f, "  {alert}")?;
            }
        }
        Ok(())
    }
}

/// Incremental analyser; feed packets in capture order.
#[derive(Debug)]
pub struct ReplayAnalyzer {
    engine: ThreatEngine,
    flows: FlowTable,
    summary: ReplaySummary,
    epoch: Instant,
    first_micros: Option<i64>,
    last_micros: i64,
    /// Alerts active as of the last check, by key.
    active: BTreeMap<String, Alert>,
    /// Engine revision at the last check.
    seen_revision: u64,
    /// Stream time (microseconds) at which to look for expired alerts again.
    next_alert_check: i64,
    level: ThreatLevel,
}

/// Longest capture span honoured (ten years); later timestamps are clamped.
const MAX_STREAM_MICROS: i64 = 10 * 365 * 24 * 3600 * 1_000_000;

/// How often, in stream time, to look for alerts that have expired.
const ALERT_RECHECK_MICROS: i64 = 1_000_000;

/// What one packet contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub event: crate::pipeline::PacketEvent,
    /// Hostname revealed by the packet, if any.
    pub insight: Option<crate::inspect::Insight>,
    /// Alerts that became active with this packet.
    pub raised: Vec<Alert>,
    /// Alerts that were active before this packet and have now expired.
    pub cleared: Vec<Alert>,
}

impl Default for ReplayAnalyzer {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

fn alert_key(kind: AlertKind, source: Option<std::net::IpAddr>, target: Option<std::net::IpAddr>) -> String {
    match (source, target) {
        (Some(s), Some(t)) => format!("{} {} -> {}", kind.label(), s, t),
        (Some(s), None) => format!("{} from {}", kind.label(), s),
        (None, Some(t)) => format!("{} on {}", kind.label(), t),
        (None, None) => kind.label().to_string(),
    }
}

impl ReplayAnalyzer {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            engine: ThreatEngine::new(config),
            flows: FlowTable::default(),
            summary: ReplaySummary::default(),
            epoch: Instant::now(),
            first_micros: None,
            last_micros: 0,
            active: BTreeMap::new(),
            seen_revision: 0,
            next_alert_check: 0,
            level: ThreatLevel::Low,
        }
    }

    /// Analyse one packet captured at `ts_micros`.
    ///
    /// Returns what the packet was and which alerts it raised or let lapse,
    /// or `None` when it could not be decoded.
    pub fn feed(&mut self, link: LinkType, ts_micros: i64, data: &[u8], wire_len: usize) -> Option<Observation> {
        let first = *self.first_micros.get_or_insert(ts_micros);
        // Timestamps can go backwards in real captures; never move the clock back.
        // (Saturating: a corrupt file can hold any timestamp.)
        self.last_micros = self.last_micros.max(ts_micros.saturating_sub(first));
        // Clamp the span: adding an absurd duration to an `Instant` panics,
        // and a corrupt timestamp must not be able to do that.
        self.last_micros = self.last_micros.min(MAX_STREAM_MICROS);
        let now = self.epoch + Duration::from_micros(self.last_micros as u64);

        let Ok((event, decoded)) = observe(link, data, wire_len) else {
            self.summary.undecodable += 1;
            return None;
        };
        self.summary.packets += 1;
        self.summary.bytes = self.summary.bytes.saturating_add(event.wire_len as u64);
        *self.summary.protocols.entry(event.protocol.label()).or_insert(0) += 1;

        self.engine.observe(&decoded, now);
        self.flows.observe(&event, now);
        let insight = crate::inspect::insight(&decoded);
        if let Some(insight) = &insight {
            self.summary.hostnames.insert(insight.name.clone());
        }

        // Re-read the alert list only when something can have changed: a new
        // alert was raised, or enough stream time has passed for one to
        // expire. Doing it on every packet dominated the cost under a flood.
        let (mut raised, mut cleared) = (Vec::new(), Vec::new());
        let revision = self.engine.revision();
        let due = self.last_micros >= self.next_alert_check;
        if revision != self.seen_revision || (due && (!self.active.is_empty() || self.engine.alert_count() > 0)) {
            self.seen_revision = revision;
            self.next_alert_check = self.last_micros.saturating_add(ALERT_RECHECK_MICROS);
            let mut still_active = BTreeMap::new();
            for alert in self.engine.active_alerts(now) {
                let key = alert_key(alert.kind, alert.source, alert.target);
                if !self.active.contains_key(&key) {
                    self.summary.alerts.insert(key.clone());
                    raised.push(alert.clone());
                }
                still_active.insert(key, alert.clone());
            }
            for (key, alert) in std::mem::take(&mut self.active) {
                if !still_active.contains_key(&key) {
                    cleared.push(alert);
                }
            }
            self.active = still_active;
            self.level = self.engine.threat_level(now);
        }

        let level = self.level;
        if self.summary.peak_level.is_none_or(|peak| level > peak) {
            self.summary.peak_level = Some(level);
        }
        Some(Observation { event, insight, raised, cleared })
    }

    /// Packets decoded so far.
    pub fn packets(&self) -> u64 {
        self.summary.packets
    }

    pub fn finish(mut self) -> ReplaySummary {
        self.summary.duration = Duration::from_micros(self.last_micros as u64);
        self.summary.flows = self.flows.total_flows();
        self.summary.top_talkers =
            self.flows.top_talkers(5).into_iter().map(|(ip, h)| (ip, h.bytes, h.packets)).collect();
        self.summary
    }
}

/// Why a capture file could not be analysed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    Pcap(PcapError),
    UnsupportedLinkType(i32),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pcap(e) => e.fmt(f),
            Self::UnsupportedLinkType(t) => write!(f, "unsupported link type {t}"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Analyse a whole pcap file held in memory.
pub fn analyze_pcap(file: &[u8]) -> Result<ReplaySummary, ReplayError> {
    let reader = PcapReader::new(file).map_err(ReplayError::Pcap)?;
    let link =
        LinkType::from_dlt(reader.link_type).ok_or(ReplayError::UnsupportedLinkType(reader.link_type))?;
    let mut analyzer = ReplayAnalyzer::default();
    for record in reader {
        let record = record.map_err(ReplayError::Pcap)?;
        analyzer.feed(link, record.ts_micros, record.data, record.wire_len);
    }
    Ok(analyzer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TcpFlags;
    use crate::pcapfile::PcapWriter;
    use crate::synth::{eth_tcp, eth_udp, ethernet};

    #[test]
    fn summary_counts_and_is_time_independent() {
        let mut w = PcapWriter::new(1);
        w.packet(1_000_000, &eth_udp([10, 0, 0, 2], [8, 8, 8, 8], 4000, 53, b"q"));
        w.packet(1_500_000, &eth_tcp([10, 0, 0, 2], [1, 1, 1, 1], 4001, 443, TcpFlags::SYN, b""));
        w.packet(1_600_000, &ethernet(0x0806, &[0; 28]));
        let file = w.finish();

        let a = analyze_pcap(&file).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let b = analyze_pcap(&file).unwrap();
        assert_eq!(a, b, "same file, same summary");

        assert_eq!(a.packets, 2);
        assert_eq!(a.undecodable, 1);
        assert_eq!(a.count(Protocol::DNS), 1);
        assert_eq!(a.count(Protocol::HTTPS), 1);
        assert_eq!(a.count(Protocol::SSH), 0);
        assert_eq!(a.duration, Duration::from_micros(600_000));
        assert_eq!(a.flows, 2);
        assert_eq!(a.top_talkers[0].0.to_string(), "10.0.0.2", "took part in both flows");
        assert!(a.to_string().contains("flows:        2"));
        assert_eq!(a.peak(), ThreatLevel::Low);
        assert!(a.alerts.is_empty());
        assert!(a.to_string().contains("alerts:       none"));
    }

    #[test]
    fn scan_spread_over_hours_is_not_flagged_but_a_burst_is() {
        let build = |gap_micros: i64| {
            let mut w = PcapWriter::new(1);
            for port in 1..=40u16 {
                let f = eth_tcp([203, 0, 113, 7], [10, 0, 0, 1], 40000, port, TcpFlags::SYN, b"");
                w.packet(i64::from(port) * gap_micros, &f);
            }
            w.finish()
        };
        // 40 ports in 2 seconds: a scan. Uses file time, not wall time.
        let burst = analyze_pcap(&build(50_000)).unwrap();
        assert_eq!(burst.alerts.iter().collect::<Vec<_>>(), ["Port scan 203.0.113.7 -> 10.0.0.1"]);
        assert_eq!(burst.peak(), ThreatLevel::High);
        // The same 40 ports, one every 5 minutes: not a scan.
        let slow = analyze_pcap(&build(300_000_000)).unwrap();
        assert!(slow.alerts.is_empty(), "{:?}", slow.alerts);
    }

    #[test]
    fn feed_reports_each_alert_once_when_raised_and_once_when_cleared() {
        let mut a = ReplayAnalyzer::default();
        let mut raised = 0;
        let mut cleared = Vec::new();
        for port in 1..=40u16 {
            let f = eth_tcp([203, 0, 113, 7], [10, 0, 0, 1], 40000, port, TcpFlags::SYN, b"");
            let obs = a.feed(LinkType::Ethernet, i64::from(port) * 10_000, &f, f.len()).unwrap();
            raised += obs.raised.len();
            assert!(obs.cleared.is_empty());
            if port == 20 {
                assert_eq!(obs.raised[0].summary(), "Port scan 203.0.113.7 -> 10.0.0.1 (20 ports in 60s)");
            }
        }
        assert_eq!(raised, 1, "a continuing scan is one alert, not twenty-one");

        // Two minutes of silence later an unrelated packet shows the alert has lapsed.
        let f = eth_udp([10, 0, 0, 2], [8, 8, 8, 8], 4000, 53, b"q");
        let obs = a.feed(LinkType::Ethernet, 120_000_000, &f, f.len()).unwrap();
        cleared.extend(obs.cleared);
        assert_eq!(cleared.len(), 1);
        assert_eq!(cleared[0].kind, AlertKind::PortScan);
        assert!(obs.raised.is_empty());
        assert_eq!(a.feed(LinkType::Ethernet, 120_000_001, &[0; 3], 3), None, "undecodable");
    }

    #[test]
    fn absurd_timestamps_do_not_panic() {
        let f = eth_udp([10, 0, 0, 2], [8, 8, 8, 8], 4000, 53, b"q");
        let mut a = ReplayAnalyzer::default();
        for ts in [0, i64::MAX, i64::MIN, -1, i64::MAX - 1, 5] {
            a.feed(LinkType::Ethernet, ts, &f, f.len());
        }
        let summary = a.finish();
        assert_eq!(summary.packets, 6);
        assert_eq!(summary.duration, Duration::from_micros(MAX_STREAM_MICROS as u64));
    }

    #[test]
    fn errors() {
        assert_eq!(analyze_pcap(b"nope"), Err(ReplayError::Pcap(PcapError::TooShort)));
        let odd = PcapWriter::new(147).finish();
        assert_eq!(analyze_pcap(&odd), Err(ReplayError::UnsupportedLinkType(147)));
        let empty = analyze_pcap(&PcapWriter::new(1).finish()).unwrap();
        assert_eq!(empty, ReplaySummary::default());
    }
}
