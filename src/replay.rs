//! Deterministic, headless analysis of a capture.
//!
//! Packets are run through exactly the pipeline the live UI uses, but the
//! clock is the capture's own timestamps rather than the wall clock, so the
//! same file always produces the same summary - on any machine, at any speed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, Instant};

use crate::alerts::{AlertKind, EngineConfig, ThreatEngine};
use crate::decode::LinkType;
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
        writeln!(f, "peak threat:  {:?}", self.peak())?;
        writeln!(f, "protocols:")?;
        for (label, count) in &self.protocols {
            writeln!(f, "  {label:<6}{count}")?;
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
    summary: ReplaySummary,
    epoch: Instant,
    first_micros: Option<i64>,
    last_micros: i64,
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
            summary: ReplaySummary::default(),
            epoch: Instant::now(),
            first_micros: None,
            last_micros: 0,
        }
    }

    /// Analyse one packet captured at `ts_micros`.
    pub fn feed(&mut self, link: LinkType, ts_micros: i64, data: &[u8], wire_len: usize) {
        let first = *self.first_micros.get_or_insert(ts_micros);
        // Timestamps can go backwards in real captures; never move the clock back.
        self.last_micros = self.last_micros.max(ts_micros - first);
        let now = self.epoch + Duration::from_micros(self.last_micros as u64);

        let Ok((event, decoded)) = observe(link, data, wire_len) else {
            self.summary.undecodable += 1;
            return;
        };
        self.summary.packets += 1;
        self.summary.bytes += event.wire_len as u64;
        *self.summary.protocols.entry(event.protocol.label()).or_insert(0) += 1;

        self.engine.observe(&decoded, now);
        for alert in self.engine.active_alerts(now) {
            self.summary.alerts.insert(alert_key(alert.kind, alert.source, alert.target));
        }
        let level = self.engine.threat_level(now);
        if self.summary.peak_level.is_none_or(|peak| level > peak) {
            self.summary.peak_level = Some(level);
        }
    }

    pub fn finish(mut self) -> ReplaySummary {
        self.summary.duration = Duration::from_micros(self.last_micros as u64);
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
    fn errors() {
        assert_eq!(analyze_pcap(b"nope"), Err(ReplayError::Pcap(PcapError::TooShort)));
        let odd = PcapWriter::new(147).finish();
        assert_eq!(analyze_pcap(&odd), Err(ReplayError::UnsupportedLinkType(147)));
        let empty = analyze_pcap(&PcapWriter::new(1).finish()).unwrap();
        assert_eq!(empty, ReplaySummary::default());
    }
}
