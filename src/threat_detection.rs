use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::alerts::{Alert, AlertKind, ThreatEngine};
use crate::decode::{decode_guess, Decoded, Transport};
use crate::{Packet, ThreatType, Severity, Anomaly, ThreatIndicator, ThreatLevel};

/// Configuration for threat detection thresholds
pub struct ThreatConfig {
    /// Time window for port scan detection (in seconds)
    pub port_scan_window: Duration,
    /// Minimum number of unique ports to consider as port scan
    pub port_scan_threshold: usize,
    /// Time window for DDoS detection
    pub ddos_window: Duration,
    /// Packet rate threshold for DDoS detection (packets per second)
    pub ddos_packet_rate_threshold: f64,
    /// SYN packet rate threshold for SYN flood detection
    pub syn_flood_threshold: usize,
    /// Time window for tracking connections
    pub connection_window: Duration,
}

impl Default for ThreatConfig {
    fn default() -> Self {
        Self {
            port_scan_window: Duration::from_secs(60),
            port_scan_threshold: 20,
            ddos_window: Duration::from_secs(10),
            ddos_packet_rate_threshold: 999.0, // Threshold for DDoS detection
            syn_flood_threshold: 100,
            connection_window: Duration::from_secs(300),
        }
    }
}

/// Connection record for tracking port access
#[derive(Debug, Clone)]
struct ConnectionRecord {
    #[allow(dead_code)]
    source_ip: IpAddr,
    port: u16,
    timestamp: Instant,
}

/// Packet statistics for DDoS detection
#[derive(Debug)]
struct PacketStats {
    packet_count: usize,
    syn_count: usize,
    window_start: Instant,
}

/// Main threat detector implementation
pub struct ThreatDetector {
    config: ThreatConfig,
    /// Track connections by source IP
    connections: HashMap<IpAddr, Vec<ConnectionRecord>>,
    /// Track packet statistics for DDoS detection
    packet_stats: PacketStats,
    /// Current threat type detected
    current_threat_type: ThreatType,
    /// Threat indicators for aggregation
    threat_indicators: Vec<ThreatIndicator>,
    /// Sliding-window engine that produces live, expiring alerts.
    engine: ThreatEngine,
    /// When stale legacy connection records were last swept.
    last_cleanup: Instant,
}

/// Upper bounds for the legacy `add_connection` table.
const MAX_LEGACY_SOURCES: usize = 4096;
const MAX_LEGACY_RECORDS_PER_SOURCE: usize = 1024;

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            config: ThreatConfig::default(),
            connections: HashMap::new(),
            packet_stats: PacketStats {
                packet_count: 0,
                syn_count: 0,
                window_start: Instant::now(),
            },
            current_threat_type: ThreatType::Unknown,
            threat_indicators: Vec::new(),
            engine: ThreatEngine::default(),
            last_cleanup: Instant::now(),
        }
    }

    /// Add a connection record
    pub fn add_connection(&mut self, ip: IpAddr, port: u16) {
        let now = Instant::now();
        // Bounded: a flood of spoofed sources must not grow this table forever.
        if self.connections.len() >= MAX_LEGACY_SOURCES && !self.connections.contains_key(&ip) {
            self.clean_old_connections();
            if self.connections.len() >= MAX_LEGACY_SOURCES {
                let oldest = self
                    .connections
                    .iter()
                    .min_by_key(|(_, c)| c.last().map(|r| r.timestamp))
                    .map(|(ip, _)| *ip);
                if let Some(oldest) = oldest {
                    self.connections.remove(&oldest);
                }
            }
        }
        let records = self.connections.entry(ip).or_default();
        records.push(ConnectionRecord { source_ip: ip, port, timestamp: now });
        if records.len() > MAX_LEGACY_RECORDS_PER_SOURCE {
            let excess = records.len() - MAX_LEGACY_RECORDS_PER_SOURCE;
            records.drain(..excess);
        }

        // Sweeping every record on every packet made this quadratic under
        // load; once a second is plenty.
        if now.duration_since(self.last_cleanup) >= Duration::from_secs(1) {
            self.clean_old_connections();
            self.last_cleanup = now;
        }
    }

    /// Check if the given IP is performing a port scan
    pub fn is_port_scan(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.engine.is_scanning(ip, now) {
            return true;
        }
        if let Some(connections) = self.connections.get(&ip) {
            let recent_ports: HashSet<u16> = connections
                .iter()
                .filter(|conn| now.duration_since(conn.timestamp) <= self.config.port_scan_window)
                .map(|conn| conn.port)
                .collect();

            recent_ports.len() >= self.config.port_scan_threshold
        } else {
            false
        }
    }

    /// Analyze a legacy [`Packet`] of unknown framing.
    ///
    /// Live capture should call [`ThreatDetector::analyze_decoded`], which
    /// reuses the already-decoded packet and its real link type.
    pub fn analyze_packet(&mut self, packet: &Packet) {
        match decode_guess(&packet.data) {
            Ok(decoded) => self.analyze_decoded(&decoded),
            Err(_) => self.count_packet(),
        }
    }

    /// Count one packet towards the traffic-rate window.
    fn count_packet(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.packet_stats.window_start) > self.config.ddos_window {
            self.packet_stats = PacketStats { packet_count: 0, syn_count: 0, window_start: now };
        }
        self.packet_stats.packet_count += 1;
    }

    /// Analyze an already-decoded packet, observed now.
    pub fn analyze_decoded(&mut self, decoded: &Decoded<'_>) {
        self.analyze_decoded_at(decoded, Instant::now());
    }

    /// Analyze an already-decoded packet observed at `now` (replay, tests).
    pub fn analyze_decoded_at(&mut self, decoded: &Decoded<'_>, now: Instant) {
        self.analyze_parts(decoded.src, decoded.dst, decoded.transport, now);
    }

    /// Analyze a packet summary that crossed the capture channel.
    pub fn analyze_event_at(&mut self, event: &crate::pipeline::PacketEvent, now: Instant) {
        self.analyze_parts(event.src, event.dst, event.transport, now);
    }

    fn analyze_parts(&mut self, src: IpAddr, dst: IpAddr, transport: Transport, now: Instant) {
        self.count_packet();
        self.engine.observe_parts(src, dst, transport, now);

        // Legacy cumulative SYN counter, kept for `ThreatConfig` users.
        if let Transport::Tcp { flags, .. } = transport {
            if flags.is_connection_attempt() {
                self.packet_stats.syn_count += 1;
            }
        }
        if self.packet_stats.syn_count >= self.config.syn_flood_threshold {
            self.current_threat_type = ThreatType::SynFlood;
        }
    }

    /// Live alerts, most severe first.
    pub fn active_alerts(&self) -> Vec<Alert> {
        self.engine.active_alerts(Instant::now()).into_iter().cloned().collect()
    }

    /// Release state for hosts and alerts that have gone quiet. Call
    /// periodically (the UI does so once a second).
    pub fn expire(&mut self) {
        let now = Instant::now();
        self.engine.expire(now);
        self.clean_old_connections();
        // The legacy threat type is only meaningful while its window is open.
        if now.duration_since(self.packet_stats.window_start) > self.config.ddos_window {
            self.current_threat_type = ThreatType::Unknown;
        }
    }

    /// Access the underlying engine (configuration, time-injected queries).
    pub fn engine(&self) -> &ThreatEngine {
        &self.engine
    }

    /// Check if DDoS attack is active
    pub fn is_ddos_active(&self) -> bool {
        let elapsed = Instant::now().duration_since(self.packet_stats.window_start);
        // Use at least 1 second to avoid division by near-zero in tests
        let elapsed_secs = elapsed.as_secs_f64().max(1.0);
        let packet_rate = self.packet_stats.packet_count as f64 / elapsed_secs;
        packet_rate > self.config.ddos_packet_rate_threshold
    }

    /// Get the current threat type: the most severe live alert, falling back
    /// to the legacy cumulative counters.
    pub fn get_threat_type(&self) -> ThreatType {
        let alerts = self.engine.active_alerts(Instant::now());
        if alerts.iter().any(|a| a.kind == AlertKind::SynFlood) {
            return ThreatType::SynFlood;
        }
        if self.current_threat_type == ThreatType::SynFlood {
            return ThreatType::SynFlood;
        }
        if alerts
            .iter()
            .any(|a| matches!(a.kind, AlertKind::PortScan | AlertKind::HostSweep | AlertKind::StealthScan))
        {
            return ThreatType::PortScan;
        }
        self.current_threat_type.clone()
    }

    /// Detect anomalies in packets
    pub fn detect_anomaly(&mut self, packet: &Packet) -> Option<Anomaly> {
        // Check for malformed packets
        if packet.data.len() < 20 {
            return Some(Anomaly {
                severity: Severity::High,
            });
        }

        // Check for unusual ports (simplified - just checking port 31337)
        if let Some(port) = extract_destination_port(packet) {
            if port == 31337 {
                return Some(Anomaly {
                    severity: Severity::Medium,
                });
            }
        }

        // Check for other anomalies (all 0xFF indicates malformed)
        if packet.data.iter().all(|&b| b == 0xFF) {
            return Some(Anomaly {
                severity: Severity::High,
            });
        }

        None
    }

    /// Add a threat indicator
    pub fn add_threat_indicator(&mut self, indicator: ThreatIndicator) {
        self.threat_indicators.push(indicator);
    }

    /// Overall threat level: the higher of the live alert level and the
    /// level implied by manually added indicators.
    pub fn get_threat_level(&self) -> ThreatLevel {
        let from_indicators = match self.threat_indicators.len() {
            0 => ThreatLevel::Low,
            1 => ThreatLevel::Medium,
            2 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        };
        from_indicators.max(self.engine.threat_level(Instant::now()))
    }

    /// Clean old connection records
    fn clean_old_connections(&mut self) {
        let now = Instant::now();
        
        for connections in self.connections.values_mut() {
            connections.retain(|conn| {
                now.duration_since(conn.timestamp) <= self.config.connection_window
            });
        }

        // Remove entries with no connections
        self.connections.retain(|_, conns| !conns.is_empty());
    }
}

/// Extract the destination port using the real layered decoder.
fn extract_destination_port(packet: &Packet) -> Option<u16> {
    decode_guess(&packet.data).ok().and_then(|d| d.dst_port())
}

#[cfg(test)]
mod live_traffic_tests {
    use super::*;
    use crate::decode::testutil::{ethernet, ipv4, tcp};
    use crate::decode::TcpFlags;

    fn frame(src: [u8; 4], dst_port: u16, flags: u8) -> Packet {
        let data = ethernet(0x0800, &ipv4(6, src, [10, 0, 0, 1], &tcp(40000, dst_port, flags, b"")));
        Packet { length: data.len(), data, timestamp: 0, src_ip: String::new(), dst_ip: String::new() }
    }

    #[test]
    fn syn_flood_is_detected_in_ethernet_frames() {
        // Live captures are Ethernet frames; the old fixed-offset check read
        // the flags from the wrong byte and could never fire on real traffic.
        let mut detector = ThreatDetector::new();
        for _ in 0..150 {
            detector.analyze_packet(&frame([203, 0, 113, 7], 80, TcpFlags::SYN));
        }
        assert_eq!(detector.get_threat_type(), ThreatType::SynFlood);
    }

    #[test]
    fn syn_ack_replies_are_not_counted_as_attack() {
        let mut detector = ThreatDetector::new();
        for port in 0..150 {
            detector.analyze_packet(&frame([203, 0, 113, 7], 1000 + port, TcpFlags::SYN | TcpFlags::ACK));
        }
        assert_eq!(detector.get_threat_type(), ThreatType::Unknown);
        assert!(!detector.is_port_scan("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn port_scan_is_detected_from_packets_alone() {
        let mut detector = ThreatDetector::new();
        for port in 1..=25 {
            detector.analyze_packet(&frame([198, 51, 100, 9], port, TcpFlags::SYN));
        }
        assert!(detector.is_port_scan("198.51.100.9".parse().unwrap()));
        assert_eq!(detector.get_threat_type(), ThreatType::PortScan);
    }

    #[test]
    fn threat_level_and_alerts_come_from_live_packets() {
        // Before the engine, nothing in the binary ever added an indicator, so
        // the panel could only ever show "Low".
        let mut detector = ThreatDetector::new();
        assert_eq!(detector.get_threat_level(), ThreatLevel::Low);
        for port in 1..=25 {
            detector.analyze_packet(&frame([198, 51, 100, 9], port, TcpFlags::SYN));
        }
        assert_eq!(detector.get_threat_level(), ThreatLevel::High);
        let alerts = detector.active_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].summary(), "Port scan 198.51.100.9 -> 10.0.0.1 (25 ports in 60s)");
    }

    #[test]
    fn legacy_connection_table_is_bounded() {
        let mut detector = ThreatDetector::new();
        for i in 0..(MAX_LEGACY_SOURCES as u32 + 500) {
            detector.add_connection(IpAddr::from(i.to_be_bytes()), 80);
        }
        assert!(detector.connections.len() <= MAX_LEGACY_SOURCES);
        let one = IpAddr::from([9, 9, 9, 9]);
        for port in 0..3000u16 {
            detector.add_connection(one, port);
        }
        assert!(detector.connections[&one].len() <= MAX_LEGACY_RECORDS_PER_SOURCE);
    }

    #[test]
    fn repeated_connections_to_one_port_are_not_a_scan() {
        let mut detector = ThreatDetector::new();
        for _ in 0..50 {
            detector.analyze_packet(&frame([198, 51, 100, 9], 443, TcpFlags::SYN));
        }
        assert!(!detector.is_port_scan("198.51.100.9".parse().unwrap()));
    }
}
