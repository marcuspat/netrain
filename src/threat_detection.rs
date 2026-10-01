use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::decode::{decode_guess, Transport};
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
        }
    }

    /// Add a connection record
    pub fn add_connection(&mut self, ip: IpAddr, port: u16) {
        let record = ConnectionRecord {
            source_ip: ip,
            port,
            timestamp: Instant::now(),
        };

        self.connections
            .entry(ip)
            .or_insert_with(Vec::new)
            .push(record);

        // Clean old connections
        self.clean_old_connections();
    }

    /// Check if the given IP is performing a port scan
    pub fn is_port_scan(&self, ip: IpAddr) -> bool {
        if let Some(connections) = self.connections.get(&ip) {
            let now = Instant::now();
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

    /// Analyze a packet for threat detection
    pub fn analyze_packet(&mut self, packet: &Packet) {
        let now = Instant::now();

        // Reset stats if window expired
        if now.duration_since(self.packet_stats.window_start) > self.config.ddos_window {
            self.packet_stats = PacketStats {
                packet_count: 0,
                syn_count: 0,
                window_start: now,
            };
        }

        self.packet_stats.packet_count += 1;

        // Decode once with real header lengths. A SYN-ACK is a server's reply,
        // not an attack, so only bare connection attempts are counted.
        if let Ok(decoded) = decode_guess(&packet.data) {
            if let Transport::Tcp { dst_port, flags, .. } = decoded.transport {
                if flags.is_connection_attempt() {
                    self.packet_stats.syn_count += 1;
                    // Feed the port-scan tracker from live traffic. Previously
                    // nothing called add_connection outside of tests, so port
                    // scans could never be detected by the running binary.
                    self.add_connection(decoded.src, dst_port);
                    if self.is_port_scan(decoded.src) {
                        self.current_threat_type = ThreatType::PortScan;
                    }
                }
            }
        }

        // A SYN flood outranks a port scan.
        if self.packet_stats.syn_count >= self.config.syn_flood_threshold {
            self.current_threat_type = ThreatType::SynFlood;
        }
    }

    /// Check if DDoS attack is active
    pub fn is_ddos_active(&self) -> bool {
        let elapsed = Instant::now().duration_since(self.packet_stats.window_start);
        // Use at least 1 second to avoid division by near-zero in tests
        let elapsed_secs = elapsed.as_secs_f64().max(1.0);
        let packet_rate = self.packet_stats.packet_count as f64 / elapsed_secs;
        packet_rate > self.config.ddos_packet_rate_threshold
    }

    /// Get the current threat type
    pub fn get_threat_type(&self) -> ThreatType {
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

    /// Get the overall threat level based on indicators
    pub fn get_threat_level(&self) -> ThreatLevel {
        match self.threat_indicators.len() {
            0 => ThreatLevel::Low,
            1 => ThreatLevel::Medium,
            2 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
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
    fn repeated_connections_to_one_port_are_not_a_scan() {
        let mut detector = ThreatDetector::new();
        for _ in 0..50 {
            detector.analyze_packet(&frame([198, 51, 100, 9], 443, TcpFlags::SYN));
        }
        assert!(!detector.is_port_scan("198.51.100.9".parse().unwrap()));
    }
}
