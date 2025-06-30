use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

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

        // Check if it's a SYN packet (simplified check)
        if is_syn_packet(packet) {
            self.packet_stats.syn_count += 1;
        }

        // Update threat type based on analysis
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

/// Check if a packet is a TCP SYN packet (simplified)
fn is_syn_packet(packet: &Packet) -> bool {
    // Very simplified check - in reality would parse TCP flags
    packet.data.len() >= 20 && packet.data[9] == 0x06 // TCP protocol
}

/// Extract destination port from packet (simplified)
fn extract_destination_port(packet: &Packet) -> Option<u16> {
    // Simplified - would normally parse IP header to find TCP/UDP header
    if packet.data.len() >= 24 {
        // Assume TCP packet with standard IP header (20 bytes) + TCP header start
        // Destination port is at bytes 22-23 (0-indexed)
        let port_bytes = &packet.data[22..24];
        Some(u16::from_be_bytes([port_bytes[0], port_bytes[1]]))
    } else {
        None
    }
}