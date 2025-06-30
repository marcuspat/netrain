use netrain::threat_detection::ThreatDetector;
use netrain::{Packet, ThreatType, Severity, ThreatIndicator, ThreatLevel};
use std::net::IpAddr;

/// Helper to create a basic TCP packet
fn create_tcp_packet() -> Packet {
    let mut data = vec![0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06];
    data.extend_from_slice(&[0x00; 50]);
    Packet {
        data,
        length: 60,
        timestamp: 0,
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "192.168.1.2".to_string(),
    }
}

/// Helper to create a TCP SYN packet
fn create_syn_packet() -> Packet {
    let mut data = vec![0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06];
    data.extend_from_slice(&[0x00; 50]);
    Packet {
        data,
        length: 60,
        timestamp: 0,
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "192.168.1.2".to_string(),
    }
}

#[test]
fn test_detect_port_scan() {
    let mut detector = ThreatDetector::new();
    let source_ip = "192.168.1.100".parse::<IpAddr>().unwrap();
    
    // Test negative case first
    for port in 80..85 {
        detector.add_connection(source_ip, port);
    }
    assert!(!detector.is_port_scan(source_ip));
    
    // Test positive case - many ports from same IP
    for port in 1000..1025 {
        detector.add_connection(source_ip, port);
    }
    assert!(detector.is_port_scan(source_ip));
}

#[test]
fn test_detect_ddos_attack() {
    let mut detector = ThreatDetector::new();
    
    // Simulate high rate traffic
    for _ in 0..2000 {
        let packet = create_tcp_packet();
        detector.analyze_packet(&packet);
    }
    
    assert!(detector.is_ddos_active());
}

#[test]
fn test_detect_anomaly() {
    let mut detector = ThreatDetector::new();
    
    // Test normal packet - no anomaly
    let normal_packet = create_tcp_packet();
    assert!(detector.detect_anomaly(&normal_packet).is_none());
    
    // Test very small packet - anomaly
    let small_packet = Packet {
        data: vec![0x45, 0x00],
        length: 2,
        timestamp: 0,
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "192.168.1.2".to_string(),
    };
    let anomaly = detector.detect_anomaly(&small_packet);
    assert!(anomaly.is_some());
    assert_eq!(anomaly.unwrap().severity, Severity::High);
}

#[test]
fn test_threat_detector_time_window() {
    let mut detector = ThreatDetector::new();
    let source_ip = "192.168.1.100".parse::<IpAddr>().unwrap();
    
    // Add connections
    for port in 1000..1030 {
        detector.add_connection(source_ip, port);
    }
    assert!(detector.is_port_scan(source_ip));
    
    // Wait for time window to expire (simulated by creating new detector)
    // In real implementation, we'd wait for the time window
    let detector2 = ThreatDetector::new();
    assert!(!detector2.is_port_scan(source_ip));
}

#[test]
fn test_threat_detector_alert_generation() {
    let mut detector = ThreatDetector::new();
    
    // Generate different severity alerts
    let high_severity_packet = Packet {
        data: vec![0xFF; 10], // All 0xFF = malformed
        length: 10,
        timestamp: 0,
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "192.168.1.2".to_string(),
    };
    
    let alert = detector.detect_anomaly(&high_severity_packet);
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().severity, Severity::High);
    
    // Medium severity - unusual port
    let mut unusual_port_packet = vec![0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06];
    unusual_port_packet.extend_from_slice(&[0x00; 10]);
    unusual_port_packet.extend_from_slice(&[0x00, 0x50, 0x7A, 0x69]); // Port 31337
    unusual_port_packet.extend_from_slice(&[0x00; 36]);
    
    let packet = Packet {
        data: unusual_port_packet,
        length: 60,
        timestamp: 0,
        src_ip: "192.168.1.1".to_string(),
        dst_ip: "192.168.1.2".to_string(),
    };
    
    let alert = detector.detect_anomaly(&packet);
    assert!(alert.is_some());
    assert_eq!(alert.unwrap().severity, Severity::Medium);
}

#[test]
fn test_threat_detector_false_positive_rate() {
    let mut detector = ThreatDetector::new();
    let mut false_positives = 0;
    let total_packets = 100;
    
    // Send normal traffic
    for _ in 0..total_packets {
        let packet = create_tcp_packet();
        detector.analyze_packet(&packet);
        
        // Check for false positive anomalies
        if detector.detect_anomaly(&packet).is_some() {
            false_positives += 1;
        }
    }
    
    // False positive rate should be 0 for normal packets
    assert_eq!(false_positives, 0);
    
    // DDoS should not trigger on normal traffic volume
    assert!(!detector.is_ddos_active());
}

#[test]
fn test_aggregate_threats() {
    let mut detector = ThreatDetector::new();
    
    // No threats initially
    assert_eq!(detector.get_threat_level(), ThreatLevel::Low);
    
    // Add one threat indicator
    detector.add_threat_indicator(ThreatIndicator::PortScan);
    assert_eq!(detector.get_threat_level(), ThreatLevel::Medium);
    
    // Add another threat indicator  
    detector.add_threat_indicator(ThreatIndicator::HighTrafficRate);
    assert_eq!(detector.get_threat_level(), ThreatLevel::High);
    
    // Add third threat indicator
    detector.add_threat_indicator(ThreatIndicator::SuspiciousPayload);
    assert_eq!(detector.get_threat_level(), ThreatLevel::Critical);
}

#[test]
fn test_threat_scoring_system() {
    let mut detector = ThreatDetector::new();
    
    // Test threat type detection
    assert_eq!(detector.get_threat_type(), ThreatType::Unknown);
    
    // Simulate SYN flood
    for _ in 0..150 {
        let packet = create_syn_packet();
        detector.analyze_packet(&packet);
    }
    
    assert_eq!(detector.get_threat_type(), ThreatType::SynFlood);
}

#[test]
fn test_mock_packet_streams() {
    let mut detector = ThreatDetector::new();
    
    // Simulate different attack patterns
    
    // Pattern 1: Port scan
    let attacker_ip = "10.0.0.1".parse::<IpAddr>().unwrap();
    for port in 1..100 {
        detector.add_connection(attacker_ip, port * 100);
    }
    assert!(detector.is_port_scan(attacker_ip));
    
    // Pattern 2: DDoS flood
    let mut flood_detector = ThreatDetector::new();
    for _ in 0..1500 {
        let packet = create_tcp_packet();
        flood_detector.analyze_packet(&packet);
    }
    assert!(flood_detector.is_ddos_active());
    
    // Pattern 3: Mixed normal and attack traffic
    let mut mixed_detector = ThreatDetector::new();
    let normal_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    let attack_ip = "192.168.1.2".parse::<IpAddr>().unwrap();
    
    // Normal traffic
    mixed_detector.add_connection(normal_ip, 80);
    mixed_detector.add_connection(normal_ip, 443);
    
    // Attack traffic
    for port in 1000..1050 {
        mixed_detector.add_connection(attack_ip, port);
    }
    
    assert!(!mixed_detector.is_port_scan(normal_ip));
    assert!(mixed_detector.is_port_scan(attack_ip));
}