use criterion::{black_box, criterion_group, criterion_main, Criterion, BatchSize};
use netrain::{
    matrix_rain::{MatrixRain, CharacterSet},
    packet::{parse_packet, classify_protocol},
    threat_detection::ThreatDetector,
    optimized::{parse_packet_optimized, parse_packet_zero_alloc, parse_packet_ultra_optimized, 
                classify_protocol_optimized, random_matrix_char_optimized},
    Packet,
};
use std::net::IpAddr;

fn bench_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parsing");
    
    // Small packet
    let small_packet = vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
                           0xb1, 0xe6, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65];
    
    group.bench_function("parse_small_packet", |b| {
        b.iter(|| {
            let result = parse_packet(black_box(&small_packet));
            black_box(result);
        });
    });
    
    group.bench_function("parse_small_packet_optimized", |b| {
        b.iter(|| {
            let result = parse_packet_optimized(black_box(&small_packet));
            black_box(result);
        });
    });
    
    group.bench_function("parse_small_packet_zero_alloc", |b| {
        b.iter(|| {
            let result = parse_packet_zero_alloc(black_box(&small_packet));
            black_box(result);
        });
    });
    
    group.bench_function("parse_small_packet_ultra", |b| {
        let mut reuse_vec = Vec::with_capacity(1500);
        b.iter(|| {
            let result = parse_packet_ultra_optimized(black_box(&small_packet), &mut reuse_vec);
            black_box(result);
        });
    });
    
    // Medium packet with payload
    let mut medium_packet = small_packet.clone();
    medium_packet.extend_from_slice(&[0u8; 100]);
    
    group.bench_function("parse_medium_packet", |b| {
        b.iter(|| {
            let result = parse_packet(black_box(&medium_packet));
            black_box(result);
        });
    });
    
    // Large packet
    let mut large_packet = small_packet.clone();
    large_packet.extend_from_slice(&[0u8; 1400]);
    
    group.bench_function("parse_large_packet", |b| {
        b.iter(|| {
            let result = parse_packet(black_box(&large_packet));
            black_box(result);
        });
    });
    
    group.finish();
}

fn bench_protocol_classification(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_classification");
    
    // TCP packet
    let tcp_packet = Packet {
        data: vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
                   0xb1, 0xe6, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65],
        length: 60,
        timestamp: 0,
        src_ip: "192.168.1.100".to_string(),
        dst_ip: "192.168.1.101".to_string(),
    };
    
    group.bench_function("classify_tcp", |b| {
        b.iter(|| {
            let protocol = classify_protocol(black_box(&tcp_packet));
            black_box(protocol);
        });
    });
    
    group.bench_function("classify_tcp_optimized", |b| {
        b.iter(|| {
            let protocol = classify_protocol_optimized(black_box(&tcp_packet));
            black_box(protocol);
        });
    });
    
    // HTTP packet
    let http_packet = Packet {
        data: b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        length: 48,
        timestamp: 0,
        src_ip: "192.168.1.100".to_string(),
        dst_ip: "192.168.1.101".to_string(),
    };
    
    group.bench_function("classify_http", |b| {
        b.iter(|| {
            let protocol = classify_protocol(black_box(&http_packet));
            black_box(protocol);
        });
    });
    
    // SSH packet
    let ssh_packet = Packet {
        data: b"SSH-2.0-OpenSSH_7.4".to_vec(),
        length: 19,
        timestamp: 0,
        src_ip: "192.168.1.100".to_string(),
        dst_ip: "192.168.1.101".to_string(),
    };
    
    group.bench_function("classify_ssh", |b| {
        b.iter(|| {
            let protocol = classify_protocol(black_box(&ssh_packet));
            black_box(protocol);
        });
    });
    
    // Mixed protocol batch
    let packets = vec![tcp_packet.clone(), http_packet.clone(), ssh_packet.clone()];
    
    group.bench_function("classify_mixed_batch", |b| {
        b.iter(|| {
            for packet in &packets {
                let protocol = classify_protocol(black_box(packet));
                black_box(protocol);
            }
        });
    });
    
    group.finish();
}

fn bench_matrix_rain_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_rain_update");
    
    // Small matrix
    group.bench_function("update_100_columns", |b| {
        b.iter_batched(
            || {
                let mut rain = MatrixRain::new(200, 50);
                for i in 0..100 {
                    rain.add_column(i);
                }
                rain
            },
            |mut rain| {
                rain.update(black_box(0.016)); // 60 FPS frame time
            },
            BatchSize::SmallInput,
        );
    });
    
    // Medium matrix
    group.bench_function("update_500_columns", |b| {
        b.iter_batched(
            || {
                let mut rain = MatrixRain::new(800, 50);
                for i in 0..500 {
                    rain.add_column(i);
                }
                rain
            },
            |mut rain| {
                rain.update(black_box(0.016));
            },
            BatchSize::SmallInput,
        );
    });
    
    // Large matrix (target case)
    group.bench_function("update_1000_columns", |b| {
        b.iter_batched(
            || {
                let mut rain = MatrixRain::new(1200, 50);
                for i in 0..1000 {
                    rain.add_column(i);
                }
                rain
            },
            |mut rain| {
                rain.update(black_box(0.016));
            },
            BatchSize::SmallInput,
        );
    });
    
    // Update with threat active
    group.bench_function("update_threat_active", |b| {
        b.iter_batched(
            || {
                let mut rain = MatrixRain::new(800, 50);
                for i in 0..500 {
                    rain.add_column(i);
                }
                rain.set_threat_active(true);
                rain
            },
            |mut rain| {
                rain.update(black_box(0.016));
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

fn bench_matrix_rain_render(c: &mut Criterion) {
    use ratatui::{buffer::Buffer, layout::Rect};
    
    let mut group = c.benchmark_group("matrix_rain_render");
    
    group.bench_function("render_500_columns", |b| {
        b.iter_batched(
            || {
                let mut rain = MatrixRain::new(800, 50);
                for i in 0..500 {
                    rain.add_column(i);
                }
                rain.update(0.016); // Initialize with one update
                (rain, Buffer::empty(Rect::new(0, 0, 80, 25)))
            },
            |(mut rain, mut buffer)| {
                use ratatui::widgets::Widget;
                rain.render(Rect::new(0, 0, 80, 25), &mut buffer);
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

fn bench_threat_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("threat_detection");
    
    // Single packet analysis
    let packet = Packet {
        data: vec![0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
                   0xb1, 0xe6, 0xc0, 0xa8, 0x01, 0x64, 0xc0, 0xa8, 0x01, 0x65],
        length: 60,
        timestamp: 0,
        src_ip: "192.168.1.100".to_string(),
        dst_ip: "192.168.1.101".to_string(),
    };
    
    group.bench_function("analyze_single_packet", |b| {
        b.iter_batched(
            || ThreatDetector::new(),
            |mut detector| {
                detector.analyze_packet(black_box(&packet));
            },
            BatchSize::SmallInput,
        );
    });
    
    // Port scan detection
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    
    group.bench_function("port_scan_check", |b| {
        b.iter_batched(
            || {
                let mut detector = ThreatDetector::new();
                // Add connections to different ports
                for port in 1000..1030 {
                    detector.add_connection(ip, port);
                }
                detector
            },
            |detector| {
                let is_scan = detector.is_port_scan(black_box(ip));
                black_box(is_scan);
            },
            BatchSize::SmallInput,
        );
    });
    
    // DDoS detection
    group.bench_function("ddos_detection", |b| {
        b.iter_batched(
            || {
                let mut detector = ThreatDetector::new();
                // Simulate high packet rate
                for _ in 0..1000 {
                    detector.analyze_packet(&packet);
                }
                detector
            },
            |detector| {
                let is_ddos = detector.is_ddos_active();
                black_box(is_ddos);
            },
            BatchSize::SmallInput,
        );
    });
    
    // Anomaly detection
    group.bench_function("anomaly_detection", |b| {
        b.iter_batched(
            || ThreatDetector::new(),
            |mut detector| {
                let anomaly = detector.detect_anomaly(black_box(&packet));
                black_box(anomaly);
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

fn bench_character_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("character_operations");
    
    // Random character generation
    group.bench_function("random_char_ascii", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let char = netrain::matrix_rain::random_matrix_char(&mut rng, CharacterSet::ASCII);
            black_box(char);
        });
    });
    
    group.bench_function("random_char_ascii_optimized", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let char = random_matrix_char_optimized(&mut rng, CharacterSet::ASCII);
            black_box(char);
        });
    });
    
    group.bench_function("random_char_katakana", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let char = netrain::matrix_rain::random_matrix_char(&mut rng, CharacterSet::Katakana);
            black_box(char);
        });
    });
    
    group.bench_function("random_char_mixed", |b| {
        let mut rng = rand::thread_rng();
        b.iter(|| {
            let char = netrain::matrix_rain::random_matrix_char(&mut rng, CharacterSet::Mixed);
            black_box(char);
        });
    });
    
    group.finish();
}

fn bench_memory_allocations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocations");
    
    // Column creation
    group.bench_function("create_column", |b| {
        let mut rain = MatrixRain::new(1000, 50);
        let mut x = 0;
        b.iter(|| {
            rain.add_column(x);
            x = (x + 1) % 1000;
        });
    });
    
    // Column removal
    group.bench_function("remove_column", |b| {
        b.iter_batched(
            || {
                let mut rain = MatrixRain::new(1000, 50);
                for i in 0..100 {
                    rain.add_column(i);
                }
                rain
            },
            |mut rain| {
                for i in 0..10 {
                    rain.remove_column(i);
                }
            },
            BatchSize::SmallInput,
        );
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_packet_parsing,
    bench_protocol_classification,
    bench_matrix_rain_update,
    bench_matrix_rain_render,
    bench_threat_detection,
    bench_character_operations,
    bench_memory_allocations
);

criterion_main!(benches);