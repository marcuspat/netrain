//! Benchmarks of the path a live packet actually takes:
//! decode -> classify -> inspect -> flows -> threat engine.
//!
//! Run with `cargo bench --bench pipeline`. Numbers are recorded in
//! `docs/PERFORMANCE.md`.

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use netrain::alerts::ThreatEngine;
use netrain::capture::{channel, PacketRecord};
use netrain::decode::{decode, LinkType, TcpFlags};
use netrain::flows::FlowTable;
use netrain::pipeline::observe;
use netrain::replay::ReplayAnalyzer;
use netrain::state::AppState;
use netrain::synth::{client_hello, dns_query, eth_tcp, eth_udp};

const CLIENT: [u8; 4] = [192, 168, 1, 10];
const SERVER: [u8; 4] = [93, 184, 216, 34];

/// A realistic mix: mostly data segments, some handshakes, DNS and a hello.
fn traffic_mix() -> Vec<Vec<u8>> {
    let payload = vec![0x17u8; 1400];
    let mut frames = Vec::new();
    for i in 0..64u16 {
        let port = 50000 + (i % 8);
        frames.push(eth_tcp(SERVER, CLIENT, 443, port, TcpFlags::ACK, &payload));
        frames.push(eth_tcp(CLIENT, SERVER, port, 443, TcpFlags::ACK, b""));
        if i % 8 == 0 {
            frames.push(eth_tcp(CLIENT, SERVER, port, 443, TcpFlags::SYN, b""));
            frames.push(eth_tcp(CLIENT, SERVER, port, 443, 0x18, &client_hello("www.example.com")));
            frames.push(eth_udp(CLIENT, [9, 9, 9, 9], 40000 + i, 53, &dns_query("www.example.com")));
        }
    }
    frames
}

/// Every packet is a SYN from a new spoofed source to a new port: the worst
/// case for the flow table and the threat engine.
fn syn_flood(n: u32) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let b = i.to_be_bytes();
            eth_tcp([11, b[1], b[2], b[3]], SERVER, 1024 + (i % 60000) as u16, 80, TcpFlags::SYN, b"")
        })
        .collect()
}

fn bench_decode(c: &mut Criterion) {
    let frames = traffic_mix();
    let mut g = c.benchmark_group("per_packet");
    g.throughput(Throughput::Elements(frames.len() as u64));

    g.bench_function("decode", |b| {
        b.iter(|| {
            for f in &frames {
                black_box(decode(LinkType::Ethernet, black_box(f)).ok());
            }
        })
    });
    g.bench_function("decode_classify", |b| {
        b.iter(|| {
            for f in &frames {
                black_box(observe(LinkType::Ethernet, black_box(f), f.len()).ok());
            }
        })
    });
    g.bench_function("capture_thread_work", |b| {
        // What the capture thread does per packet: decode, classify, look
        // for a hostname, build the record that crosses the channel.
        b.iter(|| {
            for f in &frames {
                if let Ok((event, decoded)) = observe(LinkType::Ethernet, f, f.len()) {
                    black_box(PacketRecord::from_decoded(event, &decoded, f));
                }
            }
        })
    });
    g.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    let frames = traffic_mix();
    let mut g = c.benchmark_group("end_to_end");
    g.throughput(Throughput::Elements(frames.len() as u64));

    g.bench_function("capture_to_state_normal_traffic", |b| {
        // Channel + UI-thread state: statistics, flows, threat engine, log.
        let (sink, rx, _) = channel(frames.len() + 1);
        let mut state = AppState::new();
        let now = Instant::now();
        b.iter(|| {
            for f in &frames {
                sink.submit(LinkType::Ethernet, f, f.len());
            }
            black_box(state.drain(&rx, usize::MAX, "12:00:00", now, |_| {}));
        })
    });
    g.bench_function("replay_analyzer_normal_traffic", |b| {
        b.iter_batched_ref(
            ReplayAnalyzer::default,
            |analyzer| {
                for (i, f) in frames.iter().enumerate() {
                    black_box(analyzer.feed(LinkType::Ethernet, i as i64 * 100, f, f.len()));
                }
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_under_attack(c: &mut Criterion) {
    let flood = syn_flood(20_000);
    let mut g = c.benchmark_group("under_attack");
    g.throughput(Throughput::Elements(flood.len() as u64));
    g.sample_size(20);

    g.bench_function("threat_engine_spoofed_syn_flood", |b| {
        b.iter_batched_ref(
            ThreatEngine::default,
            |engine| {
                let t0 = Instant::now();
                for (i, f) in flood.iter().enumerate() {
                    let d = decode(LinkType::Ethernet, f).unwrap();
                    engine.observe(&d, t0 + Duration::from_micros(i as u64 * 50));
                }
            },
            BatchSize::LargeInput,
        )
    });
    g.bench_function("flow_table_spoofed_syn_flood", |b| {
        b.iter_batched_ref(
            FlowTable::default,
            |flows| {
                let t0 = Instant::now();
                for (i, f) in flood.iter().enumerate() {
                    let (event, _) = observe(LinkType::Ethernet, f, f.len()).unwrap();
                    flows.observe(&event, t0 + Duration::from_micros(i as u64 * 50));
                }
            },
            BatchSize::LargeInput,
        )
    });
    g.bench_function("replay_analyzer_spoofed_syn_flood", |b| {
        b.iter_batched_ref(
            ReplayAnalyzer::default,
            |analyzer| {
                for (i, f) in flood.iter().enumerate() {
                    black_box(analyzer.feed(LinkType::Ethernet, i as i64 * 50, f, f.len()));
                }
            },
            BatchSize::LargeInput,
        )
    });
    // One source probing many ports: the per-source history is at its cap.
    let scan: Vec<Vec<u8>> =
        (0..20_000u32).map(|i| eth_tcp([203, 0, 113, 7], SERVER, 40000, (i % 60000) as u16, TcpFlags::SYN, b"")).collect();
    g.bench_function("threat_engine_single_source_scan", |b| {
        b.iter_batched_ref(
            ThreatEngine::default,
            |engine| {
                let t0 = Instant::now();
                for (i, f) in scan.iter().enumerate() {
                    let d = decode(LinkType::Ethernet, f).unwrap();
                    engine.observe(&d, t0 + Duration::from_micros(i as u64 * 50));
                }
            },
            BatchSize::LargeInput,
        )
    });
    g.finish();
}

criterion_group!(benches, bench_decode, bench_end_to_end, bench_under_attack);
criterion_main!(benches);
