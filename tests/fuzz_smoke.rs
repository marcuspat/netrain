//! A mutation fuzzer that runs on stable Rust as part of `cargo test`.
//!
//! netrain parses bytes chosen by whoever is on the network, so "no input can
//! crash it" is the property that matters most. Starting from valid packets
//! and capture files, this flips, truncates, splices and overwrites bytes and
//! pushes the results through every parser and through the stateful pipeline.
//!
//! The run is deterministic (fixed seed) so a failure reproduces. Iterations
//! default to a quick pass; raise them with `NETRAIN_FUZZ_ITERS=2000000`.
//! `fuzz/` holds equivalent `cargo-fuzz` targets for coverage-guided runs.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use netrain::capture::channel;
use netrain::decode::{decode, decode_guess, LinkType, TcpFlags};
use netrain::export::{Exporter, Format};
use netrain::pcapfile::{PcapReader, PcapWriter};
use netrain::replay::{analyze_pcap, ReplayAnalyzer};
use netrain::state::AppState;
use netrain::synth::{
    client_hello, dns_query, dns_response, eth_tcp, eth_udp, ethernet, ipv4, ipv6, tcp, udp, with_vlan,
};
use netrain::{classify, dns, inspect, Packet};

/// xorshift64*: small, fast, deterministic.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const LINKS: [LinkType; 5] =
    [LinkType::Ethernet, LinkType::RawIp, LinkType::Null, LinkType::LinuxSll, LinkType::LinuxSll2];
const INTERESTING: [u8; 10] = [0x00, 0x01, 0x04, 0x06, 0x11, 0x3f, 0x40, 0x7f, 0x80, 0xff];

fn seed_packets() -> Vec<Vec<u8>> {
    let (c, s) = ([192, 168, 1, 10], [93, 184, 216, 34]);
    let mut v6 = [0u8; 16];
    v6[0] = 0x20;
    v6[15] = 1;
    let mut ext = vec![6, 0, 0, 0, 0, 0, 0, 0]; // hop-by-hop then TCP
    ext.extend_from_slice(&tcp(1, 443, TcpFlags::SYN, b""));
    let mut frag = vec![6, 0, 0, 9, 0, 0, 0, 1]; // fragment header
    frag.extend_from_slice(&[0xde; 16]);
    vec![
        eth_tcp(c, s, 50000, 443, TcpFlags::SYN, b""),
        eth_tcp(s, c, 443, 50000, TcpFlags::SYN | TcpFlags::ACK, b""),
        eth_tcp(c, s, 50000, 443, 0x18, &client_hello("www.example.com")),
        eth_tcp(c, s, 50001, 80, 0x18, b"GET /a HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\n\r\n"),
        eth_tcp(c, s, 50002, 22, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n"),
        eth_udp(c, [9, 9, 9, 9], 40000, 53, &dns_query("www.example.com")),
        eth_udp([9, 9, 9, 9], c, 53, 40000, &dns_response("www.example.com", &[s.into(), v6.into()])),
        eth_udp(c, s, 40001, 443, &[0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8]),
        eth_udp(c, [224, 0, 0, 251], 5353, 5353, &dns_query("printer.local")),
        with_vlan(&eth_tcp(c, s, 50003, 80, TcpFlags::SYN, b""), 42),
        ethernet(0x86dd, &ipv6(17, v6, v6, &udp(546, 547, b"dhcp"))),
        ethernet(0x86dd, &ipv6(0, v6, v6, &ext)),
        ethernet(0x86dd, &ipv6(44, v6, v6, &frag)),
        ethernet(0x0800, &ipv4(1, c, s, &[8, 0, 0, 0, 0, 1, 0, 1])),
        ethernet(0x0806, &[0u8; 28]),
        ipv4(6, c, s, &tcp(1, 2, 0, b"")), // raw IP
    ]
}

fn mutate(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    let mut data = corpus[rng.below(corpus.len())].clone();
    for _ in 0..=rng.below(4) {
        match rng.below(8) {
            0 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] ^= 1 << rng.below(8);
            }
            1 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] = rng.next() as u8;
            }
            3 => data.truncate(rng.below(data.len() + 1)),
            4 => {
                // Splice the tail of another seed on.
                let other = &corpus[rng.below(corpus.len())];
                let cut = rng.below(data.len() + 1);
                data.truncate(cut);
                data.extend_from_slice(&other[rng.below(other.len() + 1)..]);
            }
            5 if data.len() >= 2 => {
                // Overwrite a 16-bit field with an extreme length.
                let i = rng.below(data.len() - 1);
                let v: u16 = [0, 1, 0x7fff, 0x8000, 0xffff, 0xfffe][rng.below(6)];
                data[i..i + 2].copy_from_slice(&v.to_be_bytes());
            }
            6 => {
                let n = rng.below(40);
                let b = rng.next() as u8;
                let at = rng.below(data.len() + 1);
                data.splice(at..at, std::iter::repeat_n(b, n));
            }
            7 if !data.is_empty() => {
                let start = rng.below(data.len());
                let end = start + rng.below(data.len() - start + 1);
                data.drain(start..end);
            }
            _ => {}
        }
    }
    data.truncate(4096);
    data
}

/// Run every stateless parser on `data`.
fn parse_everything(data: &[u8]) {
    for link in LINKS {
        if let Ok(d) = decode(link, data) {
            assert!(d.payload.len() <= data.len());
            let _ = classify::classify(&d);
            if let Some(insight) = inspect::insight(&d) {
                assert!(inspect::sanitize_hostname(insight.name.as_bytes()).is_some() || !insight.name.is_empty());
            }
        }
    }
    let _ = decode_guess(data);
    let _ = classify::classify_bytes(data);
    let _ = dns::question_name(data);
    let _ = dns::answers(data);
    for name in [inspect::tls_sni(data), inspect::http_host(data)].into_iter().flatten() {
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)), "{name:?}");
    }
    let _ = inspect::is_quic_initial(data);

    // Legacy `Packet` API.
    if let Ok(packet) = netrain::parse_packet(data) {
        let _ = netrain::classify_protocol(&packet);
        let _ = netrain::validate_packet(&packet);
        let _ = netrain::extract_protocol(&packet);
        let _ = netrain::extract_dns_query(&packet);
        let _ = netrain::get_http_method(&packet);
        let _ = netrain::is_tls_handshake(&packet);
        let _ = netrain::optimized::classify_protocol_optimized(&packet);
    }
    let empty = Packet { data: Vec::new(), length: 0, timestamp: 0, src_ip: String::new(), dst_ip: String::new() };
    let _ = netrain::classify_protocol(&empty);
    let _ = netrain::validate_packet(&empty);
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn iterations(default: usize) -> usize {
    std::env::var("NETRAIN_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[test]
fn mutated_packets_never_panic_any_parser() {
    let corpus = seed_packets();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for i in 0..iterations(60_000) {
        let data = mutate(&mut rng, &corpus);
        if catch_unwind(AssertUnwindSafe(|| parse_everything(&data))).is_err() {
            panic!("parser panicked on iteration {i}; input: {}", hex(&data));
        }
    }
}

#[test]
fn mutated_traffic_never_panics_the_stateful_pipeline() {
    // The same mutated packets, fed in sequence with hostile timestamps
    // through everything that keeps state: the capture channel and UI state,
    // the headless analyser, and the JSON exporter.
    let corpus = seed_packets();
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let (sink, rx, counters) = channel(4096);
    let mut state = AppState::new();
    let mut analyzer = ReplayAnalyzer::default();
    let mut json = Vec::new();
    let mut exporter = Exporter::new(&mut json, Format::Json, false);
    let now = Instant::now();
    let mut ts: i64 = 1_700_000_000_000_000;
    let n = iterations(60_000) / 3;

    let result = catch_unwind(AssertUnwindSafe(|| {
        for i in 0..n {
            let data = mutate(&mut rng, &corpus);
            // Mostly advancing time, sometimes backwards, sometimes absurd.
            ts = match rng.below(50) {
                0 => i64::MAX,
                1 => i64::MIN,
                2 => 0,
                3 => ts.saturating_sub(rng.below(10_000_000) as i64),
                _ => ts.saturating_add(rng.below(2_000_000) as i64),
            };
            let link = LINKS[if rng.below(4) == 0 { rng.below(LINKS.len()) } else { 0 }];
            let wire_len = if rng.below(10) == 0 { rng.next() as usize } else { data.len() };

            sink.submit(link, &data, wire_len);
            analyzer.feed(link, ts, &data, wire_len);
            exporter.feed(link, ts, &data, wire_len).unwrap();
            if i % 64 == 0 {
                state.drain(&rx, usize::MAX, "00:00:00", now, |_| {});
                state.tick_second();
                let _ = state.detector.get_threat_level();
                let _ = state.flows.top_flows(5);
                let _ = state.flows.top_talkers(5);
                let _ = state.visible_log().count();
            }
        }
    }));
    assert!(result.is_ok(), "stateful pipeline panicked");

    let summary = analyzer.finish();
    let _ = summary.to_string();
    let fed = counters.snapshot();
    assert_eq!(fed.received, n as u64);
    assert!(summary.packets + summary.undecodable == n as u64);

    // Whatever went in, every line that came out is one valid JSON object.
    exporter.finish(0).unwrap();
    let text = String::from_utf8(json).expect("output is UTF-8");
    assert!(!text.contains('\x1b'), "no escape sequences in output");
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"));
        assert!(v["type"].is_string());
    }
}

#[test]
fn mutated_capture_files_never_panic() {
    // Valid pcap files with corrupted headers, lengths and bodies.
    let mut writer = PcapWriter::new(1);
    for (i, p) in seed_packets().iter().enumerate() {
        writer.packet(1_700_000_000_000_000 + i as i64 * 1000, p);
    }
    let fixtures = ["normal_traffic", "port_scan", "ddos_attack", "mixed_protocols"].map(|name| {
        std::fs::read(format!("{}/tests/fixtures/{name}.pcap", env!("CARGO_MANIFEST_DIR"))).unwrap()
    });
    let mut corpus = vec![writer.finish(), PcapWriter::new(101).finish(), PcapWriter::new(113).finish()];
    corpus.extend(fixtures);

    let mut rng = Rng(0xA076_1D64_78BD_642F);
    for i in 0..iterations(60_000) / 10 {
        let mut file = corpus[rng.below(corpus.len())].clone();
        for _ in 0..=rng.below(6) {
            if file.is_empty() {
                break;
            }
            let at = rng.below(file.len());
            match rng.below(4) {
                0 => file[at] = rng.next() as u8,
                1 => file[at] = INTERESTING[rng.below(INTERESTING.len())],
                2 => file.truncate(at),
                _ => {
                    // Corrupt a 32-bit length or timestamp field.
                    let v: u32 = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 65_536][rng.below(6)];
                    let end = (at + 4).min(file.len());
                    file[at..end].copy_from_slice(&v.to_le_bytes()[..end - at]);
                }
            }
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(reader) = PcapReader::new(&file) {
                for record in reader.take(100_000).flatten() {
                    assert!(record.data.len() <= file.len());
                }
            }
            if let Ok(summary) = analyze_pcap(&file) {
                let _ = summary.to_string();
                let _ = netrain::export::summary_json(&summary, 0);
            }
        }));
        assert!(outcome.is_ok(), "capture-file handling panicked on iteration {i}; file: {}", hex(&file));
    }
}
