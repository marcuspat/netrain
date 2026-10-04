//! Machine-readable and plain-text output for headless use.
//!
//! One line per event on stdout, so the stream can be piped into `jq`, a log
//! shipper or `grep`. The JSON shape is documented in `docs/JSON_OUTPUT.md`
//! and pinned by tests; fields are only ever added, never renamed.

use std::io::{self, Write};
use std::net::IpAddr;

use serde::Serialize;

use crate::alerts::Alert;
use crate::decode::{LinkType, Transport};
use crate::replay::{Observation, ReplayAnalyzer, ReplaySummary};
use crate::Severity;

/// Version of the JSON schema, emitted in the summary line.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Newline-delimited JSON.
    Json,
    /// Human-readable lines.
    Text,
}

#[derive(Debug, Serialize)]
struct HostJson<'a> {
    source: &'a str,
    name: &'a str,
}

/// `{"type":"packet",...}`
#[derive(Debug, Serialize)]
struct PacketJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    /// Capture time, seconds since the Unix epoch.
    ts: f64,
    /// The same instant in whole microseconds (exact).
    ts_us: i64,
    src: IpAddr,
    dst: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<u16>,
    protocol: &'static str,
    ip_proto: u8,
    /// Bytes on the wire.
    length: usize,
    /// TCP flags as a string such as "SA" (SYN+ACK), TCP only.
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<HostJson<'a>>,
}

/// `{"type":"alert",...}`
#[derive(Debug, Serialize)]
struct AlertJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    ts: f64,
    ts_us: i64,
    /// "raised" or "cleared".
    state: &'static str,
    alert: &'static str,
    severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<IpAddr>,
    detail: &'a str,
}

#[derive(Debug, Serialize)]
struct TalkerJson {
    address: IpAddr,
    bytes: u64,
    packets: u64,
}

/// `{"type":"summary",...}` - always the last line.
#[derive(Debug, Serialize)]
struct SummaryJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    schema: u32,
    packets: u64,
    undecodable: u64,
    bytes: u64,
    duration_secs: f64,
    flows: u64,
    peak_threat: String,
    protocols: &'a std::collections::BTreeMap<&'static str, u64>,
    hostnames: &'a std::collections::BTreeSet<String>,
    alerts: &'a std::collections::BTreeSet<String>,
    top_talkers: Vec<TalkerJson>,
    /// Packets the kernel or interface dropped before we saw them (live only).
    dropped: u64,
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

/// Compact TCP flag string in the conventional order, e.g. `S`, `SA`, `FPA`.
pub fn tcp_flag_string(flags: u8) -> String {
    [
        (0x02, 'S'),
        (0x01, 'F'),
        (0x04, 'R'),
        (0x08, 'P'),
        (0x10, 'A'),
        (0x20, 'U'),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, c)| *c)
    .collect()
}

/// The JSON summary object for a capture, as one line without a newline.
pub fn summary_json(summary: &ReplaySummary, dropped: u64) -> String {
    let line = SummaryJson {
        kind: "summary",
        schema: SCHEMA_VERSION,
        packets: summary.packets,
        undecodable: summary.undecodable,
        bytes: summary.bytes,
        duration_secs: summary.duration.as_secs_f64(),
        flows: summary.flows,
        peak_threat: format!("{:?}", summary.peak()).to_lowercase(),
        protocols: &summary.protocols,
        hostnames: &summary.hostnames,
        alerts: &summary.alerts,
        top_talkers: summary
            .top_talkers
            .iter()
            .map(|(address, bytes, packets)| TalkerJson {
                address: *address,
                bytes: *bytes,
                packets: *packets,
            })
            .collect(),
        dropped,
    };
    // Every field is a plain number, string or map of them, so this cannot
    // fail; fall back to a minimal object rather than panicking if it ever does.
    serde_json::to_string(&line).unwrap_or_else(|_| r#"{"type":"summary"}"#.to_string())
}

/// Streams events for each packet fed to it.
pub struct Exporter<W: Write> {
    out: W,
    format: Format,
    /// Suppress per-packet lines; alerts and the summary are still written.
    alerts_only: bool,
    analyzer: ReplayAnalyzer,
}

impl<W: Write> Exporter<W> {
    pub fn new(out: W, format: Format, alerts_only: bool) -> Self {
        Self {
            out,
            format,
            alerts_only,
            analyzer: ReplayAnalyzer::default(),
        }
    }

    /// Packets decoded so far.
    pub fn packets(&self) -> u64 {
        self.analyzer.packets()
    }

    /// Analyse one packet and write the lines it produces.
    pub fn feed(
        &mut self,
        link: LinkType,
        ts_micros: i64,
        data: &[u8],
        wire_len: usize,
    ) -> io::Result<()> {
        let Some(observation) = self.analyzer.feed(link, ts_micros, data, wire_len) else {
            return Ok(());
        };
        let ts = ts_micros as f64 / 1_000_000.0;
        if !self.alerts_only {
            self.write_packet(ts, ts_micros, &observation)?;
        }
        for alert in &observation.raised {
            self.write_alert(ts, ts_micros, "raised", alert)?;
        }
        for alert in &observation.cleared {
            self.write_alert(ts, ts_micros, "cleared", alert)?;
        }
        Ok(())
    }

    fn write_packet(&mut self, ts: f64, ts_us: i64, observation: &Observation) -> io::Result<()> {
        let event = &observation.event;
        let tcp_flags = match event.transport {
            Transport::Tcp { flags, .. } => Some(tcp_flag_string(flags.0)),
            _ => None,
        };
        match self.format {
            Format::Json => {
                let line = PacketJson {
                    kind: "packet",
                    ts,
                    ts_us,
                    src: event.src,
                    dst: event.dst,
                    src_port: event.src_port,
                    dst_port: event.dst_port,
                    protocol: event.protocol.label(),
                    ip_proto: event.ip_proto,
                    length: event.wire_len,
                    tcp_flags,
                    host: observation.insight.as_ref().map(|i| HostJson {
                        source: i.source.tag(),
                        name: &i.name,
                    }),
                };
                serde_json::to_writer(&mut self.out, &line)?;
                self.out.write_all(b"\n")
            }
            Format::Text => {
                let endpoint = |ip: IpAddr, port: Option<u16>| match (ip, port) {
                    (IpAddr::V6(ip), Some(p)) => format!("[{ip}]:{p}"),
                    (ip, Some(p)) => format!("{ip}:{p}"),
                    (ip, None) => ip.to_string(),
                };
                write!(
                    self.out,
                    "{ts:.6} {:<5} {} -> {} {}B",
                    event.protocol.label(),
                    endpoint(event.src, event.src_port),
                    endpoint(event.dst, event.dst_port),
                    event.wire_len
                )?;
                if let Some(flags) = tcp_flags.filter(|f| !f.is_empty()) {
                    write!(self.out, " [{flags}]")?;
                }
                if let Some(insight) = &observation.insight {
                    write!(self.out, " {}", insight.label())?;
                }
                self.out.write_all(b"\n")
            }
        }
    }

    fn write_alert(
        &mut self,
        ts: f64,
        ts_us: i64,
        state: &'static str,
        alert: &Alert,
    ) -> io::Result<()> {
        match self.format {
            Format::Json => {
                let line = AlertJson {
                    kind: "alert",
                    ts,
                    ts_us,
                    state,
                    alert: alert.kind.label(),
                    severity: severity_label(alert.kind.severity()),
                    source: alert.source,
                    target: alert.target,
                    detail: &alert.detail,
                };
                serde_json::to_writer(&mut self.out, &line)?;
                self.out.write_all(b"\n")
            }
            Format::Text => {
                let tag = if state == "raised" {
                    "ALERT"
                } else {
                    "CLEARED"
                };
                writeln!(self.out, "{ts:.6} {tag} {}", alert.summary())
            }
        }
    }

    /// Push buffered lines to the reader.
    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Write the closing summary and flush. `dropped` is the number of
    /// packets lost before analysis (kernel and interface drops).
    pub fn finish(mut self, dropped: u64) -> io::Result<ReplaySummary> {
        let summary = self.analyzer.finish();
        match self.format {
            Format::Json => writeln!(self.out, "{}", summary_json(&summary, dropped))?,
            Format::Text => {
                writeln!(self.out, "--- summary ---")?;
                write!(self.out, "{summary}")?;
                if dropped > 0 {
                    writeln!(self.out, "dropped:      {dropped}")?;
                }
            }
        }
        self.out.flush()?;
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::TcpFlags;
    use crate::synth::{client_hello, dns_query, eth_tcp, eth_udp, ethernet};
    use serde_json::Value;

    const T0: i64 = 1_700_000_000_500_000;

    fn run(format: Format, alerts_only: bool, packets: &[(i64, Vec<u8>)]) -> Vec<String> {
        let mut out = Vec::new();
        let mut exporter = Exporter::new(&mut out, format, alerts_only);
        for (ts, frame) in packets {
            exporter
                .feed(LinkType::Ethernet, *ts, frame, frame.len())
                .unwrap();
        }
        exporter.finish(0).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn scan() -> Vec<(i64, Vec<u8>)> {
        (1..=25u16)
            .map(|port| {
                (
                    T0 + i64::from(port) * 1000,
                    eth_tcp(
                        [203, 0, 113, 7],
                        [10, 0, 0, 1],
                        40000,
                        port,
                        TcpFlags::SYN,
                        b"",
                    ),
                )
            })
            .collect()
    }

    #[test]
    fn every_json_line_is_an_object_with_a_type() {
        let mut packets = scan();
        packets.push((T0 + 50_000, ethernet(0x0806, &[0; 28]))); // skipped silently
        let lines = run(Format::Json, false, &packets);
        assert_eq!(
            lines.len(),
            25 + 1 + 1,
            "25 packets, one alert, one summary"
        );
        for line in &lines {
            let v: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}"));
            assert!(v["type"].is_string(), "{line}");
        }
    }

    #[test]
    fn packet_line_schema() {
        let hello = eth_tcp(
            [10, 0, 0, 2],
            [93, 184, 216, 34],
            51000,
            443,
            0x18,
            &client_hello("example.com"),
        );
        let dns = eth_udp(
            [10, 0, 0, 2],
            [9, 9, 9, 9],
            40000,
            53,
            &dns_query("example.com"),
        );
        let lines = run(Format::Json, false, &[(T0, hello.clone()), (T0 + 1, dns)]);

        let p: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(p["type"], "packet");
        assert_eq!(p["ts"], 1_700_000_000.5);
        assert_eq!(p["ts_us"], T0);
        assert_eq!(p["src"], "10.0.0.2");
        assert_eq!(p["dst"], "93.184.216.34");
        assert_eq!(p["src_port"], 51000);
        assert_eq!(p["dst_port"], 443);
        assert_eq!(p["protocol"], "HTTPS");
        assert_eq!(p["ip_proto"], 6);
        assert_eq!(p["length"], hello.len());
        assert_eq!(p["tcp_flags"], "PA");
        assert_eq!(p["host"]["source"], "sni");
        assert_eq!(p["host"]["name"], "example.com");

        let d: Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(d["protocol"], "DNS");
        assert_eq!(d["host"]["source"], "dns");
        assert!(d.get("tcp_flags").is_none(), "absent, not null, for UDP");
    }

    #[test]
    fn alert_and_summary_schema() {
        let lines = run(Format::Json, false, &scan());
        let alert: Value = lines
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .find(|v| v["type"] == "alert")
            .unwrap();
        assert_eq!(alert["state"], "raised");
        assert_eq!(alert["alert"], "Port scan");
        assert_eq!(alert["severity"], "high");
        assert_eq!(alert["source"], "203.0.113.7");
        assert_eq!(alert["target"], "10.0.0.1");
        assert_eq!(alert["detail"], "20 ports in 60s");

        let summary: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(summary["type"], "summary");
        assert_eq!(summary["schema"], SCHEMA_VERSION);
        assert_eq!(summary["packets"], 25);
        assert_eq!(summary["peak_threat"], "high");
        assert_eq!(summary["protocols"]["TCP"], 24);
        assert_eq!(summary["protocols"]["SSH"], 1, "the probe of port 22");
        assert_eq!(summary["alerts"][0], "Port scan 203.0.113.7 -> 10.0.0.1");
        assert_eq!(summary["top_talkers"][0]["packets"], 25);
        assert_eq!(summary["dropped"], 0);
    }

    #[test]
    fn alerts_only_suppresses_packet_lines() {
        let lines = run(Format::Json, true, &scan());
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"type\":\"alert\""));
        assert!(lines[1].contains("\"type\":\"summary\""));
    }

    #[test]
    fn text_format_is_greppable() {
        let lines = run(Format::Text, false, &scan());
        assert_eq!(
            lines[0],
            "1700000000.501000 TCP   203.0.113.7:40000 -> 10.0.0.1:1 54B [S]"
        );
        assert!(lines
            .iter()
            .any(|l| l.ends_with("ALERT Port scan 203.0.113.7 -> 10.0.0.1 (20 ports in 60s)")));
        assert!(lines.contains(&"--- summary ---".to_string()));
        assert!(lines.iter().any(|l| l == "packets:      25"));
    }

    #[test]
    fn hostile_hostnames_cannot_break_the_stream() {
        // The name is rejected by the sanitiser, so nothing unescaped can
        // reach the output; the line is still valid JSON.
        let evil = eth_tcp(
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            5,
            80,
            0x18,
            b"GET / HTTP/1.1\r\nHost: a\"}\n{\"x\r\n\r\n",
        );
        let lines = run(Format::Json, false, &[(T0, evil)]);
        assert_eq!(lines.len(), 2);
        let v: Value = serde_json::from_str(&lines[0]).unwrap();
        assert!(v.get("host").is_none());
    }

    #[test]
    fn flag_strings() {
        assert_eq!(tcp_flag_string(0x02), "S");
        assert_eq!(tcp_flag_string(0x12), "SA");
        assert_eq!(tcp_flag_string(0x19), "FPA");
        assert_eq!(tcp_flag_string(0x04), "R");
        assert_eq!(tcp_flag_string(0), "");
    }

    #[test]
    fn write_errors_are_returned_not_panicked() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut exporter = Exporter::new(Broken, Format::Json, false);
        let frame = eth_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0x02, b"");
        let err = exporter
            .feed(LinkType::Ethernet, 0, &frame, frame.len())
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
