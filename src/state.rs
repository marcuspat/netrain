//! Everything the UI shows, owned by the UI thread. No locks: the capture
//! thread only ever talks to it through [`crate::capture`]'s channel.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::Instant;

use crate::capture::{CaptureMsg, PacketRecord};
use crate::flows::FlowTable;
use crate::inspect::{NameCache, NameSource};
use crate::pipeline::PacketEvent;
use crate::protocol_activity::ProtocolActivityTracker;
use crate::threat_detection::ThreatDetector;
use crate::{Protocol, ProtocolStats};

/// Lines kept in the packet log. More than fit on screen, so that filtering
/// by protocol still has something to show.
pub const LOG_LINES: usize = 500;

/// One line of the packet log, remembering what it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub protocol: Protocol,
    pub line: String,
}

impl std::ops::Deref for LogEntry {
    type Target = str;
    fn deref(&self) -> &str {
        &self.line
    }
}

impl std::fmt::Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.line)
    }
}

impl PartialEq<&str> for LogEntry {
    fn eq(&self, other: &&str) -> bool {
        self.line == *other
    }
}

/// Something the user asked for, independent of which key did it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Quit,
    TogglePause,
    ToggleHelp,
    /// Show only the next protocol in the log (cycling through those seen).
    CycleFilter,
    ClearFilter,
    /// Leave whatever overlay or mode is active.
    Dismiss,
}
/// Packet samples kept for the hex dump.
pub const RAW_SAMPLES: usize = 5;

pub struct AppState {
    pub stats: ProtocolStats,
    pub activity: ProtocolActivityTracker,
    pub detector: ThreatDetector,
    pub flows: FlowTable,
    /// Address -> name, learned from DNS answers on the wire.
    pub names: NameCache,
    /// Newest first.
    pub packet_log: VecDeque<LogEntry>,
    /// While paused the log and hex dump hold still so they can be read;
    /// statistics, flows and threat detection keep running.
    pub paused: bool,
    /// Packets that arrived while paused and were not added to the log.
    pub skipped_while_paused: u64,
    /// Restrict the log to one protocol.
    pub log_filter: Option<Protocol>,
    pub show_help: bool,
    /// Newest first.
    pub raw_packets: VecDeque<Vec<u8>>,
    pub capture_error: Option<String>,
    /// Set when the source ended normally (replay reached end of file).
    pub finished: Option<String>,
    pub total_packets: u64,
    /// Packets displayed during the last full second.
    pub packet_rate: u64,
    packets_this_second: u64,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            stats: ProtocolStats::new(),
            activity: ProtocolActivityTracker::new(),
            detector: ThreatDetector::new(),
            flows: FlowTable::default(),
            names: NameCache::default(),
            packet_log: VecDeque::with_capacity(LOG_LINES + 1),
            paused: false,
            skipped_while_paused: 0,
            log_filter: None,
            show_help: false,
            raw_packets: VecDeque::with_capacity(RAW_SAMPLES + 1),
            capture_error: None,
            finished: None,
            total_packets: 0,
            packet_rate: 0,
            packets_this_second: 0,
        }
    }

    /// Fold one packet into the statistics, threat engine and log.
    pub fn apply_packet(&mut self, record: &PacketRecord, timestamp: &str, now: Instant) {
        let event = &record.event;
        self.total_packets += 1;
        self.packets_this_second += 1;
        self.stats.add_packet(event.protocol, event.wire_len);
        self.activity.record_packet(event.protocol);
        self.detector.analyze_event_at(event, now);
        self.flows.observe(event, now);

        if let Some(resolved) = &record.resolved {
            for ip in &resolved.1 {
                self.names.insert(*ip, &resolved.0);
            }
        }
        if let Some(insight) = &record.insight {
            // A connection's server name belongs on its flow; a DNS question
            // is about some other host, so it only annotates the log line.
            if insight.source != NameSource::Dns {
                self.flows.set_name(event, &insight.name);
            }
        }
        if self.paused {
            self.skipped_while_paused += 1;
            return;
        }
        let mut line = event.log_line(timestamp);
        if let Some(insight) = &record.insight {
            line.push(' ');
            line.push_str(&insight.label());
        }
        self.packet_log.push_front(LogEntry { protocol: event.protocol, line });
        self.packet_log.truncate(LOG_LINES);
        self.raw_packets.push_front(record.sample().to_vec());
        self.raw_packets.truncate(RAW_SAMPLES);
    }

    /// Log lines to display, newest first, honouring the protocol filter.
    pub fn visible_log(&self) -> impl Iterator<Item = &LogEntry> {
        let filter = self.log_filter;
        self.packet_log.iter().filter(move |e| filter.is_none_or(|p| e.protocol == p))
    }

    /// Carry out a user command. Returns `true` when the app should exit.
    pub fn command(&mut self, command: Command) -> bool {
        match command {
            Command::Quit => return true,
            Command::TogglePause => {
                self.paused = !self.paused;
                if !self.paused {
                    self.skipped_while_paused = 0;
                }
            }
            Command::ToggleHelp => self.show_help = !self.show_help,
            Command::CycleFilter => {
                // Cycle: all -> each protocol seen (busiest first) -> all.
                let seen: Vec<Protocol> = self.stats.ranked().into_iter().map(|(p, _)| p).collect();
                self.log_filter = match self.log_filter {
                    None => seen.first().copied(),
                    Some(current) => {
                        seen.iter().position(|p| *p == current).and_then(|i| seen.get(i + 1)).copied()
                    }
                };
            }
            Command::ClearFilter => self.log_filter = None,
            Command::Dismiss => {
                if self.show_help {
                    self.show_help = false;
                } else {
                    self.log_filter = None;
                }
            }
        }
        false
    }

    /// Apply up to `budget` queued messages. `on_packet` is called for each
    /// packet so the caller can drive visuals. Returns how many were applied;
    /// a full budget means more may be waiting for the next frame.
    pub fn drain(
        &mut self,
        rx: &Receiver<CaptureMsg>,
        budget: usize,
        timestamp: &str,
        now: Instant,
        mut on_packet: impl FnMut(&PacketEvent),
    ) -> usize {
        let mut applied = 0;
        while applied < budget {
            match rx.try_recv() {
                Ok(CaptureMsg::Packet(record)) => {
                    self.apply_packet(&record, timestamp, now);
                    on_packet(&record.event);
                }
                Ok(CaptureMsg::Error(message)) => self.capture_error = Some(message),
                Ok(CaptureMsg::Finished(message)) => self.finished = Some(message),
                Err(_) => break,
            }
            applied += 1;
        }
        applied
    }

    /// Call once a second: publishes the packet rate and ages out alerts.
    pub fn tick_second(&mut self) {
        self.packet_rate = self.packets_this_second;
        self.packets_this_second = 0;
        self.detector.expire();
        self.flows.expire(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::channel;
    use crate::decode::testutil::{ethernet, ipv4, tcp, udp};
    use crate::decode::{LinkType, TcpFlags};
    use crate::{Protocol, ThreatLevel};

    fn syn(src: [u8; 4], port: u16) -> Vec<u8> {
        ethernet(0x0800, &ipv4(6, src, [10, 0, 0, 1], &tcp(50000, port, TcpFlags::SYN, b"")))
    }

    #[test]
    fn capture_to_state_end_to_end() {
        let (sink, rx, _) = channel(64);
        let dns = ethernet(0x0800, &ipv4(17, [10, 0, 0, 2], [8, 8, 8, 8], &udp(40000, 53, b"")));
        sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 443), 74);
        sink.submit(LinkType::Ethernet, &dns, 90);
        sink.error("boom");

        let mut state = AppState::new();
        let mut seen = Vec::new();
        let n = state.drain(&rx, 100, "12:00:00", Instant::now(), |e| seen.push(e.protocol));

        assert_eq!(n, 3);
        assert_eq!(seen, vec![Protocol::HTTPS, Protocol::DNS]);
        assert_eq!(state.total_packets, 2);
        assert_eq!(state.stats.get_count(Protocol::HTTPS), 1);
        assert_eq!(state.stats.get_total_bytes(Protocol::DNS), 90);
        assert_eq!(state.packet_log[0], "[12:00:00] DNS   10.0.0.2 -> 8.8.8.8 [90B]");
        assert_eq!(state.packet_log[1], "[12:00:00] HTTPS 10.0.0.2 -> 10.0.0.1 [74B]");
        assert_eq!(state.raw_packets[0], dns[..]);
        assert_eq!(state.capture_error.as_deref(), Some("boom"));
        assert_eq!(state.flows.len(), 2);
        assert_eq!(state.flows.top_talkers(1)[0].0.to_string(), "10.0.0.2");

        state.tick_second();
        assert_eq!(state.packet_rate, 2);
        state.tick_second();
        assert_eq!(state.packet_rate, 0);
    }

    #[test]
    fn hostnames_reach_the_log_the_flow_and_the_name_cache() {
        use crate::synth::{client_hello, dns_query, dns_response, eth_tcp, eth_udp};
        let (client, resolver, server) = ([10, 0, 0, 2], [9, 9, 9, 9], [93, 184, 216, 34]);
        let (sink, rx, _) = channel(64);
        let q = eth_udp(client, resolver, 40000, 53, &dns_query("example.com"));
        let r = eth_udp(resolver, client, 53, 40000, &dns_response("example.com", &[server.into()]));
        let hello = eth_tcp(client, server, 50000, 443, TcpFlags::ACK, &client_hello("example.com"));
        for f in [&q, &r, &hello] {
            sink.submit(LinkType::Ethernet, f, f.len());
        }
        let mut state = AppState::new();
        state.drain(&rx, 10, "t", Instant::now(), |_| {});

        assert!(state.packet_log[2].ends_with("dns=example.com"), "{}", state.packet_log[2]);
        assert!(state.packet_log[0].ends_with("sni=example.com"), "{}", state.packet_log[0]);
        assert_eq!(state.names.display(&server.into()), "93.184.216.34 (example.com)");
        let tls = state.flows.top_flows(5).into_iter().find(|f| f.protocol == Protocol::HTTPS).unwrap();
        assert_eq!(tls.name.as_deref(), Some("example.com"));
        assert!(tls.summary().ends_with("example.com"));
        // The DNS flow is not labelled with the name it merely asked about.
        let dns = state.flows.top_flows(5).into_iter().find(|f| f.protocol == Protocol::DNS).unwrap();
        assert_eq!(dns.name, None);
    }

    #[test]
    fn pause_freezes_the_log_but_not_the_analysis() {
        let (sink, rx, _) = channel(64);
        let mut state = AppState::new();
        sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 443), 60);
        state.drain(&rx, 10, "t", Instant::now(), |_| {});
        assert!(!state.command(Command::TogglePause));
        for port in 1..=30 {
            sink.submit(LinkType::Ethernet, &syn([203, 0, 113, 7], port), 60);
        }
        state.drain(&rx, 100, "t", Instant::now(), |_| {});

        assert_eq!(state.packet_log.len(), 1, "log holds still while paused");
        assert_eq!(state.raw_packets.len(), 1);
        assert_eq!(state.skipped_while_paused, 30);
        assert_eq!(state.total_packets, 31, "statistics keep counting");
        assert_eq!(state.detector.get_threat_level(), ThreatLevel::High, "a scan is not missed");

        state.command(Command::TogglePause);
        assert!(!state.paused);
        assert_eq!(state.skipped_while_paused, 0);
        sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 80), 60);
        state.drain(&rx, 10, "t", Instant::now(), |_| {});
        assert_eq!(state.packet_log.len(), 2);
    }

    #[test]
    fn filter_cycles_through_seen_protocols_and_back_to_all() {
        use crate::synth::eth_udp;
        let (sink, rx, _) = channel(64);
        let mut state = AppState::new();
        for _ in 0..3 {
            sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 443), 60);
        }
        for _ in 0..2 {
            sink.submit(LinkType::Ethernet, &eth_udp([10, 0, 0, 2], [8, 8, 8, 8], 4000, 53, b""), 60);
        }
        sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 22), 60);
        state.drain(&rx, 100, "t", Instant::now(), |_| {});

        assert_eq!(state.visible_log().count(), 6);
        state.command(Command::CycleFilter);
        assert_eq!(state.log_filter, Some(Protocol::HTTPS), "busiest first");
        assert_eq!(state.visible_log().count(), 3);
        state.command(Command::CycleFilter);
        assert_eq!(state.log_filter, Some(Protocol::DNS));
        assert!(state.visible_log().all(|e| e.protocol == Protocol::DNS));
        state.command(Command::CycleFilter);
        assert_eq!(state.log_filter, Some(Protocol::SSH));
        state.command(Command::CycleFilter);
        assert_eq!(state.log_filter, None, "wraps to all");

        state.command(Command::CycleFilter);
        state.command(Command::ClearFilter);
        assert_eq!(state.log_filter, None);
        // Cycling with no traffic at all stays on "all".
        let mut empty = AppState::new();
        empty.command(Command::CycleFilter);
        assert_eq!(empty.log_filter, None);
    }

    #[test]
    fn help_dismiss_and_quit() {
        let mut state = AppState::new();
        state.command(Command::ToggleHelp);
        state.log_filter = Some(Protocol::DNS);
        assert!(state.show_help);
        state.command(Command::Dismiss);
        assert!(!state.show_help, "escape closes help first");
        assert_eq!(state.log_filter, Some(Protocol::DNS));
        state.command(Command::Dismiss);
        assert_eq!(state.log_filter, None, "then clears the filter");
        assert!(state.command(Command::Quit));
    }

    #[test]
    fn a_scan_seen_through_the_channel_raises_the_threat_level() {
        let (sink, rx, _) = channel(64);
        for port in 1..=30 {
            sink.submit(LinkType::Ethernet, &syn([203, 0, 113, 7], port), 60);
        }
        let mut state = AppState::new();
        state.drain(&rx, 100, "t", Instant::now(), |_| {});
        assert_eq!(state.detector.get_threat_level(), ThreatLevel::High);
        assert_eq!(state.detector.active_alerts().len(), 1);
    }

    #[test]
    fn drain_respects_its_budget_and_history_is_bounded() {
        let (sink, rx, _) = channel(512);
        for i in 0..300u16 {
            sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 443), usize::from(i));
        }
        let mut state = AppState::new();
        assert_eq!(state.drain(&rx, 100, "t", Instant::now(), |_| {}), 100);
        assert_eq!(state.total_packets, 100);
        assert_eq!(state.drain(&rx, 1000, "t", Instant::now(), |_| {}), 200);
        assert_eq!(state.packet_log.len(), 300);
        // Keep feeding well past the cap: the log stops growing.
        for i in 0..(LOG_LINES as u16 + 100) {
            sink.submit(LinkType::Ethernet, &syn([10, 0, 0, 2], 443), usize::from(i));
            state.drain(&rx, 10, "t", Instant::now(), |_| {});
        }
        assert_eq!(state.packet_log.len(), LOG_LINES);
        assert_eq!(state.raw_packets.len(), RAW_SAMPLES);
        assert!(state.packet_log[0].ends_with("[599B]"), "newest first: {}", state.packet_log[0]);
    }
}
