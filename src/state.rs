//! Everything the UI shows, owned by the UI thread. No locks: the capture
//! thread only ever talks to it through [`crate::capture`]'s channel.

use std::collections::VecDeque;
use std::sync::mpsc::Receiver;
use std::time::Instant;

use crate::capture::{CaptureMsg, PacketRecord};
use crate::flows::FlowTable;
use crate::pipeline::PacketEvent;
use crate::protocol_activity::ProtocolActivityTracker;
use crate::threat_detection::ThreatDetector;
use crate::ProtocolStats;

/// Lines kept in the packet log.
pub const LOG_LINES: usize = 50;
/// Packet samples kept for the hex dump.
pub const RAW_SAMPLES: usize = 5;

pub struct AppState {
    pub stats: ProtocolStats,
    pub activity: ProtocolActivityTracker,
    pub detector: ThreatDetector,
    pub flows: FlowTable,
    /// Newest first.
    pub packet_log: VecDeque<String>,
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
            packet_log: VecDeque::with_capacity(LOG_LINES + 1),
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

        self.packet_log.push_front(event.log_line(timestamp));
        self.packet_log.truncate(LOG_LINES);
        self.raw_packets.push_front(record.sample().to_vec());
        self.raw_packets.truncate(RAW_SAMPLES);
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
        assert_eq!(state.packet_log.len(), LOG_LINES);
        assert_eq!(state.raw_packets.len(), RAW_SAMPLES);
        assert!(state.packet_log[0].ends_with("[299B]"), "newest first: {}", state.packet_log[0]);
    }
}
