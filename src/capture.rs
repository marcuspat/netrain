//! Hand-off between the capture thread and the UI thread.
//!
//! The capture thread decodes each packet and pushes a small owned record
//! into a bounded channel; the UI thread drains it once per frame. The
//! capture thread therefore never takes a lock and never blocks on the UI:
//! when the UI cannot keep up the record is dropped and counted, which is
//! what a monitor should do under a flood.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

use std::net::IpAddr;

use crate::decode::{Decoded, LinkType, Transport};
use crate::dns;
use crate::inspect::{self, Insight};
use crate::pipeline::{observe, PacketEvent};

/// Bytes of each packet kept for the hex dump.
pub const SAMPLE_LEN: usize = 64;

/// Default queue depth between capture and UI.
pub const DEFAULT_QUEUE: usize = 8192;

/// An owned summary of one packet.
#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub event: PacketEvent,
    /// A hostname the packet revealed (DNS question, TLS SNI, HTTP Host).
    pub insight: Option<Insight>,
    /// For DNS responses: the name asked for and the addresses it resolved to.
    pub resolved: Option<Box<(String, Vec<IpAddr>)>>,
    sample: [u8; SAMPLE_LEN],
    sample_len: u8,
}

impl PacketRecord {
    pub fn new(event: PacketEvent, data: &[u8]) -> Self {
        let n = data.len().min(SAMPLE_LEN);
        let mut sample = [0u8; SAMPLE_LEN];
        sample[..n].copy_from_slice(&data[..n]);
        Self { event, insight: None, resolved: None, sample, sample_len: n as u8 }
    }

    /// Build a record from a decoded packet, extracting any hostname and
    /// DNS answers while the payload is still at hand.
    pub fn from_decoded(event: PacketEvent, decoded: &Decoded<'_>, data: &[u8]) -> Self {
        let mut record = Self::new(event, data);
        record.insight = inspect::insight(decoded);
        if let Transport::Udp { src_port: 53 | 5353, .. } = decoded.transport {
            record.resolved = dns::answers(decoded.payload).filter(|(_, a)| !a.is_empty()).map(Box::new);
        }
        record
    }

    /// The first bytes of the packet as captured.
    pub fn sample(&self) -> &[u8] {
        &self.sample[..usize::from(self.sample_len)]
    }
}

/// Messages from the capture thread.
#[derive(Debug, Clone)]
pub enum CaptureMsg {
    Packet(PacketRecord),
    /// Capture could not start or stopped; shown to the user.
    Error(String),
    /// The source ended normally (end of a replayed file).
    Finished(String),
}

/// Lock-free counters shared between capture and UI.
#[derive(Debug, Default)]
pub struct CaptureCounters {
    /// Packets handed to us by pcap.
    pub received: AtomicU64,
    /// Packets that were not IP or failed to decode.
    pub undecodable: AtomicU64,
    /// Records dropped because the UI queue was full.
    pub queue_dropped: AtomicU64,
    /// Packets the kernel dropped because our buffer was full (pcap stats).
    pub kernel_dropped: AtomicU64,
    /// Packets the interface dropped (pcap stats).
    pub interface_dropped: AtomicU64,
}

/// A point-in-time copy of [`CaptureCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterSnapshot {
    pub received: u64,
    pub undecodable: u64,
    pub queue_dropped: u64,
    pub kernel_dropped: u64,
    pub interface_dropped: u64,
}

impl CounterSnapshot {
    /// Packets we know were on the wire but never reached the display.
    pub fn total_dropped(&self) -> u64 {
        self.queue_dropped + self.kernel_dropped + self.interface_dropped
    }
}

impl CaptureCounters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            received: self.received.load(Ordering::Relaxed),
            undecodable: self.undecodable.load(Ordering::Relaxed),
            queue_dropped: self.queue_dropped.load(Ordering::Relaxed),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            interface_dropped: self.interface_dropped.load(Ordering::Relaxed),
        }
    }
}

/// The capture thread's end of the channel.
#[derive(Debug, Clone)]
pub struct CaptureSink {
    tx: SyncSender<CaptureMsg>,
    counters: Arc<CaptureCounters>,
}

/// Create the capture -> UI channel with room for `capacity` records.
pub fn channel(capacity: usize) -> (CaptureSink, Receiver<CaptureMsg>, Arc<CaptureCounters>) {
    let (tx, rx) = sync_channel(capacity.max(1));
    let counters = Arc::new(CaptureCounters::default());
    (CaptureSink { tx, counters: Arc::clone(&counters) }, rx, counters)
}

impl CaptureSink {
    /// Decode one captured packet and queue it. Never blocks.
    /// Returns `false` once the UI side has gone away.
    pub fn submit(&self, link: LinkType, data: &[u8], wire_len: usize) -> bool {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        match observe(link, data, wire_len) {
            Ok((event, decoded)) => self.push(PacketRecord::from_decoded(event, &decoded, data)),
            Err(_) => {
                self.counters.undecodable.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    /// Queue an already-built event (demo mode, replay).
    pub fn submit_event(&self, event: PacketEvent, data: &[u8]) -> bool {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        self.push(PacketRecord::new(event, data))
    }

    fn push(&self, record: PacketRecord) -> bool {
        match self.tx.try_send(CaptureMsg::Packet(record)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.counters.queue_dropped.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Decode and queue one packet, waiting for room. For replay, where
    /// losing packets to a slow UI would make the result wrong.
    pub fn submit_blocking(&self, link: LinkType, data: &[u8], wire_len: usize) -> bool {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        match observe(link, data, wire_len) {
            Ok((event, decoded)) => {
                self.tx.send(CaptureMsg::Packet(PacketRecord::from_decoded(event, &decoded, data))).is_ok()
            }
            Err(_) => {
                self.counters.undecodable.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    /// Announce a normal end of input.
    pub fn finished(&self, message: impl Into<String>) {
        let _ = self.tx.send(CaptureMsg::Finished(message.into()));
    }

    /// Report a fatal capture problem. Blocks until queued so that it cannot
    /// be lost behind a full queue.
    pub fn error(&self, message: impl Into<String>) {
        let _ = self.tx.send(CaptureMsg::Error(message.into()));
    }

    /// Publish the kernel/interface drop totals reported by pcap.
    pub fn set_kernel_stats(&self, dropped: u64, interface_dropped: u64) {
        self.counters.kernel_dropped.store(dropped, Ordering::Relaxed);
        self.counters.interface_dropped.store(interface_dropped, Ordering::Relaxed);
    }
}

/// Paces a replay by the timestamps recorded in the capture file.
#[derive(Debug, Clone)]
pub struct ReplayPacer {
    speed: f64,
    last_micros: Option<i64>,
}

impl ReplayPacer {
    /// Longest pause honoured between two packets, so a trace with an idle
    /// hour in it does not look hung.
    pub const MAX_GAP: std::time::Duration = std::time::Duration::from_secs(1);

    /// `speed` multiplies playback rate; `0` means no pacing at all.
    pub fn new(speed: f64) -> Self {
        Self { speed, last_micros: None }
    }

    /// How long to wait before delivering a packet stamped `micros`
    /// (microseconds since the epoch).
    pub fn delay_before(&mut self, micros: i64) -> std::time::Duration {
        let previous = self.last_micros.replace(micros);
        let Some(previous) = previous else {
            return std::time::Duration::ZERO;
        };
        if self.speed <= 0.0 || !self.speed.is_finite() {
            return std::time::Duration::ZERO;
        }
        // Out-of-order timestamps (they happen) mean no wait.
        let gap = micros.saturating_sub(previous).max(0) as f64 / self.speed;
        std::time::Duration::from_micros(gap as u64).min(Self::MAX_GAP)
    }
}

/// What interface selection needs to know about a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: String,
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub has_address: bool,
}

/// Pick the capture interface.
///
/// With `requested`, the name must match exactly. Otherwise prefer a
/// non-loopback interface that is up, running and has an address - on any
/// OS, rather than assuming macOS's `en0`.
pub fn choose_device(devices: &[DeviceInfo], requested: Option<&str>) -> Result<usize, String> {
    if devices.is_empty() {
        return Err("No network device found. Check your network configuration.".to_string());
    }
    if let Some(name) = requested {
        return devices.iter().position(|d| d.name == name).ok_or_else(|| {
            let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
            format!("Interface '{}' not found. Available: {}", name, names.join(", "))
        });
    }
    let score = |d: &DeviceInfo| {
        // Pseudo-devices that are not a real interface.
        let pseudo = matches!(d.name.as_str(), "any" | "nflog" | "nfqueue")
            || d.name.starts_with("bluetooth")
            || d.name.starts_with("usbmon")
            || d.name.starts_with("dbus");
        if pseudo {
            return 0;
        }
        1 + u32::from(!d.loopback) * 8
            + u32::from(d.up) * 4
            + u32::from(d.running) * 2
            + u32::from(d.has_address)
    };
    // max_by_key returns the last maximum; iterate reversed to keep the first.
    devices
        .iter()
        .enumerate()
        .rev()
        .max_by_key(|(_, d)| score(d))
        .map(|(i, _)| i)
        .ok_or_else(|| "No usable network device found.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::testutil::{ethernet, ipv4, tcp};
    use crate::decode::TcpFlags;
    use crate::Protocol;

    fn frame(port: u16) -> Vec<u8> {
        ethernet(0x0800, &ipv4(6, [10, 0, 0, 2], [10, 0, 0, 1], &tcp(50000, port, TcpFlags::SYN, b"")))
    }

    fn dev(name: &str, up: bool, running: bool, loopback: bool, has_address: bool) -> DeviceInfo {
        DeviceInfo { name: name.to_string(), up, running, loopback, has_address }
    }

    #[test]
    fn packets_cross_the_channel_with_sample_and_event() {
        let (sink, rx, counters) = channel(16);
        let f = frame(443);
        assert!(sink.submit(LinkType::Ethernet, &f, 1500));
        let CaptureMsg::Packet(rec) = rx.try_recv().unwrap() else { panic!("expected packet") };
        assert_eq!(rec.event.protocol, Protocol::HTTPS);
        assert_eq!(rec.event.wire_len, 1500);
        assert_eq!(rec.sample(), &f[..]);
        assert_eq!(counters.snapshot().received, 1);
    }

    #[test]
    fn long_packets_are_sampled_not_copied() {
        let (sink, rx, _) = channel(4);
        let mut f = frame(80);
        f.extend_from_slice(&[0xab; 1400]);
        sink.submit(LinkType::Ethernet, &f, f.len());
        let CaptureMsg::Packet(rec) = rx.try_recv().unwrap() else { panic!() };
        assert_eq!(rec.sample().len(), SAMPLE_LEN);
        assert_eq!(rec.sample(), &f[..SAMPLE_LEN]);
    }

    #[test]
    fn full_queue_drops_and_counts_instead_of_blocking() {
        let (sink, rx, counters) = channel(8);
        let f = frame(80);
        for _ in 0..100 {
            assert!(sink.submit(LinkType::Ethernet, &f, f.len()));
        }
        let snap = counters.snapshot();
        assert_eq!(snap.received, 100);
        assert_eq!(snap.queue_dropped, 92);
        assert_eq!(rx.try_iter().count(), 8);
        // Once drained there is room again.
        sink.submit(LinkType::Ethernet, &f, f.len());
        assert_eq!(counters.snapshot().queue_dropped, 92);
    }

    #[test]
    fn undecodable_packets_are_counted_not_queued() {
        let (sink, rx, counters) = channel(8);
        sink.submit(LinkType::Ethernet, &ethernet(0x0806, &[0; 28]), 42);
        sink.submit(LinkType::Ethernet, &[1, 2, 3], 3);
        assert_eq!(counters.snapshot().undecodable, 2);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn sink_reports_when_the_ui_is_gone() {
        let (sink, rx, _) = channel(8);
        drop(rx);
        let f = frame(80);
        assert!(!sink.submit(LinkType::Ethernet, &f, f.len()));
    }

    #[test]
    fn kernel_stats_and_total_dropped() {
        let (sink, _rx, counters) = channel(1);
        let f = frame(80);
        sink.submit(LinkType::Ethernet, &f, f.len());
        sink.submit(LinkType::Ethernet, &f, f.len());
        sink.set_kernel_stats(5, 2);
        assert_eq!(counters.snapshot().total_dropped(), 1 + 5 + 2);
    }

    #[test]
    fn default_device_is_the_live_non_loopback_interface_on_any_os() {
        // Linux: no en0 anywhere.
        let linux = [
            dev("any", true, true, false, false),
            dev("lo", true, true, true, true),
            dev("docker0", true, false, false, true),
            dev("eth0", true, true, false, true),
            dev("wlan0", false, false, false, false),
        ];
        assert_eq!(choose_device(&linux, None), Ok(3));
        // macOS: en0 down, en1 is the live one.
        let mac = [
            dev("lo0", true, true, true, true),
            dev("en0", true, false, false, false),
            dev("en1", true, true, false, true),
        ];
        assert_eq!(choose_device(&mac, None), Ok(2));
        // Only loopback available: still usable.
        assert_eq!(choose_device(&[dev("lo", true, true, true, true)], None), Ok(0));
        // Ties keep pcap's ordering.
        let tie = [dev("eth0", true, true, false, true), dev("eth1", true, true, false, true)];
        assert_eq!(choose_device(&tie, None), Ok(0));
    }

    #[test]
    fn replay_pacing_follows_timestamps() {
        use std::time::Duration;
        let mut p = ReplayPacer::new(1.0);
        assert_eq!(p.delay_before(1_000_000), Duration::ZERO, "first packet is immediate");
        assert_eq!(p.delay_before(1_250_000), Duration::from_millis(250));
        assert_eq!(p.delay_before(1_250_000), Duration::ZERO);
        assert_eq!(p.delay_before(1_000_000), Duration::ZERO, "out-of-order timestamp");
        assert_eq!(p.delay_before(9_000_000_000), ReplayPacer::MAX_GAP, "idle gaps are capped");

        let mut fast = ReplayPacer::new(4.0);
        fast.delay_before(0);
        assert_eq!(fast.delay_before(400_000), Duration::from_millis(100));

        let mut unpaced = ReplayPacer::new(0.0);
        unpaced.delay_before(0);
        assert_eq!(unpaced.delay_before(5_000_000), Duration::ZERO);
    }

    #[test]
    fn blocking_submit_and_finished_message() {
        let (sink, rx, counters) = channel(4);
        let f = frame(22);
        assert!(sink.submit_blocking(LinkType::Ethernet, &f, f.len()));
        assert!(sink.submit_blocking(LinkType::Ethernet, &[0; 3], 3));
        sink.finished("done");
        assert!(matches!(rx.try_recv(), Ok(CaptureMsg::Packet(_))));
        assert!(matches!(rx.try_recv(), Ok(CaptureMsg::Finished(m)) if m == "done"));
        assert_eq!(counters.snapshot().undecodable, 1);
    }

    #[test]
    fn requested_device_must_exist() {
        let devs = [dev("lo", true, true, true, true), dev("eth0", true, true, false, true)];
        assert_eq!(choose_device(&devs, Some("lo")), Ok(0));
        let err = choose_device(&devs, Some("eth9")).unwrap_err();
        assert!(err.contains("eth9") && err.contains("lo, eth0"), "{err}");
        assert!(choose_device(&[], None).is_err());
    }
}
