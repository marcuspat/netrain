// Protocol activity tracking for time-series visualization

use crate::Protocol;
use std::collections::VecDeque;

const HISTORY_SIZE: usize = 60; // Keep 60 time slices
const PROTOCOLS: usize = Protocol::ALL.len();

/// Packets per protocol during one time slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSnapshot {
    counts: [u64; PROTOCOLS],
    pub total: u64,
}

impl ProtocolSnapshot {
    fn new() -> Self {
        Self {
            counts: [0; PROTOCOLS],
            total: 0,
        }
    }

    /// Packets of `protocol` in this slice.
    pub fn get(&self, protocol: Protocol) -> u64 {
        self.counts[protocol.index()]
    }
}

pub struct ProtocolActivityTracker {
    history: VecDeque<ProtocolSnapshot>,
    current: ProtocolSnapshot,
}

impl Default for ProtocolActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolActivityTracker {
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(HISTORY_SIZE),
            current: ProtocolSnapshot::new(),
        }
    }

    pub fn record_packet(&mut self, protocol: Protocol) {
        self.current.counts[protocol.index()] += 1;
        self.current.total += 1;
    }

    pub fn tick(&mut self) {
        // Push current snapshot to history and reset
        self.history.push_back(std::mem::replace(
            &mut self.current,
            ProtocolSnapshot::new(),
        ));
        if self.history.len() > HISTORY_SIZE {
            self.history.pop_front();
        }
    }

    pub fn get_history(&self) -> &VecDeque<ProtocolSnapshot> {
        &self.history
    }

    /// The last 20 slices for `protocol`, oldest first, zero-padded at the
    /// front and ending with the slice still being filled.
    pub fn get_sparkline_data(&self, protocol: Protocol) -> Vec<u64> {
        const POINTS: usize = 20;
        let mut data: Vec<u64> = self.history.iter().map(|s| s.get(protocol)).collect();
        data.push(self.current.get(protocol));
        if data.len() > POINTS {
            data.drain(..data.len() - POINTS);
        }
        let mut padded = vec![0; POINTS - data.len()];
        padded.extend(data);
        padded
    }

    pub fn get_max_value(&self) -> u64 {
        let history_max = self.history.iter().map(|s| s.total).max().unwrap_or(0);

        // Include current snapshot in max calculation
        history_max.max(self.current.total).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_has_its_own_series() {
        let mut t = ProtocolActivityTracker::new();
        for (i, p) in Protocol::ALL.iter().enumerate() {
            for _ in 0..=i {
                t.record_packet(*p);
            }
        }
        for (i, p) in Protocol::ALL.iter().enumerate() {
            let data = t.get_sparkline_data(*p);
            assert_eq!(data.len(), 20);
            assert_eq!(*data.last().unwrap(), i as u64 + 1, "{p:?}");
            assert!(data[..19].iter().all(|&v| v == 0));
        }
        t.tick();
        assert_eq!(t.get_history()[0].get(Protocol::QUIC), 8);
        assert_eq!(t.get_history()[0].total, (1..=13).sum::<u64>());
        assert_eq!(
            *t.get_sparkline_data(Protocol::QUIC).last().unwrap(),
            0,
            "new slice starts empty"
        );
    }

    #[test]
    fn history_is_bounded_and_sparkline_shows_the_latest_twenty() {
        let mut t = ProtocolActivityTracker::new();
        for i in 0..200u64 {
            for _ in 0..i {
                t.record_packet(Protocol::DNS);
            }
            t.tick();
        }
        assert_eq!(t.get_history().len(), HISTORY_SIZE);
        let data = t.get_sparkline_data(Protocol::DNS);
        assert_eq!(data.len(), 20);
        assert_eq!(data[18], 199);
        assert_eq!(data[19], 0);
        assert_eq!(t.get_max_value(), 199);
    }

    #[test]
    fn protocol_index_matches_all() {
        for (i, p) in Protocol::ALL.iter().enumerate() {
            assert_eq!(p.index(), i);
        }
    }
}
