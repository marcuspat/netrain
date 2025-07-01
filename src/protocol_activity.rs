// Protocol activity tracking for time-series visualization

use std::collections::VecDeque;
use crate::Protocol;

const HISTORY_SIZE: usize = 60; // Keep 60 time slices

#[derive(Debug, Clone)]
pub struct ProtocolSnapshot {
    pub tcp: u64,
    pub udp: u64,
    pub http: u64,
    pub https: u64,
    pub dns: u64,
    pub ssh: u64,
    pub unknown: u64,
    pub total: u64,
}

impl ProtocolSnapshot {
    fn new() -> Self {
        Self {
            tcp: 0,
            udp: 0,
            http: 0,
            https: 0,
            dns: 0,
            ssh: 0,
            unknown: 0,
            total: 0,
        }
    }
}

pub struct ProtocolActivityTracker {
    history: VecDeque<ProtocolSnapshot>,
    current: ProtocolSnapshot,
}

impl ProtocolActivityTracker {
    pub fn new() -> Self {
        let mut history = VecDeque::with_capacity(HISTORY_SIZE);
        // Initialize with empty snapshots
        for _ in 0..HISTORY_SIZE {
            history.push_back(ProtocolSnapshot::new());
        }
        
        Self {
            history,
            current: ProtocolSnapshot::new(),
        }
    }
    
    pub fn record_packet(&mut self, protocol: Protocol) {
        match protocol {
            Protocol::TCP => self.current.tcp += 1,
            Protocol::UDP => self.current.udp += 1,
            Protocol::HTTP => self.current.http += 1,
            Protocol::HTTPS => self.current.https += 1,
            Protocol::DNS => self.current.dns += 1,
            Protocol::SSH => self.current.ssh += 1,
            Protocol::Unknown => self.current.unknown += 1,
        }
        self.current.total += 1;
    }
    
    pub fn tick(&mut self) {
        // Push current snapshot to history and reset
        self.history.push_back(self.current.clone());
        if self.history.len() > HISTORY_SIZE {
            self.history.pop_front();
        }
        self.current = ProtocolSnapshot::new();
    }
    
    pub fn get_history(&self) -> &VecDeque<ProtocolSnapshot> {
        &self.history
    }
    
    pub fn get_sparkline_data(&self, protocol: Protocol) -> Vec<u64> {
        // Include current snapshot for real-time display
        let mut data: Vec<u64> = self.history.iter().map(|snapshot| {
            match protocol {
                Protocol::TCP => snapshot.tcp,
                Protocol::UDP => snapshot.udp,
                Protocol::HTTP => snapshot.http,
                Protocol::HTTPS => snapshot.https,
                Protocol::DNS => snapshot.dns,
                Protocol::SSH => snapshot.ssh,
                Protocol::Unknown => snapshot.unknown,
            }
        }).collect();
        
        // Add current snapshot value
        data.push(match protocol {
            Protocol::TCP => self.current.tcp,
            Protocol::UDP => self.current.udp,
            Protocol::HTTP => self.current.http,
            Protocol::HTTPS => self.current.https,
            Protocol::DNS => self.current.dns,
            Protocol::SSH => self.current.ssh,
            Protocol::Unknown => self.current.unknown,
        });
        
        // Return only last 20 values for better visibility
        data.into_iter().rev().take(20).rev().collect()
    }
    
    pub fn get_max_value(&self) -> u64 {
        let history_max = self.history.iter()
            .map(|s| s.total)
            .max()
            .unwrap_or(0);
        
        // Include current snapshot in max calculation
        history_max.max(self.current.total).max(1)
    }
}