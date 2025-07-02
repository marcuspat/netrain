// Simplified matrix rain effect that actually works properly

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};
use rand::Rng;
use std::collections::{HashMap, VecDeque};

pub struct SimpleMatrixRain {
    columns: HashMap<u16, Column>,
    width: u16,
    height: u16,
    tick: u64,
    active_ips: VecDeque<(String, u32)>, // IP, count - keep it simple
}

struct Column {
    head: i16,
    tail: i16,
    speed: u8,
    chars: Vec<char>,
}

impl Column {
    fn new(height: u16) -> Self {
        let mut rng = rand::thread_rng();
        let speed = rng.gen_range(1..4); // Original fast speed
        let length = rng.gen_range(5..20);
        
        // Generate random characters for this column
        let chars: Vec<char> = (0..height + 20)
            .map(|_| {
                let c = match rng.gen_range(0..10) {
                    0..=3 => rng.gen_range(b'0'..=b'9') as char,
                    4..=6 => rng.gen_range(b'A'..=b'Z') as char,
                    _ => rng.gen_range(b'a'..=b'z') as char,
                };
                c
            })
            .collect();
        
        Self {
            head: -(rng.gen_range(0..20)),
            tail: -(length as i16),
            speed,
            chars,
        }
    }
    
    fn update(&mut self) {
        if self.speed > 0 {
            self.head += 1;
            self.tail += 1;
        }
    }
    
    fn should_reset(&self, height: u16) -> bool {
        self.tail > height as i16
    }
}

impl SimpleMatrixRain {
    pub fn new(width: u16, height: u16) -> Self {
        let mut columns = HashMap::new();
        let mut rng = rand::thread_rng();
        
        // Initialize with some columns
        for _ in 0..width / 3 {
            let x = rng.gen_range(0..width);
            if !columns.contains_key(&x) {
                columns.insert(x, Column::new(height));
            }
        }
        
        Self {
            columns,
            width,
            height,
            tick: 0,
            active_ips: VecDeque::new(),
        }
    }
    
    pub fn update(&mut self) {
        self.tick += 1;
        let mut rng = rand::thread_rng();
        
        // Update existing columns - simple and clean
        let mut to_remove = Vec::new();
        for (x, column) in self.columns.iter_mut() {
            if self.tick % column.speed as u64 == 0 {
                column.update();
                if column.should_reset(self.height) {
                    to_remove.push(*x);
                }
            }
        }
        
        // Remove finished columns
        for x in to_remove {
            self.columns.remove(&x);
        }
        
        // Add new columns occasionally
        if rng.gen_bool(0.1) && self.columns.len() < (self.width as usize * 2 / 3) {
            let x = rng.gen_range(0..self.width);
            if !self.columns.contains_key(&x) {
                self.columns.insert(x, Column::new(self.height));
            }
        }
    }
    
    pub fn add_column(&mut self, x: u16) {
        if x < self.width && !self.columns.contains_key(&x) {
            self.columns.insert(x, Column::new(self.height));
        }
    }
    
    // Simple IP tracking - rock solid
    pub fn track_ip_packet(&mut self, src_ip: &str, dst_ip: &str, _protocol: &str) {
        // Track IPs simply and reliably
        for ip in [src_ip, dst_ip] {
            let mut found = false;
            
            // Update existing IP count
            for (existing_ip, count) in &mut self.active_ips {
                if existing_ip == ip {
                    *count += 1;
                    found = true;
                    break;
                }
            }
            
            // Add new IP if not found
            if !found {
                if self.active_ips.len() < 5 {
                    self.active_ips.push_back((ip.to_string(), 1));
                } else {
                    // Replace least active IP
                    if let Some(_) = self.active_ips.pop_back() {
                        self.active_ips.push_front((ip.to_string(), 1));
                    }
                }
            }
        }
        
        // Sort by activity and keep top 5
        let mut sorted: Vec<_> = self.active_ips.drain(..).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(5);
        self.active_ips = sorted.into_iter().collect();
        
        // Just add a random column - keep it simple
        let mut rng = rand::thread_rng();
        let x = rng.gen_range(0..self.width);
        if !self.columns.contains_key(&x) && self.columns.len() < (self.width as usize / 2) {
            self.add_column(x);
        }
    }
    
    // Get active IPs for display
    pub fn get_active_ips(&self) -> Vec<(String, u32)> {
        self.active_ips.iter().cloned().collect()
    }
}

impl Widget for &SimpleMatrixRain {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Simple matrix rendering - no visual enhancements, just functional
        for (col_x, column) in &self.columns {
            if *col_x >= area.width {
                continue;
            }
            
            for y in 0..area.height {
                let char_pos = y as i16;
                
                if char_pos >= column.tail && char_pos <= column.head {
                    let char_idx = (char_pos as usize) % column.chars.len();
                    let ch = column.chars[char_idx];
                    
                    // Simple original colors - no complex effects
                    let color = if char_pos == column.head {
                        Color::White
                    } else {
                        Color::Green
                    };
                    
                    if area.x + col_x < buf.area.width && area.y + y < buf.area.height {
                        buf.get_mut(area.x + col_x, area.y + y)
                            .set_char(ch)
                            .set_style(Style::default().fg(color));
                    }
                }
            }
        }
    }
}