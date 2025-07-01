// Simplified matrix rain effect that actually works properly

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};
use rand::Rng;
use std::collections::HashMap;

pub struct SimpleMatrixRain {
    columns: HashMap<u16, Column>,
    width: u16,
    height: u16,
    tick: u64,
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
        let speed = rng.gen_range(1..4);
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
        }
    }
    
    pub fn update(&mut self) {
        self.tick += 1;
        let mut rng = rand::thread_rng();
        
        // Update existing columns
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
}

impl Widget for &SimpleMatrixRain {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Clear the area first
        for y in 0..area.height {
            for x in 0..area.width {
                buf.get_mut(area.x + x, area.y + y)
                    .set_char(' ')
                    .set_style(Style::default());
            }
        }
        
        // Render each column
        for (col_x, column) in &self.columns {
            let x = area.x + col_x;
            
            for y in 0..area.height {
                let char_pos = y as i16;
                
                if char_pos >= column.tail && char_pos <= column.head {
                    let char_idx = (char_pos + 20) as usize % column.chars.len();
                    let ch = column.chars[char_idx];
                    
                    let color = if char_pos == column.head {
                        Color::White
                    } else {
                        let distance_from_head = (column.head - char_pos) as f32;
                        let fade = 1.0 - (distance_from_head / 15.0).min(1.0);
                        let green = (fade * 255.0) as u8;
                        Color::Rgb(0, green, 0)
                    };
                    
                    if x < area.x + area.width && area.y + y < area.y + area.height {
                        buf.get_mut(x, area.y + y)
                            .set_char(ch)
                            .set_style(Style::default().fg(color));
                    }
                }
            }
        }
    }
}