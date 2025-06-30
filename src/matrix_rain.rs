use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};
use rand::Rng;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MatrixChar {
    pub value: char,
    pub intensity: f32,
    pub y: f32,
}

impl MatrixChar {
    fn new(value: char, y: f32) -> Self {
        Self {
            value,
            intensity: 1.0,
            y,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RainColumn {
    pub x: usize,
    pub chars: Vec<MatrixChar>,
    pub fall_speed: f32,
}

impl RainColumn {
    fn new(x: usize, height: usize) -> Self {
        let mut rng = rand::thread_rng();
        let chars = vec![
            MatrixChar::new(
                random_matrix_char(&mut rng),
                0.0
            )
        ];
        
        Self {
            x,
            chars,
            fall_speed: 1.0,
        }
    }
}

pub struct MatrixRain {
    width: usize,
    height: usize,
    columns: HashMap<usize, RainColumn>,
    traffic_rate: f32,
}

impl MatrixRain {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            columns: HashMap::new(),
            traffic_rate: 0.0,
        }
    }

    pub fn set_traffic_rate(&mut self, rate: f32) {
        self.traffic_rate = rate;
        // Update fall speed for existing columns
        for column in self.columns.values_mut() {
            column.fall_speed = calculate_fall_speed_from_traffic(rate);
        }
    }

    pub fn add_column(&mut self, x: usize) {
        if x < self.width && !self.columns.contains_key(&x) {
            let mut column = RainColumn::new(x, self.height);
            column.fall_speed = calculate_fall_speed_from_traffic(self.traffic_rate);
            self.columns.insert(x, column);
        }
    }

    pub fn get_column(&self, x: usize) -> Option<&RainColumn> {
        self.columns.get(&x)
    }

    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    pub fn update(&mut self, delta_time: f32) {
        // Update all columns
        for column in self.columns.values_mut() {
            // Update character positions and fade
            for char in column.chars.iter_mut() {
                // Move character down
                char.y += column.fall_speed * delta_time;
                
                // Fade character over time
                char.intensity = (char.intensity - delta_time * 0.5).max(0.0);
            }
            
            // Add new characters at top if needed
            if let Some(last_char) = column.chars.last() {
                if last_char.y > 1.0 {
                    let mut rng = rand::thread_rng();
                    column.chars.insert(0, MatrixChar::new(
                        random_matrix_char(&mut rng),
                        0.0
                    ));
                }
            }
            
            // Remove faded characters at bottom
            column.chars.retain(|c| c.y < self.height as f32 && c.intensity > 0.0);
        }
    }

    pub fn update_density(&mut self) {
        // Calculate desired column count based on traffic rate
        let desired_columns = calculate_column_count_from_traffic(self.traffic_rate, self.width);
        let current_columns = self.columns.len();
        
        if desired_columns > current_columns {
            // Add more columns
            let mut rng = rand::thread_rng();
            let columns_to_add = desired_columns - current_columns;
            
            for _ in 0..columns_to_add {
                // Find empty positions
                let mut x = rng.gen_range(0..self.width);
                let mut attempts = 0;
                while self.columns.contains_key(&x) && attempts < self.width {
                    x = (x + 1) % self.width;
                    attempts += 1;
                }
                
                if !self.columns.contains_key(&x) {
                    self.add_column(x);
                }
            }
        } else if desired_columns < current_columns {
            // Remove some columns
            let columns_to_remove = current_columns - desired_columns;
            let keys: Vec<usize> = self.columns.keys().copied().collect();
            
            for i in 0..columns_to_remove.min(keys.len()) {
                self.columns.remove(&keys[i]);
            }
        }
    }

    pub fn remove_column(&mut self, x: usize) {
        self.columns.remove(&x);
    }
}

impl Widget for &mut MatrixRain {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Render each column
        for column in self.columns.values() {
            for char in &column.chars {
                let x = column.x as u16;
                let y = char.y as u16;
                
                // Only render if within bounds
                if x < area.width && y < area.height {
                    // Calculate color based on intensity
                    let color = if char.intensity > 0.8 {
                        Color::Rgb(255, 255, 255) // Bright white
                    } else if char.intensity > 0.4 {
                        Color::Rgb(0, 255, 0) // Green
                    } else {
                        Color::Rgb(0, 128, 0) // Dark green
                    };
                    
                    buf.set_string(
                        area.x + x,
                        area.y + y,
                        char.value.to_string(),
                        Style::default().fg(color)
                    );
                }
            }
        }
    }
}

fn calculate_fall_speed_from_traffic(traffic_rate: f32) -> f32 {
    // Map traffic rate to fall speed (0-5)
    let normalized = (traffic_rate / 1000.0).min(1.0);
    0.5 + normalized * 4.5
}

fn random_matrix_char(rng: &mut impl Rng) -> char {
    // Matrix-style characters
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()[]{}|\\/<>?";
    let chars: Vec<char> = chars.chars().collect();
    chars[rng.gen_range(0..chars.len())]
}

fn calculate_column_count_from_traffic(traffic_rate: f32, width: usize) -> usize {
    // Map traffic rate to column count
    // 0 traffic = 0-1 columns
    // 1000+ traffic = width columns
    if traffic_rate <= 0.0 {
        0
    } else {
        let normalized = (traffic_rate / 1000.0).min(1.0);
        let column_count = (normalized * width as f32) as usize;
        column_count.max(1)
    }
}