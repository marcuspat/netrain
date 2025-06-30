use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};
use rand::Rng;
use std::collections::HashMap;

// Character sets for Matrix rain
const ASCII_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()[]{}|\\/<>?+=~`";
const KATAKANA_CHARS: &str = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ";
const SYMBOLS_CHARS: &str = "☆★○●◎◇◆□■△▲▽▼※〒→←↑↓〓∈∋⊆⊇⊂⊃∪∩∧∨¬⇒⇔∀∃∠⊥⌒∂∇≡≒≪≫√∽∝∵∫∬";
const BINARY_CHARS: &str = "01";
const HEX_CHARS: &str = "0123456789ABCDEF";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CharacterSet {
    ASCII,
    Katakana,
    Symbols,
    Binary,
    Hex,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VisualMode {
    Normal,
    Rainbow,
    Glitch,
    Pulse,
    Matrix,
}

#[derive(Debug, Clone)]
pub struct MatrixChar {
    pub value: char,
    pub intensity: f32,
    pub y: f32,
    pub trail_intensity: Vec<f32>, // Multiple levels of trail intensity
    pub color_override: Option<Color>,
    pub glitch_timer: f32,
}

impl MatrixChar {
    fn new(value: char, y: f32) -> Self {
        Self {
            value,
            intensity: 1.0,
            y,
            trail_intensity: vec![0.9, 0.7, 0.5, 0.3, 0.15], // 5 levels of trail
            color_override: None,
            glitch_timer: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RainColumn {
    pub x: usize,
    pub chars: Vec<MatrixChar>,
    pub fall_speed: f32,
    pub z_depth: f32, // For depth illusion (0.0 = far, 1.0 = near)
    pub character_set: CharacterSet,
    pub pulse_timer: f32,
    pub particle_timer: f32,
}

impl RainColumn {
    fn new(x: usize, _height: usize, character_set: CharacterSet) -> Self {
        let mut rng = rand::thread_rng();
        let z_depth = rng.gen_range(0.3..1.0);
        let chars = vec![
            MatrixChar::new(
                random_matrix_char(&mut rng, character_set),
                0.0
            )
        ];
        
        Self {
            x,
            chars,
            fall_speed: 0.5 + z_depth * 2.0, // Deeper columns fall faster
            z_depth,
            character_set,
            pulse_timer: 0.0,
            particle_timer: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Particle {
    pub x: f32,
    pub y: f32,
    pub vx: f32,
    pub vy: f32,
    pub lifetime: f32,
    pub char: char,
    pub color: Color,
}

pub struct MatrixRain {
    pub width: usize,
    pub height: usize,
    columns: HashMap<usize, RainColumn>,
    traffic_rate: f32,
    threat_active: bool,
    threat_pulse: f32,
    visual_mode: VisualMode,
    particles: Vec<Particle>,
    screen_flash: f32,
    global_glitch_timer: f32,
    demo_mode: bool,
    demo_timer: f32,
    rainbow_offset: f32,
}

impl MatrixRain {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            columns: HashMap::new(),
            traffic_rate: 0.0,
            threat_active: false,
            threat_pulse: 0.0,
            visual_mode: VisualMode::Matrix,
            particles: Vec::new(),
            screen_flash: 0.0,
            global_glitch_timer: 0.0,
            demo_mode: false,
            demo_timer: 0.0,
            rainbow_offset: 0.0,
        }
    }

    pub fn set_traffic_rate(&mut self, rate: f32) {
        self.traffic_rate = rate;
        
        // Trigger glitch effect on high traffic
        if rate > 800.0 {
            self.global_glitch_timer = 0.5;
        }
        
        // Update fall speed for existing columns
        for column in self.columns.values_mut() {
            column.fall_speed = calculate_fall_speed_from_traffic(rate) * column.z_depth;
        }
    }

    pub fn set_threat_active(&mut self, active: bool) {
        self.threat_active = active;
        if active {
            self.threat_pulse = 1.0;
            self.screen_flash = 1.0;
            self.visual_mode = VisualMode::Rainbow; // Switch to rainbow mode for threats
        } else {
            self.visual_mode = VisualMode::Matrix;
        }
    }

    pub fn enable_demo_mode(&mut self) {
        self.demo_mode = true;
    }

    pub fn add_column(&mut self, x: usize) {
        if x < self.width && !self.columns.contains_key(&x) {
            let mut rng = rand::thread_rng();
            let char_set = if self.visual_mode == VisualMode::Glitch {
                CharacterSet::Binary
            } else {
                match rng.gen_range(0..6) {
                    0 => CharacterSet::ASCII,
                    1 => CharacterSet::Katakana,
                    2 => CharacterSet::Symbols,
                    3 => CharacterSet::Binary,
                    4 => CharacterSet::Hex,
                    _ => CharacterSet::Mixed,
                }
            };
            
            let mut column = RainColumn::new(x, self.height, char_set);
            column.fall_speed = calculate_fall_speed_from_traffic(self.traffic_rate) * column.z_depth;
            
            // Add particle effect for new column
            self.add_particle_burst(x as f32, 0.0);
            
            self.columns.insert(x, column);
        }
    }

    fn add_particle_burst(&mut self, x: f32, y: f32) {
        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            self.particles.push(Particle {
                x,
                y,
                vx: rng.gen_range(-2.0..2.0),
                vy: rng.gen_range(-1.0..3.0),
                lifetime: 1.0,
                char: random_matrix_char(&mut rng, CharacterSet::Symbols),
                color: Color::Rgb(100, 255, 100),
            });
        }
    }

    pub fn get_column(&self, x: usize) -> Option<&RainColumn> {
        self.columns.get(&x)
    }

    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    pub fn update(&mut self, delta_time: f32) {
        // Update demo mode
        if self.demo_mode {
            self.update_demo(delta_time);
        }
        
        // Update visual effects timers
        self.threat_pulse = (self.threat_pulse - delta_time * 2.0).max(0.0);
        self.screen_flash = (self.screen_flash - delta_time * 3.0).max(0.0);
        self.global_glitch_timer = (self.global_glitch_timer - delta_time).max(0.0);
        self.rainbow_offset += delta_time * 50.0;
        
        // Update all columns
        for column in self.columns.values_mut() {
            column.pulse_timer = (column.pulse_timer + delta_time * 4.0) % (2.0 * std::f32::consts::PI);
            
            // Update character positions and effects
            for (_i, char) in column.chars.iter_mut().enumerate() {
                // Move character down with smooth interpolation
                let speed_modifier = if self.visual_mode == VisualMode::Pulse {
                    1.0 + (column.pulse_timer.sin() * 0.3)
                } else {
                    1.0
                };
                char.y += column.fall_speed * delta_time * speed_modifier;
                
                // Update intensity with smooth fade
                char.intensity = (char.intensity - delta_time * 0.5).max(0.0);
                
                // Update trail intensities
                for j in 0..char.trail_intensity.len() {
                    let fade_rate = 0.3 + (j as f32 * 0.1);
                    char.trail_intensity[j] = (char.trail_intensity[j] - delta_time * fade_rate).max(0.0);
                }
                
                // Glitch effect
                if self.global_glitch_timer > 0.0 || char.glitch_timer > 0.0 {
                    let mut rng = rand::thread_rng();
                    if rng.gen_bool(0.1) {
                        char.value = random_matrix_char(&mut rng, column.character_set);
                        char.glitch_timer = 0.2;
                    }
                }
                char.glitch_timer = (char.glitch_timer - delta_time).max(0.0);
            }
            
            // Add new characters at top if needed
            if let Some(last_char) = column.chars.last() {
                if last_char.y > 1.5 {
                    let mut rng = rand::thread_rng();
                    column.chars.insert(0, MatrixChar::new(
                        random_matrix_char(&mut rng, column.character_set),
                        0.0
                    ));
                }
            }
            
            // Remove faded characters at bottom
            column.chars.retain(|c| c.y < self.height as f32 && c.intensity > 0.0);
        }
        
        // Update particles
        self.particles.retain_mut(|particle| {
            particle.x += particle.vx * delta_time;
            particle.y += particle.vy * delta_time;
            particle.vy += 5.0 * delta_time; // Gravity
            particle.lifetime -= delta_time;
            particle.lifetime > 0.0
        });
        
        // Update density based on traffic
        self.update_density();
    }

    fn update_demo(&mut self, delta_time: f32) {
        self.demo_timer += delta_time;
        
        // Simulate traffic patterns
        let traffic = match (self.demo_timer % 20.0) as i32 {
            0..=5 => 100.0 + (self.demo_timer * 20.0).sin() * 50.0,     // Low traffic
            6..=10 => 500.0 + (self.demo_timer * 30.0).sin() * 200.0,   // Medium traffic
            11..=15 => 1000.0 + (self.demo_timer * 40.0).sin() * 300.0, // High traffic
            _ => {
                // Simulate threat/DDoS
                self.set_threat_active(true);
                2000.0
            }
        };
        
        self.set_traffic_rate(traffic);
        
        // Reset threat after demo cycle
        if (self.demo_timer % 20.0) < 16.0 {
            self.set_threat_active(false);
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
        // Apply screen flash effect
        if self.screen_flash > 0.0 {
            for y in 0..area.height {
                for x in 0..area.width {
                    let flash_color = Color::Rgb(
                        255,
                        (255.0 * (1.0 - self.screen_flash)) as u8,
                        (255.0 * (1.0 - self.screen_flash)) as u8,
                    );
                    buf.get_mut(area.x + x, area.y + y)
                        .set_bg(flash_color);
                }
            }
        }
        
        // Render particles first (background layer)
        for particle in &self.particles {
            let x = particle.x as u16;
            let y = particle.y as u16;
            
            if x < area.width && y < area.height {
                let alpha = particle.lifetime;
                let color = match particle.color {
                    Color::Rgb(r, g, b) => Color::Rgb(
                        (r as f32 * alpha) as u8,
                        (g as f32 * alpha) as u8,
                        (b as f32 * alpha) as u8,
                    ),
                    _ => particle.color,
                };
                
                buf.set_string(
                    area.x + x,
                    area.y + y,
                    particle.char.to_string(),
                    Style::default().fg(color)
                );
            }
        }
        
        // Sort columns by z_depth for proper rendering order (far to near)
        let mut sorted_columns: Vec<_> = self.columns.values().collect();
        sorted_columns.sort_by(|a, b| a.z_depth.partial_cmp(&b.z_depth).unwrap());
        
        // Render each column
        for column in sorted_columns {
            for (_char_idx, char) in column.chars.iter().enumerate() {
                let x = column.x as u16;
                let base_y = char.y as u16;
                
                // Render trail effect
                for (trail_idx, &trail_intensity) in char.trail_intensity.iter().enumerate() {
                    let trail_y = base_y.saturating_sub((trail_idx + 1) as u16);
                    
                    if x < area.width && trail_y < area.height && trail_intensity > 0.0 {
                        let trail_char = if trail_idx == 0 {
                            char.value
                        } else {
                            // Use slightly different characters for trail
                            let mut rng = rand::thread_rng();
                            if rng.gen_bool(0.3) {
                                random_matrix_char(&mut rng, column.character_set)
                            } else {
                                char.value
                            }
                        };
                        
                        let color = calculate_trail_color(
                            trail_intensity,
                            column.z_depth,
                            self.visual_mode,
                            self.rainbow_offset + (x as f32 * 10.0) + (trail_y as f32 * 5.0),
                            self.threat_pulse,
                        );
                        
                        buf.set_string(
                            area.x + x,
                            area.y + trail_y,
                            trail_char.to_string(),
                            Style::default().fg(color)
                        );
                    }
                }
                
                // Render main character
                if x < area.width && base_y < area.height {
                    let color = if let Some(override_color) = char.color_override {
                        override_color
                    } else {
                        calculate_character_color(
                            char.intensity,
                            column.z_depth,
                            self.visual_mode,
                            self.rainbow_offset + (x as f32 * 10.0) + (base_y as f32 * 5.0),
                            self.threat_pulse,
                            column.pulse_timer,
                        )
                    };
                    
                    buf.set_string(
                        area.x + x,
                        area.y + base_y,
                        char.value.to_string(),
                        Style::default().fg(color)
                    );
                }
            }
        }
    }
}

fn calculate_character_color(
    intensity: f32,
    z_depth: f32,
    mode: VisualMode,
    rainbow_offset: f32,
    _threat_pulse: f32,
    pulse_timer: f32,
) -> Color {
    match mode {
        VisualMode::Normal | VisualMode::Matrix => {
            // Classic Matrix green with depth variation
            let depth_factor = 0.5 + z_depth * 0.5;
            let green_base = (200.0 * depth_factor) as u8;
            
            if intensity > 0.9 {
                Color::Rgb(220, 255, 220) // Bright white-green
            } else if intensity > 0.7 {
                Color::Rgb(150, 255, 150) // Bright green
            } else if intensity > 0.4 {
                Color::Rgb(0, green_base + 55, 0) // Medium green
            } else {
                Color::Rgb(0, green_base, 0) // Dark green
            }
        }
        VisualMode::Rainbow => {
            // Rainbow effect for threats
            let hue = (rainbow_offset % 360.0) / 360.0;
            let (r, g, b) = hsv_to_rgb(hue, 1.0, intensity);
            Color::Rgb(r, g, b)
        }
        VisualMode::Glitch => {
            // Glitchy colors
            let mut rng = rand::thread_rng();
            if rng.gen_bool(0.1) {
                Color::Rgb(255, 0, 255) // Magenta glitch
            } else if rng.gen_bool(0.1) {
                Color::Rgb(0, 255, 255) // Cyan glitch
            } else {
                Color::Rgb(0, 255, 0) // Green
            }
        }
        VisualMode::Pulse => {
            // Pulsing effect
            let pulse = (pulse_timer.sin() + 1.0) / 2.0;
            let green = (100.0 + 155.0 * intensity * pulse) as u8;
            Color::Rgb(0, green, 0)
        }
    }
}

fn calculate_trail_color(
    intensity: f32,
    z_depth: f32,
    mode: VisualMode,
    rainbow_offset: f32,
    _threat_pulse: f32,
) -> Color {
    match mode {
        VisualMode::Normal | VisualMode::Matrix => {
            let depth_factor = 0.3 + z_depth * 0.7;
            let green = (80.0 * intensity * depth_factor) as u8;
            Color::Rgb(0, green, 0)
        }
        VisualMode::Rainbow => {
            let hue = (rainbow_offset % 360.0) / 360.0;
            let (r, g, b) = hsv_to_rgb(hue, 0.8, intensity * 0.5);
            Color::Rgb(r, g, b)
        }
        _ => Color::Rgb(0, (50.0 * intensity) as u8, 0),
    }
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h * 6.0) % 2.0 - 1.0).abs());
    let m = v - c;
    
    let (r, g, b) = match (h * 6.0) as i32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    
    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

fn calculate_fall_speed_from_traffic(traffic_rate: f32) -> f32 {
    // Map traffic rate to fall speed (0.5-5.0)
    let normalized = (traffic_rate / 1000.0).min(1.0);
    0.5 + normalized * 4.5
}

pub fn random_matrix_char(rng: &mut impl Rng, char_set: CharacterSet) -> char {
    let chars: Vec<char> = match char_set {
        CharacterSet::ASCII => ASCII_CHARS.chars().collect(),
        CharacterSet::Katakana => KATAKANA_CHARS.chars().collect(),
        CharacterSet::Symbols => SYMBOLS_CHARS.chars().collect(),
        CharacterSet::Binary => BINARY_CHARS.chars().collect(),
        CharacterSet::Hex => HEX_CHARS.chars().collect(),
        CharacterSet::Mixed => {
            // Mix all character sets
            let all_chars = format!("{}{}{}{}", ASCII_CHARS, KATAKANA_CHARS, SYMBOLS_CHARS, BINARY_CHARS);
            all_chars.chars().collect()
        }
    };
    
    if chars.is_empty() {
        '?'
    } else {
        chars[rng.gen_range(0..chars.len())]
    }
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