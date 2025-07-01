use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netrain::{
    // matrix_rain::MatrixRain,
    simple_matrix::SimpleMatrixRain,
    optimized::{parse_packet_optimized, classify_protocol_optimized},
    threat_detection::ThreatDetector,
    protocol_activity::ProtocolActivityTracker,
    Protocol, ProtocolStats, ThreatLevel,
};
use pcap::{Capture, Device};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
    Terminal,
};
use std::{
    collections::VecDeque,
    env,
    io,
    sync::{Arc, Mutex, atomic::{AtomicU64, AtomicUsize, Ordering}},
    thread,
    time::{Duration, Instant},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const ASCII_LOGO: &str = r#"
╔═╗ ╔═╗ ╔══════╗ ╔══════╗ ╔══════╗ ╔══════╗ ╔══════╗ ╔═╗ ╔═╗
║ ╚═╝ ║ ║ ╔════╝ ╚═╗  ╔═╝ ║ ╔══╗ ║ ║ ╔══╗ ║ ╚═╗  ╔═╝ ║ ╚═╝ ║
║ ╔╗  ║ ║ ╚════╗   ║  ║   ║ ╚══╝ ║ ║ ╚══╝ ║   ║  ║   ║ ╔╗  ║
║ ║╚╗ ║ ║ ╔════╝   ║  ║   ║ ╔╗ ╔═╝ ║ ╔══╗ ║   ║  ║   ║ ║╚╗ ║
║ ║ ╚╗║ ║ ╚════╗   ║  ║   ║ ║╚╗╚╗  ║ ║  ║ ║ ╔═╝  ╚═╗ ║ ║ ╚╗║
╚═╝  ╚╝ ╚══════╝   ╚══╝   ╚═╝ ╚═╝  ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚╝
         Network Traffic Analyzer with Matrix Rain Effect     
"#;

// Performance monitoring struct
struct PerformanceMonitor {
    fps_counter: AtomicUsize,
    frame_times: Mutex<VecDeque<Duration>>,
    packet_count: AtomicU64,
    packet_rate: AtomicU64,
    last_packet_reset: Mutex<Instant>,
    memory_usage: AtomicUsize,
}

impl PerformanceMonitor {
    fn new() -> Self {
        Self {
            fps_counter: AtomicUsize::new(0),
            frame_times: Mutex::new(VecDeque::with_capacity(60)),
            packet_count: AtomicU64::new(0),
            packet_rate: AtomicU64::new(0),
            last_packet_reset: Mutex::new(Instant::now()),
            memory_usage: AtomicUsize::new(0),
        }
    }
    
    fn record_frame(&self, frame_time: Duration) {
        let mut times = self.frame_times.lock().unwrap();
        times.push_back(frame_time);
        if times.len() > 60 {
            times.pop_front();
        }
        
        // Calculate average FPS from last 60 frames
        if times.len() >= 10 {
            let total: Duration = times.iter().sum();
            let avg_frame_time = total / times.len() as u32;
            let fps = 1_000_000 / avg_frame_time.as_micros().max(1);
            self.fps_counter.store(fps as usize, Ordering::Relaxed);
        }
    }
    
    fn increment_packet(&self) {
        self.packet_count.fetch_add(1, Ordering::Relaxed);
        
        // Update packet rate every second
        let mut last_reset = self.last_packet_reset.lock().unwrap();
        if last_reset.elapsed() >= Duration::from_secs(1) {
            let count = self.packet_count.swap(0, Ordering::Relaxed);
            self.packet_rate.store(count, Ordering::Relaxed);
            *last_reset = Instant::now();
        }
    }
    
    fn update_memory_usage(&self) {
        // Simple memory estimation based on active data structures
        // In production, you'd use system memory APIs
        let estimated_kb = 1024; // Placeholder
        self.memory_usage.store(estimated_kb, Ordering::Relaxed);
    }
    
    fn get_fps(&self) -> usize {
        self.fps_counter.load(Ordering::Relaxed)
    }
    
    fn get_packet_rate(&self) -> u64 {
        self.packet_rate.load(Ordering::Relaxed)
    }
    
    fn get_memory_mb(&self) -> f32 {
        self.memory_usage.load(Ordering::Relaxed) as f32 / 1024.0
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let demo_mode = args.contains(&"--demo".to_string());
    
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Show ASCII logo as splash screen
    terminal.draw(|f| {
        let area = f.size();
        
        // Clear background first
        let clear_block = Block::default()
            .style(Style::default().bg(Color::Black));
        f.render_widget(clear_block, area);
        
        let logo_lines: Vec<Line> = ASCII_LOGO
            .lines()
            .map(|line| Line::from(vec![
                Span::styled(line, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            ]))
            .collect();
        
        let logo_paragraph = Paragraph::new(logo_lines)
            .alignment(Alignment::Center)
            .block(Block::default());
            
        let vertical_center = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(35),
                Constraint::Min(10),
                Constraint::Percentage(35),
            ])
            .split(area);
            
        f.render_widget(logo_paragraph, vertical_center[1]);
        
        // Add a loading message with version
        let loading_text = Paragraph::new(format!("NetRain v{}\nInitializing packet capture...", VERSION))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        
        let loading_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(3),
            ])
            .split(vertical_center[2]);
            
        f.render_widget(loading_text, loading_area[1]);
    })?;

    // Show splash screen briefly
    thread::sleep(Duration::from_millis(1500));
    
    // IMPORTANT: Clear the terminal completely before starting main UI
    terminal.clear()?;

    // Initialize components
    let terminal_size = terminal.size()?;
    // Initialize simple matrix rain
    let matrix_width = (terminal_size.width * 70 / 100) as u16;
    let matrix_height = (terminal_size.height * 40 / 100) as u16;
    let matrix_rain = Arc::new(Mutex::new(SimpleMatrixRain::new(
        matrix_width,
        matrix_height,
    )));
    
    // Enable demo mode if requested
    if demo_mode {
        let mut rain = matrix_rain.lock().unwrap();
        // SimpleMatrixRain starts with demo behavior automatically
        // Add initial columns for immediate visual effect
        for i in 0..20 {
            rain.add_column((i * 4) % matrix_width);
        }
        drop(rain);
    }
    
    let threat_detector = Arc::new(Mutex::new(ThreatDetector::new()));
    let protocol_stats = Arc::new(Mutex::new(ProtocolStats::new()));
    let packet_log = Arc::new(Mutex::new(VecDeque::new()));
    let traffic_counter = Arc::new(Mutex::new(0u64));
    let perf_monitor = Arc::new(PerformanceMonitor::new());
    let raw_packets = Arc::new(Mutex::new(VecDeque::new())); // Store raw packet data for hex dump
    let protocol_activity = Arc::new(Mutex::new(ProtocolActivityTracker::new()));

    // Start packet capture in background thread
    if demo_mode {
        // Demo mode - generate fake packets
        let packet_log_clone = Arc::clone(&packet_log);
        let raw_packets_clone = Arc::clone(&raw_packets);
        let protocol_stats_clone = Arc::clone(&protocol_stats);
        let matrix_rain_clone = Arc::clone(&matrix_rain);
        let traffic_counter_clone = Arc::clone(&traffic_counter);
        let perf_monitor_clone = Arc::clone(&perf_monitor);
        let protocol_activity_clone = Arc::clone(&protocol_activity);
        let demo_matrix_width = matrix_width;
        
        thread::spawn(move || {
            let demo_ips = vec![
                ("192.168.1.105", "142.250.185.78"),
                ("192.168.1.105", "172.217.14.93"),
                ("192.168.1.105", "8.8.8.8"),
                ("10.0.0.42", "52.97.188.126"),
                ("172.16.0.100", "239.255.255.250"),
            ];
            
            let protocols = vec![Protocol::TCP, Protocol::UDP, Protocol::HTTP, Protocol::HTTPS, Protocol::DNS, Protocol::SSH];
            
            loop {
                // Vary the sleep time for more realistic traffic patterns
                let sleep_ms = 200 + (rand::random::<u64>() % 100); // 200-300ms
                thread::sleep(Duration::from_millis(sleep_ms));
                
                // Generate fewer packets for more realistic traffic
                let num_packets = rand::random::<usize>() % 3; // 0-2 packets
                
                // Skip this cycle sometimes for even more realistic gaps
                if num_packets > 0 {
                    for _ in 0..num_packets {
                    let (src, dst) = demo_ips[rand::random::<usize>() % demo_ips.len()];
                    let protocol = protocols[rand::random::<usize>() % protocols.len()];
                    let size = 60 + rand::random::<usize>() % 1400;
                
                // Update counters
                *traffic_counter_clone.lock().unwrap() += 1;
                perf_monitor_clone.increment_packet();
                protocol_stats_clone.lock().unwrap().add_packet(protocol, size);
                protocol_activity_clone.lock().unwrap().record_packet(protocol);
                
                // Update matrix rain
                let mut rain = matrix_rain_clone.lock().unwrap();
                let x = rand::random::<u16>() % demo_matrix_width;
                rain.add_column(x);
                drop(rain);
                
                // Create log entry
                let timestamp = chrono::Local::now().format("%H:%M:%S");
                let log_entry = match protocol {
                    Protocol::HTTP => format!("[{}] HTTP  {} -> {} [{}B]", timestamp, src, dst, size),
                    Protocol::HTTPS => format!("[{}] HTTPS {} -> {} [{}B]", timestamp, src, dst, size),
                    Protocol::DNS => format!("[{}] DNS   {} -> {} [{}B]", timestamp, src, dst, size),
                    Protocol::SSH => format!("[{}] SSH   {} -> {} [{}B]", timestamp, src, dst, size),
                    Protocol::TCP => format!("[{}] TCP   {} -> {} [{}B]", timestamp, src, dst, size),
                    Protocol::UDP => format!("[{}] UDP   {} -> {} [{}B]", timestamp, src, dst, size),
                    _ => format!("[{}] ???   {} -> {} [{}B]", timestamp, src, dst, size),
                };
                
                let mut log = packet_log_clone.lock().unwrap();
                log.push_front(log_entry);
                if log.len() > 25 {
                    log.pop_back();
                }
                drop(log);
                
                // Generate fake packet data
                let mut fake_packet = vec![0x45, 0x00]; // IPv4 header start
                fake_packet.extend_from_slice(&(size as u16).to_be_bytes());
                for _ in 0..60 {
                    fake_packet.push(rand::random::<u8>());
                }
                
                let mut raw = raw_packets_clone.lock().unwrap();
                raw.push_front(fake_packet);
                if raw.len() > 5 {
                    raw.pop_back();
                }
                    } // End of for loop
                } // End of if num_packets > 0
            }
        });
    } else {
        let matrix_rain_clone = Arc::clone(&matrix_rain);
        let threat_detector_clone = Arc::clone(&threat_detector);
        let protocol_stats_clone = Arc::clone(&protocol_stats);
        let packet_log_clone = Arc::clone(&packet_log);
        let traffic_counter_clone = Arc::clone(&traffic_counter);
        let perf_monitor_clone = Arc::clone(&perf_monitor);
        let raw_packets_clone = Arc::clone(&raw_packets);
        let protocol_activity_clone = Arc::clone(&protocol_activity);
        let capture_matrix_width = matrix_width;

        thread::spawn(move || {
            // First, try to find and list available devices
            match Device::list() {
                Ok(devices) => {
                    // Silent device selection - no debug output in UI
                    // Try to find en0 (active WiFi interface) first
                    let target_device = devices.iter()
                        .find(|d| d.name == "en0")
                        .or_else(|| devices.iter().find(|d| d.name.starts_with("en")))
                        .or_else(|| devices.first());
                    
                    if let Some(device) = target_device {
                        match Capture::from_device(device.clone()) {
                            Ok(cap_builder) => {
                                match cap_builder
                                    .promisc(true)
                                    .snaplen(5000)
                                    .timeout(1000) // Add timeout
                                    .open() {
                                    Ok(mut cap) => {
                                        
                                        // Set a filter to capture common traffic
                                        let _ = cap.filter("ip", true);
                                        
                                        loop {
                                            match cap.next_packet() {
                                                Ok(packet) => {
                                                    let data = packet.data.to_vec();
                                                    
                                                    // Update traffic counter
                                                    *traffic_counter_clone.lock().unwrap() += 1;
                                                    
                                                    // Update performance monitor
                                                    perf_monitor_clone.increment_packet();
                                                    
                                                    // Parse packet using optimized version
                                                    if let Ok(parsed) = parse_packet_optimized(&data) {
                                                        // Update protocol stats using optimized version
                                                        let protocol = classify_protocol_optimized(&parsed);
                                                        protocol_stats_clone.lock().unwrap().add_packet(protocol, parsed.length);
                                                        protocol_activity_clone.lock().unwrap().record_packet(protocol);
                                                        
                                                        // Check for threats
                                                        threat_detector_clone.lock().unwrap().analyze_packet(&parsed);
                                                        
                                                        // Update matrix rain with traffic
                                                        let mut rain = matrix_rain_clone.lock().unwrap();
                                                        let x = rand::random::<u16>() % capture_matrix_width;
                                                        rain.add_column(x);
                                                        
                                                        // Log packet with protocol-specific formatting
                                                        let mut log = packet_log_clone.lock().unwrap();
                                                        let timestamp = chrono::Local::now().format("%H:%M:%S");
                                                        
                                                        // Format based on protocol type
                                                        let log_entry = match protocol {
                                                            Protocol::HTTP => format!(
                                                                "[{}] HTTP  {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                            Protocol::HTTPS => format!(
                                                                "[{}] HTTPS {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                            Protocol::DNS => format!(
                                                                "[{}] DNS   {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                            Protocol::SSH => format!(
                                                                "[{}] SSH   {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                            Protocol::TCP => format!(
                                                                "[{}] TCP   {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                            Protocol::UDP => format!(
                                                                "[{}] UDP   {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                            _ => format!(
                                                                "[{}] ???   {} -> {} [{}B]",
                                                                timestamp, parsed.src_ip, parsed.dst_ip, parsed.length
                                                            ),
                                                        };
                                                        
                                                        log.push_front(log_entry);
                                                        if log.len() > 25 {  // Show more entries in the dedicated area
                                                            log.pop_back();
                                                        }
                                                        
                                                        // Store raw packet data for hex dump (limit to 64 bytes)
                                                        let mut raw = raw_packets_clone.lock().unwrap();
                                                        let packet_sample: Vec<u8> = data.iter().take(64).cloned().collect();
                                                        raw.push_front(packet_sample);
                                                        if raw.len() > 5 {  // Keep last 5 packets
                                                            raw.pop_back();
                                                        }
                                                    }
                                                }
                                                Err(pcap::Error::TimeoutExpired) => {
                                                    // Timeout is normal, continue
                                                    continue;
                                                }
                                                Err(_) => {
                                                    // Error reading packet, silently break
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        // Failed to open capture, silently skip
                                    }
                                }
                            }
                            Err(_) => {
                                // Failed to create capture, silently skip
                            }
                        }
                    } else {
                        // No suitable network device found
                    }
                }
                Err(_) => {
                    // Failed to list network devices
                }
            }
        });
    }

    // Main render loop
    let mut last_update = Instant::now();
    let mut last_traffic_update = Instant::now();
    let mut last_activity_tick = Instant::now();
    let mut _last_frame_time = Instant::now();
    let _frame_time = Duration::from_millis(16); // Target 60 FPS
    
    loop {
        let frame_start = Instant::now();
        // Handle input
        if event::poll(Duration::from_millis(5))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        // Demo mode already active
                    }
                    _ => {}
                }
            } else if let Event::Resize(_width, _height) = event::read()? {
                // Terminal resized - TODO: implement resize support for matrix rain
            }
        }

        // Calculate smooth frame timing
        let now = Instant::now();
        let delta_time = now.duration_since(last_update).as_secs_f32();
        
        // Update matrix rain animation with interpolated timing
        if delta_time >= 0.016 { // Cap at ~60 FPS
            matrix_rain.lock().unwrap().update();
            last_update = now;
        }

        // Update traffic rate every second
        if now.duration_since(last_traffic_update) >= Duration::from_secs(1) {
            // SimpleMatrixRain doesn't have set_traffic_rate, just reset counter
            *traffic_counter.lock().unwrap() = 0; // Reset counter
            last_traffic_update = now;
        }
        
        // Update protocol activity tracker every 150ms for smoother display
        if now.duration_since(last_activity_tick) >= Duration::from_millis(150) {
            protocol_activity.lock().unwrap().tick();
            last_activity_tick = now;
        }

        // Check threat status (SimpleMatrixRain doesn't have threat visualization yet)
        {
            let detector = threat_detector.lock().unwrap();
            let _threat_level = detector.get_threat_level();
            let _is_ddos = detector.is_ddos_active();
            // TODO: Add threat visualization to SimpleMatrixRain
        }

        // Render with simplified layout
        terminal.draw(|f| {
            // Simple two-column layout without title bar
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .margin(0)
                .constraints([
                    Constraint::Percentage(70),
                    Constraint::Percentage(30),
                ])
                .split(f.size());

            // Matrix rain with packet log and data overlays
            let matrix_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),   // Top stats bar
                    Constraint::Percentage(35), // Matrix rain area
                    Constraint::Percentage(35), // Packet log
                    Constraint::Min(10),   // Network activity graph - increased height
                ])
                .split(main_chunks[0]);
            
            // Top stats bar with real-time data
            let traffic_rate = perf_monitor.get_packet_rate();
            let fps = perf_monitor.get_fps();
            let detector = threat_detector.lock().unwrap();
            let threat_level = detector.get_threat_level();
            drop(detector);
            
            let stats_text = vec![
                Span::styled(format!(" NETRAIN v{} ", VERSION), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw("|"),
                Span::styled(format!(" FPS: {} ", fps), Style::default().fg(if fps >= 55 { Color::Green } else { Color::Yellow })),
                Span::raw("|"),
                Span::styled(format!(" {} pkt/s ", traffic_rate), Style::default().fg(Color::Cyan)),
                Span::raw("|"),
                Span::styled(
                    format!(" THREAT: {:?} ", threat_level),
                    Style::default().fg(match threat_level {
                        ThreatLevel::Low => Color::Green,
                        ThreatLevel::Medium => Color::Yellow,
                        ThreatLevel::High => Color::Red,
                        ThreatLevel::Critical => Color::Red,
                    }).add_modifier(if threat_level != ThreatLevel::Low { Modifier::BOLD } else { Modifier::empty() })
                ),
            ];
            
            let stats_bar = Paragraph::new(Line::from(stats_text))
                .style(Style::default().bg(Color::Black))
                .alignment(Alignment::Center)
                .block(Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(stats_bar, matrix_chunks[0]);
            
            // Matrix rain in the middle
            let rain = matrix_rain.lock().unwrap();
            let matrix_block = Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(if threat_level != ThreatLevel::Low { Color::Red } else { Color::Green }));
            
            let matrix_area = matrix_block.inner(matrix_chunks[1]);
            f.render_widget(matrix_block, matrix_chunks[1]);
            f.render_widget(&*rain, matrix_area);
            
            // Packet log in matrix panel
            let log = packet_log.lock().unwrap();
            let log_items: Vec<ListItem> = log.iter()
                .enumerate()
                .map(|(i, entry)| {
                    let color = if entry.contains("HTTP ") {
                        Color::Blue
                    } else if entry.contains("HTTPS") {
                        Color::Cyan
                    } else if entry.contains("DNS") {
                        Color::Yellow
                    } else if entry.contains("SSH") {
                        Color::Magenta
                    } else if entry.contains("TCP") {
                        Color::Green
                    } else if entry.contains("UDP") {
                        Color::LightGreen
                    } else {
                        Color::Gray
                    };
                    
                    let style = if i == 0 {
                        Style::default().fg(color).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(color)
                    };
                    ListItem::new(entry.as_str()).style(style)
                })
                .collect();
            
            let log_list = List::new(log_items)
                .block(Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" [ PACKET LOG ] ")
                    .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            f.render_widget(log_list, matrix_chunks[2]);
            drop(log);
            
            // Network activity graph at bottom - color-coded by protocol
            use ratatui::widgets::Sparkline;
            
            // Get protocol activity data
            let activity = protocol_activity.lock().unwrap();
            
            // Create a layout for multiple protocol sparklines
            let protocol_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(16),  // TCP
                    Constraint::Percentage(16),  // UDP
                    Constraint::Percentage(17),  // HTTP
                    Constraint::Percentage(17),  // HTTPS
                    Constraint::Percentage(17),  // DNS
                    Constraint::Percentage(17),  // SSH
                ])
                .split(matrix_chunks[3]);
            
            // Define protocol colors matching packet log
            let protocols = [
                (Protocol::TCP, Color::Green, "TCP"),
                (Protocol::UDP, Color::LightGreen, "UDP"),
                (Protocol::HTTP, Color::Blue, "HTTP"),
                (Protocol::HTTPS, Color::Cyan, "HTTPS"),
                (Protocol::DNS, Color::Yellow, "DNS"),
                (Protocol::SSH, Color::Magenta, "SSH"),
            ];
            
            // Render sparkline for each protocol
            for (i, (protocol, color, name)) in protocols.iter().enumerate() {
                let data = activity.get_sparkline_data(*protocol);
                // Calculate max for this specific protocol, with minimum of 10 for visibility
                let protocol_max = data.iter().max().copied().unwrap_or(0);
                let max_val = protocol_max.max(10);
                
                // Add current count to title for visibility
                let current_count = data.last().copied().unwrap_or(0);
                let title = if current_count > 0 {
                    format!(" {} ({}) ", name, current_count)
                } else {
                    format!(" {} ", name)
                };
                
                let sparkline = Sparkline::default()
                    .data(&data)
                    .max(max_val)
                    .style(Style::default().fg(*color))
                    .block(Block::default()
                        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
                        .border_style(Style::default().fg(Color::DarkGray))
                        .title(title));
                        
                f.render_widget(sparkline, protocol_chunks[i]);
            }
            drop(activity);

            // Right panel - properly organized layout
            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6),   // Performance stats
                    Constraint::Length(10),  // Protocol stats  
                    Constraint::Length(10),  // Threat monitor
                    Constraint::Min(15),     // Packet log
                    Constraint::Length(3),   // Help
                ])
                .split(main_chunks[1]);

            // Performance stats
            let fps = perf_monitor.get_fps();
            let packet_rate = perf_monitor.get_packet_rate();
            let memory_mb = perf_monitor.get_memory_mb();
            
            let perf_items = vec![
                ListItem::new(format!("FPS: {}", fps))
                    .style(if fps >= 55 { 
                        Style::default().fg(Color::Green) 
                    } else if fps >= 30 { 
                        Style::default().fg(Color::Yellow) 
                    } else { 
                        Style::default().fg(Color::Red) 
                    }),
                ListItem::new(format!("PKT/s: {}", packet_rate))
                    .style(Style::default().fg(Color::Cyan)),
                ListItem::new(format!("MEM: {:.1}MB", memory_mb))
                    .style(Style::default().fg(Color::Blue)),
            ];
            
            let perf_list = List::new(perf_items)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" PERF ")
                    .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            f.render_widget(perf_list, right_chunks[0]);

            // Protocol stats
            let stats = protocol_stats.lock().unwrap();
            let total_packets = stats.get_count(Protocol::TCP) + 
                                    stats.get_count(Protocol::UDP) + 
                                    stats.get_count(Protocol::HTTP) + 
                                    stats.get_count(Protocol::HTTPS) +
                                    stats.get_count(Protocol::DNS) + 
                                    stats.get_count(Protocol::SSH);
            
            let protocol_items: Vec<ListItem> = vec![
                ListItem::new(format!("TCP:   {} pkt", stats.get_count(Protocol::TCP)))
                    .style(Style::default().fg(Color::Green)),
                ListItem::new(format!("UDP:   {} pkt", stats.get_count(Protocol::UDP)))
                    .style(Style::default().fg(Color::LightGreen)),
                ListItem::new(format!("HTTP:  {} pkt", stats.get_count(Protocol::HTTP)))
                    .style(Style::default().fg(Color::Blue)),
                ListItem::new(format!("HTTPS: {} pkt", stats.get_count(Protocol::HTTPS)))
                    .style(Style::default().fg(Color::Cyan)),
                ListItem::new(format!("DNS:   {} pkt", stats.get_count(Protocol::DNS)))
                    .style(Style::default().fg(Color::Yellow)),
                ListItem::new(format!("SSH:   {} pkt", stats.get_count(Protocol::SSH)))
                    .style(Style::default().fg(Color::Magenta)),
                ListItem::new(format!("----------------"))
                    .style(Style::default().fg(Color::DarkGray)),
                ListItem::new(format!("TOT:   {} pkt", total_packets))
                    .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ];
            
            let protocols_list = List::new(protocol_items)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" PROTOCOLS ")
                    .title_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
            f.render_widget(protocols_list, right_chunks[1]);
            drop(stats);

            // Threat detection with animated warnings
            let detector = threat_detector.lock().unwrap();
            let threat_level = detector.get_threat_level();
            let threat_type = detector.get_threat_type();
            let is_ddos = detector.is_ddos_active();
            
            let threat_text = if threat_level == ThreatLevel::Low && !is_ddos {
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "[OK] System Secure",
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "No threats detected",
                        Style::default().fg(Color::Green),
                    )),
                ]
            } else {
                let threat_color = match threat_level {
                    ThreatLevel::Low => Color::Green,
                    ThreatLevel::Medium => Color::Yellow,
                    ThreatLevel::High => Color::Red,
                    ThreatLevel::Critical => Color::Red,
                };
                
                vec![
                    Line::from(Span::styled(
                        "⚠ THREAT DETECTED ⚠",
                        Style::default().fg(threat_color).add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("Type: {:?}", threat_type),
                        Style::default().fg(threat_color).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(Span::styled(
                        format!("Level: {:?}", threat_level),
                        Style::default().fg(threat_color),
                    )),
                    if is_ddos {
                        Line::from(Span::styled(
                            "⚡ DDoS ACTIVE! ⚡",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
                        ))
                    } else {
                        Line::from("")
                    },
                ]
            };
            
            let threat_block_style = if threat_level != ThreatLevel::Low || is_ddos {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };
            
            let threats_widget = Paragraph::new(threat_text)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(threat_block_style)
                    .title(" THREATS ")
                    .title_style(threat_block_style.add_modifier(Modifier::BOLD)));
            f.render_widget(threats_widget, right_chunks[2]);


            // Raw packet dump in right panel
            let mut packet_dump_text = vec![
                Line::from(Span::styled("RAW PACKET DATA:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
                Line::from(""),
            ];
            
            // Get the actual raw packet data
            let raw = raw_packets.lock().unwrap();
            let log = packet_log.lock().unwrap();
            
            if !raw.is_empty() && !log.is_empty() {
                // Show hex dump of recent packet
                packet_dump_text.push(Line::from(Span::styled("Latest Packet:", Style::default().fg(Color::Green))));
                packet_dump_text.push(Line::from(Span::styled(log[0].clone(), Style::default().fg(Color::Cyan))));
                packet_dump_text.push(Line::from(""));
                
                // Generate actual hex dump from packet data
                let packet_data = &raw[0];
                for (offset, chunk) in packet_data.chunks(16).enumerate() {
                    let mut hex_part = String::new();
                    let mut ascii_part = String::new();
                    
                    for (i, byte) in chunk.iter().enumerate() {
                        if i == 8 {
                            hex_part.push_str("  ");
                        }
                        hex_part.push_str(&format!("{:02x} ", byte));
                        
                        if byte.is_ascii_graphic() || *byte == b' ' {
                            ascii_part.push(*byte as char);
                        } else {
                            ascii_part.push('.');
                        }
                    }
                    
                    // Pad hex part if needed
                    let padding = 50 - hex_part.len();
                    hex_part.push_str(&" ".repeat(padding));
                    
                    let line = format!("{:08x}  {}  {}", offset * 16, hex_part, ascii_part);
                    packet_dump_text.push(Line::from(Span::styled(line, Style::default().fg(Color::DarkGray))));
                }
            } else {
                packet_dump_text.push(Line::from(Span::styled("Waiting for packets...", Style::default().fg(Color::DarkGray))));
            }
            drop(raw);
            drop(log);
            
            let packet_dump = Paragraph::new(packet_dump_text)
                .wrap(Wrap { trim: false })
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" [ PACKET DUMP ] ")
                    .title_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
            f.render_widget(packet_dump, right_chunks[3]);
            
            // Help text at bottom
            let help_text = Paragraph::new("Q: Quit | D: Demo Mode")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(help_text, right_chunks[4]);
        })?;
        
        // Record frame time for performance monitoring
        let frame_duration = frame_start.elapsed();
        perf_monitor.record_frame(frame_duration);
        _last_frame_time = frame_start;
        
        // Update memory usage periodically
        if frame_start.duration_since(last_traffic_update) >= Duration::from_secs(5) {
            perf_monitor.update_memory_usage();
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}