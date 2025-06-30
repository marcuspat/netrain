use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netrain::{
    matrix_rain::MatrixRain,
    packet::{parse_packet, classify_protocol},
    optimized::{parse_packet_optimized, classify_protocol_optimized},
    threat_detection::ThreatDetector,
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

    // Show ASCII logo on startup
    terminal.draw(|f| {
        let area = f.size();
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
                Constraint::Percentage(30),
                Constraint::Min(10),
                Constraint::Percentage(30),
            ])
            .split(area);
            
        f.render_widget(logo_paragraph, vertical_center[1]);
    })?;

    // Wait for 2 seconds to show the logo
    thread::sleep(Duration::from_secs(2));

    // Initialize components
    let terminal_size = terminal.size()?;
    let matrix_rain = Arc::new(Mutex::new(MatrixRain::new(
        terminal_size.width as usize * 70 / 100,
        terminal_size.height as usize,
    )));
    
    // Enable demo mode if requested
    if demo_mode {
        matrix_rain.lock().unwrap().enable_demo_mode();
    }
    
    let threat_detector = Arc::new(Mutex::new(ThreatDetector::new()));
    let protocol_stats = Arc::new(Mutex::new(ProtocolStats::new()));
    let packet_log = Arc::new(Mutex::new(VecDeque::new()));
    let traffic_counter = Arc::new(Mutex::new(0u64));
    let perf_monitor = Arc::new(PerformanceMonitor::new());

    // Start packet capture in background thread (unless in demo mode)
    if !demo_mode {
        let matrix_rain_clone = Arc::clone(&matrix_rain);
        let threat_detector_clone = Arc::clone(&threat_detector);
        let protocol_stats_clone = Arc::clone(&protocol_stats);
        let packet_log_clone = Arc::clone(&packet_log);
        let traffic_counter_clone = Arc::clone(&traffic_counter);
        let perf_monitor_clone = Arc::clone(&perf_monitor);

        thread::spawn(move || {
            // First, try to find and list available devices
            match Device::list() {
                Ok(devices) => {
                    eprintln!("🔍 Available network devices:");
                    for device in &devices {
                        eprintln!("  - {} ({})", 
                            device.name, 
                            device.desc.as_ref().unwrap_or(&"No description".to_string())
                        );
                    }
                    
                    // Try to find en0 (active WiFi interface) first
                    let target_device = devices.iter()
                        .find(|d| d.name == "en0")
                        .or_else(|| devices.iter().find(|d| d.name.starts_with("en")))
                        .or_else(|| devices.first());
                    
                    if let Some(device) = target_device {
                        eprintln!("🎯 Using device: {} ({})", 
                            device.name, 
                            device.desc.as_ref().unwrap_or(&"No description".to_string())
                        );
                        
                        match Capture::from_device(device.clone()) {
                            Ok(cap_builder) => {
                                match cap_builder
                                    .promisc(true)
                                    .snaplen(5000)
                                    .timeout(1000) // Add timeout
                                    .open() {
                                    Ok(mut cap) => {
                                        eprintln!("✅ Successfully opened packet capture on {}", device.name);
                                        
                                        // Set a filter to capture common traffic
                                        if let Err(e) = cap.filter("ip", true) {
                                            eprintln!("⚠️  Warning: Could not set filter: {}", e);
                                        }
                                        
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
                                                        
                                                        // Check for threats
                                                        threat_detector_clone.lock().unwrap().analyze_packet(&parsed);
                                                        
                                                        // Update matrix rain with traffic
                                                        let mut rain = matrix_rain_clone.lock().unwrap();
                                                        let x = rand::random::<usize>() % rain.width;
                                                        rain.add_column(x);
                                                        
                                                        // Log packet with more details
                                                        let mut log = packet_log_clone.lock().unwrap();
                                                        let timestamp = chrono::Local::now().format("%H:%M:%S");
                                                        log.push_front(format!(
                                                            "[{}] {:?} {} → {} ({} bytes)",
                                                            timestamp,
                                                            protocol,
                                                            parsed.src_ip,
                                                            parsed.dst_ip,
                                                            parsed.length
                                                        ));
                                                        if log.len() > 20 {
                                                            log.pop_back();
                                                        }
                                                    }
                                                }
                                                Err(pcap::Error::TimeoutExpired) => {
                                                    // Timeout is normal, continue
                                                    continue;
                                                }
                                                Err(e) => {
                                                    eprintln!("❌ Error reading packet: {}", e);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("❌ Failed to open capture on {}: {}", device.name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to create capture from device {}: {}", device.name, e);
                            }
                        }
                    } else {
                        eprintln!("❌ No suitable network device found");
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to list network devices: {}", e);
                }
            }
            eprintln!("🔄 Packet capture thread exiting");
        });
    }

    // Main render loop
    let mut last_update = Instant::now();
    let mut last_traffic_update = Instant::now();
    let mut last_frame_time = Instant::now();
    let _frame_time = Duration::from_millis(16); // Target 60 FPS
    
    loop {
        let frame_start = Instant::now();
        // Handle input
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        // Toggle demo mode
                        let mut rain = matrix_rain.lock().unwrap();
                        rain.enable_demo_mode();
                    }
                    _ => {}
                }
            }
        }

        // Calculate smooth frame timing
        let now = Instant::now();
        let delta_time = now.duration_since(last_update).as_secs_f32();
        
        // Update matrix rain animation with interpolated timing
        if delta_time >= 0.016 { // Cap at ~60 FPS
            matrix_rain.lock().unwrap().update(delta_time);
            last_update = now;
        }

        // Update traffic rate every second
        if now.duration_since(last_traffic_update) >= Duration::from_secs(1) {
            let count = *traffic_counter.lock().unwrap();
            let mut rain = matrix_rain.lock().unwrap();
            rain.set_traffic_rate(count as f32);
            *traffic_counter.lock().unwrap() = 0; // Reset counter
            last_traffic_update = now;
        }

        // Check threat status and update visual mode
        {
            let detector = threat_detector.lock().unwrap();
            let threat_level = detector.get_threat_level();
            let is_ddos = detector.is_ddos_active();
            
            let mut rain = matrix_rain.lock().unwrap();
            rain.set_threat_active(threat_level != ThreatLevel::Low || is_ddos);
        }

        // Render
        terminal.draw(|f| {
            // Create layout with better proportions
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
                .split(f.size());

            // Matrix rain visualization with styled border
            let mut rain = matrix_rain.lock().unwrap();
            let matrix_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" ⟨ MATRIX RAIN ⟩ ")
                .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
            
            let matrix_area = matrix_block.inner(chunks[0]);
            f.render_widget(matrix_block, chunks[0]);
            f.render_widget(&mut *rain, matrix_area);

            // Stats panel with multiple sections
            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6),   // Performance stats
                    Constraint::Length(10),  // Protocol stats
                    Constraint::Length(10),  // Threat detection
                    Constraint::Length(4),   // Controls
                    Constraint::Min(0),      // Packet log
                ])
                .split(chunks[1]);

            // Performance stats
            let fps = perf_monitor.get_fps();
            let packet_rate = perf_monitor.get_packet_rate();
            let memory_mb = perf_monitor.get_memory_mb();
            
            let perf_items = vec![
                ListItem::new(format!("⚡ FPS: {} (Target: 60)", fps))
                    .style(if fps >= 55 { 
                        Style::default().fg(Color::Green) 
                    } else if fps >= 30 { 
                        Style::default().fg(Color::Yellow) 
                    } else { 
                        Style::default().fg(Color::Red) 
                    }),
                ListItem::new(format!("📦 Packets/s: {}", packet_rate))
                    .style(Style::default().fg(Color::Cyan)),
                ListItem::new(format!("💾 Memory: {:.1} MB", memory_mb))
                    .style(Style::default().fg(Color::Blue)),
                ListItem::new(format!("🚀 Render: {:.1} ms", last_frame_time.elapsed().as_secs_f32() * 1000.0))
                    .style(Style::default().fg(Color::Magenta)),
            ];
            
            let perf_list = List::new(perf_items)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" ⟨ PERFORMANCE ⟩ ")
                    .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            f.render_widget(perf_list, right_chunks[0]);

            // Protocol stats with traffic graph
            let stats = protocol_stats.lock().unwrap();
            let total_packets = stats.get_count(Protocol::TCP) + 
                                    stats.get_count(Protocol::UDP) + 
                                    stats.get_count(Protocol::HTTP) + 
                                    stats.get_count(Protocol::DNS) + 
                                    stats.get_count(Protocol::SSH);
            
            let protocol_items: Vec<ListItem> = vec![
                ListItem::new(format!("⬤ TCP:   {} packets", stats.get_count(Protocol::TCP)))
                    .style(Style::default().fg(Color::Yellow)),
                ListItem::new(format!("⬤ UDP:   {} packets", stats.get_count(Protocol::UDP)))
                    .style(Style::default().fg(Color::Blue)),
                ListItem::new(format!("⬤ HTTP:  {} packets", stats.get_count(Protocol::HTTP)))
                    .style(Style::default().fg(Color::Green)),
                ListItem::new(format!("⬤ DNS:   {} packets", stats.get_count(Protocol::DNS)))
                    .style(Style::default().fg(Color::Magenta)),
                ListItem::new(format!("⬤ SSH:   {} packets", stats.get_count(Protocol::SSH)))
                    .style(Style::default().fg(Color::Cyan)),
                ListItem::new("".to_string()),
                ListItem::new(format!("━━━━━━━━━━━━━━━━━━━"))
                    .style(Style::default().fg(Color::DarkGray)),
                ListItem::new(format!("⬤ TOTAL: {} packets", total_packets))
                    .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ];
            
            let protocols_list = List::new(protocol_items)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" ⟨ PROTOCOL STATS ⟩ ")
                    .title_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
            f.render_widget(protocols_list, right_chunks[1]);

            // Threat detection with animated warnings
            let detector = threat_detector.lock().unwrap();
            let threat_level = detector.get_threat_level();
            let threat_type = detector.get_threat_type();
            let is_ddos = detector.is_ddos_active();
            
            let threat_text = if threat_level == ThreatLevel::Low && !is_ddos {
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "✓ System Secure",
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
                    .title(" ⟨ THREAT MONITOR ⟩ ")
                    .title_style(threat_block_style.add_modifier(Modifier::BOLD)));
            f.render_widget(threats_widget, right_chunks[2]);

            // Controls
            let controls = vec![
                Line::from(vec![
                    Span::raw("Press "),
                    Span::styled("Q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(" to quit | "),
                    Span::styled("D", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(" for demo"),
                ]),
            ];
            
            let controls_widget = Paragraph::new(controls)
                .alignment(Alignment::Center)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" ⟨ CONTROLS ⟩ "));
            f.render_widget(controls_widget, right_chunks[3]);

            // Packet log with styled entries
            let log = packet_log.lock().unwrap();
            let log_items: Vec<ListItem> = log.iter()
                .enumerate()
                .map(|(i, entry)| {
                    let style = if i == 0 {
                        Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    ListItem::new(entry.as_str()).style(style)
                })
                .collect();
            
            let log_list = List::new(log_items)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" ⟨ PACKET LOG ⟩ ")
                    .title_style(Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)));
            f.render_widget(log_list, right_chunks[4]);
        })?;
        
        // Record frame time for performance monitoring
        let frame_duration = frame_start.elapsed();
        perf_monitor.record_frame(frame_duration);
        last_frame_time = frame_start;
        
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