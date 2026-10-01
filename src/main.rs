use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netrain::{
    capture::{self, CaptureSink, DeviceInfo},
    decode::{LinkType, Transport},
    pipeline::PacketEvent,
    simple_matrix::SimpleMatrixRain,
    state::AppState,
    Protocol, ThreatLevel,
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
    sync::{Mutex, atomic::{AtomicUsize, Ordering}},
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
    memory_usage: AtomicUsize,
}

impl PerformanceMonitor {
    fn new() -> Self {
        Self {
            fps_counter: AtomicUsize::new(0),
            frame_times: Mutex::new(VecDeque::with_capacity(60)),
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
    
    fn update_memory_usage(&self) {
        // Simple memory estimation based on active data structures
        // In production, you'd use system memory APIs
        let estimated_kb = 1024; // Placeholder
        self.memory_usage.store(estimated_kb, Ordering::Relaxed);
    }
    
    fn get_fps(&self) -> usize {
        self.fps_counter.load(Ordering::Relaxed)
    }
    
    fn get_memory_mb(&self) -> f32 {
        self.memory_usage.load(Ordering::Relaxed) as f32 / 1024.0
    }
}

/// Most records applied per frame; the rest wait for the next one so a
/// flood cannot freeze rendering.
const DRAIN_BUDGET: usize = 4096;

/// Demo mode: synthesise plausible traffic without touching the network.
fn run_demo(sink: CaptureSink) {
    let demo_ips: [([u8; 4], [u8; 4]); 5] = [
        ([192, 168, 1, 105], [142, 250, 185, 78]),
        ([192, 168, 1, 105], [172, 217, 14, 93]),
        ([192, 168, 1, 105], [8, 8, 8, 8]),
        ([10, 0, 0, 42], [52, 97, 188, 126]),
        ([172, 16, 0, 100], [239, 255, 255, 250]),
    ];
    let protocols =
        [Protocol::TCP, Protocol::UDP, Protocol::HTTP, Protocol::HTTPS, Protocol::DNS, Protocol::SSH];

    loop {
        // Vary the pacing for more realistic traffic patterns.
        thread::sleep(Duration::from_millis(200 + rand::random::<u64>() % 100));
        for _ in 0..rand::random::<usize>() % 3 {
            let (src, dst) = demo_ips[rand::random::<usize>() % demo_ips.len()];
            let size = 60 + rand::random::<usize>() % 1400;
            let event = PacketEvent {
                src: src.into(),
                dst: dst.into(),
                src_port: None,
                dst_port: None,
                protocol: protocols[rand::random::<usize>() % protocols.len()],
                transport: Transport::Other,
                wire_len: size,
            };
            let mut fake_packet = vec![0x45, 0x00];
            fake_packet.extend_from_slice(&(size as u16).to_be_bytes());
            fake_packet.extend((0..60).map(|_| rand::random::<u8>()));
            if !sink.submit_event(event, &fake_packet) {
                return; // UI has exited
            }
        }
    }
}

/// Live capture: open the best interface and feed the sink until the UI exits.
fn run_capture(sink: CaptureSink) {
    let devices = match Device::list() {
        Ok(devices) => devices,
        Err(e) => {
            sink.error(format!("Failed to list network devices: {}\nTry running with 'sudo netrain'", e));
            return;
        }
    };
    let infos: Vec<DeviceInfo> = devices
        .iter()
        .map(|d| DeviceInfo {
            name: d.name.clone(),
            up: d.flags.is_up(),
            running: d.flags.is_running(),
            loopback: d.flags.is_loopback(),
            has_address: !d.addresses.is_empty(),
        })
        .collect();
    let device = match capture::choose_device(&infos, None) {
        Ok(index) => devices[index].clone(),
        Err(message) => {
            sink.error(message);
            return;
        }
    };
    let name = device.name.clone();

    let opened = Capture::from_device(device)
        .and_then(|builder| builder.promisc(true).snaplen(5000).timeout(1000).open());
    let mut cap = match opened {
        Ok(cap) => cap,
        Err(e) => {
            sink.error(format!(
                "Cannot capture on {}: run with 'sudo netrain' or use '--demo' mode\nError: {}",
                name, e
            ));
            return;
        }
    };

    // Decode with the capture's real framing instead of guessing.
    let datalink = cap.get_datalink();
    let Some(link) = LinkType::from_dlt(datalink.0) else {
        sink.error(format!("Unsupported link type {} on {}", datalink.0, name));
        return;
    };

    // IPv4 and IPv6; everything else is dropped in the kernel.
    let _ = cap.filter("ip or ip6", true);

    let mut last_stats = Instant::now();
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if !sink.submit(link, packet.data, packet.header.len as usize) {
                    return; // UI has exited
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                sink.error(format!("Capture on {} stopped: {}", name, e));
                return;
            }
        }
        if last_stats.elapsed() >= Duration::from_secs(1) {
            if let Ok(stats) = cap.stats() {
                sink.set_kernel_stats(u64::from(stats.dropped), u64::from(stats.if_dropped));
            }
            last_stats = Instant::now();
        }
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check for version flag
    if args.contains(&"--version".to_string()) || args.contains(&"-V".to_string()) {
        println!("NetRain v{}", VERSION);
        return Ok(());
    }
    
    // Check for help flag
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        println!("NetRain v{} - Matrix-style network packet monitor", VERSION);
        println!("\nUsage: netrain [OPTIONS]");
        println!("\nOptions:");
        println!("  --demo       Run in demo mode (no root required)");
        println!("  --version    Show version information");
        println!("  --help       Show this help message");
        println!("\nControls:");
        println!("  Q            Quit the application");
        return Ok(());
    }
    
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
    let mut matrix_rain = SimpleMatrixRain::new(matrix_width, matrix_height);

    // Enable demo mode if requested
    if demo_mode {
        // Add initial columns for immediate visual effect
        for i in 0..20 {
            matrix_rain.add_column((i * 4) % matrix_width);
        }
    }

    // All display state lives on this thread. The capture thread only sends
    // packet records through a bounded channel, so it never takes a lock and
    // never stalls behind rendering.
    let mut app = AppState::new();
    let (sink, capture_rx, capture_counters) = capture::channel(capture::DEFAULT_QUEUE);
    let perf_monitor = PerformanceMonitor::new();

    if demo_mode {
        thread::spawn(move || run_demo(sink));
    } else {
        thread::spawn(move || run_capture(sink));
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
            // Read exactly once per poll: a second read here used to block
            // on (and swallow) the next event.
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q')) {
                    break;
                }
            }
        }

        // Fold everything the capture thread queued since the last frame.
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        app.drain(&capture_rx, DRAIN_BUDGET, &timestamp, Instant::now(), |event| {
            matrix_rain.track_ip_packet(&event.src.to_string(), &event.dst.to_string(), event.protocol.label());
            let x = rand::random::<u16>() % matrix_width.max(1);
            matrix_rain.add_column(x);
        });
        let drops = capture_counters.snapshot();

        // Calculate smooth frame timing
        let now = Instant::now();
        let delta_time = now.duration_since(last_update).as_secs_f32();
        
        // Update matrix rain animation with interpolated timing
        if delta_time >= 0.016 { // Cap at ~60 FPS
            matrix_rain.update();
            last_update = now;
        }

        // Update traffic rate every second
        if now.duration_since(last_traffic_update) >= Duration::from_secs(1) {
            app.tick_second();
            last_traffic_update = now;
        }
        
        // Update protocol activity tracker every 150ms for smoother display
        if now.duration_since(last_activity_tick) >= Duration::from_millis(150) {
            app.activity.tick();
            last_activity_tick = now;
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
                    Constraint::Percentage(17), // Matrix rain area
                    Constraint::Percentage(70), // Packet log - much longer now
                    Constraint::Min(6),    // Network activity graph - much shorter
                ])
                .split(main_chunks[0]);
            
            // Top stats bar with real-time data
            let traffic_rate = app.packet_rate;
            let fps = perf_monitor.get_fps();
            let detector = &app.detector;
            let threat_level = detector.get_threat_level();
            
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
                Span::raw(" | "),
                Span::styled("Q:Quit", Style::default().fg(Color::DarkGray)),
            ];
            
            let stats_bar = Paragraph::new(Line::from(stats_text))
                .style(Style::default().bg(Color::Black))
                .alignment(Alignment::Center)
                .block(Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(stats_bar, matrix_chunks[0]);
            
            // Matrix rain in the middle
            let rain = &matrix_rain;
            let matrix_block = Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(if threat_level != ThreatLevel::Low { Color::Red } else { Color::Green }));
            
            let matrix_area = matrix_block.inner(matrix_chunks[1]);
            f.render_widget(matrix_block, matrix_chunks[1]);
            f.render_widget(rain, matrix_area);
            
            // Packet log in matrix panel
            let capture_err = &app.capture_error;
            let log = &app.packet_log;
            
            // Check if there's a capture error to display
            let log_items: Vec<ListItem> = if let Some(error_msg) = capture_err.as_ref() {
                // Display error message
                error_msg.lines()
                    .map(|line| ListItem::new(line).style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)))
                    .collect()
            } else if log.is_empty() && !demo_mode {
                // No packets and no error - show waiting message
                vec![ListItem::new("Waiting for packets...").style(Style::default().fg(Color::DarkGray))]
            } else {
                // Get active IPs and add them at the top
                let active_ips = rain.get_active_ips();
                let mut items = Vec::new();
                
                // Add top 3 most active IPs if any exist
                if !active_ips.is_empty() {
                    items.push(ListItem::new("--- TOP ACTIVE IPs ---").style(
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    ));
                    
                    for (i, (ip, count)) in active_ips.iter().enumerate().take(3) {
                        let ip_entry = format!("#{} {} ({} pkts)", i + 1, ip, count);
                        items.push(ListItem::new(ip_entry).style(
                            Style::default().fg(Color::Cyan)
                        ));
                    }
                    
                    items.push(ListItem::new("--- PACKETS ---").style(
                        Style::default().fg(Color::DarkGray)
                    ));
                }
                
                // Add packet log entries - fill the expanded space
                let packet_entries: Vec<ListItem> = log.iter()
                    .take(if !active_ips.is_empty() { 35 } else { 40 })
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
                
                items.extend(packet_entries);
                items
            };
            
            let log_list = List::new(log_items)
                .block(Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" [ PACKET LOG ] ")
                    .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            f.render_widget(log_list, matrix_chunks[2]);
            
            // Network activity graph at bottom - color-coded by protocol
            use ratatui::widgets::Sparkline;
            
            // Get protocol activity data
            let activity = &app.activity;
            
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

            // Right panel - properly organized layout
            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(6),   // Performance stats
                    Constraint::Length(10),  // Protocol stats  
                    Constraint::Length(11),  // Threat monitor: status + up to 3 alert lines
                    Constraint::Min(20),     // Packet dump
                ])
                .split(main_chunks[1]);

            // Performance stats
            let fps = perf_monitor.get_fps();
            let packet_rate = app.packet_rate;
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
                // Packets that were on the wire but never displayed: kernel
                // buffer overruns, interface drops, and our own full queue.
                ListItem::new(format!("DROP: {}", drops.total_dropped()))
                    .style(if drops.total_dropped() == 0 {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    }),
            ];
            
            let perf_list = List::new(perf_items)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" PERF ")
                    .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            f.render_widget(perf_list, right_chunks[0]);

            // Protocol stats
            let stats = &app.stats;
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

            // Threat detection with animated warnings
            let detector = &app.detector;
            let threat_level = detector.get_threat_level();
            let threat_type = detector.get_threat_type();
            let is_ddos = detector.is_ddos_active();
            let alerts = detector.active_alerts();
            
            let mut threat_text = if threat_level == ThreatLevel::Low && !is_ddos {
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
            
            // Who is doing what: the evidence behind the level above.
            for alert in alerts.iter().take(3) {
                threat_text.push(Line::from(Span::styled(
                    alert.summary(),
                    Style::default().fg(Color::Yellow),
                )));
            }

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
            let mut packet_dump_text = vec![];
            
            // Get the actual raw packet data
            let raw = &app.raw_packets;
            let log = &app.packet_log;
            
            if !raw.is_empty() && !log.is_empty() {
                // Show hex dump of latest packet
                packet_dump_text.push(Line::from(Span::styled("Latest Packet:", Style::default().fg(Color::Green))));
                packet_dump_text.push(Line::from(Span::styled(log[0].clone(), Style::default().fg(Color::Cyan))));
                packet_dump_text.push(Line::from("".to_string())); // One empty line
                
                // Generate hex dump from packet data
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
            
            let packet_dump = Paragraph::new(packet_dump_text)
                .wrap(Wrap { trim: false })
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" [ PACKET DUMP ] ")
                    .title_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
            f.render_widget(packet_dump, right_chunks[3]);
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