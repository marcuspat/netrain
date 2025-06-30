use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use netrain::{
    matrix_rain::MatrixRain,
    packet::{parse_packet, classify_protocol},
    threat_detection::ThreatDetector,
    Protocol, ProtocolStats, ThreatLevel, ThreatType,
};
use pcap::{Capture, Device};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Initialize components
    let terminal_size = terminal.size()?;
    let matrix_rain = Arc::new(Mutex::new(MatrixRain::new(
        terminal_size.width as usize * 70 / 100,
        terminal_size.height as usize,
    )));
    let threat_detector = Arc::new(Mutex::new(ThreatDetector::new()));
    let protocol_stats = Arc::new(Mutex::new(ProtocolStats::new()));
    let packet_log = Arc::new(Mutex::new(VecDeque::new()));

    // Start packet capture in background thread
    let matrix_rain_clone = Arc::clone(&matrix_rain);
    let threat_detector_clone = Arc::clone(&threat_detector);
    let protocol_stats_clone = Arc::clone(&protocol_stats);
    let packet_log_clone = Arc::clone(&packet_log);

    thread::spawn(move || {
        if let Ok(device) = Device::lookup() {
            if let Some(device) = device {
                if let Ok(mut cap) = Capture::from_device(device).unwrap()
                    .promisc(true)
                    .snaplen(5000)
                    .open()
                {
                    while let Ok(packet) = cap.next_packet() {
                        let data = packet.data.to_vec();
                        
                        // Parse packet
                        if let Ok(parsed) = parse_packet(&data) {
                            // Update protocol stats
                            let protocol = classify_protocol(&parsed);
                            protocol_stats_clone.lock().unwrap().add_packet(protocol, parsed.length);
                            
                            // Check for threats
                            threat_detector_clone.lock().unwrap().analyze_packet(&parsed);
                            
                            // Update matrix rain with traffic
                            let mut rain = matrix_rain_clone.lock().unwrap();
                            let x = rand::random::<usize>() % rain.width;
                            rain.add_column(x);
                            
                            // Log packet
                            let mut log = packet_log_clone.lock().unwrap();
                            log.push_front(format!("{:?} - {} bytes", protocol, parsed.length));
                            if log.len() > 20 {
                                log.pop_back();
                            }
                        }
                    }
                }
            }
        }
    });

    // Main render loop
    let mut last_update = Instant::now();
    
    loop {
        // Handle input
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Update matrix rain animation
        if last_update.elapsed() >= Duration::from_millis(100) {
            matrix_rain.lock().unwrap().update(0.1); // 100ms = 0.1s
            last_update = Instant::now();
        }

        // Render
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
                .split(f.size());

            // Matrix rain visualization
            let mut rain = matrix_rain.lock().unwrap();
            f.render_widget(&mut *rain, chunks[0]);

            // Stats panel
            let right_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Min(0),
                ])
                .split(chunks[1]);

            // Protocol stats
            let stats = protocol_stats.lock().unwrap();
            let protocol_items: Vec<ListItem> = vec![
                ListItem::new(format!("TCP: {}", stats.get_count(Protocol::TCP))),
                ListItem::new(format!("UDP: {}", stats.get_count(Protocol::UDP))),
                ListItem::new(format!("HTTP: {}", stats.get_count(Protocol::HTTP))),
                ListItem::new(format!("DNS: {}", stats.get_count(Protocol::DNS))),
                ListItem::new(format!("SSH: {}", stats.get_count(Protocol::SSH))),
            ];
            let protocols_list = List::new(protocol_items)
                .block(Block::default().borders(Borders::ALL).title("Protocols"));
            f.render_widget(protocols_list, right_chunks[0]);

            // Threat detection
            let detector = threat_detector.lock().unwrap();
            let threat_level = detector.get_threat_level();
            let threat_type = detector.get_threat_type();
            let is_ddos = detector.is_ddos_active();
            
            let threat_text = if threat_level == ThreatLevel::Low && !is_ddos {
                vec![Line::from(Span::styled(
                    "No threats detected",
                    Style::default().fg(Color::Green),
                ))]
            } else {
                vec![
                    Line::from(Span::styled(
                        format!("Type: {:?}", threat_type),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(Span::styled(
                        format!("Level: {:?}", threat_level),
                        Style::default().fg(Color::Red),
                    )),
                    if is_ddos {
                        Line::from(Span::styled(
                            "DDoS ACTIVE!",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
                        ))
                    } else {
                        Line::from("")
                    },
                ]
            };
            let threats_widget = Paragraph::new(threat_text)
                .block(Block::default().borders(Borders::ALL).title("Threats"));
            f.render_widget(threats_widget, right_chunks[1]);

            // Packet log
            let log = packet_log.lock().unwrap();
            let log_items: Vec<ListItem> = log.iter()
                .map(|entry| ListItem::new(entry.as_str()))
                .collect();
            let log_list = List::new(log_items)
                .block(Block::default().borders(Borders::ALL).title("Recent Packets"));
            f.render_widget(log_list, right_chunks[2]);
        })?;
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