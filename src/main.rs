use anyhow::{anyhow, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
};
use netrain::{
    capture::{self, CaptureSink, DeviceInfo, ReplayPacer},
    decode::{LinkType, Transport},
    flows::human_bytes,
    export::{self, Exporter, Format},
    pipeline::PacketEvent,
    replay::ReplayAnalyzer,
    simple_matrix::SimpleMatrixRain,
    state::{AppState, Command},
    Protocol, ThreatLevel,
};
use pcap::{Activated, Active, Capture, Device, Offline};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use std::{
    collections::VecDeque,
    process::ExitCode,
    io,
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}},
    thread,
    time::{Duration, Instant},
};

mod cli;
mod privs;
mod term;

use cli::{Cli, Mode};
use term::TerminalGuard;

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
        // Real resident set size; 0 means the platform does not expose it.
        let kb = netrain::sysinfo::rss_bytes().map_or(0, |bytes| (bytes / 1024) as usize);
        self.memory_usage.store(kb, Ordering::Relaxed);
    }
    
    fn get_fps(&self) -> usize {
        self.fps_counter.load(Ordering::Relaxed)
    }
    
    /// Resident memory in MB, or `None` where it cannot be measured.
    fn get_memory_mb(&self) -> Option<f32> {
        match self.memory_usage.load(Ordering::Relaxed) {
            0 => None,
            kb => Some(kb as f32 / 1024.0),
        }
    }
}

/// Smallest terminal the layout is designed for.
const MIN_COLS: u16 = 80;
const MIN_ROWS: u16 = 24;

/// Target time per frame (~60 FPS). Waiting for input for this long is what
/// paces the loop; without it the UI spun as fast as it could redraw.
const FRAME: Duration = Duration::from_millis(16);

/// Map a key press to what the user wants.
fn command_for(key: KeyCode) -> Option<Command> {
    match key {
        KeyCode::Char('q') | KeyCode::Char('Q') => Some(Command::Quit),
        KeyCode::Char(' ') | KeyCode::Char('p') | KeyCode::Char('P') => Some(Command::TogglePause),
        KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('H') | KeyCode::F(1) => Some(Command::ToggleHelp),
        KeyCode::Char('f') | KeyCode::Char('F') => Some(Command::CycleFilter),
        KeyCode::Char('a') | KeyCode::Char('A') => Some(Command::ClearFilter),
        KeyCode::Esc => Some(Command::Dismiss),
        _ => None,
    }
}

const HELP_TEXT: [(&str, &str); 6] = [
    ("q", "quit"),
    ("space / p", "pause the packet log and hex dump (analysis keeps running)"),
    ("f", "filter the log: cycle through the protocols seen"),
    ("a", "show all protocols again"),
    ("? / h", "show or hide this help"),
    ("esc", "close help, or clear the filter"),
];

/// A rectangle of at most `width` x `height`, centred in `area`.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

/// Size of the rain area for a terminal of the given size.
fn rain_size(cols: u16, rows: u16) -> (u16, u16) {
    (cols * 70 / 100, rows * 40 / 100)
}

/// Most records applied per frame; the rest wait for the next one so a
/// flood cannot freeze rendering.
const DRAIN_BUDGET: usize = 4096;

/// Display colour for a protocol, shared by every panel.
fn protocol_color(protocol: Protocol) -> Color {
    match protocol {
        Protocol::TCP => Color::Green,
        Protocol::UDP => Color::LightGreen,
        Protocol::HTTP => Color::Blue,
        Protocol::HTTPS => Color::Cyan,
        Protocol::DNS => Color::Yellow,
        Protocol::SSH => Color::Magenta,
        Protocol::ICMP => Color::LightRed,
        Protocol::QUIC => Color::LightCyan,
        Protocol::NTP => Color::LightBlue,
        Protocol::DHCP => Color::LightYellow,
        Protocol::MDNS => Color::LightMagenta,
        Protocol::SSDP => Color::Gray,
        _ => Color::DarkGray,
    }
}

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
                ip_proto: 0,
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

/// A packet source that has been opened and validated, ready to be read.
enum Source {
    Demo,
    Live { cap: Capture<Active>, link: LinkType, name: String },
    Replay { cap: Capture<Offline>, link: LinkType, name: String, speed: f64 },
}

fn device_infos(devices: &[Device]) -> Vec<DeviceInfo> {
    devices
        .iter()
        .map(|d| DeviceInfo {
            name: d.name.clone(),
            up: d.flags.is_up(),
            running: d.flags.is_running(),
            loopback: d.flags.is_loopback(),
            has_address: !d.addresses.is_empty(),
        })
        .collect()
}

fn list_devices() -> Result<Vec<Device>> {
    Device::list().map_err(|e| anyhow!("Failed to list network devices: {e}\nTry running with sudo."))
}

/// `--list-interfaces`: print what can be captured on and which one is the default.
fn print_interfaces() -> Result<()> {
    let devices = list_devices()?;
    let infos = device_infos(&devices);
    let default = capture::choose_device(&infos, None).ok();
    println!("{:<2}{:<18}{:<22}ADDRESSES", "", "INTERFACE", "STATE");
    for (i, (device, info)) in devices.iter().zip(&infos).enumerate() {
        let mut state = Vec::new();
        if info.up {
            state.push("up");
        }
        if info.running {
            state.push("running");
        }
        if info.loopback {
            state.push("loopback");
        }
        let addresses: Vec<String> = device.addresses.iter().map(|a| a.addr.to_string()).collect();
        println!(
            "{:<2}{:<18}{:<22}{}",
            if default == Some(i) { "*" } else { "" },
            device.name,
            if state.is_empty() { "down".to_string() } else { state.join(",") },
            addresses.join(" ")
        );
    }
    println!("\n* = used when --interface is not given");
    Ok(())
}

fn link_type<T: Activated + ?Sized>(cap: &Capture<T>, name: &str) -> Result<LinkType> {
    let datalink = cap.get_datalink();
    LinkType::from_dlt(datalink.0)
        .ok_or_else(|| anyhow!("Unsupported link type {} ({}) on {}", datalink.0, datalink.get_name().unwrap_or_default(), name))
}

/// Open and validate the packet source *before* the terminal is switched to
/// TUI mode, so that any problem is a plain error message and a non-zero
/// exit code rather than an empty screen.
fn open_source(cli: &Cli) -> Result<Source> {
    match cli.mode() {
        Mode::Demo => Ok(Source::Demo),
        Mode::Replay(path) => {
            let name = path.display().to_string();
            let mut cap = Capture::from_file(&path).map_err(|e| anyhow!("Cannot read {name}: {e}"))?;
            let link = link_type(&cap, &name)?;
            cap.filter(&cli.filter, true).map_err(|e| anyhow!("Invalid filter '{}': {e}", cli.filter))?;
            Ok(Source::Replay { cap, link, name, speed: cli.speed })
        }
        Mode::Live { interface } => {
            let devices = list_devices()?;
            let index = capture::choose_device(&device_infos(&devices), interface.as_deref())
                .map_err(|e| anyhow!(e))?;
            let device = devices[index].clone();
            let name = device.name.clone();
            let mut cap = Capture::from_device(device)
                // A short read timeout keeps the display and Ctrl-C responsive
                // without the CPU cost of immediate mode under load.
                .and_then(|builder| {
                    builder.promisc(cli.promiscuous).snaplen(cli.snaplen as i32).timeout(100).open()
                })
                .map_err(|e| {
                    anyhow!(
                        "Cannot capture on {name}: {e}\n\
                         Live capture needs privileges: run 'sudo netrain', or try 'netrain --demo'."
                    )
                })?;
            let link = link_type(&cap, &name)?;
            cap.filter(&cli.filter, true).map_err(|e| anyhow!("Invalid filter '{}': {e}", cli.filter))?;
            Ok(Source::Live { cap, link, name })
        }
    }
}

/// Live capture: feed the sink until the UI exits.
fn run_capture(mut cap: Capture<Active>, link: LinkType, name: String, sink: CaptureSink) {
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

/// Replay a pcap file through the same pipeline as live capture, paced by
/// the recorded timestamps so rates and alert windows behave as they did.
fn run_replay(mut cap: Capture<Offline>, link: LinkType, name: String, speed: f64, sink: CaptureSink) {
    let mut pacer = ReplayPacer::new(speed);
    let mut packets = 0u64;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let micros = header_micros(packet.header);
                let wait = pacer.delay_before(micros);
                if !wait.is_zero() {
                    thread::sleep(wait);
                }
                packets += 1;
                // Blocking: a replay must not lose packets to a full queue.
                if !sink.submit_blocking(link, packet.data, packet.header.len as usize) {
                    return;
                }
            }
            Err(pcap::Error::NoMorePackets) => {
                sink.finished(format!("Replay of {name} complete: {packets} packets"));
                return;
            }
            Err(e) => {
                sink.error(format!("Reading {name} failed after {packets} packets: {e}"));
                return;
            }
        }
    }
}

/// Microseconds since the epoch from a pcap packet header.
fn header_micros(header: &pcap::PacketHeader) -> i64 {
    // timeval field widths differ between platforms.
    #[allow(clippy::unnecessary_cast)]
    let (secs, micros) = (header.ts.tv_sec as i64, header.ts.tv_usec as i64);
    secs.saturating_mul(1_000_000).saturating_add(micros)
}

/// `--read FILE --summary`: analyse the capture on its own timestamps and
/// print the result. Deterministic; no terminal needed.
fn print_summary(mut cap: Capture<Offline>, link: LinkType, name: &str, json: bool) -> Result<()> {
    let mut analyzer = ReplayAnalyzer::default();
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                analyzer.feed(link, header_micros(packet.header), packet.data, packet.header.len as usize);
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(anyhow!("Reading {name} failed: {e}")),
        }
    }
    let summary = analyzer.finish();
    if json {
        println!("{}", export::summary_json(&summary, 0));
    } else {
        print!("{summary}");
    }
    Ok(())
}

/// A closed pipe downstream (`netrain --json | head`) is a normal way for a
/// stream to end, not an error.
fn ignore_broken_pipe(result: io::Result<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(e) => Err(anyhow!("writing output failed: {e}")),
    }
}

/// `--headless` / `--json`: stream one line per event to stdout until the
/// source ends, `--count` is reached, the reader goes away, or we are
/// interrupted - then print the summary.
fn run_headless<T: Activated + ?Sized>(
    cli: &Cli,
    mut cap: Capture<T>,
    link: LinkType,
    name: &str,
    live: bool,
) -> Result<()> {
    // Ctrl-C / SIGTERM end the run cleanly so the summary is still written.
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| anyhow!("cannot install signal handler: {e}"))?;
    }

    let format = if cli.json { Format::Json } else { Format::Text };
    let stdout = io::stdout();
    let mut exporter = Exporter::new(io::BufWriter::new(stdout.lock()), format, cli.alerts_only);
    let mut dropped = 0u64;
    let mut last_flush = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let fed = exporter.feed(link, header_micros(packet.header), packet.data, packet.header.len as usize);
                if !ignore_broken_pipe(fed)? {
                    return Ok(());
                }
                if cli.count.is_some_and(|limit| exporter.packets() >= limit) {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(anyhow!("Capture on {name} stopped: {e}")),
        }
        // Live output should appear promptly even when traffic is slow.
        if live && last_flush.elapsed() >= Duration::from_millis(200) {
            if !ignore_broken_pipe(exporter.flush())? {
                return Ok(());
            }
            last_flush = Instant::now();
        }
    }
    if live {
        if let Ok(stats) = cap.stats() {
            dropped = u64::from(stats.dropped) + u64::from(stats.if_dropped);
        }
    }
    ignore_broken_pipe(exporter.finish(dropped).map(|_| ()))?;
    Ok(())
}

fn main() -> ExitCode {
    // clap handles --help/--version and rejects unknown or conflicting flags.
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The terminal has been restored by now (TerminalGuard), so this
            // is readable.
            eprintln!("netrain: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    cli.validate().map_err(|e| anyhow!(e))?;
    if cli.list_interfaces {
        return print_interfaces();
    }
    let source = open_source(cli)?;
    // The capture (or file) is open: root is not needed from here on, and
    // everything below handles untrusted bytes.
    let privileges = privs::drop_privileges(cli.keep_privileges).map_err(|e| anyhow!(e))?;
    if cli.summary {
        let Source::Replay { cap, link, name, .. } = source else {
            unreachable!("clap requires --read with --summary");
        };
        return print_summary(cap, link, &name, cli.json);
    }
    if cli.is_headless() {
        if let Source::Live { name, .. } = &source {
            // stderr, so it never mixes into the data on stdout.
            eprintln!("netrain: capturing on {name}, {privileges}");
        }
        return match source {
            Source::Live { cap, link, name } => run_headless(cli, cap, link, &name, true),
            Source::Replay { cap, link, name, .. } => run_headless(cli, cap, link, &name, false),
            Source::Demo => unreachable!("clap rejects --demo with --headless/--json"),
        };
    }
    let demo_mode = matches!(source, Source::Demo);
    let source_label = match &source {
        Source::Demo => "demo".to_string(),
        Source::Live { name, .. } => match privileges {
            privs::Privileges::Kept => format!("{name} (root)"),
            _ => name.clone(),
        },
        Source::Replay { name, .. } => format!("replay {name}"),
    };

    // Setup terminal; restored on every exit path, including panics.
    let mut guard = TerminalGuard::enter()?;
    let terminal = &mut guard.terminal;

    if !cli.no_splash {
    // Show ASCII logo as splash screen
    terminal.draw(|f| {
        let area = f.area();
        
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
    }
    
    // IMPORTANT: Clear the terminal completely before starting main UI
    terminal.clear()?;

    // Initialize components
    let terminal_size = terminal.size()?;
    // Initialize simple matrix rain
    let (mut matrix_width, matrix_height) = rain_size(terminal_size.width, terminal_size.height);
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

    match source {
        Source::Demo => {
            thread::spawn(move || run_demo(sink));
        }
        Source::Live { cap, link, name } => {
            thread::spawn(move || run_capture(cap, link, name, sink));
        }
        Source::Replay { cap, link, name, speed } => {
            thread::spawn(move || run_replay(cap, link, name, speed, sink));
        }
    }

    // Main render loop
    let mut last_update = Instant::now();
    let mut last_traffic_update = Instant::now();
    let mut last_activity_tick = Instant::now();
    let mut last_frame_start = Instant::now();
    perf_monitor.update_memory_usage();
    
    loop {
        // Handle input. Waiting here for the rest of the frame budget is
        // what paces the loop.
        if event::poll(FRAME.saturating_sub(last_frame_start.elapsed()))? {
            // Read exactly once per poll: a second read here used to block
            // on (and swallow) the next event.
            match event::read()? {
                // Windows reports key releases too; act on presses only.
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if let Some(command) = command_for(key.code) {
                        if app.command(command) {
                            break;
                        }
                    }
                }
                Event::Resize(cols, rows) => {
                    let (w, h) = rain_size(cols, rows);
                    matrix_width = w;
                    matrix_rain.resize(w, h);
                }
                _ => {}
            }
        }

        let frame_start = Instant::now();

        // Fold everything the capture thread queued since the last frame.
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        app.drain(&capture_rx, DRAIN_BUDGET, &timestamp, Instant::now(), |event| {
            let _ = event;
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
            perf_monitor.update_memory_usage();
            last_traffic_update = now;
        }
        
        // Update protocol activity tracker every 150ms for smoother display
        if now.duration_since(last_activity_tick) >= Duration::from_millis(150) {
            app.activity.tick();
            last_activity_tick = now;
        }

        // Render with simplified layout
        terminal.draw(|f| {
            // Below the minimum size the panels would overlap into nonsense.
            let full = f.area();
            if full.width < MIN_COLS || full.height < MIN_ROWS {
                let message = format!(
                    "Terminal too small: {}x{}\nnetrain needs at least {}x{}\n(q to quit)",
                    full.width, full.height, MIN_COLS, MIN_ROWS
                );
                f.render_widget(
                    Paragraph::new(message).alignment(Alignment::Center).style(Style::default().fg(Color::Yellow)),
                    full,
                );
                return;
            }

            // Simple two-column layout without title bar
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .margin(0)
                .constraints([
                    Constraint::Percentage(70),
                    Constraint::Percentage(30),
                ])
                .split(f.area());

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
                Span::styled(format!(" {} ", source_label), Style::default().fg(Color::Cyan)),
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
                if app.paused {
                    Span::styled(
                        format!("PAUSED (+{}) ", app.skipped_while_paused),
                        Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::raw("")
                },
                Span::styled("?:Help Q:Quit", Style::default().fg(Color::DarkGray)),
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
                let waiting = app.finished.clone().unwrap_or_else(|| "Waiting for packets...".to_string());
                vec![ListItem::new(waiting).style(Style::default().fg(Color::DarkGray))]
            } else {
                // Get active IPs and add them at the top
                let mut items = Vec::new();
                if let Some(done) = &app.finished {
                    items.push(ListItem::new(done.clone()).style(
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                    ));
                }
                
                // Top talkers by bytes, then the heaviest flows.
                let talkers = app.flows.top_talkers(3);
                if !talkers.is_empty() {
                    items.push(ListItem::new("--- TOP TALKERS (bytes) ---").style(
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    ));
                    for (i, (ip, host)) in talkers.iter().enumerate() {
                        let entry = format!("#{} {} {} ({} pkts)", i + 1, app.names.display(ip), human_bytes(host.bytes), host.packets);
                        items.push(ListItem::new(entry).style(Style::default().fg(Color::Cyan)));
                    }
                    items.push(ListItem::new(format!("--- TOP FLOWS ({} active) ---", app.flows.len())).style(
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    ));
                    for flow in app.flows.top_flows(3) {
                        items.push(ListItem::new(flow.summary()).style(Style::default().fg(Color::Cyan)));
                    }
                    items.push(ListItem::new("--- PACKETS ---").style(
                        Style::default().fg(Color::DarkGray)
                    ));
                }
                
                // Add packet log entries - fill the expanded space
                let packet_entries: Vec<ListItem> = app
                    .visible_log()
                    .take(if !talkers.is_empty() { 31 } else { 40 })
                    .enumerate()
                    .map(|(i, entry)| {
                        let style = Style::default().fg(protocol_color(entry.protocol));
                        ListItem::new(entry.line.as_str())
                            .style(if i == 0 { style.add_modifier(Modifier::BOLD) } else { style })
                    })
                    .collect();
                
                items.extend(packet_entries);
                items
            };
            
            let log_list = List::new(log_items)
                .block(Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(match app.log_filter {
                        Some(p) => format!(" [ PACKET LOG: {} only - f next, a all ] ", p.label()),
                        None => " [ PACKET LOG ] ".to_string(),
                    })
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
            
            // One sparkline per slot, for the busiest protocols seen so far;
            // until there is traffic, the classic six.
            let mut shown: Vec<Protocol> = app.stats.ranked().into_iter().map(|(p, _)| p).take(6).collect();
            for p in [Protocol::TCP, Protocol::UDP, Protocol::HTTP, Protocol::HTTPS, Protocol::DNS, Protocol::SSH] {
                if shown.len() < 6 && !shown.contains(&p) {
                    shown.push(p);
                }
            }
            shown.sort();
            let protocols: Vec<(Protocol, Color, &str)> =
                shown.into_iter().map(|p| (p, protocol_color(p), p.label())).collect();
            
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
                ListItem::new(match memory_mb {
                    Some(mb) => format!("MEM: {:.1}MB", mb),
                    None => "MEM: n/a".to_string(),
                })
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
            // Every protocol actually seen, busiest first, as many as fit.
            let mut protocol_items: Vec<ListItem> = stats
                .ranked()
                .into_iter()
                .take(6) // the panel has room for six rows plus the total
                .map(|(p, count)| {
                    ListItem::new(format!("{:<7}{} pkt", format!("{}:", p.label()), count))
                        .style(Style::default().fg(protocol_color(p)))
                })
                .collect();
            protocol_items.push(ListItem::new("----------------").style(Style::default().fg(Color::DarkGray)));
            protocol_items.push(
                ListItem::new(format!("TOT:   {} pkt", stats.total_packets()))
                    .style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            );
            
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
                packet_dump_text.push(Line::from(Span::styled(log[0].line.clone(), Style::default().fg(Color::Cyan))));
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

            if app.show_help {
                let lines: Vec<Line> = HELP_TEXT
                    .iter()
                    .map(|(key, what)| {
                        Line::from(vec![
                            Span::styled(format!(" {:<10}", key), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            Span::raw(*what),
                        ])
                    })
                    .collect();
                let area = centered(full, 76, HELP_TEXT.len() as u16 + 2);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(lines).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_type(BorderType::Double)
                            .border_style(Style::default().fg(Color::Green))
                            .title(" KEYS "),
                    ),
                    area,
                );
            }
        })?;
        
        // FPS is measured between frame starts, i.e. what is actually drawn
        // per second, not how fast a single frame could be rendered.
        perf_monitor.record_frame(frame_start.duration_since(last_frame_start));
        last_frame_start = frame_start;
    }

    // The guard restores the terminal when it goes out of scope.
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod ui_tests {
    use super::*;

    #[test]
    fn keys_map_to_commands() {
        assert_eq!(command_for(KeyCode::Char('q')), Some(Command::Quit));
        assert_eq!(command_for(KeyCode::Char('Q')), Some(Command::Quit));
        assert_eq!(command_for(KeyCode::Char(' ')), Some(Command::TogglePause));
        assert_eq!(command_for(KeyCode::Char('p')), Some(Command::TogglePause));
        assert_eq!(command_for(KeyCode::Char('?')), Some(Command::ToggleHelp));
        assert_eq!(command_for(KeyCode::F(1)), Some(Command::ToggleHelp));
        assert_eq!(command_for(KeyCode::Char('f')), Some(Command::CycleFilter));
        assert_eq!(command_for(KeyCode::Char('a')), Some(Command::ClearFilter));
        assert_eq!(command_for(KeyCode::Esc), Some(Command::Dismiss));
        assert_eq!(command_for(KeyCode::Char('x')), None);
        assert_eq!(command_for(KeyCode::Enter), None);
    }

    #[test]
    fn every_documented_key_is_bound() {
        // The help overlay must not advertise a key that does nothing.
        for key in ['q', ' ', 'p', 'f', 'a', '?', 'h'] {
            assert!(command_for(KeyCode::Char(key)).is_some(), "{key:?}");
        }
        assert_eq!(HELP_TEXT.len(), 6);
    }

    #[test]
    fn centered_never_exceeds_its_area() {
        let area = Rect { x: 0, y: 0, width: 100, height: 40 };
        assert_eq!(centered(area, 76, 8), Rect { x: 12, y: 16, width: 76, height: 8 });
        // A popup larger than the screen is clamped, not overflowed.
        let tiny = Rect { x: 0, y: 0, width: 20, height: 4 };
        assert_eq!(centered(tiny, 76, 8), tiny);
        assert_eq!(centered(Rect::default(), 76, 8), Rect::default());
    }

    #[test]
    fn rain_area_scales_with_the_terminal() {
        assert_eq!(rain_size(200, 50), (140, 20));
        assert_eq!(rain_size(80, 24), (56, 9));
        assert_eq!(rain_size(0, 0), (0, 0));
    }
}
