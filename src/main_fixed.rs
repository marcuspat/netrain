// New simplified main render function
use ratatui::{
    layout::{Constraint, Direction, Layout, Alignment, Rect},
    style::{Color, Style, Modifier},
    widgets::{Block, Borders, BorderType, Paragraph, List, ListItem, Gauge, Sparkline},
    text::{Line, Span},
    Frame,
};

pub fn render_ui(f: &mut Frame) {
    // Simple two-column layout
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(0)
        .constraints([
            Constraint::Percentage(70),
            Constraint::Percentage(30),
        ])
        .split(f.size());

    // Left side - Matrix rain with cool overlays
    render_matrix_panel(f, main_chunks[0]);

    // Right side - Packet log and help
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),     // Packet log
            Constraint::Length(2),   // Help
        ])
        .split(main_chunks[1]);

    render_packet_log(f, right_chunks[0]);
    render_help(f, right_chunks[1]);
}

fn render_matrix_panel(f: &mut Frame, area: Rect) {
    // Split the matrix area into sections
    let matrix_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // Title/stats bar
            Constraint::Min(0),      // Matrix rain
            Constraint::Length(5),   // Bottom data visualization
        ])
        .split(area);

    // Top stats bar
    let stats_text = format!(
        " NETRAIN │ FPS: 60 │ Packets: 1337 │ Active Threats: 0 │ Uptime: 00:42:13 "
    );
    let stats_bar = Paragraph::new(stats_text)
        .style(Style::default().fg(Color::Green).bg(Color::Black))
        .alignment(Alignment::Center)
        .block(Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(stats_bar, matrix_chunks[0]);

    // Matrix rain area with border
    let matrix_block = Block::default()
        .borders(Borders::LEFT | Borders::RIGHT)
        .border_style(Style::default().fg(Color::Green));
    f.render_widget(matrix_block, matrix_chunks[1]);
    
    // Render matrix rain inside
    // matrix_rain.render(f, matrix_block.inner(matrix_chunks[1]));

    // Bottom visualization - Network activity graph
    let sparkline_data = vec![1, 5, 10, 15, 20, 25, 30, 35, 40, 35, 30, 25, 20, 15, 10, 5];
    let network_graph = Sparkline::default()
        .data(&sparkline_data)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Network Activity "));
    f.render_widget(network_graph, matrix_chunks[2]);
}

fn render_packet_log(f: &mut Frame, area: Rect) {
    let packets = vec![
        "[23:51:47] TCP   192.168.1.105 → 142.250.185.78 [60B]",
        "[23:51:47] HTTPS 192.168.1.105 → 172.217.14.93 [1420B]",
        "[23:51:47] DNS   192.168.1.105 → 8.8.8.8 [78B]",
        "[23:51:46] TCP   192.168.1.105 → 52.97.188.126 [52B]",
        "[23:51:46] UDP   192.168.1.105 → 239.255.255.250 [137B]",
    ];

    let log_items: Vec<ListItem> = packets.iter()
        .enumerate()
        .map(|(i, entry)| {
            let color = if entry.contains("TCP") {
                Color::Green
            } else if entry.contains("HTTPS") {
                Color::Cyan
            } else if entry.contains("DNS") {
                Color::Yellow
            } else if entry.contains("UDP") {
                Color::Blue
            } else {
                Color::Gray
            };
            
            let style = if i == 0 {
                Style::default().fg(color).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(color)
            };
            ListItem::new(*entry).style(style)
        })
        .collect();

    let log_list = List::new(log_items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title(" PACKETS "));
    f.render_widget(log_list, area);
}

fn render_help(f: &mut Frame, area: Rect) {
    let help = Paragraph::new("Q: Quit │ D: Demo")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, area);
}