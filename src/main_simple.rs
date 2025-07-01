// Simplified UI layout for testing
use ratatui::{
    layout::{Constraint, Direction, Layout, Alignment},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn render_simple_ui(f: &mut Frame) {
    // Simple two-panel layout
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([
            Constraint::Percentage(70),  // Matrix rain
            Constraint::Percentage(30),  // Stats
        ])
        .split(f.size());

    // Left panel - Matrix Rain
    let matrix_block = Block::default()
        .title(" MATRIX ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));
    f.render_widget(matrix_block, chunks[0]);

    // Right panel - Stats
    let stats_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),    // Title
            Constraint::Length(10),   // Stats
            Constraint::Min(5),       // Packets
            Constraint::Length(3),    // Help
        ])
        .split(chunks[1]);

    // Stats title
    let stats_title = Paragraph::new("NETRAIN")
        .style(Style::default().fg(Color::Green))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(stats_title, stats_chunks[0]);

    // Protocol stats
    let stats = Paragraph::new("TCP: 0\nUDP: 0\nHTTP: 0\nDNS: 0")
        .block(Block::default().title(" PROTOCOLS ").borders(Borders::ALL));
    f.render_widget(stats, stats_chunks[1]);

    // Packet log
    let packets = Paragraph::new("No packets yet...")
        .block(Block::default().title(" PACKETS ").borders(Borders::ALL));
    f.render_widget(packets, stats_chunks[2]);

    // Help
    let help = Paragraph::new("Q:Quit D:Demo")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, stats_chunks[3]);
}