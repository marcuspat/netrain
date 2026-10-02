//! Command-line interface.

use std::path::PathBuf;

use clap::Parser;

/// Default kernel filter: IPv4 and IPv6, including inside an 802.1Q VLAN
/// tag. A bare `ip or ip6` silently drops every VLAN-tagged frame, because
/// BPF matches the EtherType at a fixed offset.
pub const DEFAULT_FILTER: &str = "ip or ip6 or (vlan and (ip or ip6))";

#[derive(Parser, Debug, Clone, PartialEq)]
#[command(
    name = "netrain",
    version,
    about = "Matrix-style network packet monitor with threat detection",
    after_help = "Controls:\n  q    Quit\n\nLive capture needs permission to open the interface: run with sudo, or grant the\nbinary cap_net_raw. --demo and --read need no privileges."
)]
pub struct Cli {
    /// Capture on this interface instead of the auto-selected one
    #[arg(short, long, value_name = "NAME", conflicts_with_all = ["demo", "read"])]
    pub interface: Option<String>,

    /// List capture interfaces and exit
    #[arg(short, long, conflicts_with_all = ["demo", "read", "interface"])]
    pub list_interfaces: bool,

    /// BPF capture filter, e.g. "tcp port 443" or "host 10.0.0.5"
    #[arg(short, long, value_name = "EXPR", default_value = DEFAULT_FILTER, conflicts_with = "demo")]
    pub filter: String,

    /// Replay a pcap file instead of capturing live (no root required)
    #[arg(short, long, value_name = "FILE", conflicts_with = "demo")]
    pub read: Option<PathBuf>,

    /// Replay speed multiplier for --read; 0 replays as fast as possible
    #[arg(long, value_name = "FACTOR", default_value_t = 1.0, requires = "read", value_parser = parse_speed, allow_negative_numbers = true)]
    pub speed: f64,

    /// With --read: print a summary (protocols, alerts) and exit, no UI
    #[arg(long, requires = "read")]
    pub summary: bool,

    /// No UI: print one line per packet and alert to stdout
    #[arg(long, conflicts_with = "demo")]
    pub headless: bool,

    /// No UI: print newline-delimited JSON (see docs/JSON_OUTPUT.md)
    #[arg(long, conflicts_with = "demo")]
    pub json: bool,

    /// With --headless/--json: print alerts and the summary, not every packet
    #[arg(long)]
    pub alerts_only: bool,

    /// With --headless/--json: stop after this many packets
    #[arg(short = 'c', long, value_name = "N")]
    pub count: Option<u64>,

    /// Run with synthetic traffic (no root required)
    #[arg(long)]
    pub demo: bool,

    /// Skip the start-up splash screen
    #[arg(long)]
    pub no_splash: bool,
}

fn parse_speed(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("'{s}' is not a number"))?;
    if v.is_finite() && v >= 0.0 {
        Ok(v)
    } else {
        Err("speed must be zero or a positive number".to_string())
    }
}

/// Where packets come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Demo,
    Replay(PathBuf),
    Live { interface: Option<String> },
}

impl Cli {
    /// Is output going to stdout as lines rather than to the TUI?
    pub fn is_headless(&self) -> bool {
        self.headless || self.json
    }

    /// Checks clap's declarative rules cannot express.
    pub fn validate(&self) -> Result<(), String> {
        if (self.alerts_only || self.count.is_some()) && !self.is_headless() {
            return Err("--alerts-only and --count need --headless or --json".to_string());
        }
        if self.summary && self.headless && !self.json {
            return Err("--summary already prints text; use it alone or with --json".to_string());
        }
        Ok(())
    }

    pub fn mode(&self) -> Mode {
        if self.demo {
            Mode::Demo
        } else if let Some(path) = &self.read {
            Mode::Replay(path.clone())
        } else {
            Mode::Live { interface: self.interface.clone() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("netrain").chain(args.iter().copied()))
    }

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults_to_live_capture_on_the_auto_interface() {
        let cli = parse(&[]).unwrap();
        assert_eq!(cli.mode(), Mode::Live { interface: None });
        assert_eq!(cli.filter, DEFAULT_FILTER);
        assert!(!cli.no_splash && !cli.list_interfaces);
        assert_eq!(cli.speed, 1.0);
    }

    #[test]
    fn existing_flags_keep_working() {
        assert_eq!(parse(&["--demo"]).unwrap().mode(), Mode::Demo);
        assert_eq!(parse(&["--version"]).unwrap_err().kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(parse(&["-V"]).unwrap_err().kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(parse(&["--help"]).unwrap_err().kind(), clap::error::ErrorKind::DisplayHelp);
        assert_eq!(parse(&["-h"]).unwrap_err().kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn interface_filter_and_read() {
        let cli = parse(&["-i", "eth0", "-f", "tcp port 443"]).unwrap();
        assert_eq!(cli.mode(), Mode::Live { interface: Some("eth0".into()) });
        assert_eq!(cli.filter, "tcp port 443");

        let cli = parse(&["--read", "trace.pcap", "--speed", "0", "--filter", "udp"]).unwrap();
        assert_eq!(cli.mode(), Mode::Replay("trace.pcap".into()));
        assert_eq!(cli.speed, 0.0);
        assert!(parse(&["--list-interfaces"]).unwrap().list_interfaces);
        assert!(parse(&["-r", "t.pcap", "--summary"]).unwrap().summary);
        assert_eq!(
            parse(&["--summary"]).unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn headless_flags() {
        let cli = parse(&["--json", "-c", "100", "--alerts-only"]).unwrap();
        assert!(cli.is_headless() && cli.json && cli.alerts_only);
        assert_eq!(cli.count, Some(100));
        assert!(cli.validate().is_ok());
        assert!(parse(&["--headless", "-i", "eth0"]).unwrap().is_headless());
        assert!(!parse(&[]).unwrap().is_headless());

        assert!(parse(&["--alerts-only"]).unwrap().validate().is_err());
        assert!(parse(&["--count", "5"]).unwrap().validate().is_err());
        assert!(parse(&["-r", "x.pcap", "--summary", "--headless"]).unwrap().validate().is_err());
        assert!(parse(&["-r", "x.pcap", "--summary", "--json"]).unwrap().validate().is_ok());
        assert_eq!(
            parse(&["--demo", "--json"]).unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn contradictory_or_unknown_arguments_are_rejected() {
        use clap::error::ErrorKind::*;
        assert_eq!(parse(&["--demo", "--read", "x.pcap"]).unwrap_err().kind(), ArgumentConflict);
        assert_eq!(parse(&["--demo", "-i", "eth0"]).unwrap_err().kind(), ArgumentConflict);
        assert_eq!(parse(&["-i", "eth0", "-r", "x.pcap"]).unwrap_err().kind(), ArgumentConflict);
        assert_eq!(parse(&["--demo", "-f", "tcp"]).unwrap_err().kind(), ArgumentConflict);
        assert_eq!(parse(&["--speed", "2"]).unwrap_err().kind(), MissingRequiredArgument);
        assert_eq!(parse(&["-r", "x.pcap", "--speed", "-1"]).unwrap_err().kind(), ValueValidation);
        assert_eq!(parse(&["-r", "x.pcap", "--speed", "fast"]).unwrap_err().kind(), ValueValidation);
        // A typo used to be ignored silently and start a live capture.
        assert_eq!(parse(&["--dmeo"]).unwrap_err().kind(), UnknownArgument);
    }
}
