//! Black-box tests of the `netrain` binary. None of these need root, a
//! network interface or a terminal: every case exits before the TUI starts.

use std::process::{Command, Output};

fn netrain(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_netrain")).args(args).output().expect("failed to run netrain")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The terminal must never be switched into TUI mode on an error path.
fn assert_no_tui(out: &Output) {
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(!all.contains("\x1b[?1049h"), "entered the alternate screen: {all:?}");
}

#[test]
fn version_and_help() {
    let out = netrain(&["--version"]);
    assert!(out.status.success());
    assert_eq!(text(&out.stdout).trim(), format!("netrain {}", env!("CARGO_PKG_VERSION")));

    let out = netrain(&["--help"]);
    assert!(out.status.success());
    let help = text(&out.stdout);
    for flag in ["--interface", "--list-interfaces", "--filter", "--read", "--speed", "--demo", "--no-splash"] {
        assert!(help.contains(flag), "help is missing {flag}:\n{help}");
    }
}

#[test]
fn unknown_flag_is_an_error_not_a_silent_live_capture() {
    let out = netrain(&["--dmeo"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("--dmeo"));
    assert_no_tui(&out);
}

#[test]
fn conflicting_flags_are_rejected() {
    let out = netrain(&["--demo", "--read", "x.pcap"]);
    assert_eq!(out.status.code(), Some(2));
    assert_no_tui(&out);
}

#[test]
fn missing_capture_file_is_a_plain_error() {
    let out = netrain(&["--read", "/nonexistent/trace.pcap"]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.starts_with("netrain: Cannot read /nonexistent/trace.pcap"), "{err}");
    assert_no_tui(&out);
}

#[test]
fn file_that_is_not_a_pcap_is_a_plain_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-capture.pcap");
    std::fs::write(&path, b"this is not a capture file").unwrap();
    let out = netrain(&["--read", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("Cannot read"));
    assert_no_tui(&out);
}

/// A minimal, valid little-endian pcap file (Ethernet) with one packet.
fn valid_pcap() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
    f.extend_from_slice(&2u16.to_le_bytes()); // version major
    f.extend_from_slice(&4u16.to_le_bytes()); // version minor
    f.extend_from_slice(&[0; 8]); // thiszone, sigfigs
    f.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    f.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    let packet = [0u8; 60];
    f.extend_from_slice(&[0; 8]); // ts_sec, ts_usec
    f.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    f.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    f.extend_from_slice(&packet);
    f
}

#[test]
fn invalid_filter_is_reported_before_the_ui_starts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("one.pcap");
    std::fs::write(&path, valid_pcap()).unwrap();
    let out = netrain(&["--read", path.to_str().unwrap(), "--filter", "this is not bpf"]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("Invalid filter 'this is not bpf'"), "{err}");
    assert_no_tui(&out);
}

#[test]
fn unknown_interface_names_the_alternatives_or_explains_permissions() {
    let out = netrain(&["--interface", "definitely-not-an-interface0"]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    // Either we could list devices (and say which exist), or listing itself
    // was refused; both are clear, and neither starts the UI.
    assert!(
        err.contains("definitely-not-an-interface0") || err.contains("Failed to list network devices")
            || err.contains("No network device"),
        "{err}"
    );
    assert_no_tui(&out);
}

#[test]
fn list_interfaces_prints_a_table_and_exits() {
    let out = netrain(&["--list-interfaces"]);
    assert_no_tui(&out);
    if out.status.success() {
        let table = text(&out.stdout);
        assert!(table.contains("INTERFACE") && table.contains("STATE"), "{table}");
    } else {
        assert!(text(&out.stderr).starts_with("netrain: "));
    }
}
