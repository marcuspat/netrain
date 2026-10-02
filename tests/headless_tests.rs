//! Black-box tests of `--json` / `--headless` on the built binary.

use std::io::Read;
use std::process::{Command, Stdio};

use serde_json::Value;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_netrain"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json_lines(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

#[test]
fn json_stream_for_a_port_scan() {
    let (code, stdout, stderr) = run(&["--read", &fixture("port_scan.pcap"), "--json"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        !stdout.contains('\x1b'),
        "no terminal control codes in machine output"
    );
    let lines = json_lines(&stdout);

    let count = |t: &str| lines.iter().filter(|v| v["type"] == t).count();
    assert_eq!(count("packet"), 40);
    assert_eq!(count("alert"), 1);
    assert_eq!(count("summary"), 1);
    assert_eq!(
        lines.last().unwrap()["type"],
        "summary",
        "summary is the last line"
    );

    let alert = lines.iter().find(|v| v["type"] == "alert").unwrap();
    assert_eq!(alert["alert"], "Port scan");
    assert_eq!(alert["source"], "203.0.113.7");
    // The alert follows the packet that triggered it: the 20th probe.
    let position = lines.iter().position(|v| v["type"] == "alert").unwrap();
    assert_eq!(position, 20);
    assert_eq!(lines[position - 1]["dst_port"], 20);
}

#[test]
fn output_is_identical_across_runs() {
    let args = ["--read", &fixture("mixed_protocols.pcap"), "--json"];
    assert_eq!(run(&args).1, run(&args).1);
}

#[test]
fn alerts_only_and_count() {
    let (_, stdout, _) = run(&[
        "--read",
        &fixture("ddos_attack.pcap"),
        "--json",
        "--alerts-only",
    ]);
    let lines = json_lines(&stdout);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["alert"], "SYN flood");
    assert_eq!(lines[1]["peak_threat"], "critical");

    let (_, stdout, _) = run(&[
        "--read",
        &fixture("ddos_attack.pcap"),
        "--json",
        "--count",
        "7",
    ]);
    let lines = json_lines(&stdout);
    assert_eq!(lines.len(), 8, "seven packets and the summary");
    assert_eq!(lines[7]["packets"], 7);
}

#[test]
fn summary_json_is_one_object() {
    let (code, stdout, _) = run(&[
        "--read",
        &fixture("normal_traffic.pcap"),
        "--summary",
        "--json",
    ]);
    assert_eq!(code, 0);
    let lines = json_lines(&stdout);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["type"], "summary");
    assert_eq!(lines[0]["hostnames"][0], "example.com");
    assert_eq!(lines[0]["protocols"]["HTTPS"], 5);
}

#[test]
fn text_mode_prints_lines_and_a_summary() {
    let (code, stdout, _) = run(&["--read", &fixture("normal_traffic.pcap"), "--headless"]);
    assert_eq!(code, 0);
    assert!(stdout
        .contains(" HTTPS 192.168.1.10:50001 -> 93.184.216.34:443 134B [PA] sni=example.com\n"));
    assert!(stdout.contains("--- summary ---\npackets:      13\n"));
}

#[test]
fn a_reader_that_goes_away_is_not_an_error() {
    // Equivalent of `netrain --json | head -1`.
    let mut child = Command::new(env!("CARGO_BIN_EXE_netrain"))
        .args(["--read", &fixture("ddos_attack.pcap"), "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = [0u8; 16];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut first)
        .unwrap();
    drop(child.stdout.take()); // close the pipe
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn misused_flags_are_explained() {
    let (code, _, stderr) = run(&["--alerts-only"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("--alerts-only and --count need --headless or --json"),
        "{stderr}"
    );
    let (code, _, _) = run(&["--demo", "--json"]);
    assert_eq!(code, 2);
}

/// Live capture on loopback. Needs permission to capture, so it only runs
/// where the test process is root (CI containers); elsewhere it is a no-op.
#[cfg(target_os = "linux")]
#[test]
fn live_capture_drops_root_and_keeps_working() {
    use std::net::UdpSocket;
    use std::time::Duration;

    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let is_root = status
        .lines()
        .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(2) == Some("0"));
    if !is_root {
        eprintln!("skipped: not root");
        return;
    }

    let child = Command::new(env!("CARGO_BIN_EXE_netrain"))
        .args([
            "-i",
            "lo",
            "--json",
            "--count",
            "3",
            "--filter",
            "udp port 47999",
        ])
        .env_remove("SUDO_UID")
        .env_remove("SUDO_GID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Keep sending until netrain has seen its three packets and exited.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender = std::thread::spawn(move || {
        for _ in 0..100 {
            let _ = socket.send_to(b"netrain-test", "127.0.0.1:47999");
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let out = child.wait_with_output().unwrap();
    drop(sender); // detached; it stops on its own
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    if stderr.contains("Cannot capture")
        || stderr.contains("Failed to list")
        || stderr.contains("not found")
    {
        eprintln!("skipped: capture unavailable here: {stderr}");
        return;
    }
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("capturing on lo, dropped root, running as uid 65534 gid 65534"),
        "root must be given up once the capture is open: {stderr}"
    );
    // ...and packets still arrive after the drop.
    let lines = json_lines(&stdout);
    assert_eq!(lines.len(), 4, "{stdout}");
    assert_eq!(lines[0]["dst_port"], 47999);
    assert_eq!(lines[0]["src"], "127.0.0.1");
    assert_eq!(lines[3]["packets"], 3);
}
