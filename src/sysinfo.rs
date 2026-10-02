//! Facts about our own process, read without extra dependencies.

/// Resident set size of this process in bytes, where the platform exposes
/// it cheaply (Linux `/proc`). `None` elsewhere - the UI then says so rather
/// than showing a made-up number.
pub fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        parse_vm_rss(&std::fs::read_to_string("/proc/self/status").ok()?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Extract `VmRSS` from the text of `/proc/<pid>/status`.
pub fn parse_vm_rss(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let mut parts = line["VmRSS:".len()..].split_whitespace();
    let value: u64 = parts.next()?.parse().ok()?;
    match parts.next() {
        Some("kB") | None => value.checked_mul(1024),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_status() {
        let status = "Name:\tnetrain\nVmPeak:\t  200000 kB\nVmRSS:\t   12345 kB\nThreads:\t2\n";
        assert_eq!(parse_vm_rss(status), Some(12345 * 1024));
        assert_eq!(parse_vm_rss("Name:\tx\n"), None);
        assert_eq!(parse_vm_rss("VmRSS:\tlots kB\n"), None);
        assert_eq!(parse_vm_rss("VmRSS:\t5 MB\n"), None);
        assert_eq!(parse_vm_rss("VmRSS:\t18446744073709551615 kB\n"), None, "overflow");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reports_a_plausible_figure_for_this_process() {
        let rss = rss_bytes().expect("Linux exposes VmRSS");
        // A running test binary is certainly between 100 KB and 100 GB.
        assert!((100 * 1024..100 * 1024 * 1024 * 1024).contains(&rss), "{rss}");
    }
}
