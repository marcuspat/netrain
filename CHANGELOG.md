# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This is a large change set and includes breaking changes to the library API, so the next
release should be a minor bump (0.3.0).

### Added
- Layered packet decoder: Ethernet with VLAN tags, raw IP, loopback, Linux cooked captures;
  IPv4 and IPv6 with extension headers; TCP, UDP, ICMP.
- Threat engine: port scans, host sweeps, NULL/FIN/Xmas stealth scans, SYN floods and traffic
  spikes, with alerts that carry source, target and evidence and expire when the behaviour stops.
- Flow table with per-direction counters and TCP state; top talkers ranked by bytes.
- Hostnames from DNS queries, TLS SNI and HTTP `Host`; a passive address-to-name cache.
- Protocols: ICMP, QUIC, NTP, DHCP, mDNS, SSDP.
- Command line: `--interface`, `--list-interfaces`, `--filter`, `--read`, `--speed`,
  `--summary`, `--json`, `--headless`, `--alerts-only`, `--count`, `--promiscuous`,
  `--snaplen`, `--keep-privileges`, `--no-splash`.
- pcap replay, a deterministic capture summary, and NDJSON/text output (`docs/JSON_OUTPUT.md`).
- UI: pause, protocol filter, help overlay, resize handling, alert details, drop counter,
  flows and top talkers, real memory figure.
- Root is dropped once the capture is open (`docs/PRIVILEGES.md`).
- CI (lint, tests on Linux and macOS, MSRV, fuzz pass, cargo-deny) and a release workflow.
- Benchmarks of the real packet path (`docs/PERFORMANCE.md`); a mutation fuzzer in the test suite.

### Changed
- **Promiscuous mode is off by default**; pass `--promiscuous` to enable it.
- Default snap length is 1600 bytes (was 5000); default filter includes IPv6 and VLAN traffic.
- The default interface is the first live non-loopback one on any OS (was `en0`).
- Unknown or conflicting command-line flags are an error (they used to be ignored).
- Mouse capture is no longer enabled, so terminal text selection works.
- The render loop is paced at about 60 FPS instead of spinning.
- Minimum Rust version is 1.88. ratatui 0.29, crossterm 0.28.
- `tokio` is no longer a runtime dependency; `thiserror` and `mockall` are removed.

### Fixed
- Threat detection never fired on live traffic: TCP flags were read at the wrong offset for
  Ethernet frames, SYN-ACK replies were counted as attacks, nothing fed the port-scan tracker,
  and the threat level had no input.
- VLAN-tagged frames were silently dropped by the default capture filter.
- Packet length was reported as 60 for every packet by one parser; the DNS query name was a
  constant; two classification functions panicked on some inputs.
- The terminal is restored on every exit path, including panics and errors.
- A keypress could be swallowed by a second `event::read()`.
- Memory grew without bound in the per-source connection table; all tables are now capped.
- The memory figure in the UI was a constant.
- Corrupt capture files could panic on absurd timestamps or lengths.
- Dependencies with security advisories updated: `anyhow`, `rand`, `crossbeam-epoch`.
- Test fixtures in `tests/fixtures/` were not valid pcap files; they are now generated.

### Breaking (library)
- `extract_dns_query` returns `Option<String>` (was `Option<&str>`).
- `validate_packet`, `classify_protocol`, `classify_protocol_optimized` and
  `calculate_rain_density` return a value where they used to panic.
- `ProtocolSnapshot`'s per-protocol fields are replaced by `get(protocol)`.
- `Protocol` and `AlertKind` are `#[non_exhaustive]`; `Protocol` has new variants.
- `ThreatDetector::get_threat_level` reflects live alerts as well as manual indicators.

## [0.2.7] - 2025-01-01
### Fixed
- Fixed packet dump display with broken Unicode characters
- Restored hex dump to show packet contents
- Added proper spacing between packet info and hex dump
- Simplified display without decorative lines

### Changed
- Clarified Rust requirement in README - cargo doesn't come by default

## [0.2.6] - 2025-01-01
### Fixed
- Removed duplicate "Q: Quit | D: Demo Mode" help text from bottom of UI
- UI now only shows "Q:Quit" in the top stats bar, avoiding redundancy

## [0.2.5] - 2025-01-01
### Fixed
- Removed inaccurate "Japanese katakana characters" claim - uses alphanumeric characters
- Kept "3D depth illusion" feature description as it is actually implemented

## [0.2.4] - 2025-01-01
### Fixed
- Removed GitHub release badge since no releases exist
- Removed "D for demo" from keyboard controls list
- Changed "Configurable thresholds" to "Pre-configured thresholds" (more accurate)
- Removed links to non-existent Wiki and GitHub Discussions

## [0.2.3] - 2025-01-01
### Fixed
- Removed non-functional "Toggle demo mode" keyboard control from help
- Removed 'D' key handler that didn't work

## [0.2.2] - 2025-01-01
### Changed
- Cleaned up README to only show working installation methods
- Removed references to non-existent Homebrew installation
- Removed references to install script that doesn't exist
- Removed non-existent configuration options from documentation

## [0.2.1] - 2025-01-01
### Fixed
- Added clear error messages when running without proper permissions
- Fixed empty interface issue when packet capture fails
- Improved user experience for crates.io installation

### Changed
- Updated README with clearer sudo/permission requirements

## [0.2.0] - 2025-01-01
### Added
- Protocol-based color coding for network activity graphs
- Individual protocol sparklines (TCP, UDP, HTTP, HTTPS, DNS, SSH)
- Real-time packet counting in sparkline titles
- Protocol activity tracking module (`protocol_activity.rs`)

### Changed
- Network activity display now shows separate graphs per protocol
- Protocol stats colors now match packet log colors
- Activity tick rate optimized to 150ms for better visualization
- Demo mode timing adjusted for more realistic traffic simulation (200-300ms intervals)
- Updated repository URL in Cargo.toml

### Fixed
- Activity graphs now properly display data in both demo and real capture modes
- Graph responsiveness improved to better match packet log updates
- Demo mode packet generation reduced to better simulate real network traffic

## [0.1.0] - 2024-12-31
### Added
- Matrix rain visualization for network packets
- Real-time packet capture and analysis
- Protocol detection (TCP, UDP, HTTP, HTTPS, DNS, SSH)
- Threat detection system
- Performance monitoring
- Demo mode for testing without network access
- Hex dump view for raw packet data
- Pre-commit hooks for running tests
- GitHub Actions CI workflow for Rust projects

[Unreleased]: https://github.com/marcuspat/netrain/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/marcuspat/netrain/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/marcuspat/netrain/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/marcuspat/netrain/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/marcuspat/netrain/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/marcuspat/netrain/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/marcuspat/netrain/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/marcuspat/netrain/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/marcuspat/netrain/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/marcuspat/netrain/releases/tag/v0.1.0