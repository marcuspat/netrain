# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/marcuspat/netrain/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/marcuspat/netrain/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/marcuspat/netrain/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/marcuspat/netrain/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/marcuspat/netrain/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/marcuspat/netrain/releases/tag/v0.1.0