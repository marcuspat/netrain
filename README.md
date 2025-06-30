# NetRain

[![CI](https://github.com/yourusername/netrain/workflows/CI/badge.svg)](https://github.com/yourusername/netrain/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/yourusername/netrain/branch/main/graph/badge.svg?token=YOUR_TOKEN)](https://codecov.io/gh/yourusername/netrain)
[![Crates.io](https://img.shields.io/crates/v/netrain.svg)](https://crates.io/crates/netrain)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=yourusername/netrain)](https://dependabot.com)

Matrix-style network packet monitor with real-time threat detection capabilities.

## Features

- Real-time packet capture and analysis
- Matrix-style "digital rain" visualization
- Threat detection for common attack patterns:
  - DDoS attacks
  - Port scanning
  - Suspicious traffic patterns
- Cross-platform support (Linux, macOS, Windows)
- Terminal-based UI using ratatui

## Installation

### From crates.io

```bash
cargo install netrain
```

### From source

```bash
git clone https://github.com/yourusername/netrain.git
cd netrain
cargo build --release
```

### System Requirements

- libpcap (Linux/macOS) or WinPcap/Npcap (Windows)
- Rust 1.70 or higher

#### Installing dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libpcap-dev
```

**macOS:**
```bash
brew install libpcap
```

**Windows:**
Download and install [Npcap](https://npcap.com/) or WinPcap

## Usage

Run with default settings (requires sudo/admin for packet capture):

```bash
sudo netrain
```

Specify network interface:

```bash
sudo netrain -i eth0
```

## Development

### Running tests

```bash
cargo test
```

### Code coverage

```bash
cargo tarpaulin --verbose --all-features --workspace --timeout 120 --out html
```

### Contributing

Please read our [Contributing Guidelines](CONTRIBUTING.md) and ensure your commits follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Branch Protection

This repository uses branch protection rules. See [BRANCH_PROTECTION.md](.github/BRANCH_PROTECTION.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please email security@netrain.example.com instead of using the issue tracker.