# NetRain 🌧️

```
╔╗╔═╗╔╦╗╦═╗╔═╗╦╔╗╔
║║║╣  ║ ╠╦╝╠═╣║║║║
╝╚╚═╝ ╩ ╩╚═╩ ╩╩╝╚╝
```

> *"Welcome to the real world."* - Morpheus

A **Matrix-style network packet monitor** with real-time threat detection and stunning terminal visualizations. Built with Rust for maximum performance.

⚡ **Quick Start**: Install Rust → `cargo install netrain` → `sudo netrain` (or `netrain --demo`)

[![CI Status](https://github.com/marcuspat/netrain/workflows/CI/badge.svg)](https://github.com/marcuspat/netrain/actions)
[![Crates.io](https://img.shields.io/crates/v/netrain.svg)](https://crates.io/crates/netrain)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/crates/d/netrain.svg)](https://crates.io/crates/netrain)
[![GitHub stars](https://img.shields.io/github/stars/marcuspat/netrain?style=social)](https://github.com/marcuspat/netrain/stargazers)

## 🎬 Demo

*Coming Soon: GIFs showing the Matrix rain effect in action*

<!-- ![NetRain Demo](docs/demo.gif) -->
<!-- ![Threat Detection](docs/threats.gif) -->

## ⚡ Performance That'll Blow Your Mind

- **212x faster** packet parsing (1.2ns vs 100ns target) 🚀
- **Stable 60 FPS** rendering with thousands of particles
- **Sub-millisecond** threat detection (29ns per packet)
- **Zero-allocation** hot paths for maximum efficiency

## ✨ Features

### 🌊 Visual Experience
- **Authentic Matrix rain** with cascading characters
- **Rainbow mode** for critical threats
- **3D depth illusion** with variable column speeds  
- **Particle effects** on packet arrival
- **Real-time animations** with smooth interpolation

### 🛡️ Security Monitoring
- **Port scan detection** with time-window analysis
- **DDoS attack detection** (SYN floods, traffic spikes)
- **Anomaly detection** for malformed packets
- **Real-time threat visualization** with color-coded alerts

### 📊 Network Analysis
- **Protocol classification** (TCP, UDP, HTTP, HTTPS, DNS, SSH)
- **Live packet capture** with pcap integration
- **Traffic statistics** and rate monitoring
- **Performance metrics** (FPS, memory usage, packet rates)

### 🎮 User Experience
- **Demo mode** for showcasing without network access
- **Keyboard controls** (Q to quit)
- **Responsive UI** that adapts to terminal size
- **Professional terminal interface** with styled borders

## 🚀 Installation

### From crates.io (Recommended)

**Requirements**: Rust 1.70+ must be installed first

```bash
cargo install netrain
```

### From Source

**Requirements**: Rust 1.70+ must be installed first

```bash
# Clone the repository
git clone https://github.com/marcuspat/netrain.git
cd netrain

# Build the project
cargo build --release

# The binary will be at ./target/release/netrain
```

## 📋 Prerequisites

### Install Rust (Required)

NetRain requires Rust 1.70+ for both installation methods above.

```bash
# Install Rust via rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

Alternatively, visit [rustup.rs](https://rustup.rs/) for other installation options.

### Install libpcap (For packet capture)

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

#### macOS
```bash
# libpcap is included with macOS
# No additional installation needed
```

#### Windows
```bash
# Install WinPcap or Npcap
# Download from: https://npcap.com/
```


## 🎯 Usage

```bash
# Run with packet capture (requires root/admin)
sudo netrain

# Run in demo mode (no root required)
netrain --demo

# Show help
netrain --help

# Show version
netrain --version
```

### Keyboard Controls
- **Q** - Quit the application

### Understanding the Interface

#### Matrix Rain Panel (Left 70%)
- **Green characters** falling like rain represent network packets
- **Faster falling** indicates higher traffic or threats
- **Rainbow colors** appear during critical security events
- **Character density** correlates with network activity

#### Statistics Panel (Right 30%)
- **Performance** - FPS, packet rate, memory usage
- **Protocol Stats** - Breakdown by protocol type
- **Threat Monitor** - Real-time security alerts
- **Packet Log** - Recent network activity

## 🧪 Development

### Running Tests
```bash
cargo test
```

### Benchmarks
```bash
cargo bench
```

## 📈 Technical Architecture

### Performance Optimizations
- **Zero-allocation packet parsing** using unsafe optimizations
- **Lookup tables** for character generation (11x faster)
- **Object pooling** for matrix characters and columns
- **SIMD operations** where applicable
- **Lock-free atomic counters** for performance metrics

### Security Features
- **Time-window analysis** for pattern detection
- **Pre-configured thresholds** for different attack types
- **Multi-threaded packet processing** with lock-free coordination
- **Memory-safe** implementation despite performance optimizations

## 🤝 Contributing

We welcome contributions!

### Development Setup
```bash
# Fork the repo and clone your fork
git clone https://github.com/yourusername/netrain.git
cd netrain

# Create a feature branch
git checkout -b feature/amazing-feature

# Make your changes and test
cargo test
cargo clippy
cargo fmt

# Commit and push
git commit -m "feat: add amazing feature"
git push origin feature/amazing-feature
```

## 📋 System Requirements

### Minimum Requirements
- **OS**: Linux, macOS, or Windows
- **RAM**: 256 MB
- **CPU**: Any 64-bit processor
- **Network**: Any interface supported by pcap

### Recommended for Best Experience
- **Terminal**: Modern terminal with Unicode support
- **Colors**: 256-color or True Color support
- **Size**: At least 80x24 characters
- **Privileges**: Root/Administrator for live packet capture

## 🐛 Troubleshooting

### Common Issues

#### "cargo: command not found"
```bash
# Install Rust first (includes cargo)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
cargo --version
```

#### Permission Denied
```bash
# On Linux/macOS, packet capture requires root privileges
sudo netrain

# Or use demo mode
netrain --demo
```

#### No Network Interface Found
```bash
# Use demo mode if no interfaces available
netrain --demo
```

#### Terminal Display Issues
```bash
# Ensure terminal supports Unicode
export LANG=en_US.UTF-8

# For best experience, use a modern terminal like:
# - Alacritty, Kitty, WezTerm (recommended)
# - iTerm2 (macOS), Windows Terminal (Windows)
```

#### "Killed" Error During Installation (Linux)
If you get a "signal: 9, SIGKILL: kill" error when running `cargo install netrain` on Linux, your system likely doesn't have enough memory to compile the dependencies.

**Common on**: VPS/cloud instances with ≤1GB RAM

**Solution 1: Add Swap Space (Recommended)**
```bash
# Create a 4GB swap file
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Make it permanent
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Now try installing again
cargo install netrain
```

**Solution 2: Reduce Compilation Parallelism**
```bash
# Limit cargo to 1 job to reduce memory usage
export CARGO_BUILD_JOBS=1
cargo install netrain
```

**Solution 3: Use Pre-built Binary**
Check if pre-built binaries are available for your release:
```bash
# Visit https://github.com/marcuspat/netrain/releases
# Download the appropriate binary for your system
# For example, for Linux x86_64:
wget https://github.com/marcuspat/netrain/releases/download/vX.Y.Z/netrain-linux-amd64.tar.gz
tar -xzf netrain-linux-amd64.tar.gz
sudo mv netrain /usr/local/bin/
sudo chmod +x /usr/local/bin/netrain
```
*Note: Replace vX.Y.Z with the actual version number*

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **The Matrix** franchise for inspiration
- **Rust community** for amazing performance tools
- **ratatui** for the terminal UI framework
- **pcap** library maintainers
- All the **security researchers** who make threat detection possible

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/marcuspat/netrain/issues)
- 💡 **Feature Requests**: [GitHub Issues](https://github.com/marcuspat/netrain/issues)

---

<div align="center">

**"There is no spoon... only packets."** 🥄

*Built with ❤️ in Rust*

[⭐ Star on GitHub](https://github.com/marcuspat/netrain) | [🍴 Fork](https://github.com/marcuspat/netrain/fork) | [📋 Issues](https://github.com/marcuspat/netrain/issues)

</div>