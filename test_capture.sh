#!/bin/bash
echo "🚀 Testing NetRain packet capture..."
echo "📡 This will show debug output for network interface detection"
echo "⏰ Run for 10 seconds then Ctrl+C to exit"
echo ""

# Build first
cargo build --release

# Run with sudo and capture stderr to see debug output
echo "Running: sudo ./target/release/netrain"
echo "Press Q to quit or Ctrl+C to stop"
echo ""

sudo ./target/release/netrain