#!/bin/bash

echo "NetRain Matrix Visual Effects Demo"
echo "=================================="
echo ""
echo "This demo showcases the enhanced Matrix rain visual effects."
echo ""
echo "Features demonstrated:"
echo "- ASCII art logo on startup"
echo "- Multiple character sets (ASCII, Katakana, Symbols, Binary, Hex)"
echo "- Color gradients with depth perception"
echo "- Trail effects with 5 intensity levels"
echo "- Particle effects on new packets"
echo "- Screen flash on threat detection"
echo "- Rainbow mode during threats"
echo "- Glitch effects during high traffic"
echo "- Smooth 60 FPS animations"
echo ""
echo "Press 'D' during runtime to activate demo mode!"
echo "Press 'Q' to quit"
echo ""
echo "Starting NetRain in 3 seconds..."
sleep 3

# Run NetRain with demo mode flag
cargo run -- --demo