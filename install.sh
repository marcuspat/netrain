#!/bin/bash
# NetRain installer script

set -e

REPO="marcuspat/netrain"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Map architecture names
case "$ARCH" in
    x86_64)
        ARCH="x64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Get latest release
echo "🔍 Finding latest NetRain release..."
LATEST_RELEASE=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo "❌ Could not find latest release"
    exit 1
fi

echo "📦 Latest version: $LATEST_RELEASE"

# Download URL
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_RELEASE/netrain-${LATEST_RELEASE}-${OS}-${ARCH}.tar.gz"

# Download and install
echo "⬇️  Downloading NetRain..."
TEMP_DIR=$(mktemp -d)
curl -sL "$DOWNLOAD_URL" -o "$TEMP_DIR/netrain.tar.gz"

echo "📂 Extracting..."
tar -xzf "$TEMP_DIR/netrain.tar.gz" -C "$TEMP_DIR"

echo "🔧 Installing to $INSTALL_DIR..."
sudo mv "$TEMP_DIR/netrain" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/netrain"

# Cleanup
rm -rf "$TEMP_DIR"

echo "✅ NetRain installed successfully!"
echo ""
echo "Run 'netrain --help' to get started"
echo "Use 'sudo netrain' for network monitoring or 'netrain --demo' for demo mode"