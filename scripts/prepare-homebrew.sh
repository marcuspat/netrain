#!/bin/bash
# Script to prepare NetRain for Homebrew distribution

set -e

VERSION=$(grep '^version' Cargo.toml | cut -d'"' -f2)
echo "🍺 Preparing Homebrew formula for NetRain v${VERSION}..."

# Create release archive
ARCHIVE_NAME="netrain-v${VERSION}.tar.gz"
echo "📦 Creating release archive: ${ARCHIVE_NAME}"

# Create a temporary directory for the release
TEMP_DIR=$(mktemp -d)
RELEASE_DIR="${TEMP_DIR}/netrain-${VERSION}"

# Copy files to release directory
mkdir -p "${RELEASE_DIR}"
git archive --format=tar --prefix="netrain-${VERSION}/" HEAD | tar -x -C "${TEMP_DIR}"

# Create the archive
cd "${TEMP_DIR}"
tar -czf "${ARCHIVE_NAME}" "netrain-${VERSION}"
mv "${ARCHIVE_NAME}" "$OLDPWD/"
cd "$OLDPWD"

# Calculate SHA256
echo "🔐 Calculating SHA256..."
SHA256=$(shasum -a 256 "${ARCHIVE_NAME}" | cut -d' ' -f1)

# Update the formula
echo "📝 Updating Homebrew formula..."
sed -i.bak "s/v[0-9]\+\.[0-9]\+\.[0-9]\+/v${VERSION}/g" homebrew/netrain.rb
sed -i.bak "s/PLACEHOLDER_SHA256/${SHA256}/g" homebrew/netrain.rb
rm homebrew/netrain.rb.bak

# Clean up
rm -rf "${TEMP_DIR}"

echo "✅ Homebrew preparation complete!"
echo ""
echo "Archive: ${ARCHIVE_NAME}"
echo "SHA256: ${SHA256}"
echo ""
echo "Next steps:"
echo "1. Create a GitHub release and upload ${ARCHIVE_NAME}"
echo "2. Submit the formula to homebrew-core or create a tap"
echo ""
echo "To create a tap:"
echo "  1. Create repo: homebrew-netrain"
echo "  2. Copy homebrew/netrain.rb to Formula/netrain.rb"
echo "  3. Users can install with: brew tap marcuspat/netrain && brew install netrain"