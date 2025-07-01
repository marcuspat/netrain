#!/bin/bash
# Script to publish NetRain to crates.io

set -e

echo "🚀 Publishing NetRain to crates.io..."

# Check if we're on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "❌ Error: Must be on main branch to publish"
    echo "Current branch: $BRANCH"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Error: Working directory has uncommitted changes"
    exit 1
fi

# Pull latest changes
echo "📥 Pulling latest changes..."
git pull origin main

# Run tests
echo "🧪 Running tests..."
cargo test --all

# Build in release mode
echo "🔨 Building release..."
cargo build --release

# Dry run first
echo "🔍 Running cargo publish dry run..."
cargo publish --dry-run

# Ask for confirmation
echo ""
echo "Ready to publish to crates.io?"
echo "Version: $(grep '^version' Cargo.toml | cut -d'"' -f2)"
read -p "Continue? (y/N) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📦 Publishing to crates.io..."
    cargo publish
    echo "✅ Successfully published to crates.io!"
    echo ""
    echo "View at: https://crates.io/crates/netrain"
else
    echo "❌ Publishing cancelled"
    exit 1
fi