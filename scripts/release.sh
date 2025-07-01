#!/bin/bash
# Release script for NetRain
# This script ensures GitHub tags stay in sync with crates.io releases

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the current version from Cargo.toml
VERSION=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)

echo -e "${GREEN}Preparing to release NetRain v${VERSION}${NC}"

# Check if we're on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo -e "${RED}Error: You must be on the main branch to release${NC}"
    exit 1
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}Error: Working directory has uncommitted changes${NC}"
    exit 1
fi

# Pull latest changes
echo -e "${YELLOW}Pulling latest changes from origin...${NC}"
git pull origin main

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
cargo test

# Build release
echo -e "${YELLOW}Building release...${NC}"
cargo build --release

# Create git tag
echo -e "${YELLOW}Creating git tag v${VERSION}...${NC}"
if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
    echo -e "${YELLOW}Tag v${VERSION} already exists, skipping...${NC}"
else
    git tag -a "v${VERSION}" -m "Release v${VERSION}"
    echo -e "${GREEN}Created tag v${VERSION}${NC}"
fi

# Push to GitHub
echo -e "${YELLOW}Pushing to GitHub...${NC}"
git push origin main
git push origin "v${VERSION}"

# Publish to crates.io
echo -e "${YELLOW}Publishing to crates.io...${NC}"
cargo publish

echo -e "${GREEN}✅ Successfully released NetRain v${VERSION}!${NC}"
echo -e "${GREEN}   - GitHub tag: https://github.com/marcuspat/netrain/releases/tag/v${VERSION}${NC}"
echo -e "${GREEN}   - Crates.io: https://crates.io/crates/netrain/${VERSION}${NC}"