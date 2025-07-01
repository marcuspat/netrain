#!/bin/bash
# Script to update version number in README.md when Cargo.toml is updated

# Get the version from Cargo.toml
VERSION=$(grep -E '^version = ' Cargo.toml | sed 's/version = "//' | sed 's/"//')

# Update the version in README.md
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/> \*\*Current Version\*\*: v[0-9]\+\.[0-9]\+\.[0-9]\+/> **Current Version**: v${VERSION}/" README.md
else
    # Linux
    sed -i "s/> \*\*Current Version\*\*: v[0-9]\+\.[0-9]\+\.[0-9]\+/> **Current Version**: v${VERSION}/" README.md
fi

echo "Updated README.md to version v${VERSION}"