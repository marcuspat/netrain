# Distribution Guide for NetRain

This guide covers how to distribute NetRain through various package managers.

## Table of Contents
- [Crates.io (Rust Package Registry)](#cratesio)
- [Homebrew (macOS/Linux)](#homebrew)
- [GitHub Releases](#github-releases)

## Crates.io

✅ **NetRain is now published on crates.io!** Users can install it with `cargo install netrain`.

### Prerequisites
1. Create account at https://crates.io
2. Login locally: `cargo login`
3. Ensure you're a crate owner (first publish or added as owner)

### Publishing Process
```bash
# Use the provided script
./scripts/publish-crate.sh

# Or manually:
cargo test --all
cargo publish --dry-run
cargo publish
```

### Installation for Users
Once published, users can install with:
```bash
cargo install netrain
```

## Homebrew

NetRain can be distributed via Homebrew for easy installation on macOS and Linux.

### Option 1: Homebrew Core (Official)
For inclusion in homebrew-core:
1. Ensure project meets [Homebrew acceptance criteria](https://docs.brew.sh/Acceptable-Formulae)
2. Create a stable release on GitHub
3. Submit PR to homebrew-core

### Option 2: Custom Tap (Recommended for now)
Create your own tap for immediate distribution:

1. **Prepare the release:**
   ```bash
   ./scripts/prepare-homebrew.sh
   ```

2. **Create GitHub release:**
   - Go to https://github.com/marcuspat/netrain/releases
   - Create new release with the generated tar.gz file
   - Tag as `v0.2.0` (or current version)

3. **Create tap repository:**
   - Create new repo: `homebrew-netrain`
   - Create `Formula` directory
   - Copy `homebrew/netrain.rb` to `Formula/netrain.rb`
   - Commit and push

4. **Users can install with:**
   ```bash
   brew tap marcuspat/netrain
   brew install netrain
   ```

### Formula Maintenance
- Update formula when releasing new versions
- Test formula locally: `brew install --build-from-source ./homebrew/netrain.rb`

## GitHub Releases

For direct binary distribution:

### Creating a Release
1. Build binaries for target platforms:
   ```bash
   # macOS (Intel)
   cargo build --release --target x86_64-apple-darwin
   
   # macOS (Apple Silicon)
   cargo build --release --target aarch64-apple-darwin
   
   # Linux
   cargo build --release --target x86_64-unknown-linux-gnu
   ```

2. Create archives:
   ```bash
   # Example for macOS
   tar -czf netrain-v0.2.0-macos-x64.tar.gz -C target/x86_64-apple-darwin/release netrain
   ```

3. Create GitHub release:
   - Tag: `v0.2.0`
   - Title: `NetRain v0.2.0`
   - Upload binary archives
   - Include changelog

### Installation Script
Users can install with:
```bash
# macOS/Linux
curl -sSL https://github.com/marcuspat/netrain/releases/latest/download/netrain-$(uname -s)-$(uname -m).tar.gz | tar xz
sudo mv netrain /usr/local/bin/
```

## Version Management
1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Commit with message: `chore: bump version to X.Y.Z`
4. Create git tag: `git tag -a vX.Y.Z -m "Release version X.Y.Z"`
5. Push: `git push origin main --tags`

## Platform Notes

### macOS
- Requires libpcap (included in macOS)
- May require security approval for packet capture
- Recommend using Homebrew for easy installation

### Linux
- Requires libpcap-dev package
- Different distros may have different package names
- Consider creating packages for major distros (deb, rpm)

### Windows
- Requires WinPcap or Npcap
- Consider providing installer with bundled dependencies

## Checklist for New Release
- [ ] Update version in Cargo.toml
- [ ] Update CHANGELOG.md
- [ ] Run all tests
- [ ] Update README if needed
- [ ] Commit and tag version
- [ ] Push to GitHub with tags
- [ ] Publish to crates.io
- [ ] Create GitHub release
- [ ] Update Homebrew formula
- [ ] Announce release