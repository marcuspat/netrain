# Releasing NetRain

This document describes the release process for NetRain to ensure GitHub and crates.io stay in sync.

## Quick Release

Use the release script for a streamlined process:

```bash
./scripts/release.sh
```

This script will:
1. Verify you're on the main branch with a clean working directory
2. Run tests
3. Build the release
4. Create and push a git tag
5. Push to GitHub
6. Publish to crates.io

## Manual Release Process

### 1. Update Version

Edit `Cargo.toml` and update the version:
```toml
version = "X.Y.Z"
```

### 2. Update CHANGELOG

Add a new section to `CHANGELOG.md`:
```markdown
## [X.Y.Z] - YYYY-MM-DD
### Added/Changed/Fixed
- Your changes here
```

### 3. Commit Changes

```bash
git add Cargo.toml CHANGELOG.md
git commit -m "chore: bump version to X.Y.Z"
```

### 4. Create and Push Tag

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

### 5. GitHub Actions

Once the tag is pushed, GitHub Actions will automatically:
- Create a GitHub release with changelog
- Build binaries for Linux, macOS, and Windows
- Generate checksums
- ⚠️ **Note**: Publishing to crates.io requires setting up the `CARGO_REGISTRY_TOKEN` secret

### 6. Publish to Crates.io

If automatic publishing isn't configured, manually publish:
```bash
cargo publish
```

## GitHub Actions Setup

The `.github/workflows/release.yml` workflow handles releases automatically when tags are pushed.

### Required Secrets

To enable automatic publishing to crates.io:
1. Get your API token from https://crates.io/me
2. Add it as a repository secret named `CARGO_REGISTRY_TOKEN`

## Version Sync

The release process ensures version synchronization:
- Git tags (vX.Y.Z) match the Cargo.toml version
- GitHub releases are created from tags
- Crates.io versions match git tags
- Binary releases are built for each version

## Best Practices

1. Always update CHANGELOG.md with user-facing changes
2. Use semantic versioning:
   - MAJOR: Breaking changes
   - MINOR: New features (backwards compatible)
   - PATCH: Bug fixes and minor improvements
3. Test thoroughly before releasing
4. Keep commit messages clear and descriptive