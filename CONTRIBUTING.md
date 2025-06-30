# Contributing to NetRain 🌧️

First off, thank you for considering contributing to NetRain! It's people like you that make NetRain such a great tool. The Matrix has you, and we're glad you're here.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@netrain.dev.

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples to demonstrate the steps
- Describe the behavior you observed after following the steps
- Explain which behavior you expected to see instead and why
- Include screenshots if possible
- Include your OS, NetRain version, and Rust version

### 💡 Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- Use a clear and descriptive title
- Provide a step-by-step description of the suggested enhancement
- Provide specific examples to demonstrate the steps
- Describe the current behavior and explain which behavior you expected to see instead
- Explain why this enhancement would be useful

### 🔨 Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes: `cargo test`
5. Make sure your code follows the style guidelines: `cargo fmt`
6. Make sure your code passes clippy: `cargo clippy`
7. Issue that pull request!

## Development Setup

1. **Clone your fork**
   ```bash
   git clone https://github.com/yourusername/netrain.git
   cd netrain
   ```

2. **Install dependencies**
   ```bash
   # macOS
   brew install libpcap

   # Ubuntu/Debian
   sudo apt-get install libpcap-dev

   # Arch
   sudo pacman -S libpcap
   ```

3. **Build and test**
   ```bash
   cargo build
   cargo test
   cargo run -- --demo
   ```

## Style Guidelines

### Rust Code Style

- Follow standard Rust naming conventions
- Use `cargo fmt` before committing
- Use `cargo clippy` and fix any warnings
- Write doc comments for public APIs
- Prefer `const` and `let` over `mut` when possible
- Use descriptive variable names

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only changes
- `style:` - Code style changes (formatting, missing semicolons, etc)
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `perf:` - Performance improvement
- `test:` - Adding missing tests
- `chore:` - Changes to build process or auxiliary tools

Example:
```
feat: add rainbow mode for threat visualization

- Implement HSV color cycling during active threats
- Add configuration option for rainbow speed
- Update visual effects documentation
```

### Documentation

- Update README.md if you change functionality
- Add doc comments to new public functions/modules
- Include examples in doc comments when helpful
- Update CHANGELOG.md following Keep a Changelog format

## Testing

- Write unit tests for new functionality
- Write integration tests for cross-module features
- Ensure all tests pass before submitting PR
- Add test data files to `tests/fixtures/` if needed
- Run benchmarks if you're making performance claims

## Performance Considerations

NetRain is performance-critical. When contributing:

- Run benchmarks before and after your changes
- Avoid allocations in hot paths
- Use `cargo flamegraph` to profile if needed
- Document performance implications
- Consider using `#[inline]` for small, frequently-called functions

## Feature Ideas

Looking for something to work on? Check out:

- GPU acceleration for rendering
- Additional character sets (emoji mode?)
- Network topology visualization
- Custom color themes
- Pcap file replay mode
- Alert webhooks
- Configuration file support

## Recognition

Contributors will be recognized in:
- The project README
- Release notes
- The AUTHORS file
- Special thanks in social media announcements

## Questions?

Feel free to:
- Open an issue for clarification
- Join our Discord server
- Email maintainers@netrain.dev

---

*"There is no spoon" - but there are definitely bugs. Help us squash them!* 🥄🐛