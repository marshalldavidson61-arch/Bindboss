# Contributing to Bindboss

Thanks for your interest in contributing! 📦

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/Bindboss.git`
3. **Install** Go 1.23+: [go.dev/dl](https://go.dev/dl/)
4. **Build**: `go build -o bindboss .`
5. **Branch**: `git checkout -b my-feature`
6. **Test**: `go test ./...`
7. **Push** and open a pull request

## Project Structure

```
Bindboss/
├── main.go              # Entry point, CLI commands
├── cmd/                 # Command implementations
├── internal/            # Internal packages
│   ├── packer/          # Core packing logic
│   ├── stub/            # Self-extracting stub
│   └── signer/          # Ed25519 signing
├── pkg/                 # Public API packages
├── stub/                # Stub template
├── testdata/            # Test fixtures
├── install.example.json # Example install config
└── tamper_helper.py     # Tamper detection helper
```

## What to Contribute

- **New features**: Additional packing options, compression methods
- **Bug fixes**: Extraction edge cases, cross-platform issues
- **Tests**: Improve coverage for packer, signer, and stub
- **Docs**: README improvements, usage examples
- **Platform support**: Testing on different OS/arch combinations

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep packages focused — single responsibility
- Error handling: wrap errors with context, never swallow silently
- Tests alongside implementation files

## Pull Requests

- One feature or fix per PR
- Include tests for new functionality
- Update README if adding new flags or commands
- Run `go vet ./...` and `go test ./...` before submitting

---

*Part of [grug-group420](https://github.com/grug-group420) — "complexity very very bad" 🪨*
