# STIX 2.1 Python Library Status

## Overview
Rust-based STIX 2.1 library with Python bindings via pyo3/maturin.

## Implemented Types

### SDOs (19/19) ✅
- AttackPattern, Campaign, CourseOfAction, Grouping, Identity
- Incident, Indicator, Infrastructure, IntrusionSet, Location
- Malware, MalwareAnalysis, Note, ObservedData, Opinion
- Report, ThreatActor, Tool, Vulnerability

### SCOs (18/18) ✅
- IPv4Address, IPv6Address, DomainName, URL
- EmailAddress, EmailMessage, MacAddr, AutonomousSystem
- File, Software, Directory, Mutex
- Process, NetworkTraffic, UserAccount
- WindowsRegistryKey, X509Certificate, Artifact

### SROs (2/2) ✅
- Relationship, Sighting

### Meta Objects (3/3) ✅
- MarkingDefinition, ExtensionDefinition, LanguageContent

## Language Bindings

### Python (pyo3/maturin) ✅
- 94 tests passing
- Located in `python/tests/`
- Build: `cd python && uv run maturin develop`

### Node.js/TypeScript (napi-rs v3) ✅
- TypeScript test passing
- Located in `node/`
- Build: `napi build --release`

### Go (Extism) ✅
- Go SDK with builder pattern
- Test passing
- Located in `go/stixflayer/`
- Uses wasm32-wasip1 plugin from `wasm-plugin/`

## Known Issues

### 1. Empty JSON for Some Types
Types like `Grouping`, `Report`, `Relationship` return `{}` when built without required fields (validation fails silently in to_json). Should propagate errors instead.

## Build

```bash
# Rust
cargo check --workspace

# Python
cd python && uv run maturin develop

# Wasm Plugin
cd wasm-plugin
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release

# Go
cd go
go mod tidy
go test -v ./...
```

## Future Work
- Fix empty JSON error handling
- Java bindings