# STIX 2.1 Python Library Status

## Overview
Rust-based STIX 2.1 library with Python bindings via pyo3/maturin.

## Implemented Types

### SDOs (19/19) ✅
- AttackPattern, Campaign, CourseOfAction, Grouping, Identity
- Incident, Indicator, Infrastructure, IntrusionSet, Location
- Malware, MalwareAnalysis, Note, ObservedData, Opinion
- Report, ThreatActor, Tool, Vulnerability

### SCOs (17/17) ✅
- IPv4Address, IPv6Address, DomainName, URL
- EmailAddress, MacAddr, AutonomousSystem
- File, Software, Directory, Mutex
- Process, NetworkTraffic, UserAccount
- WindowsRegistryKey, X509Certificate, Artifact

### SROs (2/2) ✅
- Relationship, Sighting

### Meta Objects (3/3) ✅
- MarkingDefinition, ExtensionDefinition, LanguageContent

## Language Bindings

### Python (pyo3/maturin) ✅
- 74 tests passing
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

### 2. LanguageContent Complex API
The Rust `insert_content()` method expects `StixDictionary<ContentType>` - a nested dictionary structure requiring multiple insert calls. Not suitable for simple Python API.

### 3. EmailMessage SCO Not Implemented
Complex multipart email object - needs separate implementation.

### 4. pcre2 and Wasm
The pattern parser uses `pcre2` which requires a C library that doesn't compile for wasm targets. A `pattern` feature flag has been added to make it optional. For full wasm support, replace pcre2 with native Rust regex (see stix2 crate for reference implementation using nom + regex).

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
- Implement EmailMessage
- Simplify LanguageContent API in Rust for easier Python bindings
- Replace pcre2 with native Rust regex for wasm compatibility
- Java bindings