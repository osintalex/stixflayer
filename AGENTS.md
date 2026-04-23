# AGENTS.md - Agent Guidelines for stixflayer

This file provides guidelines for agentic coding agents operating in this repository.

## Project Overview

This is a Rust implementation of STIX 2.1 (Structured Threat Information Expression). The project is a Cargo workspace with the main `rust-stix2` crate in the `rust/` directory, exposing Python bindings via pyo3/maturin.

- **Repository**: Forked from OASIS TC cti-rust-stix
- **Edition**: Rust 2021
- **Dependencies**: See `rust/Cargo.toml` (note: pattern MATCHES operator does not validate regex syntax - runtime validation is the responsibility of the consuming application)

---

## Build Commands

### Rust

```bash
# Check if code compiles (faster than build)
cargo check --workspace

# Full build
cargo build --workspace

# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Test
cargo test --workspace --verbose
```

### Python

In `python/` directory:

```bash
# Setup
uv venv .venv --python 3.11
uv pip install maturin ruff pyrefly pytest --python .venv/bin/python

# Build
.venv/bin/python -m maturin build -b pyo3 -i .venv/bin/python

# Lint
.venv/bin/python -m ruff check .

# Format check
.venv/bin/python -m ruff format --check .

# Type check
.venv/bin/python -m pyrefly check .

# Run tests
.venv/bin/python -m pytest -v
```

---

## Python API Design Guidelines

### Core Philosophy

**The value proposition is ergonomic, idiomatic Python** - not a 1:1 translation of the Rust API. Aim for Pythonic patterns that feel natural to Python developers.

### Class-based Construction

**DO**: Use direct class instantiation with keyword arguments.

```python
# Good - idiomatic Python
from stixflayer import AttackPattern, Identity, StatementMarking

# Create domain objects directly
attack_pattern = AttackPattern(name="Spear Phishing", description="Phishing attack")
identity = Identity(name="ACME Corp", identity_class="organization")

# Create marking definitions
marking = StatementMarking(statement="TLP:RED")

# SCOs work the same way
file = File(name="malware.exe", md5="d41d8cd98f00b204e9800998ecf8427e")
ipv4 = IPv4Address(value="192.0.2.1")
```

**DON'T**: Use builder pattern like Rust.

```python
# Bad - too Rust-like, not Pythonic
attack_pattern = stixflayer.builder("attack-pattern")
attack_pattern.name("Spear Phishing")
attack_pattern.build()
```

### Error Handling

**DO**: Use standard Python exceptions.

```python
# Good - use ValueError, TypeError, etc.
from stixflayer import AttackPattern

try:
    attack_pattern = AttackPattern()  # missing required field
except ValueError as e:
    print(f"Validation error: {e}")
```

**DON'T**: Create custom exception types unless truly necessary.

```python
# Bad - custom exceptions are not Pythonic
from stixflayer import StixError
with pytest.raises(stixflayer.StixError):
    AttackPattern()
```

### Constants and Enums

**DO**: Use constants or enums from the library.

```python
# Good - using provided constants at top-level
from stixflayer import AttackMotivation, IdentityClass

# Check against vocabulary
motivation = AttackMotivation("organizational-gain")
```

### Type Hints

**DO**: Use type hints throughout.

```python
from stixflayer import AttackPattern, Indicator

def validate_indicator(indicator: Indicator) -> bool:
    """Validate an indicator."""
    ...
```

### Serialization

**DO**: Use standard JSON serialization on objects.

```python
import json
from stixflayer import AttackPattern, Bundle

# To JSON (method on object)
attack_pattern = AttackPattern(name="Test")
json_str = attack_pattern.to_json()

# From JSON (class method)
attack_pattern = AttackPattern.from_json(json_str)

# Or use json module directly
json_str = json.dumps(attack_pattern)
```

---

## Test Organization

### Test Structure

```python
# tests/
# ├── __init__.py
# ├── utils.py        # Helper functions for loading test data
# ├── test_sdos.py    # Domain object tests
# ├── test_scos.py   # Cyber observable tests
# ├── test_sros.py   # Relationship tests
# ├── test_meta.py   # Meta object tests
# ├── test_patterns.py # Pattern language tests
# └── test_types.py   # Core type tests
```

### Test Utilities (tests/utils.py)

**DO**: Put data loaders and helpers in utils.py.

```python
from pathlib import Path
import json

# Path to shared test data
DATA_DIR = Path(__file__).parent.parent.parent / "data" / "stix"

def load_stix_json(filename: str) -> dict:
    """Load a STIX JSON file from shared test data."""
    with open(DATA_DIR / filename) as f:
        return json.load(f)

def load_sdo(sdo_type: str) -> dict:
    """Load SDO test data."""
    return load_stix_json(f"sdos/{sdo_type}.json")

# SDO/SCO type constants for tests
SDO_TYPES = ["attack-pattern", "campaign", "identity", ...]
SCO_TYPES = ["ipv4-addr", "file", "domain-name", ...]
```

### Test Conventions

**Rust**: Use pytest and test_log for Rust tests.

```rust
#[cfg(test)]
mod test {
    use test_log::test;
    
    #[test]
    fn my_test() { ... }
}
```

**Python**: Use pytest for Python tests.

```python
import pytest
from stixflayer import AttackPattern

class TestAttackPattern:
    def test_create_with_name(self):
        ap = AttackPattern(name="Spear Phishing")
        assert ap.name == "Spear Phishing"
    
    def test_missing_required_field(self):
        with pytest.raises(ValueError):
            AttackPattern()
```

---

## Module Structure

### Rust (rust/src/)

- `lib.rs` - Main library
- `error.rs` - Error definitions  
- `domain_objects/` - SDOs
- `cyber_observable_objects/` - SCOs
- `relationship_objects/` - SROs
- `meta_objects/` - Meta objects
- `pattern/` - Pattern language

### Python (python/src/)

- `lib.rs` - pyo3 bindings exposing all classes at top-level
- All STIX objects available directly: `AttackPattern`, `Identity`, `IPv4Address`, etc.
- Functions: `stix_case()`, `get_object_type()`, `validate_pattern()`
- No submodules - classes imported directly from stixflayer

### Shared Data (data/stix/)

Test data in repo root for all language bindings:
- `data/stix/sdos/*.json` - SDO samples
- `data/stix/scos/*.json` - SCO samples
- `data/stix/sros/*.json` - SRO samples
- `data/stix/meta/*.json` - Meta object samples
- `data/stix/patterns/*.json` - Pattern test cases

---

## CI/CD

### Rust CI (.github/workflows/ci.yml)

1. Build: `cargo check --workspace`
2. Format: `cargo fmt --all -- --check`
3. Lint: `cargo clippy --workspace --all-targets -- -D warnings`
4. Test: `cargo test --workspace --verbose`

### Python CI (.github/workflows/python.yml)

1. Lint: `ruff check .`
2. Format: `ruff format --check .`
3. Typecheck: `pyrefly check .`
4. Build: `maturin build`
5. Test: `pytest -v`

---

## Architecture Notes

This is a fork of the OASIS cti-rust-stix repository. The goal (per ARCHITECTURE.md) is to create a STIX library in Rust that exposes idiomatic Python bindings via pyo3/maturin.

The key design principles:
1. **Pythonic API** - use direct class instantiation, not builders
2. **Standard exceptions** - use ValueError, TypeError, etc.
3. **Type hints** - throughout for IDE support
4. **Shared test data** - STIX samples in `data/stix/` for all language bindings

---

## Wasm Plugin (Extism)

The `wasm-plugin/` directory contains a Rust Wasm plugin that uses Extism PDK to expose STIX functionality to Go applications.

### Build

```bash
# Build the Wasm plugin
cd wasm-plugin
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
# Output: target/wasm32-wasip1/release/stix_wasm_plugin.wasm
```

### Adding New STIX Types

1. Add a new function in `wasm-plugin/src/lib.rs`:

```rust
#[plugin_fn]
pub fn identity(input: String) -> FnResult<String> {
    let input: Value = serde_json::from_str(&input).map_err(Error::new)?;

    let mut builder = DomainObjectBuilder::new("identity").map_err(Error::new)?;

    if let Some(name) = input.get("name").and_then(|v| v.as_str()) {
        builder = builder.name(name.to_string()).map_err(Error::new)?;
    }
    // ... more fields

    let domain_object = builder.build().map_err(Error::new)?;
    let json = serde_json::to_string(&domain_object).map_err(Error::new)?;

    Ok(json.into())
}
```

2. Use snake_case for the function name (e.g., `attack_pattern`, not `attack-pattern`)

3. Rebuild the wasm plugin

---

## Go Bindings (Extism)

The `go/` directory contains Go bindings that use the Extism Go SDK to load and run the Wasm plugin.

### Build & Test

```bash
cd go
go mod tidy
go test -v ./...
```

### Usage

```go
package main

import (
    "context"
    "fmt"
    "github.com/stixflayer/go/stixflayer"
)

func main() {
    plugin, err := stixflayer.NewPlugin("path/to/stix_wasm_plugin.wasm")
    if err != nil {
        panic(err)
    }
    defer plugin.Close(context.Background())

    result, err := stixflayer.NewDomainObjectBuilder(plugin, "attack_pattern").
        Name("Spear Phishing").
        Description("Phishing attack").
        Build(context.Background())

    fmt.Printf("%+v\n", result)
}
```

### Note on Function Names

The Go builder uses snake_case function names to match the Wasm exports:
- `"attack_pattern"` not `"attack-pattern"`
- More mappings can be added as new STIX types are supported