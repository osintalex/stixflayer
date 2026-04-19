# stixflayer

High-performance STIX 2.1 library written in Rust with bindings for Python, Go, and Node.js.

## Features

- **Rust core**: Fast STIX 2.1 serialization/deserialization
- **Python**: Idiomatic Python API via pyo3/maturin
- **Go**: Using Extism WASM bindings
- **Node.js**: TypeScript-compatible bindings via napi-rs
- **Wasm plugin**: Universal STIX object builder

## Quick Start

### Python

```bash
cd python
pip install -e .
```

```python
from stixflayer import AttackPattern

attack_pattern = AttackPattern(name="Spear Phishing", description="Phishing attack")
print(attack_pattern.to_json())
```

### Go

```bash
cd go
go mod tidy
go test -v ./...
```

### Rust

```bash
cargo check --workspace
cargo test --workspace
```

## Project Structure

```
rust/           - Core STIX library
python/         - Python bindings
node/           - Node.js/TypeScript bindings  
go/             - Go bindings (Extism)
wasm-plugin/    - WASM plugin for universal bindings
java/           - Java bindings (experimental)
```

## License

BSD-3-Clause - see LICENSE file for details.
