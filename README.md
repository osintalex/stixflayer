# 🧠 Stixflayer 🦑

Rust-native STIX 2.1 engine. One spec-compliant core, consumed by many.

## Why another STIX library?

- **Battle-tested, but faster** ⚔️: Built from the official OASIS reference implementation, with full parity (and then some) against the industry-standard [`cti-stix-validator`](https://github.com/oasis-open/cti-stix-validator). Same trusted spec compliance, but rewritten in Rust for speed, correctness, and interoperability.
- **One engine, no validation gaps** 🌍: Most STIX libraries are reimplemented per-language, which creates subtle interoperability bugs. stixflayer uses a single Rust core everywhere — data validates the same way in all supported languages.
- **Stricter where it matters** 🧐: Actively improves on `stix2validator` by enforcing rules it skips — rejecting empty bundles, invalid vocabulary values, and incorrect SCO UUIDv5 hashes.



## Languages 🔌

| Language | Status | Binding |
|----------|--------|---------|
| Python | 🐍🚀 First release coming soon | Native ([pyo3](https://pyo3.rs/)) |
| Rust | ⚙️🚀 First release coming soon | Native |
| TypeScript | 🧙🛠️ Planned | [napi.rs](https://napi.rs/) |
| Go, Java, and more | 🧪🛠️ Planned | WASM + Extism |

Native bindings = native Rust performance when validating STIX 🦾 



## Quick Start 🗡️

```bash
cd python
pip install -e .
```

```python
from stixflayer import AttackPattern

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries can clear or remove bash_history to hide their tracks...",
    spec_version="2.1"
)
print(ap.to_json())
```

## Structure 🏰

```
rust/       Core engine
python/     Python SDK
poc/        Experimental language bindings & prototypes
```

## Credits & License 📜

Indebted to [OASIS](https://github.com/oasis-open/cti-rust-stix) for the official STIX 2.1 reference implementation.  
[BSD-3-Clause](LICENSE). Community-driven, in the spirit of STIX interoperability. ⚔️🛡️
