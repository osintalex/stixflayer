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

## Dev sandbox with microsandbox 🧱

This project ships a [microsandbox](https://docs.microsandbox.dev/) dev setup that runs OpenCode inside an isolated microVM with Rust, Python, uv, and git ready to go.

One-time setup:

```bash
# Build the image
# (Install microsandbox first: https://docs.microsandbox.dev/)
docker build -f Dockerfile.dev -t opencode-dev:latest .

# Load it into the local microsandbox image store
docker save opencode-dev:latest | msb load --tag opencode-dev:latest

# Copy local config templates
cp opencode.json.example opencode.json
cp .env.example .env
# edit .env with your Cloudflare AI Gateway credentials
```

Launch OpenCode in the sandbox:

```bash
source .env
msb run -t --conf microsandbox.yaml
```

The real `CLOUDFLARE_API_TOKEN` stays on the host and is injected only for requests to `api.cloudflare.com` via microsandbox secrets. OpenCode is denied access to `.env` files through `opencode.json` permissions.

Run headless checks:

```bash
# Rust tests
msb run --conf microsandbox.yaml --no-tty --entrypoint sh -- -c \
  'cd /workspace/rust && cargo test --quiet'

# Python tests (also builds the pyo3 extension)
msb run --conf microsandbox.yaml --no-tty --entrypoint sh -- -c \
  'cd /workspace && uv run maturin develop && uv run pytest -q'
```

## Performance 🚀⚡

stixflayer uses a single Rust core for validation and serialization, so you
get native Rust throughput from every language binding.

| Operation | [`stix2-validator`](https://github.com/oasis-open/cti-stix-validator) | `stixflayer` | speedup |
|-----------|-------------------------------|--------------|---------|
| Parse + validate `apt1` bundle | ~47 ms | ~1.6 ms | ~**30×** 🏎️💨 |
| Parse + validate `poisonivy` bundle | ~99 ms | ~2.3 ms | ~**40×** 🏎️💨 |

Serialization back to JSON is also single-digit microseconds for these
bundles — see `benchmarks/BENCHMARKING.md` for the harness, fixtures, and
numbers.

## Structure 🏰

```
rust/       Core engine
python/     Python SDK
poc/        Experimental language bindings & prototypes
```

## Credits & License 📜

Indebted to [OASIS](https://github.com/oasis-open/cti-rust-stix) for the official STIX 2.1 reference implementation.  
[BSD-3-Clause](LICENSE). Community-driven, in the spirit of STIX interoperability. ⚔️🛡️
