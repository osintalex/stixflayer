# 🧠 Stixflayer 🦑

[![CI](https://github.com/osintalex/stixflayer/actions/workflows/ci.yml/badge.svg)](https://github.com/osintalex/stixflayer/actions/workflows/ci.yml)

Rust-native STIX 2.1 engine. One spec-compliant core, consumed by many.

## Performance 🚀⚡

stixflayer uses a single Rust core for validation and serialization, so you
get native Rust throughput from every language binding.

| Operation | [`stix2-validator`](https://github.com/oasis-open/cti-stix-validator) | `stixflayer` | speedup |
|-----------|-------------------------------|--------------|---------|
| Parse + validate `apt1` bundle | ~47 ms | ~1.6 ms | ~**30×** 🏎️💨 |
| Parse + validate `poisonivy` bundle | ~99 ms | ~2.3 ms | ~**40×** 🏎️💨 |

| Operation | [`stix2`](https://github.com/oasis-open/cti-stix) | `stixflayer` | speedup |
|-----------|-------------------------------|--------------|---------|
| Serialize `apt1` bundle back to JSON | ~0.6 ms | ~0.06 ms | ~**10×** 🏎️💨 |
| Serialize `poisonivy` bundle back to JSON | ~1.0 ms | ~0.09 ms | ~**12×** 🏎️💨 |

See [`benchmarks/BENCHMARKING.md`](benchmarks/BENCHMARKING.md) for
the harness, fixtures, and how to reproduce the numbers.

## Credits 🙏

Stixflayer is deeply indebted to [OASIS CTI's `cti-rust-stix`](https://github.com/oasis-open/cti-rust-stix), the official STIX 2.1 reference implementation in Rust. This project's object model, validation behavior, and pattern grammar all build on that foundation — it is the starting point from which the stixflayer engine grew, and we are grateful for the rigor and generosity of that work.

We also benchmark against, and owe a debt of comparison to, [`cti-stix-validator`](https://github.com/oasis-open/cti-stix-validator), the industry-standard Python validator.

## Why another STIX library? 🤔

- **One engine, no validation gaps** 🌍: Most STIX libraries are reimplemented
  per-language, which creates subtle interoperability bugs — the same document
  can be valid in one language and rejected in another. stixflayer solves this
  by shipping a single Rust core into every supported language: data validates
  the same way everywhere.
- **Battle-tested, but faster** ⚔️: Built from the official OASIS reference
  implementation, with full parity (and then some) against the industry-standard
  [`cti-stix-validator`](https://github.com/oasis-open/cti-stix-validator). Same
  trusted spec compliance, rewritten in Rust for speed, correctness, and
  interoperability.
- **Stricter where it matters** 🧐: Actively improves on `stix2validator` by
  enforcing rules it skips — rejecting empty bundles, invalid vocabulary
  values, and incorrect SCO UUIDv5 hashes.

## Languages 🔌

| Language | Status | Binding |
|----------|--------|---------|
| Rust | ⚙️🚀 First release coming soon | Native |
| Python | 🐍🚀 First release coming soon | Native ([pyo3](https://pyo3.rs/)) |
| TypeScript | 🧙🛠️ Next up | [napi.rs](https://napi.rs/) |
| Go, Java, and more | 🧪🛠️ Planned | WASM + Extism |

Python and Rust ship first; TypeScript is next. Native bindings mean native
Rust performance when validating STIX 🦾

## Quick Start 🗡️

The published packages are coming soon. Until then, install from source:

```bash
pip install -e .
```

## Examples

> 📚 **Full documentation is coming soon.** Until then, here are the most
> common things you can do with the Python bindings today.

**Parse and validate a STIX bundle:**

```python
from stixflayer import Bundle

bundle = Bundle.from_json(open("bundle.json").read())
print(bundle.object_count)  # number of objects
for obj in bundle.objects:  # live Python wrappers, not raw dicts
    print(obj.type, obj.id)
```

**Build an SDO:**

```python
from stixflayer import AttackPattern

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries clear or remove bash_history to hide their tracks.",
    spec_version="2.1",
)
```

**Catch structured validation errors:**

```python
from stixflayer import AttackPattern, ValidationError

try:
    AttackPattern.from_json(
        '{"type": "attack-pattern", "spec_version": "2.1", "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830", "created": "2019-04-24T15:12:36.609Z", "modified": "2023-03-24T15:14:15.637Z"}'
    )
except ValidationError as e:
    print(e.errors)  # [{'kind': 'missing_property', 'message': "...", 'property': 'name'}]
```

**Validate a STIX pattern:**

```python
import stixflayer

stixflayer.validate_pattern("[ipv4-addr:value = '192.0.2.1']")
```

**Serialize back to JSON:**

```python
import json

roundtrip = json.loads(ap.to_json())
```

## Structure 🏰

```
rust/         Core engine (Rust crate + pyo3 bindings + derive macros)
src/          Python package (stixflayer)
tests/        Python test suite
benchmarks/   Speed benchmarks vs stix2-validator (see BENCHMARKING.md)
testdata/     STIX fixtures used by tests and benchmarks
```

## Continuous integration ⚙️

Every pull request and every push to `main` runs a two-stage pipeline
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

1. **Quality gate** — six parallel jobs that must all pass:
   `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo build` for the
   Rust workspace; `ruff format --check`, `ruff check`, and `pyrefly check`
   for the Python code.
2. **Tests** — only once the whole gate is green: the Rust test suite on
   Linux, macOS, and Windows, cross-compile builds for
   `aarch64-linux` and `x86_64-musl` targets, and the Python test suite
   against the freshly built extension on all three operating systems.

## Releasing 🚀

Releases happen automatically on merge to `main`
([`.github/workflows/release.yml`](.github/workflows/release.yml)) — but only
if you bumped a version:

- **Python package**: raise the version in `pyproject.toml` → the release
  pipeline builds one `abi3` wheel per platform (Linux x86_64 + aarch64, both
  glibc and musl; macOS arm64; Windows x86_64), smoke-tests each wheel, and
  publishes all of them to PyPI in a single release.
- **Rust library**: raise the version in `rust/Cargo.toml` → the pipeline
  verifies tests and cross-compiles on all supported targets, then publishes
  to crates.io.

A version that hasn't changed since its last release tag (`py-v*` /
`rust-v*`) publishes nothing — a merge without a bump is just a merge.

**Bump both Rust crates together.** The release gate keys on the main
crate's version in `rust/Cargo.toml`; `stixflayer_derive` (the proc-macro
crate) must be published before `stixflayer` can be, so when you bump, raise
both crates' versions in the same change and the pipeline handles the
publish order.

**One-time setup prerequisites:**

- Register the [PyPI trusted publisher](https://docs.pypi.org/trusted-publishers/)
  for `osintalex/stixflayer`, workflow `release.yml`, environment `pypi`.
- Add the crates.io API token as the `CARGO_REGISTRY_TOKEN` repository secret.
- Set the `ci.yml` jobs as required status checks on `main` (GitHub branch
  protection settings).

## Development 🛠️

Python quality gates:

```bash
uv run ruff check .     # linting (aggressive rule set, see pyproject.toml)
uv run pyrefly check    # type checking
uv run pytest           # tests
```

Rust quality gates:

```bash
cargo fmt --all -- --check                             # formatting
cargo clippy --workspace --all-targets -- -D warnings  # lints
cargo test                                             # tests
```

**Type stubs policy:** the public entry points (`stixflayer/__init__.pyi`,
`stixflayer/stixflayer.pyi`) are fully typed so IDEs and type checkers resolve
the whole public API. Stubs cover the public surface only — we don't maintain
`.pyi` files for internals. When the compiled surface changes, update the
stubs in the same change.

## License 📜

[BSD-3-Clause](LICENSE). Community-driven, in the spirit of STIX interoperability. ⚔️🛡️
