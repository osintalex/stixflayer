# 🧠 Stixflayer 🦑

[![CI](https://github.com/osintalex/stixflayer/actions/workflows/ci.yml/badge.svg)](https://github.com/osintalex/stixflayer/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/stixflayer)](https://pypi.org/project/stixflayer/)
[![crates.io](https://img.shields.io/crates/v/stixflayer)](https://crates.io/crates/stixflayer)

Rust-native STIX 2.1 engine. One spec-compliant core, consumed by many.

## Performance 🚀⚡

stixflayer uses a single Rust core for validation and serialization, so you
get native Rust throughput from every language binding.

| Operation | Baseline Python validator | `stixflayer` | speedup |
|-----------|---------------------------|--------------|---------|
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

## Why another STIX library? 🤔

- **One engine, no validation gaps** 🌍: Most STIX libraries are reimplemented
  per-language, which creates subtle interoperability bugs — the same document
  can be valid in one language and rejected in another. stixflayer solves this
  by shipping a single Rust core into every supported language: data validates
  the same way everywhere.
- **Spec-first, not tool-first** ⚔️: Behavior follows the OASIS STIX 2.1
  specification, including its MUST/SHOULD distinction. MUST violations fail;
  SHOULD findings are reported as warnings without rejecting the document.
- **Complete structural validation** 🧐: Rejects empty bundles, malformed
  identifiers, incorrect SCO UUIDv5 hashes, and closed-enumeration violations,
  and validates every object exactly once.

## Languages 🔌

| Language | Status | Binding |
|----------|--------|---------|
| Rust | 🦀✅ Released ([crates.io](https://crates.io/crates/stixflayer)) | Native |
| Python | 🐍✅ Released ([PyPI](https://pypi.org/project/stixflayer/)) | Native ([pyo3](https://pyo3.rs/)) |
| TypeScript | 🧙🛠️ Next up | [napi.rs](https://napi.rs/) |
| Go, Java, and more | 🧪🛠️ Planned | WASM + Extism |

Python and Rust ship first; TypeScript is next. Native bindings mean native
Rust performance when validating STIX 🦾

## Quick Start 🗡️

```bash
pip install stixflayer
```

Rust users: `cargo add stixflayer`, or browse the API on
[docs.rs](https://docs.rs/stixflayer). Full documentation, guides, and a
curated API reference live at
[osintalex.github.io/stixflayer](https://osintalex.github.io/stixflayer/).

## Examples

The most common things you can do with the Python bindings. Every example
below is executed in CI — what you see is what it prints.

**Parse and validate a STIX bundle:**

```python
import json

from stixflayer import Bundle

document = json.dumps(
    {
        "type": "bundle",
        "id": "bundle--0c7b5d88-7c1c-4a8b-8f0c-6e9d4f2b1a55",
        "objects": [
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
                "created": "2019-04-24T15:12:36.609Z",
                "modified": "2023-03-24T15:14:15.637Z",
                "name": "Clear Command History",
            },
        ],
    }
)

bundle = Bundle.from_json(document)
print(bundle.object_count)
#> 1
for obj in bundle.objects:  # live Python wrappers, not raw dicts
    print(obj.type, obj.id)
    #> attack-pattern attack-pattern--d3046a90-580c-4004-8208-66915bc29830
```

**Build an SDO and serialize it back to JSON:**

```python
import json

from stixflayer import AttackPattern

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries clear or remove bash_history to hide their tracks.",
    spec_version="2.1",
)
roundtrip = json.loads(ap.to_json())
print(roundtrip["type"], roundtrip["name"])
#> attack-pattern Clear Command History
```

**Catch structured validation errors:**

```python
from stixflayer import AttackPattern, ValidationError

try:
    AttackPattern.from_json(
        '{"type": "attack-pattern", "spec_version": "2.1", "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830", "created": "2019-04-24T15:12:36.609Z", "modified": "2023-03-24T15:14:15.637Z"}'
    )
except ValidationError as e:
    print(e.errors)
    """
    [
        {
            "kind": "missing_property",
            "message": "`attack-pattern` is missing required property 'name'",
            "property": "name",
        }
    ]
    """
```

**Validate a STIX pattern:**

```python
import stixflayer

stixflayer.validate_pattern("[ipv4-addr:value = '192.0.2.1']")

try:
    stixflayer.validate_pattern("[ipv4-addr:value = 192.0.2.1]")
except Exception as e:
    print(type(e).__name__, "-", e)
    """
    ValidationError
    -
    Failed to parse STIX Pattern [ipv4-addr:value = 192.0.2.1]: 1:25: expected 'AND' or 'OR' or ']', found .
    """
```

## Spec conformance notes 🔍

The OASIS STIX 2.1 specification is authoritative. These notes record the
places where behavior is easy to get wrong and where stixflayer follows the
specification deliberately.

- **SHOULD findings are warnings.** Open-vocabulary values outside the
  suggested terms, non-SHA-256 hashes, uppercase `extensions` keys, custom
  relationship types, and similar recommendations do not reject a document.
  They are returned in `.warnings`, and exceptions carry both `.errors` and
  `.warnings`.
- **Dictionary keys allow up to 250 characters.** STIX 2.1 caps dictionary and
  hash keys at 250 ASCII characters; shorter keys are not rejected.
- **Language tags are well-formed RFC 5646 values.** Both the common `lang`
  property and `Software.languages` accept well-formed tags, including ISO
  639-2 three-letter codes such as `eng`. Registry membership is a SHOULD.
- **HTTP header names are unrestricted.** The `request_header` dictionary
  accepts any valid header field name; headers keep their case.
- **Zero qualifier values.** The specification requires `REPEATS` to be a
  positive integer and `WITHIN` to be a positive value. stixflayer rejects
  `REPEATS 0` and `WITHIN 0`.
- **Hash value inspection in patterns.** Pattern validation follows the
  grammar and does not inspect hash formats.
- **Leading block comments.** A pattern may start with a block comment because
  the grammar skips comments.
- **Negative list indices.** The grammar allows `IntNegLiteral`, so an index
  such as `body_multipart[-1]` is accepted.
- **Custom SCO type casing.** Custom SCO type names must be 3-250 characters
  of lowercase ASCII letters, digits, or hyphens.
- **Reversed or empty `START`/`STOP` ranges.** The specification defines the
  matched range as `x <= observation < y` but does not prohibit `x >= y`.
  Reversed and equal ranges are accepted.

## Structure 🏰

```
rust/         Core engine (Rust crate + pyo3 bindings + derive macros)
src/          Python package (stixflayer)
tests/        Python test suite
benchmarks/   Speed benchmarks (see BENCHMARKING.md)
testdata/     STIX fixtures used by tests and benchmarks
```

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
