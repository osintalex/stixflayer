# 🧠 Stixflayer 🦑

[![CI](https://github.com/osintalex/stixflayer/actions/workflows/ci.yml/badge.svg)](https://github.com/osintalex/stixflayer/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/stixflayer)](https://pypi.org/project/stixflayer/)
[![crates.io](https://img.shields.io/crates/v/stixflayer)](https://crates.io/crates/stixflayer)

The fastest, most spec-correct STIX 2.1 library for Python, powered by a Rust engine, with a native CLI.

## Install

```console
pip install stixflayer
```

The CLI is a standalone binary. Install it with the release script:

```console
curl -LsSf https://github.com/osintalex/stixflayer/releases/latest/download/install.sh | sh
```

`pip install stixflayer-cli`, `pipx install stixflayer-cli`, and `cargo install stixflayer-cli` also work.

## Examples

**Parse and validate a bundle:**

```python
from stixflayer import Bundle

bundle = Bundle.from_json(
    '{"type": "bundle", "id": "bundle--0c7b5d88-7c1c-4a8b-8f0c-6e9d4f2b1a55", "objects": ['
    '{"type": "ipv4-addr", "id": "ipv4-addr--9ddd739e-87b1-587d-83f2-62ef1130af2f", "value": "203.0.113.7"}'
    "]}"
)
print(bundle.object_count)
#> 1
for obj in bundle.objects:  # live Python wrappers, not raw dicts
    print(obj.type, obj.id)
    #> ipv4-addr ipv4-addr--9ddd739e-87b1-587d-83f2-62ef1130af2f
```

**Catch a structured validation error:**

```python
from stixflayer import AttackPattern, ValidationError

try:
    AttackPattern.from_json(
        '{"type": "attack-pattern", "spec_version": "2.1", "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830", "created": "2019-04-24T15:12:36.609Z", "modified": "2023-03-24T15:14:15.637Z"}'
    )
except ValidationError as e:
    print(e.errors[0]["kind"], e.errors[0]["property"])
    #> missing_property name
```

**Validate a STIX pattern:**

```python
import stixflayer

stixflayer.validate_pattern("[ipv4-addr:value = '192.0.2.1']")

try:
    stixflayer.validate_pattern("[ipv4-addr:value = 192.0.2.1]")
except Exception as e:
    print(type(e).__name__)
    #> ValidationError
```

## CLI

Validate a file, a directory, or standard input:

```console
stixflayer testdata/stix/valid/bundle.json
```

Exit `0` means every document is valid, `1` means at least one is invalid, and `2` means a usage or I/O failure. See the [CLI reference](https://osintalex.github.io/stixflayer/cli/).

## Why stixflayer

- **Speed**: one Rust engine parses, validates, and serializes at native speed. See the [benchmark table](benchmarks/BENCHMARKING.md).
- **MUST/SHOULD correctness**: MUST violations fail; SHOULD findings are warnings.
- **Complete structural validation**: rejects empty bundles, malformed identifiers, incorrect SCO UUIDv5 hashes, and closed-enumeration violations.

| Fixture | `stix2-validator` | `stixflayer` | speedup |
|---|---|---|---|
| `apt1` bundle | ~47 ms | ~1.6 ms | ~**30×** |
| `poisonivy` bundle | ~99 ms | ~2.3 ms | ~**43×** |

## Documentation

- [Quickstart](https://osintalex.github.io/stixflayer/quickstart/) · [Guides](https://osintalex.github.io/stixflayer/guides/parsing/)
- [Conformance](https://osintalex.github.io/stixflayer/guides/conformance/) · [API reference](https://osintalex.github.io/stixflayer/api/overview/)
- [CLI reference](https://osintalex.github.io/stixflayer/cli/) · [Rust crate](https://crates.io/crates/stixflayer) · [docs.rs](https://docs.rs/stixflayer)

## Credits and license

Stixflayer builds on [OASIS CTI's `cti-rust-stix`](https://github.com/oasis-open/cti-rust-stix), the official STIX 2.1 reference implementation in Rust. Its object model, validation behavior, and pattern grammar are the starting point from which this engine grew. Released under [BSD-3-Clause](LICENSE).
