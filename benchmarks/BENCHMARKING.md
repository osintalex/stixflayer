# Benchmarking stixflayer

This directory contains repeatable benchmarks comparing `stixflayer` against
`stix2-validator` on representative STIX 2.1 bundles.

## Running the benchmarks

```bash
# Build the release extension first so the Python harness uses optimised Rust.
uv run maturin develop --release

# Parse benchmarks (single objects and bundles)
uv run pytest benchmarks/test_parse_benchmarks.py --benchmark-only

# Serialization benchmarks
uv run pytest benchmarks/test_serialization_benchmarks.py --benchmark-only

# Iteration benchmarks
uv run pytest benchmarks/test_iteration_benchmarks.py --benchmark-only
```

## Fixtures

- `apt1.json` — publicly available APT1 threat intel bundle.
- `poisonivy.json` — publicly available Poison Ivy threat intel bundle.
- `testdata/stix/valid/` — curated single-object SDO/SCO/SRO/meta fixtures.

## Results

The numbers below are produced by this harness on a local development machine
and are intended as a representative snapshot, not a formal release benchmark.

### Parse + validate

| Fixture | `stix2-validator` | `stixflayer` | speedup |
|---------|-------------------|--------------|---------|
| `apt1` bundle | ~47 ms | ~1.6 ms | ~30× |
| `poisonivy` bundle | ~99 ms | ~2.3 ms | ~43× |

### Serialize back to JSON

| Fixture | `stix2` | `stixflayer` | speedup |
|---------|---------|--------------|---------|
| `apt1` bundle | ~0.6 ms | ~0.06 ms | ~10× |
| `poisonivy` bundle | ~1.0 ms | ~0.09 ms | ~12× |

## Notes

- Rounds and warmup are configured in the individual test files via
  `benchmark.pedantic(...)`.
- Generated `.json` benchmark result files are ignored by git; only the
  summarised Markdown numbers are committed.
