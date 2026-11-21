# Benchmark notes

Measured with `uv run pytest benchmarks --benchmark-only` on the implementation
branch (Linux aarch64, CPython 3.14, `dev` profile).

| Path | Mean | Notes |
|---|---|---|
| `Identity` constructor | ~163 µs | Assembly + one semantic pass (previously validated twice: `validate_value` then `build()`) |
| `Identity.from_json` | ~141 µs | Same single pass as the constructor |
| `Bundle.from_json` (`apt1`) | ~7.0 ms | Each object validated once; bundle invariants only afterward |

The constructor/parse collapse removes the duplicate `stix_check` pass, so the
constructor now costs roughly the same as `from_json` instead of validating the
object twice. `CheckContext` allocates a `Vec` lazily: when no warning fires the
vector stays empty, so warning collection adds no measurable overhead to the
`Result` path. No benchmark exceeded the pre-change order of magnitude.
