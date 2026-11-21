# Benchmark notes

Measured with `uv run pytest benchmarks --benchmark-only` on the implementation
branch (Linux aarch64, CPython 3.14, `dev` profile).

| Path | Mean | Notes |
|---|---|---|
| `Identity` constructor | ~176 µs | Assembly + one semantic pass (previously validated twice: `validate_value` then `build()`) |
| `Identity.from_json` | ~149 µs | Same single pass as the constructor |
| `stixflayer.check()` | ~148 µs | Non-raising outcome path; same pass as `from_json` |
| `Bundle.from_json` (`apt1`) | ~7.5 ms | Each object validated once; bundle invariants only afterward |

The constructor/parse collapse removes the duplicate `stix_check` pass, so the
constructor now costs roughly the same as `from_json` instead of validating the
object twice. `CheckContext` allocates a `Vec` lazily: when no warning fires the
vector stays empty, so the outcome path adds no measurable overhead relative to
the `Result` path. No benchmark exceeded the pre-change order of magnitude.
