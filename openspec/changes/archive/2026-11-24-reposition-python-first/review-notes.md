# Review notes

## Task 6.2 — README CLI example

The README's CLI example depends on the `add-validation-cli` change (archived
as `2026-11-23-add-validation-cli`). It was verified against the applied CLI:

```console
cargo run --quiet --manifest-path rust/Cargo.toml -p stixflayer-cli -- testdata/stix/valid/bundle.json
1 files: 1 valid, 0 invalid, 0 skipped; 2 objects, 0 errors, 0 warnings
exit=0
```

## Task 5.1 — Documentation examples

```console
uv run pytest tests/test_docs_examples.py -q
40 passed
```

## Task 5.2 — Site build

```console
.venv-docs/bin/zensical build --clean --strict
No issues found
```

## Task 6.1 — Quality gates

```console
uv run ruff check .        # All checks passed
uv run pyrefly check       # 0 errors (1 suppressed)
uv run pytest              # 487 passed, 100 skipped
cargo fmt --all -- --check # clean
cargo test -p stixflayer --doc # 1 passed
```

## Task 3.1 — Conformance claim checks

- Every fixture, matrix rule, and Rust source path cited by
  `docs/guides/conformance.md` exists.
- Every OASIS section anchor used by the page exists in the local
  `stix-2.1-spec.html`.
- The `request_header` note was checked manually with a network-traffic
  object carrying mixed-case keys (`X-Custom-Header`, `user-agent`): the keys
  are accepted and their case is preserved.

### Follow-up observation

The manual `request_header` check used string values. STIX 2.1 §6.12.2
requires each `request_header` value to be a list of strings, but
`rust/src/extensions/network_traffic.rs` models it as
`StixDictionary<String>`. This pre-existing value-type gap is outside this
documentation-only change and should be tracked separately.
