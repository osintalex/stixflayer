# Review notes

## Task 4.3 — CLI verdicts for the new fixtures

Valid fixture — single-value and repeated `request_header` entries:

```console
cargo run --quiet --manifest-path rust/Cargo.toml -p stixflayer-cli -- testdata/stix/valid/scos/network-traffic-http-request-headers.json
1 files: 1 valid, 0 invalid, 0 skipped; 1 objects, 0 errors, 0 warnings
exit=0
```

Invalid fixture — bare string `request_header` value:

```console
cargo run --quiet --manifest-path rust/Cargo.toml -p stixflayer-cli -- testdata/stix/invalid/sco/network-traffic-http-request-header-string.json
testdata/stix/invalid/sco/network-traffic-http-request-header-string.json: error [deserialization_error] (network-traffic--550e8400-e29b-51d4-a716-446655440027) Deserialization error: invalid type: string "www.example.com", expected a sequence
1 files: 0 valid, 1 invalid, 0 skipped; 1 objects, 1 errors, 0 warnings
exit=1
```

## Task 4.1 — Rust quality gates

```console
cargo fmt --all -- --check                          # clean
cargo clippy --workspace --all-targets -- -D warnings # clean
cargo test --workspace                              # all suites pass
```

The CLI matrix harness (`rust/stixflayer-cli/tests/cli.rs`) now recognizes
`deserialization_error` as an invalid-document expectation, which the new
`http-request-header-string-invalid` rule requires.

## Task 4.2 — Python quality gates

```console
uv run ruff check .   # All checks passed
uv run pyrefly check  # 0 errors (1 suppressed)
uv run pytest         # 492 passed, 102 skipped
```
