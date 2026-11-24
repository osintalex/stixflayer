# Tasks

## 1. Extension model

- [ ] 1.1 Change `HttpRequestExtension.request_header` to `StixDictionary<Vec<String>>` in `rust/src/extensions/network_traffic.rs` and update its doc comment to state that each value is a list of strings; verify `cargo check -p stixflayer` passes.
- [ ] 1.2 Update `deserialize_network_traffic_http_dict` in `rust/src/cyber_observable_objects/sco/network_traffic.rs` to use list values and assert the round-trip, and replace `deserialize_network_traffic_http_request_invalid_header` with a test that a bare string value is rejected; verify `cargo test -p stixflayer network_traffic` passes.
- [ ] 1.3 Update `http_request_headers_accept_custom_names` in `rust/tests/validation_outcomes.rs` to use list values, keep the no-lowercase-warning assertion, and add a case asserting a string value is invalid; verify `cargo test -p stixflayer --test validation_outcomes` passes.

## 2. Fixtures and matrix

- [ ] 2.1 Add `testdata/stix/valid/scos/network-traffic-http-request-headers.json` with a single-value header and a repeated header, plus an `http-request-header-values-valid` rule in `testdata/test_matrix.json`; verify `uv run pytest tests/test_matrix.py -q` passes.
- [ ] 2.2 Add `testdata/stix/invalid/sco/network-traffic-http-request-header-string.json` with a bare string value and an `http-request-header-string-invalid` rule expecting `deserialization_error`; verify `uv run pytest tests/test_matrix.py -q` passes.

## 3. Python coverage and docs

- [ ] 3.1 Add `tests/test_network_traffic_extensions.py` covering a list-valued header round-trip through `NetworkTraffic.from_json` and a bare string value raising `DeserializationError`; verify `uv run pytest tests/test_network_traffic_extensions.py -q` passes.
- [ ] 3.2 Update the HTTP header note in `docs/guides/conformance.md` to state that `request_header` values are lists of strings and cite §6.12.2; verify `.venv-docs/bin/zensical build --clean --strict` succeeds.

## 4. Integration verification

- [ ] 4.1 Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` from `rust/`; verify all pass.
- [ ] 4.2 Run `uv run ruff check .`, `uv run pyrefly check`, and `uv run pytest`; verify all pass.
- [ ] 4.3 Run the CLI against the new valid fixture and verify exit `0`, then against the new invalid fixture and verify exit `1`; record both commands and results in the change review notes.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Note the breaking Rust constructor change in the next release notes.
