# stixflayer

Fast, strict STIX 2.1 parsing, validation, and serialization in Rust.

stixflayer validates STIX 2.1 JSON against the OASIS specification, including
its MUST/SHOULD distinction. The same engine also powers the Python package and
the `stixflayer` CLI, so every interface returns the same verdict.

## Install

```console
cargo add stixflayer
```

## Parse and validate

Parsing validates. `Bundle::from_json` returns a parsed bundle or a structured
`StixError`; there is no separate validate call to forget.

```rust
use stixflayer::Bundle;

fn main() -> Result<(), stixflayer::StixError> {
    let json = r#"{
        "type": "bundle",
        "id": "bundle--0c7b5d88-7c1c-4a8b-8f0c-6e9d4f2b1a55",
        "objects": [{
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
            "created": "2019-04-24T15:12:36.609Z",
            "modified": "2023-03-24T15:14:15.637Z",
            "name": "Clear Command History"
        }]
    }"#;

    let bundle = Bundle::from_json(json)?;
    assert_eq!(bundle.get_objects().len(), 1);

    // Warnings are SHOULD findings; they do not make the document invalid.
    let outcome = Bundle::from_json_outcome(json);
    assert!(outcome.valid);
    assert!(outcome.errors.is_empty());

    Ok(())
}
```

## Validation model

- Structural checks always run: required properties, JSON types, identifiers,
  timestamps, and closed enumerations.
- MUST violations are errors. SHOULD findings are warnings and never reject a
  document. `from_json_outcome` returns both lists as structured entries with
  `kind`, `message`, and optional `property`, `value`, and `object_id` fields.
- `ValidationOptions::new(allow_custom, strict)` controls unknown properties
  and semantic checks. The default is `(false, true)`: unknown properties are
  rejected and SHOULD checks run.
- Validation collects independent findings instead of stopping at the first
  error. Object-scoped findings carry the object's `id`.

See the [`StixError`](https://docs.rs/stixflayer/latest/stixflayer/enum.StixError.html)
API documentation for the error and warning kinds.

## Command-line validation

The `stixflayer` binary validates files, directories, and standard input
without a Python or Rust project:

```console
cargo install stixflayer-cli
stixflayer path/to/bundle.json
```

It exits `0` when every document is valid, `1` when any document is invalid,
and `2` on a usage or I/O failure.

## Related packages

- Python library: `pip install stixflayer`
- CLI: `cargo install stixflayer-cli` or `pip install stixflayer-cli`
- Guides and conformance notes: <https://osintalex.github.io/stixflayer/>
- API reference: <https://docs.rs/stixflayer>

## License

[BSD-3-Clause](https://github.com/osintalex/stixflayer/blob/main/LICENSE)
