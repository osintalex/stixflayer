# Design

## Context

See `proposal.md` — Why. Three facts shape the approach:

1. Requiredness is enforced in two places: `check_required_fields` in `rust/src/domain_objects/sdo.rs` (called from `DomainObject::check`) and per-type `check()` overrides such as `Indicator::check` in `rust/src/domain_objects/sdo/indicator.rs`. Both hand-write rules that the specification states in its property tables.
2. `StixError` is an enum. Structured entries are produced by `StixError::errors() -> Vec<Entry>`, which is the single conversion point used by Python exceptions, `Outcome`, and `to_json()`.
3. `validate_value_from_object_parts` (`rust/src/validation.rs`) is the single choke point for every parse path: bundle objects, single-object `from_json`, Python builders, and meta objects. `validate_value_from_object_outcome` delegates to it.

## Goals / Non-Goals

**Goals:**
- Stop rejecting the Amnesty and MVT feeds, with regression fixtures that encode the spec clause.
- Attribute object-scoped findings to their object without changing the `Entry` shape.
- Keep the changes additive for both the Rust and Python surfaces.

**Non-Goals:**
- Generating requiredness from the spec tables (a larger refactor; see Risks).
- Any STIX 2.0 support.
- Changing pattern grammar, vocabularies, or warning classification beyond the identifier rule.

## Decisions

### D1: Fix the rules in place rather than generate them from a table

The two false positives are localized: delete the `Indicator` name check, and make the `Malware` name check conditional. A table-driven requiredness model would eliminate this class of drift, but it would touch every SDO and is not needed to close these findings. The drift guard is the fixture matrix: every rule that is changed gets a valid and an invalid fixture in `testdata/test_matrix.json`.

*Alternative considered:* derive required properties from a checked-in spec table. Rejected for this change — larger blast radius, and the matrix already gives us a differential harness for the future CLI work.

### D2: Attach the id with a wrapper variant, not a field on every variant

```rust
/// An error attributed to a specific STIX object.
#[error("{error}")]
Located {
    object_id: String,
    #[source]
    error: Box<StixError>,
},
```

`errors()` flattens it and stamps any entry that does not already carry an id:

```rust
StixError::Located { object_id, error } => {
    let mut entries = error.errors();
    for entry in &mut entries {
        if entry.object_id.is_none() {
            entry.object_id = Some(object_id.clone());
        }
    }
    entries
}
```

`Display` delegates to the inner error, so human messages are unchanged. `ValidationErrors` keeps flattening; a `Located` inside it stamps only its own subtree. `KNOWN_ERROR_KINDS` is unaffected because `Located` never surfaces as an entry `kind`.

*Alternatives rejected:* adding `object_id` to every variant (noise, and most variants have no object); converting errors to `Vec<Entry>` early and adding a `ValidationEntries` variant (two representations of the same error, and it bypasses `StixError` for no gain).

### D3: Stamp at the validation choke point

`validate_value_from_object_parts` reads `id` before the value is moved and wraps the single returned `Result`:

```rust
let object_id = value.get("id").and_then(Value::as_str).map(str::to_owned);
let (result, warnings) = validate_value_from_object_parts_inner(value, allow_custom, strict);
let result = result.map_err(|error| match object_id {
    Some(id) if !matches!(error, Error::Located { .. }) => Error::Located { object_id: id, error: Box::new(error) },
    _ => error,
});
```

This covers bundles, single objects, and Python constructors without touching `from_json_parts`, which keeps accumulating `Vec<StixError>` unchanged.

### D4: Bundle invariants stamp their own entries

`check_invariants` runs outside any object, so it wraps the errors it creates where the subject is known: duplicate-id findings use the duplicated id, relationship-reference findings use the relationship's id. `check_invariants` returns `Result<(), Error>`; each branch wraps with `Error::Located`.

### D5: A distinct warning kind for identifier UUID versions

`Identifier::check` already receives `&mut CheckContext`, so the UUIDv5 case becomes `ctx.warn(Entry::new("identifier_uuid_not_v4", …))` and the function returns `Ok(())`. The new kind is added to `KNOWN_WARNING_KINDS` and the error/warning catalog. Keeping it distinct from the existing `invalid_uuid` error keeps the error and warning kind sets disjoint: `invalid_uuid` continues to mean "not a UUID version STIX supports" (v1, v3, etc.), which remains an error.

The message must state the spec correctly: identifiers **SHOULD** use UUIDv4; the current text says MUST.

### D6: Conditional Malware name

In `check_required_fields`, require `name` only when `malware.is_family` is true. `is_family` already defaults to `false` through serde, so an absent `is_family` means "instance" and a missing name is accepted.

### D7: Report only the fields that are absent

Replace the `Indicator` arm's all-or-nothing error with a per-field check that pushes a `MissingProperty` for each absent or empty required field. This removes the two phantom findings described in `specs/spec-conformance/spec.md`.

### D8: Remove the redundant `stix_check()` calls

The `Location` and `Malware` arms of `check_required_fields` call `stix_check()` and discard the result; `DomainObject::check` already runs the per-type check. Remove the dead calls so the function only checks requiredness. This is a cleanup with no behavior change.

## Risks / Trade-offs

- **Loosening validation could accept genuinely invalid documents** → each loosened rule gets an invalid counterpart fixture (Malware family without a name must still fail), and the existing suite runs unchanged.
- **`StixError` gains a variant, so exhaustive matches may need a case** → `strum`'s discriminant enum gains `Located`; the compiler flags any exhaustive match at build time. No runtime fallback is needed.
- **The unarchived `add-validation-outcomes` change touches the same files** (`validation.rs`, `error/`, `indicator.rs`) → implement this change on top of that work or rebase onto it before applying; the delta is small and mechanical.
- **The new warning kind is public surface** → it is added to `KNOWN_WARNING_KINDS` and the catalog, with a drift test, before release.
- **Hand-written requiredness can drift again** → the fixture matrix is the guard; a future table-driven refactor is the structural fix, explicitly deferred.

## Migration Plan

No user migration. The changes are additive or loosening: `.errors` entries gain an optional `object_id`, UUIDv5 non-SCO identifiers move from rejected to accepted-with-warning, and Indicator/Malware documents that were previously rejected become valid. Rollback is a straight revert; no persisted state changes.

## Open Questions

None that affect the specs, approach, or task breakdown.
