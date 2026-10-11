# Design

## Context

The Rust engine has a typed error enum (`StixError`) whose structured entries flow to Python as an `.errors` list on exceptions (see `rust/src/error/mod.rs`, `rust/src/python_bindings/error.rs`). Today only three variants produce entries (`MissingProperty`, `UnknownProperties`, `InvalidPropertyType`); everything else yields an empty list. Vocabulary checks are centralized in one function (`rust/src/common/validation.rs`), nested "X is not a valid Y: …" messages are composed at four sites, and the pattern parser reports nom's Debug form. The `CustomObject` constructor feeds named kwargs and the `custom_properties` argument into the same map, but the argument *replaces* the map. Motivation: proposal.md — Why.

## Goals / Non-Goals

**Goals:**
- Make error reporting deterministic: same input → same exception, same message, same entries.
- Guarantee `.errors` is non-empty for every exception the library can raise.
- Make every user-facing message free of Rust-internal formatting.
- Pin all fixed behaviors with tests plus a runnable, throwaway release gate.

**Non-Goals:**
- No warnings-as-data / SHOULD-violation surfacing (parked — direction recorded below).
- No logging bridges (pyo3-log) in any binding.
- No pattern grammar changes (backlog ticket exists).
- No change to `x_` prefix enforcement (SHOULD; unenforced by design).
- No changes to validation strictness beyond the CustomObject conflict rule.

## Decisions

### D1: CustomObject conflict → raise, order-independent

The `custom_properties` argument currently *replaces* the map accumulated from named kwargs, so `CustomObject(name="X", custom_properties={...})` silently drops `name`, while the reversed order works. Chosen: merge the dict into the accumulated map, raising a validation error naming the property when a key arrives from both channels — regardless of order, even when both values are equal.

Rationale: STIX 2.1 §11.2 — "Common property names MUST NOT be reused"; on the wire there is one slot per property, so two sources for one slot is a caller error. Raising on identical values keeps the contract to one sentence.

Alternatives considered:
- *Merge, last-wins* — smallest diff, but order-dependent outcomes survive; rejected.
- *Remove the `custom_properties` kwarg* — tests and the established pattern rely on it; rejected.

### D2: `.errors` becomes a total contract

`to_entry()` keeps its three rich variants and gains rich entries for variants with natural structure: `InvalidHash` (hash type), `ParseTimestampError`, `ParseIdentifierError`, `ParsePatternError` (the pattern text), and the new `InvalidVocabValue` (D3). A catch-all gives every remaining variant `{"kind": "<variant-name-snake-case>", "message": <display>}`, so future variants cannot produce an empty list. Kind strings are API surface — documented in stubs and kept stable.

### D3: Structured vocabulary variant at the single check site

`common/validation.rs` formats `Value '{}' is not a valid {} value.` into a generic `ValidationError(String)`. Replace with `InvalidVocabValue { value, vocabulary }`: one call site, rich entries (`value`, `vocabulary` fields), and it removes the largest contributor to the double-prefix problem. A prefix-stripping nesting helper (D4) remains for the other generic `ValidationError(String)` sites (dictionary/hash key rules).

### D4: Nesting helper for single-prefix messages

Add a method that returns an error's message without the leading `STIX validation error:` prefix, and use it at the four composition sites (`domain_objects/sdo.rs`, `cyber_observable_objects/sco.rs`, `relationship_objects/mod.rs` ×2). Without it, outer messages that embed inner `Display` output repeat the prefix.

### D5: Pattern errors — humanized text, validation category

At the `map_err` in `pattern/mod.rs`, replace `e.to_string()` (nom's Display prints Debug of the inner error) with a small describer mapping nom `ErrorKind`s to plain language plus the remaining input. Move `ParsePatternError` from the `"stix"` fallback to the `"validation"` envelope category so `validate_pattern` raises `ValidationError` — invalid input gets one catch type, consistent with every other invalid-input path.

### D6: Non-object JSON classification

`classify_top_level_type_error` already recovers property names for the kwargs path but bails when the top-level input is not an object, leaking serde's `expected struct DomainObject`. Handle the non-object case explicitly *before* that bail: "Expected a STIX object (JSON object), got array/number/string/boolean/null."

### D7: Release gate — dependency-free scripts

`release-gate/` at repo root: plain stdlib Python scripts (`01_pro_workflows.py`, `02_error_audit.py`, `03_speed_sanity.py`, `04_readme_examples.py`, plus a README stating pass criteria), run with `PYTHONPATH=src`. No pytest or package deps so it runs in a bare environment. It encodes the fixed behaviors as checks (including the D1 conflict scenarios), runs the professional-workflow and speed sanity checks, and is deleted before publishing — never committed.

### D8: Parked direction (recorded, not built)

SHOULD-violation reporting is deferred to a post-release change. Agreed direction: the core computes an outcome that always carries `{value?, errors, warnings}`; bindings map it to their idioms (Python: success → object with `.warnings`, failure → exception with `.errors` and `.warnings`) rather than wrapping every return value. Warning entries carry a `level` field. The existing `warn!` sites get triaged in that change (data / delete dev residue / keep as Rust logs).

### D9: Remove `create_timestamp`

The helper is an orphan: defined in the bindings layer, registered for Python, declared in the stubs — and called by nothing (internals use `Timestamp::new` directly; no test, benchmark, or README usage). Its echo-on-error behavior silently returns invalid input unchanged, and its normalization is redundant with what constructors already do to `created`/`modified`/`valid` inputs. Chosen: delete the function, its registration, its `pub use` entry, and its stub declaration — keeping `parse_extension_type`, which the meta bindings use internally and is not Python-registered. Alternatives: make it raise (keeps surface with no workflow behind it), document pass-through (keeps the footgun).

## Risks / Trade-offs

- [`validate_pattern` exception type changes `StixError` → `ValidationError`] → Nothing is published; note the change in release notes. `ValidationError` subclasses `StixError`, so broad `except StixError` handlers are unaffected.
- [Catch-all kinds become API surface] → Document the kind taxonomy; adding variants is additive, renames are breaking and avoided.
- [Conflict-raise surprises callers who unknowingly mixed channels] → The error names the property; pre-release, so no silent-behavior debt is carried forward.
- [Nom describer may be imprecise for exotic grammar failures] → Message always includes the pattern text and where parsing stopped; grammar completeness is a separate backlog item anyway.
- [Release-gate scripts drift from reality] → They are throwaway by design; a fresh copy can be regenerated from this change's record.

## Migration Plan

Pre-release: no migration. Land the Rust changes with unit tests, update Python regression tests, run the release gate, delete `release-gate/` before publishing. Rollback is a plain revert; nothing external depends on the new behavior yet.
