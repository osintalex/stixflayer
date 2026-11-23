# Design

## Context

See `proposal.md` for motivation. The engine currently treats a custom object without a `new-sdo` / `new-sco` / `new-sro` extension as a hard error (`CustomObject::get_object_type`), and `Relationship::check` requires every endpoint type to be in the generated `SdoTypes` / `ScoTypes` enums and every spec-defined relationship type to match its table-defined pair. The CLI passes only `allow_custom` and `strict` into the engine.

## Goals / Non-Goals

**Goals:**

- Align extension-less custom-object handling with STIX 2.1 §11.2 (SHOULD, not MUST).
- Keep strict relationship validation as the default.
- Give callers an explicit, documented way to accept ATT&CK-style relationship shapes.
- Keep the existing report shape and existing default behavior stable.

**Non-Goals:**

- Making ATT&CK valid without opting in.
- Inferring that an extension-less custom object is an SDO/SCO/SRO from its name or properties.
- Changing the meaning of `--allow-custom` (custom properties).
- Adding leniency to every Python typed-object constructor in this change.

## Decisions

### D1: Treat extension-less custom objects as generic custom objects

`CustomObject` gains a `CustomObjectKind` of `Sdo`, `Sco`, `Sro`, or `Generic`. A `new-*` extension selects the corresponding kind; no extension selects `Generic`. Generic objects run:

- the §11.2 custom-object type-name rules,
- identifier and common-property checks that do not depend on SDO/SCO/SRO classification,
- custom-property name and suffix-value checks.

They do not run `check_sdo_properties` / `check_sco_properties` / `check_sro_properties`, because those require a declared object kind. Missing extension produces the existing `custom_missing_extension` kind as a warning. Keeping the kind string preserves machine-readable continuity; it moves from `KNOWN_ERROR_KINDS` to `KNOWN_WARNING_KINDS`.

*Alternative rejected:* infer SDO/SCO/SRO from the object name (`x-mitre-*` as SDO). That would be guesswork and would silently validate properties the object never declared.

### D2: Thread a relationship policy through `CheckContext`

Add a `RelationshipPolicy` enum (`Strict`, `AllowCustom`) to `CheckContext`. `CheckContext::new()` keeps `Strict`; a new constructor/setter carries the caller's choice. This avoids changing the `Stix::check(&self, ctx)` signature used by every object type.

Add a `ValidationOptions` struct with `allow_custom`, `strict`, and `relationship_policy`. Existing public functions keep their signatures and delegate to the strict policy. New `*_with_options` entry points carry the full options through object, bundle, and envelope parsing.

*Alternative rejected:* add a boolean parameter to every `Stix::check` implementation. That touches every object type for a policy only relationships need.

### D3: Leniency relaxes exactly two checks and warns

In `Relationship::check`:

- Strict: current endpoint and pair checks.
- AllowCustom: an endpoint outside `SdoTypes` / `ScoTypes` produces a `custom_object_relationship_endpoint` warning instead of an error; a spec-defined relationship type used with an undefined pair produces a `relationship_pair_not_suggested` warning instead of an error.

Custom relationship names keep their existing `relationship_type_not_suggested` warning. Both new kinds are added to `KNOWN_WARNING_KINDS` and the error catalog docs. The outcome/report shape is unchanged.

### D4: CLI flag is explicit

`stixflayer` gains `--allow-custom-relationships`, mapped to `RelationshipPolicy::AllowCustom`. It is independent of `--allow-custom` so users can accept custom properties without accepting custom relationship shapes, and vice versa.

### D5: Python exposure is minimal and opt-in

`Bundle.from_json` and `CustomObject.from_json` gain `allow_custom_relationships=False`. Existing typed-object `from_json` signatures stay strict; callers who need lenient bundle validation use `Bundle.from_json`. This covers the ATT&CK use case without changing every constructor.

### D6: Small regression fixtures, not the ATT&CK file

Add hand-written fixtures under `testdata/stix/` for:

- an extension-less custom object,
- a relationship from an extension-less custom object to an Attack Pattern,
- a `tool uses attack-pattern` relationship.

Tests assert strict rejection, lenient acceptance with the documented warnings, and unchanged default behavior. The 52 MB ATT&CK file is used only for the manual verification task.

## Risks / Trade-offs

- **Moving `custom_missing_extension` from errors to warnings changes the verdict for extension-less custom objects** → This is the intended spec fix; document it in the error catalog and release notes, and keep the kind string stable.
- **Lenient mode can hide non-conformant feeds** → It is opt-in, emits warnings for every relaxed check, and leaves the report shape unchanged.
- **Generic custom objects cannot enforce SDO/SCO/SRO-specific common properties** → That is inherent without a declaration; the warning tells callers the object was treated generically.
- **Python exposure is partial** → Document that `Bundle.from_json` is the lenient entry point; typed constructors remain strict.
