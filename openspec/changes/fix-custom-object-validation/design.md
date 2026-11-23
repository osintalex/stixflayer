# Design

## Context

See `proposal.md` for motivation. `CustomObject::get_object_type` currently returns an error when no `new-sdo` / `new-sco` / `new-sro` extension is present, and `CustomObject::check` propagates it as a MUST-level `custom_missing_extension` error. `Relationship::check` already enforces SDO/SCO endpoints and spec-defined pairs; that behavior stays unchanged.

## Goals / Non-Goals

**Goals:**

- Align extension-less custom-object handling with STIX 2.1 §11.2 (SHOULD, not MUST).
- Keep relationship validation strict.
- Preserve the existing report shape and existing default relationship behavior.

**Non-Goals:**

- Accepting custom-object relationship endpoints or non-spec-defined pairs.
- Adding CLI flags or Python keywords for non-conformant relationship shapes.
- Inferring that an extension-less custom object is an SDO/SCO/SRO from its name or properties.
- Changing `allow_custom` semantics for custom properties.

## Decisions

### D1: Treat extension-less custom objects as generic custom objects

`CustomObject` gains a `CustomObjectKind` of `Sdo`, `Sco`, `Sro`, or `Generic`. A `new-*` extension selects the corresponding kind; no extension selects `Generic`. Generic objects run:

- the §11.2 custom-object type-name rules,
- identifier and common-property checks that do not depend on SDO/SCO/SRO classification,
- custom-property name and suffix-value checks.

They do not run `check_sdo_properties` / `check_sco_properties` / `check_sro_properties`, because those require a declared object kind. Missing extension produces the existing `custom_missing_extension` kind as a warning. Keeping the kind string preserves machine-readable continuity; it moves from `KNOWN_ERROR_KINDS` to `KNOWN_WARNING_KINDS`.

*Alternative rejected:* infer SDO/SCO/SRO from the object name (`x-mitre-*` as SDO). That would be guesswork and would silently validate properties the object never declared.

### D2: Generic custom objects are buildable from parsed input

`CustomObjectBuilder::from_generic` reconstructs a generic custom object with `CommonPropertiesBuilder::from_existing("custom", ...)`. `from_parsed` uses it when no new-object extension is present, so `CustomObject.from_json` can expose generic custom objects and their warnings without adding an extension.

### D3: Relationship strictness is unchanged

`Relationship::check` keeps the existing endpoint and pair checks. No policy, flag, or option is added for relaxing them. ATT&CK's `x-mitre-*` endpoints and `tool -> attack-pattern` `uses` pairs remain invalid, and the CLI reports them as errors.

## Risks / Trade-offs

- **Moving `custom_missing_extension` from errors to warnings changes the verdict for extension-less custom objects** → This is the intended spec fix; document it in the error catalog and release notes, and keep the kind string stable.
- **Removing the error variant is a breaking Rust API change** → Document it in the proposal and release notes.
- **Generic custom objects cannot enforce SDO/SCO/SRO-specific common properties** → That is inherent without a declaration; the warning tells callers the object was treated generically.
- **ATT&CK remains invalid** → That is correct strict STIX 2.1 behavior; the validation notes record the exact non-conformances.
