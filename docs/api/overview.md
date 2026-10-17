# API overview

Everything is importable from the top-level package. The full type surface is
declared in type stubs, so IDEs and type checkers resolve all of it.

## What's in the box

| Group | Members | Reference |
|---|---|---|
| Exceptions | `StixError`, `ValidationError`, `DeserializationError` | [Exceptions](exceptions.md) |
| Functions | `version()`, `validate_pattern()` | [Functions](functions.md) |
| Domain objects | 19 SDO classes (`AttackPattern`, `Identity`, `Malware`, …) | [Domain objects](domain-objects.md) |
| Relationship objects | `Relationship`, `Sighting` | [Domain objects](domain-objects.md) |
| Meta objects | `MarkingDefinition`, `ExtensionDefinition`, `LanguageContent` | [Domain objects](domain-objects.md) |
| Cyber-observables | 18 SCO classes (`File`, `IPv4Address`, `NetworkTraffic`, …) | [Cyber-observables](cyber-objects.md) |
| Vocabularies | 8 enum classes (`.values()`, `.is_valid()`) | [Vocabularies](vocabularies.md) |
| Bundles & custom | `Bundle`, `CustomObject` | [Domain objects](domain-objects.md) |

## Shared behavior

All SDO and SCO classes share the same interface:

- `Class(**properties)` — construct; required properties enforced
- `Class.from_json(json_str, strict=True, allow_custom=False)` — parse and validate
- `obj.to_json()` — serialize back to STIX 2.1 JSON
- `obj.type`, `obj.id`, `obj.spec_version` — common properties
- `obj.custom_properties` — properties outside the specification
- Typed accessors for standard properties; unknown attributes raise `AttributeError`

See [validation modes](../guides/validation.md) for `strict` and
`allow_custom` semantics, and [error handling](../guides/errors.md) for the
structured error entries.
