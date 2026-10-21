# Exceptions

All errors derive from `StixError`. Every error carries a structured
`errors` list — see [error handling](../guides/errors.md) for the catalog of
entry kinds and fields.

## Hierarchy

```text
StixError
├── ValidationError      # parses, but violates STIX 2.1 rules
└── DeserializationError # cannot be parsed as STIX JSON
```

```python
from stixflayer import DeserializationError, StixError, ValidationError

print(issubclass(ValidationError, StixError))
#> True
print(issubclass(DeserializationError, StixError))
#> True
```

## Attributes

| Attribute | Type | Present on |
|---|---|---|
| `errors` | `list[dict]` | Every `StixError` — at least one entry with `kind` and `message` |
| `args[0]` | `str` | Human-readable message |

## Typical handling

```python
import json

from stixflayer import AttackPattern, DeserializationError, ValidationError

bad_json = '{"type": "attack-pattern"'  # truncated — not valid JSON
not_stix = json.dumps({"hello": "world"})

for payload in (bad_json, not_stix):
    try:
        AttackPattern.from_json(payload)
    except DeserializationError as e:
        print("cannot parse:", type(e).__name__)
        #> cannot parse: DeserializationError
    except ValidationError as e:
        print("parsed, invalid:", e.errors[0]["kind"])
        #> parsed, invalid: missing_property
```
