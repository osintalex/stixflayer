# Validation modes

stixflayer validates by default. Two options control how lenient parsing and
construction are: `allow_custom` for custom properties, and `strict` for
spec conformance checks.

## What is always enforced

Required properties are enforced in every mode — an object missing `name`
never passes, strict or not.

```python
import json

from stixflayer import AttackPattern

incomplete = json.dumps(
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
        "created": "2019-04-24T15:12:36.609Z",
        "modified": "2023-03-24T15:14:15.637Z",
    }
)
try:
    AttackPattern.from_json(incomplete)
except Exception as e:
    print(type(e).__name__)
    #> ValidationError
```

## Custom properties: `allow_custom`

Properties outside the STIX 2.1 specification are rejected by default.
Pass `allow_custom=True` to accept them.

```python
from stixflayer import AttackPattern

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries clear or remove bash_history to hide their tracks.",
    spec_version="2.1",
    allow_custom=True,
    x_mitre_detection="Monitor command history",
)
print(ap.x_mitre_detection)
#> Monitor command history
```

## Spec conformance: `strict`

With `strict=True` (the default), values are checked against the STIX
vocabularies. With `strict=False`, those conformance checks are skipped —
useful for processing incomplete or non-conformant data you cannot fix.

```python
from stixflayer import Identity, ValidationError

kwargs = dict(
    id="identity--c78b4a5a-3b42-4f2e-9b1a-7f8e9d0c1a2b",
    name="Acme Corp",
    spec_version="2.1",
    created="2019-04-24T15:12:36.609Z",
    modified="2023-03-24T15:14:15.637Z",
)

try:
    Identity(identity_class="bogus-class", **kwargs)
except ValidationError as e:
    print(e.errors[0]["kind"], e.errors[0]["value"])
    #> invalid_vocab_value bogus-class

lenient = Identity(identity_class="bogus-class", strict=False, **kwargs)
print(lenient.identity_class)
#> bogus-class
```

## All errors at once

Validation collects every problem it finds — inspect `errors` as a list
instead of fixing one error per attempt.

```python
import json

from stixflayer import AttackPattern, ValidationError

document = json.dumps(
    {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
        "created": "2019-04-24T15:12:36.609Z",
        "modified": "2023-03-24T15:14:15.637Z",
        "bogus_property": "x",
    }
)
try:
    AttackPattern.from_json(document)
except ValidationError as e:
    print([entry["kind"] for entry in e.errors])
    #> ['unknown_property', 'missing_property']
```

See [error handling](errors.md) for the full error catalog.
