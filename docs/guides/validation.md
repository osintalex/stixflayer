# Validation modes

stixflayer validates by default. Two options control how lenient parsing and
construction are: `allow_custom` for custom properties, and `strict` for
semantic checks.

## What is always enforced

Structural checks run in every mode: required properties must be present, JSON
types must match, unknown properties are rejected unless `allow_custom=True`,
and timestamps and identifiers must be well formed.

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

## Semantic checks: `strict`

With `strict=True` (the default), STIX MUST rules produce errors and SHOULD
recommendations produce warnings. Errors raise; warnings never do.

With `strict=False`, semantic checks are skipped entirely, so there are no
semantic errors and no warnings. Structural checks still apply.

```python
from stixflayer import Identity

kwargs = dict(
    id="identity--c78b4a5a-3b42-4f2e-9b1a-7f8e9d0c1a2b",
    name="Acme Corp",
    spec_version="2.1",
    created="2019-04-24T15:12:36.609Z",
    modified="2023-03-24T15:14:15.637Z",
)

# `bogus-class` is outside identity-class-ov. That is a SHOULD finding, so
# construction succeeds and the finding is available as a warning.
identity = Identity(identity_class="bogus-class", **kwargs)
print(identity.identity_class)
#> bogus-class
print([entry["kind"] for entry in identity.warnings])
#> ['open_vocab_value_not_suggested']

# With strict=False the semantic check is skipped, so there are no warnings.
lenient = Identity(identity_class="bogus-class", strict=False, **kwargs)
print(lenient.warnings)
#> []
```

## Warnings on objects and exceptions

Objects returned by constructors and `from_json` expose `.warnings`.
Exceptions expose both `.errors` and `.warnings`, because a document can
violate a MUST rule and a SHOULD recommendation at the same time.

```python
from stixflayer import Identity, ValidationError

try:
    Identity(
        name="Acme",
        identity_class="organization",
        extensions={
            "extension-definition--550e8400-e29b-41d4-a716-446655440000": {"extension_type": "not-a-real-type"}
        },
    )
except ValidationError as e:
    print(e.errors[0]["kind"], e.errors[0]["vocabulary"])
    #> invalid_vocab_value extension-type-enum
```

## Non-raising checks with `check()`

`check()` validates without raising and returns the raw outcome. Use it when
you want to branch on findings instead of catching exceptions.

```python
import json

import stixflayer

outcome = stixflayer.check(
    json.dumps(
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--c78b4a5a-3b42-4f2e-9b1a-7f8e9d0c1a2b",
            "created": "2019-04-24T15:12:36.609Z",
            "modified": "2023-03-24T15:14:15.637Z",
            "name": "Acme",
            "identity_class": "bogus-class",
        }
    )
)
print(outcome.valid)
#> True
print([entry["kind"] for entry in outcome.warnings])
#> ['open_vocab_value_not_suggested']
print(outcome.errors)
#> []
```

`check()` returns `valid=False` and a non-empty `errors` list for MUST
violations instead of raising.

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

See [error handling](errors.md) for the full errors and warnings catalog.
