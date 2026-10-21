# Quickstart

Install stixflayer, parse a STIX 2.1 document, and handle validation errors.
Every code block on this page is executed in CI — what you see is what it prints.

## Install

```console
pip install stixflayer
```

Requires Python 3.11 or newer. Rust users: `cargo add stixflayer`, with the API
reference on [docs.rs](https://docs.rs/stixflayer).

## Parse and validate a document

Parsing validates: a document that fails STIX 2.1 rules is rejected at
`from_json`, not silently accepted.

```python
import json

from stixflayer import Bundle

document = json.dumps(
    {
        "type": "bundle",
        "id": "bundle--0c7b5d88-7c1c-4a8b-8f0c-6e9d4f2b1a55",
        "objects": [
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
                "created": "2019-04-24T15:12:36.609Z",
                "modified": "2023-03-24T15:14:15.637Z",
                "name": "Clear Command History",
            },
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--a924e94c-4d7d-4f9a-9c9e-2b0f8f4b9f1d",
                "created": "2019-04-24T15:12:36.609Z",
                "modified": "2023-03-24T15:14:15.637Z",
                "name": "Malicious IP",
                "pattern": "[ipv4-addr:value = '203.0.113.7']",
                "pattern_type": "stix",
                "valid_from": "2019-04-24T15:12:36.609Z",
            },
        ],
    }
)

bundle = Bundle.from_json(document)
print(bundle.object_count)
#> 2
for obj in bundle.objects:
    print(obj.type, obj.id)
    #> attack-pattern attack-pattern--d3046a90-580c-4004-8208-66915bc29830
    #> indicator indicator--a924e94c-4d7d-4f9a-9c9e-2b0f8f4b9f1d
```

## Build an object

Build STIX Domain Objects directly or with builders. Required properties are
enforced on construction.

```python
from stixflayer import AttackPattern

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries clear or remove bash_history to hide their tracks.",
    spec_version="2.1",
)
print(ap.name)
#> Clear Command History
```

## Handle validation errors

Failures raise a structured exception — every error carries a machine-readable
`errors` list, not just a message.

```python
from stixflayer import AttackPattern, ValidationError

try:
    AttackPattern.from_json(
        '{"type": "attack-pattern", "spec_version": "2.1", "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830", "created": "2019-04-24T15:12:36.609Z", "modified": "2023-03-24T15:14:15.637Z"}'
    )
except ValidationError as e:
    print(e.errors[0]["kind"], e.errors[0]["property"])
    #> missing_property name
```

## Next steps

- [Parsing and validation](guides/parsing.md) — bundles, objects, JSON round-trips
- [Building objects](guides/building.md) — constructors and builders
- [Validation modes](guides/validation.md) — strict vs `allow_custom`
- [API reference](api/overview.md)
