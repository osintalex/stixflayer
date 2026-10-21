# Parsing and validation

stixflayer parses STIX 2.1 JSON and validates it in one step: `from_json`
returns a live object or raises — there is no separate validate call to forget.

## Load a bundle

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
        ],
    }
)

bundle = Bundle.from_json(document)
print(bundle.object_count)
#> 1
for obj in bundle.objects:
    print(obj.type, obj.id)
    #> attack-pattern attack-pattern--d3046a90-580c-4004-8208-66915bc29830
```

`bundle.objects` contains live Python objects with typed accessors, not raw
dictionaries — unknown attributes raise `AttributeError`.

## Load a single object

Every object class has a `from_json` constructor.

```python
from stixflayer import IPv4Address

ip = IPv4Address.from_json(
    '{"type": "ipv4-addr", "id": "ipv4-addr--9ddd739e-87b1-587d-83f2-62ef1130af2f", "value": "203.0.113.7"}'
)
print(ip.value, ip.id)
#> 203.0.113.7 ipv4-addr--9ddd739e-87b1-587d-83f2-62ef1130af2f
```

## Round-trip to JSON

`to_json` serializes back to STIX 2.1 JSON.

```python
import json

from stixflayer import AttackPattern

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    description="Adversaries clear or remove bash_history to hide their tracks.",
    spec_version="2.1",
)
roundtrip = json.loads(ap.to_json())
print(roundtrip["type"], roundtrip["name"])
#> attack-pattern Clear Command History
```

## Invalid input raises

Documents that break STIX 2.1 rules — or aren't STIX JSON at all — raise
before you get an object. See [validation modes](validation.md) and
[error handling](errors.md) for what comes back and how to handle it.

```python
from stixflayer import Bundle

try:
    Bundle.from_json('{"type": "bundle", "id": "bundle--0c7b5d88-7c1c-4a8b-8f0c-6e9d4f2b1a55"}')
except Exception as e:
    print(type(e).__name__)
    #> DeserializationError
```
