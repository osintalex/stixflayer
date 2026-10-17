# Building objects

Construct STIX objects directly with keyword arguments. Required properties
are enforced on construction — you cannot build an invalid object by accident.

## Domain objects

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

Missing required properties raise [`ValidationError`](errors.md) immediately:

```python
from stixflayer import AttackPattern, ValidationError

try:
    AttackPattern(
        id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
        spec_version="2.1",
    )
except ValidationError as e:
    print(e.errors[0]["kind"], e.errors[0]["property"])
    #> missing_property name
```

## Cyber-observable objects

SCOs get their deterministic UUIDv5 identifier from their content — you never
supply an `id`.

```python
from stixflayer import IPv4Address

ip = IPv4Address(value="203.0.113.7")
print(ip.type, ip.id)
#> ipv4-addr ipv4-addr--9ddd739e-87b1-587d-83f2-62ef1130af2f
```

## Custom properties

Standard objects accept properties outside the specification with
`allow_custom=True`. They are readable as attributes and collected in
`custom_properties`.

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
print(ap.custom_properties)
#> {'x_mitre_detection': 'Monitor command history'}
```

## User-defined object types

For objects with a custom `type`, use `CustomObject` with `extension_type`
set to `new-sdo`, `new-sco`, or `new-sro` depending on what it extends.

```python
from stixflayer import CustomObject

co = CustomObject(
    type_="x-example-thing",
    extension_type="new-sco",
    name="Example",
    version=2,
)
print(co.type, co.name)
#> x-example-thing Example
```
