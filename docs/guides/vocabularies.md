# Vocabularies

STIX defines open vocabularies for fields like threat actor types and
industries. stixflayer exposes each as an enum-like class that validates
values and lists what's allowed.

## Check and list values

```python
from stixflayer import IdentitySectors, ThreatActorSophistication

print(ThreatActorSophistication.values())
#> ['advanced', 'expert', 'innovator', 'intermediate', 'none', 'minimal', 'strategic']
print(IdentitySectors.is_valid("technology"))
#> True
```

## Use a vocabulary value

Vocabulary fields on objects accept plain strings and are validated on
construction — an invalid value raises with the vocabulary name and the
rejected value.

```python
from stixflayer import Identity, ValidationError

try:
    Identity(
        id="identity--c78b4a5a-3b42-4f2e-9b1a-7f8e9d0c1a2b",
        name="Acme Corp",
        spec_version="2.1",
        created="2019-04-24T15:12:36.609Z",
        modified="2023-03-24T15:14:15.637Z",
        identity_class="bogus-class",
    )
except ValidationError as e:
    entry = e.errors[0]
    print(entry["kind"], "|", entry["vocabulary"], "|", entry["value"])
    #> invalid_vocab_value | identity-class-ov | bogus-class
```

## Available vocabularies

Each class supports `.values()` (all valid values), `.is_valid(value)`, and
construction from a string.

| Class | STIX vocabulary |
|---|---|
| `AttackMotivation` | attack-motivation-ov |
| `AttackResourceLevel` | attack-resource-level-ov |
| `IdentitySectors` | identity-sector-ov |
| `IndicatorType` | indicator-type-ov |
| `MalwareType` | malware-type-ov |
| `ReportType` | report-type-ov |
| `ThreatActorSophistication` | threat-actor-sophistication-ov |
| `ThreatActorType` | threat-actor-type-ov |
