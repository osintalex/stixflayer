# Vocabularies

Enum-like classes for STIX open vocabularies. Every class supports the same
interface.

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

## Interface

| Member | Description |
|---|---|
| `Class(value)` | Construct from a string; invalid values raise |
| `Class.values()` | All valid values, as `list[str]` |
| `Class.is_valid(value)` | `True`/`False` without raising |
| `.value()` | The string value of an instance |

```python
from stixflayer import ThreatActorSophistication

sophistication = ThreatActorSophistication("advanced")
print(sophistication.value())
#> advanced
print(ThreatActorSophistication.is_valid("advanced"))
#> True
print(ThreatActorSophistication.is_valid("bogus"))
#> False
```

Object fields that use a vocabulary accept plain strings and are validated on
construction — see [vocabularies guide](../guides/vocabularies.md).
