# Domain objects

All classes below share the [common interface](overview.md#shared-behavior):
keyword construction, `from_json`, `to_json`, and typed property accessors.

## STIX Domain Objects (SDOs)

| Class | Required name property |
|---|---|
| `AttackPattern` | `name` |
| `Campaign` | `name` |
| `CourseOfAction` | `name` |
| `Grouping` | `context`, `object_refs` |
| `Identity` | `name` |
| `Incident` | `name` |
| `Indicator` | `name`, `pattern`, `pattern_type`, `valid_from` |
| `Infrastructure` | `name` |
| `IntrusionSet` | `name` |
| `Location` | — |
| `Malware` | `name`, `is_family` |
| `MalwareAnalysis` | `product`, `version` |
| `Note` | `content`, `object_refs` |
| `ObservedData` | `objects`, `first_observed`, `last_observed`, `number_observed` |
| `Opinion` | `opinion`, `object_refs` |
| `Report` | `name`, `published`, `object_refs` |
| `ThreatActor` | `name` |
| `Tool` | `name` |
| `Vulnerability` | `name` |

```python
from stixflayer import ThreatActor

ta = ThreatActor(
    id="threat-actor--0ab1f132-d6c5-4d4f-a0e3-ff9bda992932",
    name="Foobar",
    spec_version="2.1",
    created="2019-04-24T15:12:36.609Z",
    modified="2023-03-24T15:14:15.637Z",
    threat_actor_types=["crime-syndicate"],
)
print(ta.name)
#> Foobar
```

## Relationship objects (SROs)

| Class | Notes |
|---|---|
| `Relationship` | Connects two objects via `relationship_type` |
| `Sighting` | Records that an object was seen |

```python
from stixflayer import Relationship

rel = Relationship(
    id="relationship--0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
    spec_version="2.1",
    created="2019-04-24T15:12:36.609Z",
    modified="2023-03-24T15:14:15.637Z",
    relationship_type="uses",
    source_ref="threat-actor--0ab1f132-d6c5-4d4f-a0e3-ff9bda992932",
    target_ref="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
)
print(rel.relationship_type)
#> uses
```

## Meta objects

| Class | Purpose |
|---|---|
| `MarkingDefinition` | Data marking / handling labels |
| `ExtensionDefinition` | Defines a STIX extension |
| `LanguageContent` | Language-specific content for an object |

## Bundles and custom objects

| Class | Purpose |
|---|---|
| `Bundle` | Container of STIX objects; rejects empty bundles |
| `CustomObject` | User-defined object types (`new-sdo` / `new-sco` / `new-sro`) |

```python
from stixflayer import AttackPattern, Bundle

ap = AttackPattern(
    id="attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
    name="Clear Command History",
    spec_version="2.1",
    created="2019-04-24T15:12:36.609Z",
    modified="2023-03-24T15:14:15.637Z",
)
bundle = Bundle(objects=[ap])
bundle.add(ap.to_json())
print(bundle.object_count)
#> 2
```
