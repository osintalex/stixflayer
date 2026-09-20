"""Property-access harness: every wire property must be reachable via attribute.

For every fixture, every key in the object's serialized form (the wire
format) must be accessible as a Python attribute and survive the
json_to_py type conversion.
"""

import json

import pytest
import stixflayer

from tests.utils import DATA_DIR, class_for_type, parse_timestamp

ALL_FIXTURES = sorted(
    path
    for family in ("sdos", "scos", "sros", "meta")
    for path in (DATA_DIR / "valid" / family).glob("*.json")
)


@pytest.mark.parametrize(
    "fixture_path",
    ALL_FIXTURES,
    ids=lambda p: f"{p.parent.name}/{p.stem}",
)
def test_every_wire_property_is_accessible(fixture_path):
    """getattr(obj, key) must equal the wire value for every serialized key."""
    fixture_str = fixture_path.read_text()
    fixture = json.loads(fixture_str)
    cls = class_for_type(fixture["type"])

    obj = cls.from_json(fixture_str)
    wire = json.loads(obj.to_json())
    assert set(wire) >= set(fixture) | {"spec_version"}

    for key, expected in wire.items():
        actual = getattr(obj, key)
        if key in ("created", "modified"):
            assert parse_timestamp(actual) == parse_timestamp(expected), key
        else:
            assert actual == expected, key


@pytest.mark.parametrize(
    "factory",
    [stixflayer.AttackPattern],
    ids=["attack-pattern"],
)
def test_unknown_attribute_raises(factory):
    """Unknown attrs raise AttributeError per class, never return None."""
    obj = factory(name="T")
    with pytest.raises(AttributeError):
        getattr(obj, "not_a_real_property")
