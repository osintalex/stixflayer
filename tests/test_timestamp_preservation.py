"""Timestamp-preservation harness for the from_parsed rollout.

Red/green ground truth for the rollout: parsing a STIX object is not
versioning it, so `from_json` must never alter `id`, `created`, or
`modified`. Before the `DomainObjectBuilder::from_parsed` core change,
`from_json` bumps `modified` (versioning semantics), so every fixture
fails here. After the change, all fixtures must pass.

Assertions go through `to_json()` (the wire format) rather than Python
attributes, since `__getattr__` property access is only rolled out to
AttackPattern so far.
"""

import json
from datetime import datetime

import pytest

import stixflayer

from tests.utils import DATA_DIR

SDO_FIXTURES = sorted((DATA_DIR / "valid" / "sdos").glob("*.json"))


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _wire(obj) -> dict:
    return json.loads(obj.to_json())


def _class_for(stix_type: str):
    name = "".join(part.title() for part in stix_type.split("-"))
    return getattr(stixflayer, name)


@pytest.mark.parametrize("fixture_path", SDO_FIXTURES, ids=lambda p: p.stem)
def test_from_json_preserves_versioning_properties(fixture_path):
    """from_json must not alter id/created/modified — parsing is not versioning."""
    fixture_str = fixture_path.read_text()
    fixture = json.loads(fixture_str)
    cls = _class_for(fixture["type"])

    obj = _wire(cls.from_json(fixture_str))
    assert obj["id"] == fixture["id"]
    assert _instant(obj["created"]) == _instant(fixture["created"])
    assert _instant(obj["modified"]) == _instant(fixture["modified"])

    # A to_json -> from_json roundtrip must stay faithful too.
    obj2 = _wire(cls.from_json(json.dumps(obj)))
    assert obj2["id"] == obj["id"]
    assert _instant(obj2["created"]) == _instant(obj["created"])
    assert _instant(obj2["modified"]) == _instant(obj["modified"])


def test_revoked_object_parses_and_preserves_everything():
    """Revoked objects are valid STIX (only versioning them is prohibited)."""
    fixture_str = (DATA_DIR / "valid" / "sdos" / "attack-pattern-revoked.json").read_text()
    fixture = json.loads(fixture_str)

    obj = _wire(stixflayer.AttackPattern.from_json(fixture_str))
    assert obj["revoked"] is True
    assert obj["id"] == fixture["id"]
    assert _instant(obj["created"]) == _instant(fixture["created"])
    assert _instant(obj["modified"]) == _instant(fixture["modified"])
