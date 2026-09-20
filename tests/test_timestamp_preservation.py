"""Timestamp-preservation harness for the from_parsed rollout.

Red/green ground truth for the rollout: parsing a STIX object is not
versioning it, so `from_json` must never alter `id`, `created`, or
`modified`. Before the `DomainObjectBuilder::from_parsed` core change,
`from_json` bumps `modified` (versioning semantics), so every fixture
fails here. After the change, all fixtures must pass.
"""

import json

import pytest

import stixflayer

from tests.utils import DATA_DIR, class_for_type, parse_timestamp, to_parsed_json

SDO_FIXTURES = sorted((DATA_DIR / "valid" / "sdos").glob("*.json"))


@pytest.mark.parametrize("fixture_path", SDO_FIXTURES, ids=lambda p: p.stem)
def test_from_json_preserves_versioning_properties(fixture_path):
    """from_json must not alter id/created/modified — parsing is not versioning."""
    fixture_str = fixture_path.read_text()
    fixture = json.loads(fixture_str)
    cls = class_for_type(fixture["type"])

    obj = to_parsed_json(cls.from_json(fixture_str))
    assert obj["id"] == fixture["id"]
    assert parse_timestamp(obj["created"]) == parse_timestamp(fixture["created"])
    assert parse_timestamp(obj["modified"]) == parse_timestamp(fixture["modified"])

    # A to_json -> from_json roundtrip must stay faithful too.
    obj2 = to_parsed_json(cls.from_json(json.dumps(obj)))
    assert obj2["id"] == obj["id"]
    assert parse_timestamp(obj2["created"]) == parse_timestamp(obj["created"])
    assert parse_timestamp(obj2["modified"]) == parse_timestamp(obj["modified"])


def test_revoked_object_parses_and_preserves_everything():
    """Revoked objects are valid STIX (only versioning them is prohibited)."""
    fixture_str = (DATA_DIR / "valid" / "sdos" / "attack-pattern-revoked.json").read_text()
    fixture = json.loads(fixture_str)

    obj = to_parsed_json(stixflayer.AttackPattern.from_json(fixture_str))
    assert obj["revoked"] is True
    assert obj["id"] == fixture["id"]
    assert parse_timestamp(obj["created"]) == parse_timestamp(fixture["created"])
    assert parse_timestamp(obj["modified"]) == parse_timestamp(fixture["modified"])
