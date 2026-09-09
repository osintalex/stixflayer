"""Non-strict mode tests for stixflayer.

These tests verify the contract that ``strict=False`` skips semantic validation
(``stix_check``) while still enforcing structural deserialization and required
fields. After a non-strict parse, ``to_json()`` must serialize the preserved
(invalid) data without re-validating it, and the output must be parseable again
under ``strict=False``.
"""

import json
from pathlib import Path

import pytest
import stixflayer


# Project root is one level up from tests/
DATA_DIR = Path(__file__).parent.parent / "testdata" / "stix"


def _load_fixture(path: str) -> dict:
    """Load a JSON fixture and parse it into a dict."""
    return json.loads((DATA_DIR / path).read_text())


# Mapping of every top-level Python wrapper class to a valid fixture path.
# We mutate the ``spec_version`` field to ``"2.0"`` to produce a semantic
# validation failure that is still structurally parseable.
_OBJECT_CASES = [
    # SDOs
    (stixflayer.AttackPattern, "valid/sdos/attack-pattern.json"),
    (stixflayer.Campaign, "valid/sdos/campaign.json"),
    (stixflayer.CourseOfAction, "valid/sdos/course-of-action.json"),
    (stixflayer.Grouping, "valid/sdos/grouping.json"),
    (stixflayer.Identity, "valid/sdos/identity.json"),
    (stixflayer.Incident, "valid/sdos/incident.json"),
    (stixflayer.Indicator, "valid/sdos/indicator.json"),
    (stixflayer.Infrastructure, "valid/sdos/infrastructure.json"),
    (stixflayer.IntrusionSet, "valid/sdos/intrusion-set.json"),
    (stixflayer.Location, "valid/sdos/location.json"),
    (stixflayer.Malware, "valid/sdos/malware.json"),
    (stixflayer.MalwareAnalysis, "valid/sdos/malware-analysis.json"),
    (stixflayer.Note, "valid/sdos/note.json"),
    (stixflayer.ObservedData, "valid/sdos/observed-data.json"),
    (stixflayer.Opinion, "valid/sdos/opinion.json"),
    (stixflayer.Report, "valid/sdos/report.json"),
    (stixflayer.ThreatActor, "valid/sdos/threat-actor.json"),
    (stixflayer.Tool, "valid/sdos/tool.json"),
    (stixflayer.Vulnerability, "valid/sdos/vulnerability.json"),
    # SCOs
    (stixflayer.IPv4Address, "valid/scos/ipv4-addr.json"),
    (stixflayer.IPv6Address, "valid/scos/ipv6-addr.json"),
    (stixflayer.DomainName, "valid/scos/domain-name.json"),
    (stixflayer.URL, "valid/scos/url.json"),
    (stixflayer.EmailAddress, "valid/scos/email-addr.json"),
    (stixflayer.EmailMessage, "valid/scos/email-message.json"),
    (stixflayer.MacAddr, "valid/scos/mac-addr.json"),
    (stixflayer.AutonomousSystem, "valid/scos/autonomous-system.json"),
    (stixflayer.File, "valid/scos/file.json"),
    (stixflayer.Software, "valid/scos/software.json"),
    (stixflayer.Directory, "valid/scos/directory.json"),
    (stixflayer.Mutex, "valid/scos/mutex.json"),
    (stixflayer.Process, "valid/scos/process.json"),
    (stixflayer.NetworkTraffic, "valid/scos/network-traffic.json"),
    (stixflayer.UserAccount, "valid/scos/user-account.json"),
    (stixflayer.WindowsRegistryKey, "valid/scos/windows-registry-key.json"),
    (stixflayer.X509Certificate, "valid/scos/x509-certificate.json"),
    (stixflayer.Artifact, "valid/scos/artifact.json"),
    # SROs
    (stixflayer.Relationship, "valid/sros/relationship.json"),
    (stixflayer.Sighting, "valid/sros/sighting.json"),
    # Meta objects
    (stixflayer.ExtensionDefinition, "valid/meta/extension-definition.json"),
    (stixflayer.LanguageContent, "valid/meta/language-content.json"),
]


@pytest.mark.parametrize("cls, fixture_path", _OBJECT_CASES)
class TestNonStrictFromJsonRoundtrip:
    def test_strict_default_rejects_bad_spec_version(self, cls, fixture_path):
        """Default strict mode rejects an invalid spec_version."""
        data = _load_fixture(fixture_path)
        data["spec_version"] = "2.0"
        json_str = json.dumps(data)

        with pytest.raises(stixflayer.ValidationError, match="2.1"):
            cls.from_json(json_str)

    def test_non_strict_parses_and_serializes_bad_spec_version(self, cls, fixture_path):
        """Non-strict mode parses invalid spec_version, serializes, and roundtrips."""
        data = _load_fixture(fixture_path)
        data["spec_version"] = "2.0"
        json_str = json.dumps(data)

        obj = cls.from_json(json_str, strict=False)
        assert obj.spec_version == "2.0"

        # Serialization must not re-validate.
        out = obj.to_json()
        out_data = json.loads(out)
        assert out_data["spec_version"] == "2.0"

        # And the serialized output can be parsed back non-strictly.
        obj2 = cls.from_json(out, strict=False)
        assert obj2.spec_version == "2.0"

    def test_to_json_preserves_data_after_non_strict_parse(self, cls, fixture_path):
        """The non-strict JSON output contains the same invalid value we fed in."""
        data = _load_fixture(fixture_path)
        data["spec_version"] = "2.0"
        json_str = json.dumps(data)

        obj = cls.from_json(json_str, strict=False)
        out_data = json.loads(obj.to_json())

        # We only assert on spec_version here because the serializer may reorder
        # or reformat other fields (timestamps, identifiers) in valid ways.
        assert out_data["spec_version"] == "2.0"


class TestMarkingDefinitionNonStrict:
    """MarkingDefinition has its own parser; cover it separately."""

    def test_non_strict_roundtrips_bad_spec_version(self):
        data = _load_fixture("valid/meta/marking-definition.json")
        data["spec_version"] = "2.0"
        json_str = json.dumps(data)

        obj = stixflayer.MarkingDefinition.from_json(json_str, strict=False)
        assert obj.spec_version == "2.0"

        out = obj.to_json()
        out_data = json.loads(out)
        assert out_data["spec_version"] == "2.0"

        obj2 = stixflayer.MarkingDefinition.from_json(out, strict=False)
        assert obj2.spec_version == "2.0"


class TestCustomObjectNonStrict:
    """CustomObject has no fixture; exercise it with inline JSON."""

    def test_non_strict_roundtrips_invalid_custom_object(self):
        data = {
            "type": "x-custom-object",
            "id": "x-custom-object--00000000-0000-0000-0000-000000000001",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-01T00:00:00Z",
            "spec_version": "2.0",
            "extensions": {
                "extension-definition--00000000-0000-0000-0000-000000000000": {
                    "extension_type": "new-sdo",
                    "tactic": "invalid-tactic",
                }
            },
        }
        json_str = json.dumps(data)

        with pytest.raises(stixflayer.ValidationError, match="2.1"):
            stixflayer.CustomObject.from_json(json_str)

        obj = stixflayer.CustomObject.from_json(json_str, strict=False)
        out_data = json.loads(obj.to_json())
        assert out_data["spec_version"] == "2.0"

    def test_constructor_non_strict_skips_validation(self):
        obj = stixflayer.CustomObject(
            type_="x-custom-object",
            extension_type="new-sdo",
            strict=False,
            custom_properties={"tactic": "invalid-tactic"},
        )
        out_data = json.loads(obj.to_json())
        assert out_data["type"] == "x-custom-object"
        assert out_data["tactic"] == "invalid-tactic"


class TestNonStrictConstructors:
    """Constructor ``strict=False`` skips semantic validation just like from_json."""

    def test_sdo_constructor_non_strict(self):
        # spec_version="2.0" is semantically invalid but structurally fine.
        obj = stixflayer.AttackPattern(
            strict=False,
            name="Bad spec version",
            spec_version="2.0",
        )
        out_data = json.loads(obj.to_json())
        assert out_data["spec_version"] == "2.0"
        assert out_data["name"] == "Bad spec version"

    def test_sco_constructor_non_strict(self):
        obj = stixflayer.IPv4Address(
            strict=False,
            value="not-an-ip",
            spec_version="2.0",
        )
        out_data = json.loads(obj.to_json())
        assert out_data["value"] == "not-an-ip"
        assert out_data["spec_version"] == "2.0"

    def test_sro_constructor_non_strict(self):
        obj = stixflayer.Relationship(
            strict=False,
            relationship_type="invalid-relationship",
            source_ref="identity--00000000-0000-0000-0000-000000000001",
            target_ref="identity--00000000-0000-0000-0000-000000000002",
            spec_version="2.0",
        )
        out_data = json.loads(obj.to_json())
        assert out_data["relationship_type"] == "invalid-relationship"
        assert out_data["spec_version"] == "2.0"


class TestStrictStillEnforcesRequiredFields:
    """Non-strict mode does not bypass required-field checks."""

    def test_non_strict_from_json_still_requires_required_properties(self):
        json_str = json.dumps({"type": "attack-pattern", "spec_version": "2.1"})
        with pytest.raises(stixflayer.ValidationError, match="name"):
            stixflayer.AttackPattern.from_json(json_str, strict=False)

    def test_non_strict_constructor_still_requires_required_properties(self):
        with pytest.raises(stixflayer.ValidationError, match="name"):
            stixflayer.AttackPattern(strict=False)
