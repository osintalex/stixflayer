"""Validation tests that mirror Rust fixture-driven e2e tests.

These tests load the same JSON fixtures used by rust/tests/e2e_fixtures.rs
and assert that valid fixtures are accepted and invalid fixtures raise the
new structured ``stixflayer`` exception hierarchy.
"""

import json

import pytest
import stixflayer

from tests.utils import load_fixture


# ============================================================================
# Valid fixture acceptance tests
# ============================================================================


class TestValidFixtures:
    def test_valid_indicator_roundtrip(self):
        """Valid indicator fixture loads and roundtrips through JSON."""
        json_str = load_fixture("valid/sdos/indicator.json")
        obj = stixflayer.Indicator.from_json(json_str)
        assert obj.type == "indicator"

        # Roundtrip
        out = obj.to_json()
        obj2 = stixflayer.Indicator.from_json(out)
        assert obj2.type == obj.type

    def test_valid_bundle_accepted(self):
        """Valid bundle fixture loads successfully."""
        json_str = load_fixture("valid/bundle.json")
        bundle = stixflayer.Bundle.from_json(json_str)
        assert bundle.type == "bundle"


# ============================================================================
# Invalid fixture rejection tests
# ============================================================================


class TestInvalidFixtures:
    def test_invalid_indicator_missing_name(self):
        """Indicator missing required name raises ValidationError."""
        json_str = load_fixture("invalid/sdo/indicator-no-name.json")
        with pytest.raises(stixflayer.ValidationError, match="missing required property 'name'"):
            stixflayer.Indicator.from_json(json_str)

    def test_invalid_indicator_bad_pattern_type(self):
        """Indicator with invalid pattern_type raises ValidationError."""
        json_str = load_fixture("invalid/sdo/indicator-bad-pattern-type.json")
        with pytest.raises(stixflayer.ValidationError, match="pattern type should come from the STIX pattern type open vocabulary"):
            stixflayer.Indicator.from_json(json_str)

    def test_invalid_malware_bad_types(self):
        """Malware with invalid malware_types raises ValidationError."""
        json_str = load_fixture("invalid/sdo/malware-bad-malware-types.json")
        with pytest.raises(stixflayer.ValidationError, match="malware_types"):
            stixflayer.Malware.from_json(json_str)

    def test_invalid_ipv4_bad_format(self):
        """IPv4 address with invalid format raises ValidationError."""
        json_str = load_fixture("invalid/sco/ipv4-bad-format.json")
        with pytest.raises(stixflayer.ValidationError, match="IPv4 address must be a valid dotted-decimal format"):
            stixflayer.IPv4Address.from_json(json_str)

    def test_invalid_bundle_empty(self):
        """Empty bundle raises ValidationError."""
        json_str = load_fixture("invalid/bundle/bundle-empty.json")
        with pytest.raises(stixflayer.ValidationError, match="Bundle must contain at least one object"):
            stixflayer.Bundle.from_json(json_str)

    def test_invalid_indicator_non_strict_parses(self):
        """Invalid fixture parses successfully when strict=False."""
        json_str = load_fixture("invalid/sdo/indicator-no-name.json")
        obj = stixflayer.Indicator.from_json(json_str, strict=False)
        assert obj.type == "indicator"

    def test_invalid_indicator_spec_version_not_2_1(self):
        """Indicator with spec_version != 2.1 raises ValidationError."""
        json_str = load_fixture("invalid/sdo/indicator-spec-version-2.0.json")
        with pytest.raises(stixflayer.ValidationError, match="must be 2.1"):
            stixflayer.Indicator.from_json(json_str)

    def test_malformed_json_raises_deserialization_error(self):
        """Completely malformed JSON raises DeserializationError."""
        with pytest.raises(stixflayer.DeserializationError, match="expected"):
            stixflayer.Indicator.from_json("not json")

    def test_to_json_does_not_revalidate(self):
        """Serializing an object parsed with strict=False does not re-run validation."""
        json_str = load_fixture("invalid/sdo/indicator-spec-version-2.0.json")
        obj = stixflayer.Indicator.from_json(json_str, strict=False)
        # If serialization re-validated, this would raise ValidationError.
        out = obj.to_json()
        # And the serialized output can be parsed back (still non-strict).
        obj2 = stixflayer.Indicator.from_json(out, strict=False)
        assert obj2.type == "indicator"

    def test_invalid_top_level_type_raises_deserialization_error(self):
        """A type-level type mismatch (e.g. spec_version as float) raises DeserializationError."""
        bad = {
            "type": "attack-pattern",
            "id": "attack-pattern--00000000-0000-0000-0000-000000000001",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": 2.1,
            "name": "foo",
        }
        with pytest.raises(stixflayer.DeserializationError, match="expected a string"):
            stixflayer.AttackPattern.from_json(json.dumps(bad))

    def test_validation_error_is_stix_error(self):
        """ValidationError is a subclass of the base StixError."""
        json_str = load_fixture("invalid/sdo/indicator-no-name.json")
        with pytest.raises(stixflayer.StixError):
            stixflayer.Indicator.from_json(json_str)

    def test_constructor_type_error_raises_validation_error(self):
        """Passing a Python value of the wrong type to a constructor raises ValidationError."""
        with pytest.raises(stixflayer.ValidationError, match="invalid value for property 'name'") as exc_info:
            stixflayer.Malware(name=2)
        assert exc_info.value.errors == [
            {
                "kind": "invalid_property_type",
                "message": str(exc_info.value),
                "property": "name",
                "expected": "a string",
                "got": "integer `2`",
            }
        ]

    def test_validation_error_errors_attribute(self):
        """ValidationError exposes a structured .errors attribute."""
        with pytest.raises(stixflayer.ValidationError) as exc_info:
            stixflayer.AttackPattern(y="love")

        errors = exc_info.value.errors
        assert len(errors) == 2
        assert {e["kind"] for e in errors} == {"missing_property", "unknown_property"}
        assert any(e["kind"] == "missing_property" and e["property"] == "name" for e in errors)
        assert any(e["kind"] == "unknown_property" and e["properties"] == ["y"] for e in errors)

    def test_deserialization_error_has_empty_errors(self):
        """DeserializationError that can't be broken down has an empty .errors list."""
        with pytest.raises(stixflayer.DeserializationError) as exc_info:
            stixflayer.Indicator.from_json("not json")
        assert exc_info.value.errors == []
