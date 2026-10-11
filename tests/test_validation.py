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
        with pytest.raises(
            stixflayer.ValidationError, match="pattern type should come from the STIX pattern type open vocabulary"
        ):
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

    def test_deserialization_error_carries_entry(self):
        """Even unclassifiable deserialization failures carry a structured entry.

        The `.errors` contract is total: every exception carries at least one
        entry (the catch-all `deserialization_error` entry here).
        """
        with pytest.raises(stixflayer.DeserializationError) as exc_info:
            stixflayer.Indicator.from_json("not json")
        errs = exc_info.value.errors
        assert len(errs) == 1
        assert errs[0]["kind"] == "deserialization_error"
        assert errs[0]["message"]


# ============================================================================
# Error-reporting fixes (change: fix-python-release-gaps)
# ============================================================================


class TestNestedValidationMessages:
    def test_invalid_vocab_threat_actor_single_prefix(self):
        """A vocab failure nested in an object-level failure keeps the prefix once."""
        with pytest.raises(stixflayer.ValidationError) as exc_info:
            stixflayer.ThreatActor(name="Bogus Actor", sophistication="not-a-real-level")

        message = str(exc_info.value)
        assert message.count("STIX validation error:") == 1, f"message: {message}"
        assert "not-a-real-level" in message
        assert "threat-actor-sophistication-ov" in message

        # The structured entries carry the vocabulary context even through the
        # object-level nesting.
        entries = exc_info.value.errors
        vocab_entries = [e for e in entries if e["kind"] == "invalid_vocab_value"]
        assert vocab_entries, f"no vocab entry: {entries}"
        assert vocab_entries[0]["value"] == "not-a-real-level"
        assert vocab_entries[0]["vocabulary"] == "threat-actor-sophistication-ov"


class TestPatternErrorReporting:
    def test_invalid_pattern_raises_validation_error(self):
        """A syntactically invalid pattern raises ValidationError, not the base StixError."""
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.validate_pattern("AND OR [ipv4-addr:value = '198.51.100.1']")

    def test_pattern_message_has_no_parser_internals(self):
        """Pattern failure messages describe the problem without parser debug structures."""
        with pytest.raises(stixflayer.ValidationError) as exc_info:
            stixflayer.validate_pattern("[ipv4-addr:value = ]")
        message = str(exc_info.value)
        assert "Error {" not in message, f"parser debug leaked: {message}"
        assert "ErrorKind" not in message, f"parser debug leaked: {message}"
        assert " at: '" not in message, f"parser debug leaked: {message}"
        assert "ipv4-addr" in message


class TestNonObjectJsonInput:
    def test_from_json_array_reports_clear_message(self):
        """A JSON array reports that a STIX object was expected, naming the array."""
        with pytest.raises(
            stixflayer.DeserializationError,
            match=r"Expected a STIX object \(JSON object\), got array\.",
        ):
            stixflayer.Indicator.from_json("[1,2,3]")

    def test_from_json_scalar_reports_received_kind(self):
        """Scalar JSON inputs name the received kind, with no Rust type names."""
        for json_str, kind in [
            ("42", "number"),
            ('"just a string"', "string"),
            ("true", "boolean"),
            ("null", "null"),
        ]:
            with pytest.raises(
                stixflayer.DeserializationError,
                match=rf"Expected a STIX object \(JSON object\), got {kind}\.",
            ):
                stixflayer.Indicator.from_json(json_str)

    def test_non_object_message_has_no_rust_type_names(self):
        """The message references no Rust internal type names."""
        with pytest.raises(stixflayer.DeserializationError) as exc_info:
            stixflayer.Indicator.from_json("[1,2,3]")
        message = str(exc_info.value)
        assert "DomainObject" not in message
        assert "struct" not in message.lower()
