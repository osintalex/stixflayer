"""Python ergonomics tests — construction, roundtripping, and type hints.

These tests validate the Pythonic API surface and do not appear in the
language-agnostic test matrix.
"""

import pytest
import stixflayer

from datetime import datetime


class TestIndicatorErgonomics:
    def test_indicator_kwargs_constructor(self):
        """Direct construction with kwargs works and produces a typed object."""
        obj = stixflayer.Indicator(
            name="Test Indicator",
            pattern="[file:hashes.'SHA-256' = 'd41d8cd98f00b204e9800998ecf8427e']",
            pattern_type="stix",
            valid_from="2016-01-01T00:00:00Z",
        )
        assert obj.type == "indicator"

    def test_indicator_to_json(self):
        """to_json() returns a string containing the object type."""
        obj = stixflayer.Indicator(
            name="Test",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from="2016-01-01T00:00:00Z",
        )
        json_str = obj.to_json()
        assert '"type":"indicator"' in json_str

    def test_indicator_missing_required_raises(self):
        """Missing required field raises ValidationError at construction."""
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.Indicator(name="Missing pattern")  # pattern is required

    def test_indicator_roundtrip(self):
        """Roundtrip through to_json / from_json preserves type."""
        original = stixflayer.Indicator(
            name="Roundtrip Test",
            pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            pattern_type="stix",
            valid_from="2016-01-01T00:00:00Z",
        )
        json_str = original.to_json()
        restored = stixflayer.Indicator.from_json(json_str)
        assert restored.type == "indicator"


class TestBundleErgonomics:
    def test_bundle_kwargs_constructor(self):
        """Bundle can be constructed with kwargs."""
        indicator = stixflayer.Indicator(
            name="Bundled",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from="2016-01-01T00:00:00Z",
        )
        bundle = stixflayer.Bundle(objects=[indicator.to_json()])
        assert bundle.type == "bundle"

    def test_bundle_empty_raises(self):
        """Bundle with no objects raises ValidationError."""
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.Bundle(objects=[])


class TestAttackPatternErgonomics:
    def test_attack_pattern_name_getter(self):
        """Generic property access returns the name set at construction."""
        obj = stixflayer.AttackPattern(name="Spear Phishing Against Executives")
        assert obj.name == "Spear Phishing Against Executives"

    def test_attack_pattern_optional_property_absent(self):
        """Unset optional properties raise AttributeError (no registry to distinguish typos)."""
        obj = stixflayer.AttackPattern(name="Test")
        with pytest.raises(AttributeError):
            obj.description  # noqa: B018

    def test_attack_pattern_common_properties(self):
        """Common STIX properties are accessible via the same mechanism."""
        obj = stixflayer.AttackPattern(name="Test")
        assert obj.id.startswith("attack-pattern--")
        assert obj.spec_version == "2.1"
        # modified is timestamped when the object is built, so it is never
        # earlier than created
        assert datetime.fromisoformat(obj.modified) >= datetime.fromisoformat(obj.created)

    def test_attack_pattern_unknown_attribute_raises(self):
        """Unknown attributes raise AttributeError, not None."""
        obj = stixflayer.AttackPattern(name="Test")
        with pytest.raises(AttributeError):
            obj.not_a_real_property  # noqa: B018

    def test_attack_pattern_from_json_getattr(self):
        """Properties resolve after a from_json roundtrip."""
        original = stixflayer.AttackPattern(name="Roundtrip Pattern")
        restored = stixflayer.AttackPattern.from_json(original.to_json())
        assert restored.name == "Roundtrip Pattern"

    def test_attack_pattern_optional_property_roundtrip(self):
        """Optional list/dict-typed properties survive the roundtrip."""
        original = stixflayer.AttackPattern(
            name="Phishing",
            aliases=["Spear Phishing"],
        )
        restored = stixflayer.AttackPattern.from_json(original.to_json())
        assert restored.aliases == ["Spear Phishing"]


class TestTimestampOverrides:
    """Callers may supply created/modified; otherwise both default to now."""

    def test_default_created_equals_modified(self):
        obj = stixflayer.AttackPattern(name="Test")
        assert obj.created == obj.modified

    def test_caller_supplied_created_preserved(self):
        obj = stixflayer.AttackPattern(
            name="Test",
            created="2020-01-01T00:00:00.000Z",
        )
        # jiff normalizes trailing zero fractional seconds — compare instants
        assert datetime.fromisoformat(obj.created) == datetime.fromisoformat(
            "2020-01-01T00:00:00.000Z"
        )

    def test_caller_supplied_modified_preserved(self):
        obj = stixflayer.AttackPattern(
            name="Test",
            created="2020-01-01T00:00:00.000Z",
            modified="2021-06-01T12:00:00.000Z",
        )
        assert datetime.fromisoformat(obj.created) == datetime.fromisoformat(
            "2020-01-01T00:00:00.000Z"
        )
        assert datetime.fromisoformat(obj.modified) == datetime.fromisoformat(
            "2021-06-01T12:00:00.000Z"
        )


class TestTypeHints:
    def test_indicator_type_annotation(self):
        """Type annotation on indicator assignment is valid Python syntax."""
        obj: stixflayer.Indicator = stixflayer.Indicator(
            name="Type Hint Test",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            valid_from="2016-01-01T00:00:00Z",
        )
        assert obj.type == "indicator"
