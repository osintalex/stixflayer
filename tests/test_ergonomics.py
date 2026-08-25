"""Python ergonomics tests — construction, roundtripping, and type hints.

These tests validate the Pythonic API surface and do not appear in the
language-agnostic test matrix.
"""

import pytest
import stixflayer


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
        """Missing required field raises ValueError at construction."""
        with pytest.raises(ValueError):
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
        """Bundle with no objects raises ValueError."""
        with pytest.raises(ValueError):
            stixflayer.Bundle(objects=[])


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
