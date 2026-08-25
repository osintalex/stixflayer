"""Validation tests that mirror Rust fixture-driven e2e tests.

These tests load the same JSON fixtures used by rust/tests/e2e_fixtures.rs
and assert that valid fixtures are accepted and invalid fixtures raise
ValueError with expected error substrings.
"""

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
        """Indicator missing required name raises ValueError."""
        json_str = load_fixture("invalid/sdo/indicator-no-name.json")
        with pytest.raises(ValueError, match="missing required property 'name'"):
            stixflayer.Indicator.from_json(json_str)

    def test_invalid_indicator_bad_pattern_type(self):
        """Indicator with invalid pattern_type raises ValueError."""
        json_str = load_fixture("invalid/sdo/indicator-bad-pattern-type.json")
        with pytest.raises(ValueError, match="pattern type should come from the STIX pattern type open vocabulary"):
            stixflayer.Indicator.from_json(json_str)

    def test_invalid_malware_bad_types(self):
        """Malware with invalid malware_types raises ValueError."""
        json_str = load_fixture("invalid/sdo/malware-bad-malware-types.json")
        with pytest.raises(ValueError, match="malware_types"):
            stixflayer.Malware.from_json(json_str)

    def test_invalid_ipv4_bad_format(self):
        """IPv4 address with invalid format raises ValueError."""
        json_str = load_fixture("invalid/sco/ipv4-bad-format.json")
        with pytest.raises(ValueError, match="IPv4 address must be a valid dotted-decimal format"):
            stixflayer.IPv4Address.from_json(json_str)

    def test_invalid_bundle_empty(self):
        """Empty bundle raises ValueError."""
        json_str = load_fixture("invalid/bundle/bundle-empty.json")
        with pytest.raises(ValueError, match="Bundle must contain at least one object"):
            stixflayer.Bundle.from_json(json_str)

    def test_invalid_indicator_non_strict_parses(self):
        """Invalid fixture parses successfully when strict=False."""
        json_str = load_fixture("invalid/sdo/indicator-no-name.json")
        obj = stixflayer.Indicator.from_json(json_str, strict=False)
        assert obj.type == "indicator"

    def test_invalid_indicator_spec_version_not_2_1(self):
        """Indicator with spec_version != 2.1 raises ValueError."""
        json_str = load_fixture("invalid/sdo/indicator-spec-version-2.0.json")
        with pytest.raises(ValueError, match="must be 2.1"):
            stixflayer.Indicator.from_json(json_str)
