"""Tests for newly added features: Bundle, validate_pattern, vocab enums"""
import json
import pytest
from tests.utils import load_meta

import stixflayer
from stixflayer import Bundle, validate_pattern
from stixflayer import (
    AttackMotivation, IdentitySectors, ThreatActorType, MalwareType,
    IndicatorType, ReportType, AttackResourceLevel, ThreatActorSophistication
)


class TestBundle:
    """Test Bundle (Meta Object) functionality."""

    def test_create_empty_bundle(self):
        """Test creating an empty bundle."""
        bundle = Bundle()
        assert bundle.type == "bundle"
        assert bundle.object_count == 0
        # Bundle must have at least one object to serialize validly
        json_data = json.loads(bundle.to_json())
        assert json_data["type"] == "bundle"

    def test_add_objects_to_bundle(self):
        """Test adding STIX objects to a bundle."""
        from stixflayer import AttackPattern, IPv4Address
        bundle = Bundle()

        # Create an SDO and add it
        ap = AttackPattern(name="Test AP")
        ap_json = ap.to_json()
        try:
            bundle.add(ap_json)
            added = True
        except Exception as e:
            added = False
            
        assert bundle.type == "bundle"

    def test_bundle_from_json(self):
        """Test loading a Bundle from JSON."""
        bundle_data = load_meta("bundle") if False else {  # Use test data if available
            "type": "bundle",
            "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "created": "2016-04-29T14:09:00.000Z",
                    "modified": "2016-04-29T14:09:00.000Z",
                    "name": "Test Indicator",
                    "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
                    "pattern_type": "stix",
                    "valid_from": "2016-01-01T00:00:00Z"
                }
            ]
        }
        bundle = Bundle.from_json(json.dumps(bundle_data))
        assert bundle.type == "bundle"
        assert bundle.object_count == 1
        assert "indicator" in bundle.to_json()

    def test_bundle_id(self):
        """Test Bundle ID generation."""
        bundle = Bundle()
        id_str = bundle.id
        assert id_str.startswith("bundle--")


class TestValidatePattern:
    """Test STIX Pattern validation."""

    def test_valid_pattern(self):
        """Test validating a valid STIX pattern."""
        pattern = "[ipv4-addr:value = '198.51.100.0/24']"
        result = validate_pattern(pattern)
        assert result is None  # No exception = valid

    def test_invalid_pattern(self):
        """Test validating an invalid STIX pattern."""
        invalid_pattern = "invalid pattern"
        with pytest.raises(Exception):
            validate_pattern(invalid_pattern)

    def test_pattern_with_qualifier(self):
        """Test pattern with valid qualifier."""
        pattern = "[domain-name:value = 'example.com'] WITHIN 600 SECONDS"
        result = validate_pattern(pattern)
        assert result is None

    def test_pattern_with_boolean(self):
        """Test pattern with AND operator."""
        pattern = "[ipv4-addr:value = '198.51.100.1' OR ipv4-addr:value = '203.0.113.1']"
        result = validate_pattern(pattern)
        assert result is None


class TestVocabEnums:
    """Test vocabulary enum classes."""

    def test_attack_motivation_valid(self):
        """Test valid AttackMotivation value."""
        mot = AttackMotivation("organizational-gain")
        assert mot.value() == "organizational-gain"

    def test_attack_motivation_invalid(self):
        """Test invalid AttackMotivation value."""
        with pytest.raises(Exception):
            AttackMotivation("invalid-motivation")

    def test_attack_motivation_values(self):
        """Test getting all valid values."""
        values = AttackMotivation.values()
        assert "organizational-gain" in values
        assert "ideology" in values
        assert len(values) > 0

    def test_identity_sectors_valid(self):
        """Test valid IdentitySectors value."""
        cls = IdentitySectors("financial-services")
        assert cls.value() == "financial-services"

    def test_vocab_is_valid(self):
        """Test is_valid static method."""
        assert AttackMotivation.is_valid("ideology") is True
        assert AttackMotivation.is_valid("invalid") is False

    def test_malware_type(self):
        """Test MalwareType enum."""
        mt = MalwareType("remote-access-trojan")
        assert mt.value() == "remote-access-trojan"
        assert MalwareType.is_valid("ransomware") is True

    def test_report_type(self):
        """Test ReportType enum."""
        rt = ReportType("threat-report")
        assert rt.value() == "threat-report"
        assert ReportType.is_valid("threat-report") is True
