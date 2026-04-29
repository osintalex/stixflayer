# STIX 2.1 Domain Objects (SDOs) Test Suite
import json
import pytest

from stixflayer import (
    AttackPattern,
    Campaign,
    CourseOfAction,
    Identity,
    Infrastructure,
    IntrusionSet,
    Location,
    Malware,
    Report,
    ThreatActor,
    Tool,
    Vulnerability,
    IPv4Address,
    Grouping,
)


class TestSDOsWithName:
    """Test SDOs that have a 'name' field and no other required fields."""

    @pytest.mark.parametrize(
        "cls,stix_type",
        [
            (AttackPattern, "attack-pattern"),
            (Campaign, "campaign"),
            (CourseOfAction, "course-of-action"),
            (Identity, "identity"),
            (Infrastructure, "infrastructure"),
            (IntrusionSet, "intrusion-set"),
            (Location, "location"),
            (Malware, "malware"),
            (Report, "report"),
            (ThreatActor, "threat-actor"),
            (Tool, "tool"),
            (Vulnerability, "vulnerability"),
        ],
    )
    def test_create_with_name(self, cls, stix_type):
        """Test creating SDO with name."""
        obj = cls(name="Test")
        assert obj.type == stix_type

    @pytest.mark.parametrize(
        "cls,stix_type",
        [
            (AttackPattern, "attack-pattern"),
            (Campaign, "campaign"),
            (Identity, "identity"),
            (Malware, "malware"),
            (Tool, "tool"),
        ],
    )
    def test_to_json(self, cls, stix_type):
        """Test JSON serialization."""
        obj = cls(name="Test")
        data = json.loads(obj.to_json())

        assert data["type"] == stix_type
        assert data["name"] == "Test"
        assert "id" in data
        assert data["id"].startswith(stix_type + "--")
        assert "created" in data
        assert "modified" in data
        assert data["spec_version"] == "2.1"


class TestMalware:
    """Test Malware with optional description."""

    def test_with_name_only(self):
        malware = Malware(name="Emotet")
        data = json.loads(malware.to_json())
        assert data["name"] == "Emotet"

    def test_with_name_and_description(self):
        malware = Malware(name="Emotet", description="Banking trojan")
        data = json.loads(malware.to_json())
        assert data["name"] == "Emotet"
        assert data["description"] == "Banking trojan"


class TestIPv4Address:
    """Test IPv4Address SCO."""

    def test_create_with_value(self):
        ip = IPv4Address(value="192.0.2.1")
        assert ip.type == "ipv4-addr"
        assert ip.value == "192.0.2.1"

    def test_to_json(self):
        ip = IPv4Address(value="10.0.0.1")
        data = json.loads(ip.to_json())

        assert data["type"] == "ipv4-addr"
        assert data["value"] == "10.0.0.1"
        assert "id" in data
        assert data["id"].startswith("ipv4-addr--")


class TestTypeGetters:
    """Test type getters."""

    def test_attack_pattern_type(self):
        assert AttackPattern(name="Test").type == "attack-pattern"

    def test_identity_type(self):
        assert Identity(name="Test").type == "identity"

    def test_malware_type(self):
        assert Malware(name="Test").type == "malware"

    def test_ipv4_type(self):
        assert IPv4Address(value="1.1.1.1").type == "ipv4-addr"

    def test_ipv4_value(self):
        assert IPv4Address(value="1.1.1.1").value == "1.1.1.1"


class TestKnownLimitations:
    """Tests for types that need more work - these are expected to fail/empty."""

    def test_grouping_needs_context(self):
        """Grouping requires context and object_refs - not just name."""
        grouping = Grouping(name="Test", description="Test desc")
        # This will produce empty JSON because context is required
        # We just verify it doesn't crash
        result = grouping.to_json()
        assert result == "{}"

    def test_report_needs_published(self):
        """Report requires published timestamp - not just name."""
        report = Report(name="Test")
        result = report.to_json()
        assert result == "{}"


class TestExtensions:
    """Test extensions parameter with Python dict."""

    def test_sdo_with_extensions_dict(self):
        """Test creating SDO with extensions as Python dict."""
        ext = {"ext--123": {"property1": "value1", "property2": 42}}
        obj = AttackPattern(name="Test", extensions=ext)
        data = json.loads(obj.to_json())
        assert "extensions" in data
        assert "ext--123" in data["extensions"]

    def test_sdo_without_extensions(self):
        """Test creating SDO without extensions."""
        obj = AttackPattern(name="Test")
        data = json.loads(obj.to_json())
        assert "extensions" not in data

    def test_malware_with_extensions(self):
        """Test Malware with extensions dict."""
        ext = {"ext--456": {"analysis": "static"}}
        obj = Malware(name="Emotet", extensions=ext)
        data = json.loads(obj.to_json())
        assert "extensions" in data

    def test_identity_with_extensions(self):
        """Test Identity with extensions dict."""
        ext = {"ext--789": {"sector": "technology"}}
        obj = Identity(name="ACME Corp", extensions=ext)
        data = json.loads(obj.to_json())
        assert "extensions" in data
