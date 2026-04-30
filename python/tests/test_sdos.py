# STIX 2.1 Domain Objects (SDOs) Test Suite
import json
import pytest
from tests.utils import load_sdo, SDO_TYPES

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
    Incident,
    Indicator,
    MalwareAnalysis,
    Note,
    ObservedData,
    Opinion,
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


class TestUntestedSDOs:
    """Test SDOs that were previously untested."""

    def test_incident_create(self):
        """Test Incident creation."""
        from stixflayer import Incident
        obj = Incident()
        assert obj.type == "incident"

    def test_indicator_create(self):
        """Test Indicator creation."""
        from stixflayer import Indicator
        obj = Indicator()
        assert obj.type == "indicator"

    def test_malware_analysis_create(self):
        """Test MalwareAnalysis creation."""
        from stixflayer import MalwareAnalysis
        obj = MalwareAnalysis()
        assert obj.type == "malware-analysis"

    def test_note_create(self):
        """Test Note creation."""
        from stixflayer import Note
        obj = Note()
        assert obj.type == "note"

    def test_observed_data_create(self):
        """Test ObservedData creation."""
        from stixflayer import ObservedData
        obj = ObservedData()
        assert obj.type == "observed-data"

    def test_opinion_create(self):
        """Test Opinion creation."""
        from stixflayer import Opinion
        obj = Opinion()
        assert obj.type == "opinion"


class TestSDOFromJson:
    """Test SDO creation from JSON using shared test data."""

    @pytest.mark.parametrize("sdo_type", SDO_TYPES)
    def test_load_from_json(self, sdo_type):
        """Test loading SDO from canonical test data."""
        data = load_sdo(sdo_type)
        # SDO classes that have from_json (only make_sdo! has it)
        cls_map = {
            "attack-pattern": AttackPattern,
            "campaign": Campaign,
            "course-of-action": CourseOfAction,
            "identity": Identity,
        }
        cls = cls_map.get(sdo_type)
        if cls is None:
            pytest.skip(f"{sdo_type} doesn't have from_json method")
            return
        json_str = json.dumps(data)
        obj = cls.from_json(json_str)
        assert obj.type == sdo_type
        assert json.loads(obj.to_json())["type"] == sdo_type
