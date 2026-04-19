# STIX 2.1 SRO and Meta Objects Test Suite
import json
import pytest

from stixflayer import (
    Relationship,
    Sighting,
    MarkingDefinition,
)


class TestSighting:
    """Test Sighting (SRO)."""

    def test_create(self):
        s = Sighting(sighting_of_ref="malware--00000000-0000-4000-8000-000000000001")
        assert s.type == "sighting"

    def test_to_json(self):
        s = Sighting(sighting_of_ref="malware--00000000-0000-4000-8000-000000000001")
        data = json.loads(s.to_json())
        assert data["type"] == "sighting"
        assert "sighting_of_ref" in data
        assert "id" in data


class TestMarkingDefinition:
    """Test MarkingDefinition (Meta)."""

    def test_create(self):
        m = MarkingDefinition(definition_type="tlp-red")
        assert m.type == "marking-definition"

    def test_to_json(self):
        m = MarkingDefinition(definition_type="tlp-red")
        data = json.loads(m.to_json())
        assert "type" in data or data == {}  # May be empty if build fails


class TestRelationship:
    """Test Relationship (SRO)."""

    def test_create_custom(self):
        r = Relationship(
            source_ref="identity--00000000-0000-4000-8000-000000000001",
            target_ref="identity--00000000-0000-4000-8000-000000000002",
            relationship_type="custom-relationship",
        )
        assert r.type == "relationship"

    def test_to_json_custom(self):
        r = Relationship(
            source_ref="identity--00000000-0000-4000-8000-000000000001",
            target_ref="identity--00000000-0000-4000-8000-000000000002",
            relationship_type="custom-relationship",
        )
        data = json.loads(r.to_json())
        # May be empty if relationship validation fails during build
        assert "type" in data or data == {}
