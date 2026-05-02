# STIX 2.1 Custom Objects & Extensions Test Suite
import json
import pytest

from stixflayer import (
    AttackPattern,
    IPv4Address,
    Identity,
    CustomObject,
    ExtensionDefinition,
)


class TestCustomObject:
    """Test CustomObject class for new object types."""

    def test_create_custom_sdo(self):
        """Create a custom SDO with arbitrary type."""
        obj = CustomObject(
            type_="my-custom-sdo",
            extension_type="new-sdo",
            custom_properties_json=json.dumps(
                {
                    "name": "My Custom Object",
                    "x-custom-field": "custom-value",
                }
            ),
        )
        json_str = obj.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "my-custom-sdo"
        assert parsed["name"] == "My Custom Object"
        assert parsed["x-custom-field"] == "custom-value"

    def test_create_custom_sco(self):
        """Create a custom SCO."""
        obj = CustomObject(
            type_="my-custom-sco",
            extension_type="new-sco",
            custom_properties_json=json.dumps(
                {
                    "value": "mysco.example.com",
                }
            ),
        )
        json_str = obj.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "my-custom-sco"
        assert parsed["value"] == "mysco.example.com"

    def test_create_custom_sro(self):
        """Create a custom SRO."""
        obj = CustomObject(
            type_="my-custom-sro",
            extension_type="new-sro",
            custom_properties_json=json.dumps(
                {
                    "relationship_type": "uses",
                }
            ),
        )
        json_str = obj.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "my-custom-sro"
        assert "extensions" in parsed

    def test_serialize_to_json(self):
        """CustomObject serializes to JSON."""
        original = CustomObject(
            type_="roundtrip-test",
            extension_type="new-sdo",
            custom_properties_json=json.dumps(
                {
                    "name": "Roundtrip Test",
                    "x-foo": "bar",
                }
            ),
        )
        json_str = original.to_json()
        assert json_str is not None
        parsed = json.loads(json_str)
        assert parsed["type"] == "roundtrip-test"

    def test_from_json(self):
        """CustomObject deserializes from JSON."""
        original = CustomObject(
            type_="my-custom-sdo",
            extension_type="new-sdo",
            custom_properties_json=json.dumps(
                {
                    "name": "Test Object",
                }
            ),
        )
        json_str = original.to_json()
        restored = CustomObject.from_json(json_str)
        assert restored.type == "my-custom-sdo"


class TestCustomProperties:
    """Test custom properties on standard objects via extensions."""

    def test_standard_sdo_basic(self):
        """Test standard AttackPattern still works."""
        attack_pattern = AttackPattern(name="Spear Phishing")
        json_str = attack_pattern.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "attack-pattern"
        assert parsed["name"] == "Spear Phishing"

    def test_sdo_with_extensions(self):
        """Test AttackPattern with custom properties via extensions."""
        attack_pattern = AttackPattern(
            name="Spear Phishing",
            extensions={
                "extension-definition--abc123": {
                    "extension_type": "property-extension",
                    "x-threat-actor": "APT29",
                }
            },
        )
        json_str = attack_pattern.to_json()
        parsed = json.loads(json_str)
        assert parsed["name"] == "Spear Phishing"
        assert "extensions" in parsed
        ext = parsed["extensions"]["extension-definition--abc123"]
        assert ext["x-threat-actor"] == "APT29"

    def test_sdo_with_multiple_extensions(self):
        """Test AttackPattern with multiple custom properties."""
        attack_pattern = AttackPattern(
            name="Phishing",
            extensions={
                "extension-definition--ext1": {
                    "extension_type": "property-extension",
                    "x-custom-1": "value1",
                },
                "extension-definition--ext2": {
                    "extension_type": "property-extension",
                    "x-custom-2": "value2",
                },
            },
        )
        json_str = attack_pattern.to_json()
        parsed = json.loads(json_str)
        assert "extensions" in parsed
        assert len(parsed["extensions"]) == 2

    def test_standard_sco_basic(self):
        """Test standard IPv4Address still works."""
        ipv4 = IPv4Address(value="192.168.1.100")
        json_str = ipv4.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "ipv4-addr"
        assert parsed["value"] == "192.168.1.100"

    def test_sco_with_extensions(self):
        """Test IPv4Address with custom properties via extensions."""
        ipv4 = IPv4Address(
            value="192.168.1.100",
            extensions={
                "extension-definition--xyz789": {
                    "extension_type": "property-extension",
                    "x-internal-id": "firewall-001",
                }
            },
        )
        json_str = ipv4.to_json()
        parsed = json.loads(json_str)
        assert parsed["value"] == "192.168.1.100"
        assert "extensions" in parsed
        ext = parsed["extensions"]["extension-definition--xyz789"]
        assert ext["x-internal-id"] == "firewall-001"

    def test_identity_with_extensions(self):
        """Test Identity with custom properties."""
        identity = Identity(
            name="ACME Corp",
            extensions={
                "extension-definition--org": {
                    "extension_type": "property-extension",
                    "x-org-id": "ORG-12345",
                }
            },
        )
        json_str = identity.to_json()
        parsed = json.loads(json_str)
        assert parsed["name"] == "ACME Corp"
        assert parsed["extensions"]["extension-definition--org"]["x-org-id"] == "ORG-12345"


class TestExtensionDefinition:
    """Test ExtensionDefinition for defining extensions."""

    def test_create_property_extension(self):
        """Create an extension definition for custom properties."""
        ext_def = ExtensionDefinition(
            name="My Custom Properties",
            schema="https://example.com/schema.json",
            version="1.0.0",
            extension_type="property",
            created_by_ref="identity--c78cb6d5-3867-4e77-9a2f-978e0d1d3c7e",
        )
        json_str = ext_def.to_json()
        parsed = json.loads(json_str)
        assert parsed["name"] == "My Custom Properties"
        assert "property-extension" in parsed["extension_types"]

    def test_create_new_object_extension(self):
        """Create an extension definition for a new object type."""
        ext_def = ExtensionDefinition(
            name="My New Object Type",
            schema="https://example.com/new-object.json",
            version="1.0.0",
            extension_type="new-sdo",
            created_by_ref="identity--c78cb6d5-3867-4e77-9a2f-978e0d1d3c7e",
        )
        json_str = ext_def.to_json()
        parsed = json.loads(json_str)
        assert "new-sdo" in parsed["extension_types"]
