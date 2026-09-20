"""Sample use cases and error patterns for STIX extensions, custom objects,
markings, bundles, and explicit timestamps.

These tests are written as readable examples. Each failure case asserts that
the expected validation error is raised.
"""

from __future__ import annotations

import json

import pytest

import stixflayer

from tests.constants import EXT_ID, TS, TS_LATER


class TestPassingTimestamps:
    """You can pass explicit `created`/`modified` to constructors."""

    def test_indicator_preserves_timestamps(self):
        ind = stixflayer.Indicator(
            name="Bad domain",
            pattern="[domain-name:value = 'evil.example.com']",
            pattern_type="stix",
            valid_from=TS,
            created=TS,
            modified=TS_LATER,
        )
        assert ind.created == TS
        assert ind.modified == TS_LATER
        wire = json.loads(ind.to_json())
        assert wire["created"] == TS
        assert wire["modified"] == TS_LATER

    def test_extension_definition_preserves_timestamps(self):
        identity = stixflayer.Identity(name="Vendor", identity_class="organization")
        ext = stixflayer.ExtensionDefinition(
            name="vendor-enrichment",
            description="A vendor enrichment extension.",
            schema="https://vendor.com/schemas/enrichment.json",
            version="1.0.0",
            extension_type="property-extension",
            created_by_ref=identity.id,
            created=TS,
            modified=TS_LATER,
        )
        assert ext.created == TS
        assert ext.modified == TS_LATER

    def test_language_content_preserves_timestamps(self):
        file_obj = stixflayer.File(name="suspicious.dll")
        lc = stixflayer.LanguageContent(
            object_ref=file_obj.id,
            created=TS,
            modified=TS_LATER,
            contents={"es": {"name": "archivo sospechoso"}},
        )
        assert lc.created == TS
        assert lc.modified == TS_LATER

    def test_marking_definition_preserves_created(self):
        marking = stixflayer.MarkingDefinition(
            name="TLP:AMBER",
            definition_type="tlp",
            definition={"tlp": "amber"},
            created=TS,
        )
        assert marking.created == TS


class TestCustomObjectErrors:
    """Custom objects must declare a ``new-sdo``/``new-sro``/``new-sco``
    extension and follow custom object naming rules.
    """

    def test_custom_object_valid(self):
        obj = stixflayer.CustomObject(
            type_="vendor-enrichment-sdo",
            extension_type="new-sdo",
            custom_properties={
                "name": "Vendor enrichment",
                "x_risk_score": 5,
            },
            extension_definition_id=EXT_ID,
        )
        wire = json.loads(obj.to_json())
        assert wire["type"] == "vendor-enrichment-sdo"
        assert wire["extensions"][EXT_ID]["extension_type"] == "new-sdo"
        assert "created" in wire  # sanity: common properties were populated
        # New Python-friendly attributes
        assert obj.id.startswith("vendor-enrichment-sdo--")
        assert obj.created is not None
        assert obj.extension_type == "new-sdo"
        assert obj.extension_definition_id == EXT_ID
        assert isinstance(obj.custom_properties, dict)
        assert obj.custom_properties["x_risk_score"] == 5

    def test_wrong_extension_type_in_extensions_is_rejected(self):
        bad_json = {
            "type": "vendor-enrichment-sdo",
            "spec_version": "2.1",
            "id": "vendor-enrichment-sdo--12345678-1234-1234-1234-123456789abc",
            "created": TS,
            "modified": TS,
            "name": "Bad",
            "extensions": {
                EXT_ID: {"extension_type": "property-extension"},
            },
        }
        with pytest.raises(stixflayer.ValidationError, match="extension|property-extension"):
            stixflayer.CustomObject.from_json(json.dumps(bad_json))

    def test_custom_object_missing_extensions_rejected(self):
        bad_json = {
            "type": "vendor-enrichment-sdo",
            "spec_version": "2.1",
            "id": "vendor-enrichment-sdo--12345678-1234-1234-1234-123456789abc",
            "created": TS,
            "modified": TS,
            "name": "Bad",
        }
        with pytest.raises(stixflayer.ValidationError, match="extension"):
            stixflayer.CustomObject.from_json(json.dumps(bad_json))

    def test_custom_object_type_with_underscore_rejected(self):
        with pytest.raises(stixflayer.ValidationError, match="underscore"):
            stixflayer.CustomObject(
                type_="vendor_enrichment_sdo",
                extension_type="new-sdo",
                custom_properties={"name": "Bad"},
                extension_definition_id=EXT_ID,
            )

    def test_custom_property_starting_with_digit_accepted(self):
        obj = stixflayer.CustomObject(
            type_="vendor-enrichment-sdo",
            extension_type="new-sdo",
            custom_properties={"1sev": 5},
            extension_definition_id=EXT_ID,
        )
        assert obj.custom_properties["1sev"] == 5

    def test_custom_property_invalid_name_rejected(self):
        with pytest.raises(stixflayer.ValidationError, match="characters outside the allowed set"):
            stixflayer.CustomObject(
                type_="vendor-enrichment-sdo",
                extension_type="new-sdo",
                custom_properties={"bad-key": 5},
                extension_definition_id=EXT_ID,
            )


class TestBundleErrors:
    """Bundles validate every object and enforce id-duplicate / reference rules."""

    def test_bundle_accepts_valid_object_strings(self):
        identity = stixflayer.Identity(name="Acme", identity_class="organization", created=TS, modified=TS_LATER)
        bundle = stixflayer.Bundle(objects=[identity.to_json()])
        assert bundle.object_count == 1

    def test_bundle_rejects_duplicate_object_ids(self):
        duplicate_id = "identity--12345678-1234-1234-1234-123456789abc"
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": duplicate_id,
            "created": TS,
            "modified": TS,
            "name": "Acme",
            "identity_class": "organization",
        }
        bundle_json = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "objects": [identity_obj, identity_obj],
        }
        with pytest.raises(stixflayer.ValidationError, match="duplicate"):
            stixflayer.Bundle.from_json(json.dumps(bundle_json))

    def test_bundle_rejects_relationship_to_missing_object(self):
        # The relationship itself is valid (indicator -> malware with `indicates`),
        # but the target object is not present in the bundle.
        bundle_json = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--11111111-1111-4111-8111-111111111111",
                    "created": TS,
                    "modified": TS,
                    "name": "Bad domain",
                    "pattern": "[domain-name:value = 'evil.example.com']",
                    "pattern_type": "stix",
                    "valid_from": TS,
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--22222222-2222-4222-8222-222222222222",
                    "created": TS,
                    "modified": TS,
                    "relationship_type": "indicates",
                    "source_ref": "indicator--11111111-1111-4111-8111-111111111111",
                    "target_ref": "malware--33333333-3333-4333-8333-333333333333",
                },
            ],
        }
        with pytest.raises(stixflayer.ValidationError, match="not found in current bundle"):
            stixflayer.Bundle.from_json(json.dumps(bundle_json))


class TestExtensionAndMarkingErrors:
    """Standard extension definitions and data markings are also validated."""

    def test_extension_definition_missing_created_by_ref(self):
        with pytest.raises(stixflayer.ValidationError, match="created_by_ref"):
            stixflayer.ExtensionDefinition(
                name="vendor-ext",
                description="Test",
                schema="https://example.com/schema.json",
                version="1.0.0",
                extension_type="property-extension",
                created=TS,
                modified=TS,
            )

    def test_property_extension_with_extension_properties_rejected(self):
        identity = stixflayer.Identity(name="Vendor", identity_class="organization")
        with pytest.raises(stixflayer.ValidationError, match="extension_properties"):
            stixflayer.ExtensionDefinition(
                name="vendor-ext",
                description="Test",
                schema="https://example.com/schema.json",
                version="1.0.0",
                extension_type="property-extension",
                extension_properties=["severity"],
                created_by_ref=identity.id,
                created=TS,
                modified=TS,
            )

    def test_marking_definition_modified_rejected(self):
        with pytest.raises(stixflayer.ValidationError, match="modified"):
            stixflayer.MarkingDefinition(
                name="TLP:AMBER",
                definition_type="tlp",
                definition={"tlp": "amber"},
                created=TS,
                modified=TS,
            )

    def test_unknown_file_extension_key_rejected(self):
        with pytest.raises(stixflayer.ValidationError, match="(?i)wrong extension|not-a-known-ext"):
            stixflayer.File(
                name="x.dll",
                extensions={"not-a-known-ext": {"foo": "bar"}},
            )
