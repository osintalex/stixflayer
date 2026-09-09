"""Sample use cases and error patterns for STIX extensions, custom objects,
markings, bundles, and explicit timestamps.

These tests are written as readable examples. Each failure case prints the
actual structured error message so the expected library behavior is obvious.
"""

from __future__ import annotations

import json

import pytest

import stixflayer

TS = "2024-01-15T09:00:00Z"
TS2 = "2024-02-20T10:30:00Z"
EXT_ID = "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62"


def _dump_error(fn):
    """Helper that runs *fn* and returns the ValidationError string."""
    with pytest.raises(stixflayer.ValidationError) as exc_info:
        fn()
    return str(exc_info.value)


class TestPassingTimestamps:
    """You can pass explicit `created`/`modified` to constructors."""

    def test_indicator_preserves_timestamps(self):
        ind = stixflayer.Indicator(
            name="Bad domain",
            pattern="[domain-name:value = 'evil.example.com']",
            pattern_type="stix",
            valid_from=TS,
            created=TS,
            modified=TS2,
        )
        assert ind.created == TS
        assert ind.modified == TS2
        wire = json.loads(ind.to_json())
        assert wire["created"] == TS
        assert wire["modified"] == TS2

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
            modified=TS2,
        )
        assert ext.created == TS
        assert ext.modified == TS2

    def test_language_content_preserves_timestamps(self):
        file_obj = stixflayer.File(name="suspicious.dll")
        lc = stixflayer.LanguageContent(
            object_ref=file_obj.id,
            created=TS,
            modified=TS2,
            contents={"es": {"name": "archivo sospechoso"}},
        )
        assert lc.created == TS
        assert lc.modified == TS2

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
                "severity": 5,
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
        assert obj.custom_properties["severity"] == 5

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
        msg = _dump_error(lambda: stixflayer.CustomObject.from_json(json.dumps(bad_json)))
        print("\n[CustomObject wrong extension_type]\n", msg)
        assert "extension" in msg.lower() or "property-extension" in msg.lower()

    def test_custom_object_missing_extensions_rejected(self):
        bad_json = {
            "type": "vendor-enrichment-sdo",
            "spec_version": "2.1",
            "id": "vendor-enrichment-sdo--12345678-1234-1234-1234-123456789abc",
            "created": TS,
            "modified": TS,
            "name": "Bad",
        }
        msg = _dump_error(lambda: stixflayer.CustomObject.from_json(json.dumps(bad_json)))
        print("\n[CustomObject missing extensions]\n", msg)
        assert "extension" in msg.lower()

    def test_custom_object_type_with_underscore_rejected(self):
        msg = _dump_error(
            lambda: stixflayer.CustomObject(
                type_="vendor_enrichment_sdo",
                extension_type="new-sdo",
                custom_properties={"name": "Bad"},
                extension_definition_id=EXT_ID,
            )
        )
        print("\n[CustomObject type underscore]\n", msg)
        assert "underscore" in msg.lower()

    def test_custom_property_starting_with_digit_rejected(self):
        msg = _dump_error(
            lambda: stixflayer.CustomObject(
                type_="vendor-enrichment-sdo",
                extension_type="new-sdo",
                custom_properties={"1sev": 5},
                extension_definition_id=EXT_ID,
            )
        )
        print("\n[CustomObject digit property]\n", msg)
        assert "digit" in msg.lower()


class TestBundleErrors:
    """Bundles validate every object and enforce id-duplicate / reference rules."""

    def _identity_obj(self, identity_id: str):
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": TS,
            "modified": TS,
            "name": "Acme",
            "identity_class": "organization",
        }

    def test_bundle_accepts_valid_object_strings(self):
        identity = stixflayer.Identity(
            name="Acme", identity_class="organization", created=TS, modified=TS2
        )
        bundle = stixflayer.Bundle(objects=[identity.to_json()])
        assert bundle.object_count == 1

    def test_bundle_rejects_duplicate_object_ids(self):
        duplicate_id = "identity--12345678-1234-1234-1234-123456789abc"
        bundle_json = {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "objects": [
                self._identity_obj(duplicate_id),
                self._identity_obj(duplicate_id),
            ],
        }
        msg = _dump_error(lambda: stixflayer.Bundle.from_json(json.dumps(bundle_json)))
        print("\n[Bundle duplicate id]\n", msg)
        assert "duplicate" in msg.lower()

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
        msg = _dump_error(lambda: stixflayer.Bundle.from_json(json.dumps(bundle_json)))
        print("\n[Bundle missing relationship target]\n", msg)
        assert "not found in current bundle" in msg.lower()


class TestExtensionAndMarkingErrors:
    """Standard extension definitions and data markings are also validated."""

    def test_extension_definition_missing_created_by_ref(self):
        msg = _dump_error(
            lambda: stixflayer.ExtensionDefinition(
                name="vendor-ext",
                description="Test",
                schema="https://example.com/schema.json",
                version="1.0.0",
                extension_type="property-extension",
                created=TS,
                modified=TS,
            )
        )
        print("\n[ExtensionDefinition missing created_by_ref]\n", msg)
        assert "created_by_ref" in msg.lower()

    def test_property_extension_with_extension_properties_rejected(self):
        identity = stixflayer.Identity(name="Vendor", identity_class="organization")
        msg = _dump_error(
            lambda: stixflayer.ExtensionDefinition(
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
        )
        print("\n[ExtensionDefinition forbidden extension_properties]\n", msg)
        assert "extension_properties" in msg.lower()

    def test_marking_definition_modified_rejected(self):
        msg = _dump_error(
            lambda: stixflayer.MarkingDefinition(
                name="TLP:AMBER",
                definition_type="tlp",
                definition={"tlp": "amber"},
                created=TS,
                modified=TS,
            )
        )
        print("\n[MarkingDefinition modified]\n", msg)
        assert "modified" in msg.lower()

    def test_unknown_file_extension_key_rejected(self):
        msg = _dump_error(
            lambda: stixflayer.File(
                name="x.dll",
                extensions={"not-a-known-ext": {"foo": "bar"}},
            )
        )
        print("\n[File unknown extension key]\n", msg)
        assert "wrong extension" in msg.lower() or "not-a-known-ext" in msg.lower()
