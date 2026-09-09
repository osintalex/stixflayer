"""End-to-end use case for custom STIX extensions, markings, and language content.

This test exercises a realistic enrichment scenario:

- An ``Identity`` object defines the producer.
- An ``ExtensionDefinition`` declares a vendor-specific file enrichment extension.
- ``MarkingDefinition`` objects capture handling (TLP:Amber + strict-internal
  statement).
- A ``File`` SCO combines a standard predefined extension (``ntfs-ext``) with
  the custom extension, plus ``object_marking_refs``.
- A ``LanguageContent`` object provides a translation for the file.
- All of the above are bundled together and round-tripped.

It also includes negative tests proving that validation rejects non-compliant
uses of custom extensions.
"""

from __future__ import annotations

import json

import pytest

import stixflayer

TS = "2024-01-15T09:00:00Z"


def _sha256(dummy: str) -> str:
    """Return a syntactically valid SHA-256 hash string."""
    # Valid hex length for SHA-256; content is arbitrary.
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestExtensionDefinitionUseCase:
    """Positive scenario: spec-compliant custom extension enrichment."""

    def test_full_extension_use_case_roundtrips(self):
        identity = stixflayer.Identity(
            name="Recorded Future",
            identity_class="organization",
            created=TS,
            modified=TS,
        )
        assert identity.created == TS
        assert identity.modified == TS

        ext = stixflayer.ExtensionDefinition(
            name="rf-file-enrichment",
            description=(
                "Recorded Future file enrichment. Defines: benign_count, "
                "grayware_count, malicious_count, internal_source."
            ),
            schema="https://example.com/schemas/rf-file-enrichment.json",
            version="1.0.0",
            extension_type="property-extension",
            created_by_ref=identity.id,
            created=TS,
            modified=TS,
        )
        ext_id = ext.id
        assert ext.created == TS
        assert ext.modified == TS

        tlp_amber = stixflayer.MarkingDefinition(
            name="TLP:AMBER",
            definition_type="tlp",
            definition={"tlp": "amber"},
            created=TS,
        )
        assert tlp_amber.created == TS

        internal = stixflayer.MarkingDefinition(
            name="Internal Use Only",
            definition_type="statement",
            definition={"statement": "Amber-strict equivalent: do not share externally"},
            created=TS,
        )
        assert internal.created == TS

        file_obj = stixflayer.File(
            name="suspicious.dll",
            size=123456,
            magic_number_hex="4d5a",
            mime_type="application/x-dosexec",
            hashes={"SHA-256": _sha256("dummy")},
            extensions={
                "ntfs-ext": {
                    "sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                },
                ext_id: {
                    "extension_type": "property-extension",
                    "benign_count": 12,
                    "grayware_count": 3,
                    "malicious_count": 1,
                    "internal_source": "recorded-future",
                },
            },
            object_marking_refs=[tlp_amber.id, internal.id],
        )

        assert file_obj.type == "file"
        assert file_obj.name == "suspicious.dll"
        assert file_obj.size == 123456
        assert file_obj.object_marking_refs == [tlp_amber.id, internal.id]

        ext_data = file_obj.extensions[ext_id]
        assert ext_data["extension_type"] == "property-extension"
        assert ext_data["benign_count"] == 12
        assert ext_data["grayware_count"] == 3
        assert ext_data["malicious_count"] == 1
        assert ext_data["internal_source"] == "recorded-future"

        # The custom extension is nested inside ``extensions``, so it round-trips
        # even under the default strict/allow_custom=False path.
        rt_file = stixflayer.File.from_json(file_obj.to_json())
        assert rt_file.extensions[ext_id]["malicious_count"] == 1

        lc = stixflayer.LanguageContent(
            object_ref=file_obj.id,
            created=TS,
            modified=TS,
            contents={"es": {"name": "archivo sospechoso"}},
        )
        assert lc.object_ref == file_obj.id
        assert lc.created == TS
        assert lc.modified == TS

        # Incremental insertion still works after construction.
        lc.insert_content_strings("fr", {"name": "fichier suspect"})

        bundle = stixflayer.Bundle(
            objects=[
                identity.to_json(),
                ext.to_json(),
                tlp_amber.to_json(),
                internal.to_json(),
                file_obj.to_json(),
                lc.to_json(),
            ]
        )
        assert bundle.type == "bundle"
        assert bundle.object_count == 6

        bundle2 = stixflayer.Bundle.from_json(bundle.to_json())
        assert bundle2.object_count == 6


class TestCustomExtensionValidationErrors:
    """Negative tests: validation rejects non-compliant custom objects."""

    def _make_ext(self, **kwargs):
        identity = stixflayer.Identity(name="ACME", identity_class="organization")
        defaults = {
            "name": "rf-file-enrichment",
            "description": "Test",
            "schema": "https://example.com/s.json",
            "version": "1.0.0",
            "extension_type": "property-extension",
            "created_by_ref": identity.id,
        }
        defaults.update(kwargs)
        return stixflayer.ExtensionDefinition(**defaults)

    def _make_file(self, **kwargs):
        ext = self._make_ext()
        ext_id = ext.id
        defaults = {
            "name": "x.dll",
            "extensions": {
                ext_id: {
                    "extension_type": "property-extension",
                    "malicious_count": 1,
                },
            },
        }
        defaults.update(kwargs)
        return stixflayer.File(**defaults)

    def test_extension_definition_missing_created_by_ref(self):
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.ExtensionDefinition(
                name="rf-file-enrichment",
                description="Test",
                schema="https://example.com/s.json",
                version="1.0.0",
                extension_type="property-extension",
                # created_by_ref intentionally omitted
            )

    def test_extension_definition_property_extension_with_extension_properties(self):
        """`extension_properties` is only permitted with toplevel-property-extension."""
        with pytest.raises(stixflayer.ValidationError):
            self._make_ext(extension_properties=["benign_count"])

    def test_file_top_level_custom_property_rejected(self):
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.File(name="x.dll", benign_count=12)

    def test_file_custom_extension_missing_extension_type(self):
        ext = self._make_ext()
        ext_id = ext.id
        bad_file = {
            "type": "file",
            "id": "file--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "name": "x.dll",
            "extensions": {
                ext_id: {
                    "malicious_count": 1,
                    # missing required extension_type
                },
            },
        }
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.File.from_json(json.dumps(bad_file))

    def test_file_unknown_extension_key_rejected(self):
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.File(
                name="x.dll",
                extensions={"not-a-known-ext": {"foo": "bar"}},
            )

    def test_marking_definition_modified_rejected(self):
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.MarkingDefinition(
                name="TLP:AMBER",
                definition_type="tlp",
                definition={"tlp": "amber"},
                modified=TS,
            )

    def test_marking_definition_missing_definition(self):
        with pytest.raises(stixflayer.ValidationError):
            stixflayer.MarkingDefinition(name="empty")
