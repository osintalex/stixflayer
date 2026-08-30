"""End-to-end ergonomics test across every STIX object category.

This test exercises the full public API surface for SDOs, SROs, SCOs,
meta objects, custom objects, and bundles. It verifies that:

* every object exposes the common STIX properties as Python attributes;
* type-specific properties (markings, extension definitions, language content,
  custom objects) are accessible without round-tripping through JSON;
* created/modified timestamps can be passed in explicitly and preserved;
* validation failures surface a structured ``.errors`` list;
* bundles expose their contained objects as instantiated Python objects.
"""

from __future__ import annotations

import json

import pytest

import stixflayer


TS_CREATED = "2016-05-12T08:17:27Z"
TS_MODIFIED = "2016-05-12T08:17:27Z"
TS_OBJECT_MODIFIED = "2017-02-08T21:31:22.007Z"
EXT_ID = "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62"
IDENTITY_ID = "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"


def _assert_common(obj, object_type: str) -> None:
    """Common property assertions that should hold for every STIX object."""
    assert obj.type == object_type
    assert obj.id
    assert isinstance(obj.id, str)


def test_sdo_sro_sco_dynamic_properties():
    """SDOs, SROs and SCOs expose all wire properties through dynamic access."""
    identity = stixflayer.Identity(
        name="Acme", identity_class="organization", created=TS_CREATED, modified=TS_MODIFIED
    )
    _assert_common(identity, "identity")
    assert identity.name == "Acme"
    assert identity.created == TS_CREATED
    assert identity.modified == TS_MODIFIED

    ipv4 = stixflayer.IPv4Address(value="192.0.2.1")
    _assert_common(ipv4, "ipv4-addr")
    assert ipv4.value == "192.0.2.1"

    rel = stixflayer.Relationship(
        relationship_type="indicates",
        source_ref="indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        target_ref="malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
    )
    _assert_common(rel, "relationship")
    assert rel.relationship_type == "indicates"


def test_marking_definition_ergonomics():
    """MarkingDefinition exposes id/created/definition as typed attributes."""
    tlp = stixflayer.MarkingDefinition(
        definition_type="tlp",
        definition={"tlp": "amber"},
        created=TS_CREATED,
    )
    _assert_common(tlp, "marking-definition")
    assert tlp.created == TS_CREATED
    assert tlp.definition_type == "tlp"
    assert tlp.definition == {"tlp": "amber"}

    statement = stixflayer.MarkingDefinition(
        definition_type="statement",
        definition={"statement": "Copyright 2026"},
    )
    assert statement.definition == {"statement": "Copyright 2026"}

    # Unknown kwargs are rejected rather than silently ignored.
    with pytest.raises(stixflayer.StixError):
        stixflayer.MarkingDefinition(definition_type="tlp", definition={"tlp": "red"}, bogus=True)


def test_extension_definition_ergonomics():
    """ExtensionDefinition exposes all spec properties as typed attributes."""
    ext_def = stixflayer.ExtensionDefinition(
        name="Example enrichment",
        description="An example extension",
        schema="https://example.com/schema.json",
        version="1.0.0",
        extension_types=["new-sdo", "property-extension"],
        created=TS_CREATED,
        modified=TS_MODIFIED,
        created_by_ref=IDENTITY_ID,
    )
    _assert_common(ext_def, "extension-definition")
    assert ext_def.name == "Example enrichment"
    assert ext_def.schema == "https://example.com/schema.json"
    assert ext_def.version == "1.0.0"
    assert ext_def.extension_types == ["new-sdo", "property-extension"]
    assert ext_def.created == TS_CREATED
    assert ext_def.modified == TS_MODIFIED
    assert ext_def.created_by_ref == IDENTITY_ID

    # Singular convenience form also works.
    singular = stixflayer.ExtensionDefinition(
        name="Singular",
        description="Singular form",
        schema="https://example.com/s.json",
        version="1.0.0",
        extension_type="new-sco",
        created_by_ref=IDENTITY_ID,
    )
    assert singular.extension_types == ["new-sco"]


def test_language_content_ergonomics():
    """LanguageContent exposes id/created/modified/object_ref/contents."""
    target_id = "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
    lc = stixflayer.LanguageContent(
        object_ref=target_id,
        object_modified=TS_OBJECT_MODIFIED,
        created=TS_CREATED,
        modified=TS_MODIFIED,
        contents={"de": {"name": "Bösartige Aktivität"}, "fr": {"name": "Activité malveillante"}},
    )
    _assert_common(lc, "language-content")
    assert lc.object_ref == target_id
    assert lc.object_modified == TS_OBJECT_MODIFIED
    assert lc.created == TS_CREATED
    assert lc.modified == TS_MODIFIED
    assert lc.contents["de"]["name"] == "Bösartige Aktivität"
    assert lc.contents["fr"]["name"] == "Activité malveillante"


def test_custom_object_ergonomics():
    """CustomObject exposes id/created/modified/extension info and a dict custom_properties."""
    co = stixflayer.CustomObject(
        type_="vendor-enrichment-sdo",
        extension_type="new-sdo",
        extension_definition_id=EXT_ID,
        custom_properties={
            "name": "Vendor enrichment",
            "severity": 5,
            "tactic": "initial-access",
        },
        created=TS_CREATED,
        modified=TS_MODIFIED,
    )
    _assert_common(co, "vendor-enrichment-sdo")
    assert co.created == TS_CREATED
    assert co.modified == TS_MODIFIED
    assert co.extension_type == "new-sdo"
    assert co.extension_definition_id == EXT_ID
    assert isinstance(co.custom_properties, dict)
    assert co.custom_properties["severity"] == 5
    # Dynamic access to arbitrary custom properties still works.
    assert co.tactic == "initial-access"

    # New-SCO form also works.
    sco = stixflayer.CustomObject(
        type_="x-example-sco",
        extension_type="new-sco",
        custom_properties={"value": "192.0.2.99"},
    )
    assert sco.type == "x-example-sco"
    assert sco.extension_type == "new-sco"


def test_invalid_extension_type_rejected():
    """CustomObject only accepts spec-valid extension types for top-level objects."""
    with pytest.raises(stixflayer.StixError) as exc_info:
        stixflayer.CustomObject(
            type_="x-bad",
            extension_type="new-smo",
            custom_properties={"name": "Bad"},
        )
    assert "new-smo" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()


def test_custom_object_from_json_round_trip():
    """CustomObject.from_json returns an object whose attributes are all accessible."""
    original = stixflayer.CustomObject(
        type_="vendor-enrichment-sdo",
        extension_type="new-sdo",
        extension_definition_id=EXT_ID,
        custom_properties={"name": " Vendor enrichment", "severity": 5},
    )
    recovered = stixflayer.CustomObject.from_json(original.to_json())
    assert recovered.type == original.type
    assert recovered.id == original.id
    assert recovered.extension_type == original.extension_type
    assert recovered.extension_definition_id == original.extension_definition_id
    assert recovered.custom_properties == original.custom_properties


def test_validation_errors_are_structured():
    """Validation failures carry a structured ``.errors`` list on the exception."""
    with pytest.raises(stixflayer.ValidationError) as exc_info:
        # Identity `name` is required; omitting it should raise a structured error.
        stixflayer.Identity(identity_class="organization")

    # All validation exceptions expose ``.errors`` even when a single issue occurs.
    errs = exc_info.value.errors
    assert errs
    assert isinstance(errs, list)
    assert any("name" in str(err).lower() for err in errs)

    # Each error entry is a structured dict with diagnostic keys.
    for err in errs:
        assert "kind" in err
        assert "message" in err


def test_bundle_contains_instantiated_objects():
    """Bundle.objects returns live Python wrappers, not raw JSON strings/dicts."""
    identity = stixflayer.Identity(name="Acme", identity_class="organization")
    ext_def = stixflayer.ExtensionDefinition(
        name="Example",
        description="Desc",
        schema="https://example.com/schema.json",
        version="1.0.0",
        extension_type="new-sdo",
        created_by_ref=identity.id,
    )
    tlp = stixflayer.MarkingDefinition(definition_type="tlp", definition={"tlp": "green"})
    lang = stixflayer.LanguageContent(
        object_ref=identity.id,
        object_modified=identity.modified,
        contents={"es": {"name": "Ácme"}},
    )
    custom = stixflayer.CustomObject(
        type_="vendor-enrichment-sdo",
        extension_type="new-sdo",
        custom_properties={"name": "Enrichment"},
    )
    ipv4 = stixflayer.IPv4Address(value="198.51.100.1")
    indicator = stixflayer.Indicator(
        name="Bad IP",
        pattern="[ipv4-addr:value = '198.51.100.1']",
        pattern_type="stix",
        valid_from=TS_CREATED,
    )
    malware = stixflayer.Malware(name="Poison Ivy", is_family=False)
    rel = stixflayer.Relationship(
        relationship_type="indicates",
        source_ref=indicator.id,
        target_ref=malware.id,
    )

    bundle = stixflayer.Bundle(
        objects=[
            identity.to_json(),
            ext_def.to_json(),
            tlp.to_json(),
            lang.to_json(),
            custom.to_json(),
            ipv4.to_json(),
            indicator.to_json(),
            malware.to_json(),
            rel.to_json(),
        ]
    )

    _assert_common(bundle, "bundle")
    assert bundle.object_count == 9

    objects = bundle.objects
    assert len(objects) == 9
    assert isinstance(objects[0], stixflayer.Identity)
    assert isinstance(objects[1], stixflayer.ExtensionDefinition)
    assert isinstance(objects[2], stixflayer.MarkingDefinition)
    assert isinstance(objects[3], stixflayer.LanguageContent)
    assert isinstance(objects[4], stixflayer.CustomObject)
    assert isinstance(objects[5], stixflayer.IPv4Address)
    assert isinstance(objects[6], stixflayer.Indicator)
    assert isinstance(objects[7], stixflayer.Malware)
    assert isinstance(objects[8], stixflayer.Relationship)

    # Attributes are reachable directly on the recovered objects.
    rec_identity = objects[0]
    assert rec_identity.name == "Acme"
    assert rec_identity.id == identity.id

    rec_ext = objects[1]
    assert rec_ext.schema == "https://example.com/schema.json"

    rec_tlp = objects[2]
    assert rec_tlp.definition == {"tlp": "green"}

    rec_custom = objects[4]
    assert rec_custom.custom_properties["name"] == "Enrichment"
    assert rec_custom.extension_definition_id == custom.extension_definition_id


def test_bundle_round_trip():
    """Bundles round-trip through JSON and their objects remain live wrappers."""
    identity = stixflayer.Identity(name="Acme", identity_class="organization")
    bundle = stixflayer.Bundle(objects=[identity.to_json()])
    bundle2 = stixflayer.Bundle.from_json(bundle.to_json())
    assert bundle2.objects[0].id == identity.id
    assert bundle2.objects[0].name == "Acme"
