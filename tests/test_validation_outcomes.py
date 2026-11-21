"""Tests for the cross-language validation outcome contract."""

import json

import pytest

import stixflayer

IDENTITY_ID = "identity--550e8400-e29b-41d4-a716-446655440000"


def identity_json(**overrides):
    data = {
        "type": "identity",
        "id": IDENTITY_ID,
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Acme",
    }
    data.update(overrides)
    return json.dumps(data)


class TestObjectWarnings:
    def test_constructor_exposes_warnings(self):
        identity = stixflayer.Identity(name="Acme", identity_class="bogus-class")
        assert identity.identity_class == "bogus-class"
        assert len(identity.warnings) == 1
        warning = identity.warnings[0]
        assert warning["kind"] == "open_vocab_value_not_suggested"
        assert warning["property"] == "identity_class"
        assert warning["value"] == "bogus-class"
        assert warning["vocabulary"] == "identity-class-ov"
        assert warning["object_id"] == identity.id

    def test_from_json_exposes_warnings(self):
        identity = stixflayer.Identity.from_json(identity_json(identity_class="bogus-class"))
        assert any(w["kind"] == "open_vocab_value_not_suggested" for w in identity.warnings)

    def test_clean_object_has_no_warnings(self):
        identity = stixflayer.Identity(name="Acme", identity_class="organization")
        assert identity.warnings == []

    def test_strict_false_has_no_warnings(self):
        identity = stixflayer.Identity(name="Acme", identity_class="bogus-class", strict=False)
        assert identity.identity_class == "bogus-class"
        assert identity.warnings == []

    def test_warning_shape_has_no_legacy_fields(self):
        identity = stixflayer.Identity(name="Acme", identity_class="bogus-class")
        warning = identity.warnings[0]
        for key in ("level", "severity", "properties", "expected", "got"):
            assert key not in warning


class TestExceptionWarnings:
    def test_exception_exposes_errors_and_warnings(self):
        # Missing `name` is a MUST error; the bogus identity_class is a SHOULD
        # finding collected during the same pass.
        with pytest.raises(stixflayer.ValidationError) as exc_info:
            stixflayer.Identity(name="", identity_class="bogus-class")

        errors = exc_info.value.errors
        warnings = exc_info.value.warnings
        assert any(entry["kind"] == "missing_property" for entry in errors)
        assert any(entry["kind"] == "open_vocab_value_not_suggested" for entry in warnings)


class TestBundleAttribution:
    def test_bundle_and_objects_carry_warnings(self):
        bundle_json = json.dumps(
            {
                "type": "bundle",
                "id": "bundle--550e8400-e29b-41d4-a716-446655440001",
                "objects": [json.loads(identity_json(identity_class="bogus-class"))],
            }
        )
        bundle = stixflayer.Bundle.from_json(bundle_json)
        assert len(bundle.warnings) == 1
        assert bundle.warnings[0]["object_id"] == IDENTITY_ID

        objects = bundle.objects
        assert len(objects) == 1
        assert objects[0].id == IDENTITY_ID
        assert len(objects[0].warnings) == 1
        assert objects[0].warnings[0]["object_id"] == IDENTITY_ID

    def test_bundle_emits_one_warning_per_object(self):
        bundle_json = json.dumps(
            {
                "type": "bundle",
                "id": "bundle--550e8400-e29b-41d4-a716-446655440001",
                "objects": [
                    json.loads(identity_json(identity_class="bogus-class")),
                    json.loads(
                        identity_json(
                            id="identity--550e8400-e29b-41d4-a716-446655440002",
                            identity_class="bogus-class",
                        )
                    ),
                ],
            }
        )
        bundle = stixflayer.Bundle.from_json(bundle_json)
        assert len(bundle.warnings) == 2


class TestDedupe:
    def test_one_warning_per_finding(self):
        identity = stixflayer.Identity(name="Acme", identity_class="bogus-class")
        kinds = [w["kind"] for w in identity.warnings]
        assert kinds.count("open_vocab_value_not_suggested") == 1


class TestConstructorFromJsonParity:
    def test_same_errors_and_warnings(self):
        kwargs = {
            "id": IDENTITY_ID,
            "name": "",
            "identity_class": "bogus-class",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
        }
        with pytest.raises(stixflayer.ValidationError) as constructor:
            stixflayer.Identity(**kwargs)
        with pytest.raises(stixflayer.ValidationError) as from_json:
            stixflayer.Identity.from_json(identity_json(name="", identity_class="bogus-class"))

        assert [e["kind"] for e in constructor.value.errors] == [e["kind"] for e in from_json.value.errors]
        assert [w["kind"] for w in constructor.value.warnings] == [w["kind"] for w in from_json.value.warnings]
