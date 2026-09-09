"""Tests for allow_custom support on standard STIX objects."""

import json

import pytest

import stixflayer as sf


@pytest.fixture
def indicator_kwargs():
    return {
        "name": "Evil indicator",
        "pattern": "[file:name = 'evil.exe']",
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00.000Z",
    }


INDICATOR_JSON = json.dumps(
    {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--0d4a1f02-1a5b-4c9e-9a8f-3f1b2c3d4e5f",
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
        "name": "Evil indicator",
        "pattern": "[file:name = 'evil.exe']",
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00.000Z",
        "x_foo": "custom-value",
    }
)


def test_from_json_allow_custom_true_preserves_property():
    obj = sf.Indicator.from_json(INDICATOR_JSON, allow_custom=True)
    assert obj.custom_properties == {"x_foo": "custom-value"}


def test_from_json_allow_custom_true_roundtrips_to_json():
    obj = sf.Indicator.from_json(INDICATOR_JSON, allow_custom=True)
    out = json.loads(obj.to_json())
    assert out["x_foo"] == "custom-value"


def test_from_json_allow_custom_false_rejects_custom_property():
    with pytest.raises(sf.ValidationError):
        sf.Indicator.from_json(INDICATOR_JSON, allow_custom=False)


def test_getattr_custom_property_after_from_json():
    obj = sf.Indicator.from_json(INDICATOR_JSON, allow_custom=True)
    assert obj.x_foo == "custom-value"


def test_constructor_kwargs_custom_property_with_allow_custom(indicator_kwargs):
    obj = sf.Indicator(**indicator_kwargs, x_foo="custom-value", allow_custom=True)
    out = json.loads(obj.to_json())
    assert out["x_foo"] == "custom-value"
    assert obj.custom_properties == {"x_foo": "custom-value"}


def test_constructor_kwargs_custom_property_without_allow_custom_fails(indicator_kwargs):
    with pytest.raises(sf.ValidationError):
        sf.Indicator(**indicator_kwargs, x_foo="custom-value", allow_custom=False)


def test_constructor_kwargs_custom_property_strict_still_validates():
    """allow_custom=True does not disable required-field validation."""
    with pytest.raises(sf.ValidationError):
        sf.Indicator(name="Evil indicator", x_foo="custom-value", allow_custom=True)


def test_custom_property_name_validation():
    """Invalid custom property names are rejected even with allow_custom=True."""
    bad_json = json.dumps(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--0d4a1f02-1a5b-4c9e-9a8f-3f1b2c3d4e5f",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Evil indicator",
            "pattern": "[file:name = 'evil.exe']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00.000Z",
            "1bad": "value",
        }
    )
    with pytest.raises(sf.ValidationError):
        sf.Indicator.from_json(bad_json, allow_custom=True)


def test_reserved_custom_property_name_rejected():
    bad_json = json.dumps(
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--0d4a1f02-1a5b-4c9e-9a8f-3f1b2c3d4e5f",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Evil indicator",
            "pattern": "[file:name = 'evil.exe']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00.000Z",
            "severity": 5,
        }
    )
    with pytest.raises(sf.ValidationError):
        sf.Indicator.from_json(bad_json, allow_custom=True)


def test_custom_properties_empty_when_no_custom_keys(indicator_kwargs):
    obj = sf.Indicator(**indicator_kwargs, allow_custom=True)
    assert obj.custom_properties == {}


def test_sdo_from_json_allow_custom_true():
    ap = json.dumps(
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--0d4a1f02-1a5b-4c9e-9a8f-3f1b2c3d4e5f",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Spear Phishing",
            "x_foo": "bar",
        }
    )
    obj = sf.AttackPattern.from_json(ap, allow_custom=True)
    assert obj.custom_properties == {"x_foo": "bar"}
    assert json.loads(obj.to_json())["x_foo"] == "bar"


def test_sro_from_json_allow_custom_true():
    rel = json.dumps(
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--3f1b2c3d-4e5f-4a0b-8c1d-2e3f4a5b6c7d",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "indicator--0d4a1f02-1a5b-4c9e-9a8f-3f1b2c3d4e5f",
            "target_ref": "indicator--0d4a1f02-1a5b-4c9e-9a8f-3f1b2c3d4e5f",
            "x_foo": "custom-value",
        }
    )
    obj = sf.Relationship.from_json(rel, allow_custom=True)
    assert obj.custom_properties == {"x_foo": "custom-value"}


def test_sco_from_json_allow_custom_true():
    f = json.dumps(
        {
            "type": "file",
            "id": "file--8c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
            "name": "evil.exe",
            "x_foo": "custom-value",
        }
    )
    obj = sf.File.from_json(f, allow_custom=True)
    assert obj.custom_properties == {"x_foo": "custom-value"}


def test_sco_constructor_with_custom_property():
    obj = sf.File(name="evil.exe", x_foo="bar", allow_custom=True)
    out = json.loads(obj.to_json())
    assert out["x_foo"] == "bar"


def test_bundle_roundtrip_preserves_custom_property():
    obj = sf.Indicator.from_json(INDICATOR_JSON, allow_custom=True)
    bundle = sf.Bundle.from_json(
        json.dumps(
            {
                "type": "bundle",
                "id": "bundle--11111111-1111-41e1-a1e1-111111111111",
                "objects": [json.loads(obj.to_json())],
            }
        )
    )
    out = json.loads(bundle.to_json())
    assert out["objects"][0]["x_foo"] == "custom-value"
