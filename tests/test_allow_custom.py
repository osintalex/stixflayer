"""Tests for allow_custom support.

The from_json parsing semantics are driven by ``testdata/test_matrix.json``
(see ``tests/test_matrix.py``). This module keeps Python API-specific checks:
construction via kwargs, dynamic property access, bundle round-trips, and the
empty-custom-properties state.
"""

from __future__ import annotations

import json

import pytest

import stixflayer as sf

from tests.utils import load_fixture

CUSTOM_INDICATOR_JSON = load_fixture("allow_custom/valid/sdos/indicator-custom.json")


@pytest.fixture
def indicator_kwargs():
    return {
        "name": "Evil indicator",
        "pattern": "[file:name = 'evil.exe']",
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00.000Z",
    }


def test_getattr_custom_property_after_from_json():
    obj = sf.Indicator.from_json(CUSTOM_INDICATOR_JSON, allow_custom=True)
    assert obj.x_foo == "custom-value"


def test_constructor_kwargs_custom_property_with_allow_custom(indicator_kwargs):
    obj = sf.Indicator(**indicator_kwargs, x_foo="custom-value", allow_custom=True)
    assert obj.custom_properties == {"x_foo": "custom-value"}

    out = json.loads(obj.to_json())
    assert out["x_foo"] == "custom-value"


def test_constructor_kwargs_custom_property_without_allow_custom_fails(indicator_kwargs):
    with pytest.raises(sf.ValidationError):
        sf.Indicator(**indicator_kwargs, x_foo="custom-value", allow_custom=False)


def test_constructor_kwargs_custom_property_strict_still_validates():
    """allow_custom=True does not disable required-field validation."""
    with pytest.raises(sf.ValidationError):
        sf.Indicator(name="Evil indicator", x_foo="custom-value", allow_custom=True)


def test_custom_properties_empty_when_no_custom_keys(indicator_kwargs):
    obj = sf.Indicator(**indicator_kwargs, allow_custom=True)
    assert obj.custom_properties == {}


def test_bundle_roundtrip_preserves_custom_property():
    obj = sf.Indicator.from_json(CUSTOM_INDICATOR_JSON, allow_custom=True)
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
