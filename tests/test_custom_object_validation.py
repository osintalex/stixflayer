"""Tests for extension-less custom objects and opt-in relationship leniency."""

from __future__ import annotations

import json

import pytest

import stixflayer
from tests.utils import load_fixture

CUSTOM_OBJECT = "custom_objects/extensionless-custom-object.json"
CUSTOM_RELATIONSHIP = "custom_objects/custom-object-relationship.json"
TOOL_USES = "custom_objects/tool-uses-attack-pattern.json"


def warning_kinds(obj) -> list[str]:
    return [warning["kind"] for warning in obj.warnings]


def test_extensionless_custom_object_is_valid_with_a_warning():
    obj = stixflayer.CustomObject.from_json(load_fixture(CUSTOM_OBJECT))
    assert obj.type == "x-example-com-customobject"
    assert "custom_missing_extension" in warning_kinds(obj)


def test_custom_object_with_new_sdo_does_not_warn():
    obj = stixflayer.CustomObject.from_json(
        json.dumps(
            {
                "type": "x-example-com-customobject",
                "spec_version": "2.1",
                "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "extensions": {
                    "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62": {
                        "extension_type": "new-sdo"
                    }
                },
                "name": "Custom SDO",
            }
        )
    )
    assert "custom_missing_extension" not in warning_kinds(obj)


def test_custom_object_relationship_is_strict_by_default():
    with pytest.raises(stixflayer.ValidationError) as exc_info:
        stixflayer.Bundle.from_json(load_fixture(CUSTOM_RELATIONSHIP))

    assert any(entry["kind"] == "invalid_nested_object" for entry in exc_info.value.errors)


def test_tool_uses_attack_pattern_is_strict_by_default():
    with pytest.raises(stixflayer.ValidationError):
        stixflayer.Bundle.from_json(load_fixture(TOOL_USES))
