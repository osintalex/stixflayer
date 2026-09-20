"""Generic matrix-driven tests.

This module consumes ``testdata/test_matrix.json`` and generates one pytest case
per rule so that the matrix (not the test file) is the source of truth. The
fixtures and matrix are intended to be reusable by other language bindings
(Rust first, then JavaScript/Go/Java, etc.).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import stixflayer as sf

from tests.utils import class_for_type, load_fixture

MATRIX_PATH = Path(__file__).parent.parent / "testdata" / "test_matrix.json"

ERROR_CLASSES = {
    "deserialization_error": sf.DeserializationError,
    "validation_error": sf.ValidationError,
}


def matrix_section(section: str) -> list:
    """Return pytest parameters for one section of the test matrix."""
    matrix = json.loads(MATRIX_PATH.read_text())
    return [pytest.param(key, entry, id=key) for key, entry in matrix[section].items()]


def parse_fixture(cls: type, json_str: str, entry: dict[str, Any]) -> Any:
    """Parse a fixture using the flags recorded in the matrix entry."""
    if entry["object_type"] == "bundle":
        return cls.from_json(json_str)

    return cls.from_json(
        json_str,
        version="2.1",
        strict=entry.get("strict", True),
        allow_custom=entry.get("allow_custom", False),
    )


@pytest.mark.parametrize(("key", "entry"), matrix_section("validation_rules"))
def test_validation_rule(key: str, entry: dict[str, Any]) -> None:
    cls = class_for_type(entry["object_type"])
    json_str = load_fixture(entry["fixture"])
    behavior = entry.get("expected_behavior", "validation_error")
    substring = entry.get("expected_error_substring")

    if behavior == "parses_successfully":
        obj = parse_fixture(cls, json_str, entry)
        assert obj.type == entry["object_type"]
    else:
        exc_class = ERROR_CLASSES.get(behavior, sf.ValidationError)
        with pytest.raises(
            exc_class,
            match=re.escape(substring) if substring else None,
        ):
            parse_fixture(cls, json_str, entry)


@pytest.mark.parametrize(("key", "entry"), matrix_section("custom_properties"))
def test_custom_property_rule(key: str, entry: dict[str, Any]) -> None:
    cls = class_for_type(entry["object_type"])
    json_str = load_fixture(entry["fixture"])
    behavior = entry.get("expected_behavior", "validation_error")
    substring = entry.get("expected_error_substring")
    expected_custom = entry.get("expected_custom")

    if behavior == "parses_successfully":
        obj = parse_fixture(cls, json_str, entry)
        assert obj.type == entry["object_type"]

        if expected_custom:
            assert obj.custom_properties == expected_custom

            # Round-trip assertion: custom keys survive serialization.
            roundtrip = json.loads(obj.to_json())
            for prop, value in expected_custom.items():
                assert roundtrip[prop] == value
    else:
        exc_class = ERROR_CLASSES.get(behavior, sf.ValidationError)
        with pytest.raises(
            exc_class,
            match=re.escape(substring) if substring else None,
        ):
            parse_fixture(cls, json_str, entry)
