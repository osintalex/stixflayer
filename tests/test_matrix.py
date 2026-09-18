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

from tests.utils import load_fixture

MATRIX_PATH = Path(__file__).parent.parent / "testdata" / "test_matrix.json"

# Explicit mapping for object types whose Python class name is not a simple
# kebab-to-PascalCase conversion.
OBJECT_TYPE_TO_CLASS: dict[str, type] = {
    "indicator": sf.Indicator,
    "attack-pattern": sf.AttackPattern,
    "malware": sf.Malware,
    "bundle": sf.Bundle,
    "file": sf.File,
    "relationship": sf.Relationship,
    "ipv4-addr": sf.IPv4Address,
    "email-addr": sf.EmailAddress,
    "mac-addr": sf.MacAddr,
    "ipv6-addr": sf.IPv6Address,
    "x509-certificate": sf.X509Certificate,
    "autonomous-system": sf.AutonomousSystem,
    "windows-registry-key": sf.WindowsRegistryKey,
}


def _stix_class(object_type: str) -> type:
    """Return the stixflayer class for a STIX object type string."""
    if object_type in OBJECT_TYPE_TO_CLASS:
        return OBJECT_TYPE_TO_CLASS[object_type]

    parts = object_type.split("-")
    conventional = "".join(part.capitalize() for part in parts)
    cls = getattr(sf, conventional, None)
    if cls is None:
        pytest.exit(f"test_matrix.py: unknown object_type {object_type!r}", returncode=2)
    return cls


def _matrix_section(section: str) -> list:
    matrix = json.loads(MATRIX_PATH.read_text())
    return [pytest.param(key, entry, id=key) for key, entry in matrix[section].items()]


def _call_from_json(cls: type, json_str: str, entry: dict[str, Any]) -> Any:
    object_type = entry["object_type"]
    kwargs: dict[str, Any] = {"version": "2.1"}

    strict = entry.get("strict", True)
    allow_custom = entry.get("allow_custom", False)

    # Bundle has a narrower from_json signature.
    if object_type == "bundle":
        return cls.from_json(json_str)

    kwargs["strict"] = strict
    kwargs["allow_custom"] = allow_custom
    return cls.from_json(json_str, **kwargs)


def _exc_class_for(behavior: str) -> type:
    if behavior == "deserialization_error":
        return sf.DeserializationError
    return sf.ValidationError


@pytest.mark.parametrize(("key", "entry"), _matrix_section("validation_rules"))
def test_validation_rule(key: str, entry: dict[str, Any]) -> None:
    cls = _stix_class(entry["object_type"])
    json_str = load_fixture(entry["fixture"])
    behavior = entry.get("expected_behavior", "validation_error")
    substring = entry.get("expected_error_substring")

    if behavior == "parses_successfully":
        obj = _call_from_json(cls, json_str, entry)
        assert obj.type == entry["object_type"]
    else:
        exc_class = _exc_class_for(behavior)
        with pytest.raises(
            exc_class,
            match=re.escape(substring) if substring else None,
        ):
            _call_from_json(cls, json_str, entry)


@pytest.mark.parametrize(("key", "entry"), _matrix_section("custom_properties"))
def test_custom_property_rule(key: str, entry: dict[str, Any]) -> None:
    cls = _stix_class(entry["object_type"])
    json_str = load_fixture(entry["fixture"])
    behavior = entry.get("expected_behavior", "validation_error")
    substring = entry.get("expected_error_substring")
    expected_custom = entry.get("expected_custom")

    if behavior == "parses_successfully":
        obj = _call_from_json(cls, json_str, entry)
        assert obj.type == entry["object_type"]

        if expected_custom:
            assert obj.custom_properties == expected_custom

            # Round-trip assertion: custom keys survive serialization.
            roundtrip = json.loads(obj.to_json())
            for prop, value in expected_custom.items():
                assert roundtrip[prop] == value
    else:
        exc_class = _exc_class_for(behavior)
        with pytest.raises(
            exc_class,
            match=re.escape(substring) if substring else None,
        ):
            _call_from_json(cls, json_str, entry)
