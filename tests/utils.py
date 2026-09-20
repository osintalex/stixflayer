"""Shared test utilities for stixflayer Python tests."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import stixflayer

# Project root is one level up from tests/
DATA_DIR = Path(__file__).parent.parent / "testdata" / "stix"

# Object types whose Python class name is not a plain kebab-to-title-case
# conversion.
_CLASS_NAME_OVERRIDES = {
    "attack-pattern": "AttackPattern",
    "autonomous-system": "AutonomousSystem",
    "course-of-action": "CourseOfAction",
    "email-addr": "EmailAddress",
    "extension-definition": "ExtensionDefinition",
    "intrusion-set": "IntrusionSet",
    "ipv4-addr": "IPv4Address",
    "ipv6-addr": "IPv6Address",
    "language-content": "LanguageContent",
    "mac-addr": "MacAddr",
    "malware-analysis": "MalwareAnalysis",
    "marking-definition": "MarkingDefinition",
    "observed-data": "ObservedData",
    "threat-actor": "ThreatActor",
    "url": "URL",
    "windows-registry-key": "WindowsRegistryKey",
    "x509-certificate": "X509Certificate",
}


def load_fixture(path: str) -> str:
    """Load a fixture file from testdata/stix/ as a string."""
    fixture_path = DATA_DIR / path
    return fixture_path.read_text()


def load_fixture_json(path: str) -> dict:
    """Load a fixture file from testdata/stix/ and parse as JSON."""
    return json.loads(load_fixture(path))


def class_for_type(stix_type: str) -> type:
    """Return the stixflayer Python class for a STIX object type string."""
    class_name = _CLASS_NAME_OVERRIDES.get(stix_type) or "".join(
        part.capitalize() for part in stix_type.split("-")
    )
    return getattr(stixflayer, class_name)


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp string to a datetime."""
    return datetime.fromisoformat(value)


def to_parsed_json(obj) -> dict:
    """Serialize a stixflayer object to JSON and parse it back to a dict."""
    return json.loads(obj.to_json())


def assert_common_properties(obj, object_type: str) -> None:
    """Assert the common STIX properties every object should expose."""
    assert obj.type == object_type
    assert isinstance(obj.id, str)
    assert obj.id
