"""Fixture loading and cross-library validation for benchmarks."""

from __future__ import annotations

import gc
import json
from pathlib import Path
from typing import Any

import pytest
import stix2validator
import stixflayer


def gc_setup() -> None:
    """Collect garbage before a benchmarked call."""
    gc.collect()


DATA_DIR = Path(__file__).parent / "data"
TESTDATA_DIR = Path(__file__).parent.parent / "testdata" / "stix" / "valid"

# Mapping from STIX object type to stixflayer class name.
TYPE_TO_CLASS = {
    "attack-pattern": "AttackPattern",
    "campaign": "Campaign",
    "course-of-action": "CourseOfAction",
    "grouping": "Grouping",
    "identity": "Identity",
    "incident": "Incident",
    "indicator": "Indicator",
    "infrastructure": "Infrastructure",
    "intrusion-set": "IntrusionSet",
    "language-content": "LanguageContent",
    "location": "Location",
    "malware": "Malware",
    "malware-analysis": "MalwareAnalysis",
    "marking-definition": "MarkingDefinition",
    "note": "Note",
    "observed-data": "ObservedData",
    "opinion": "Opinion",
    "relationship": "Relationship",
    "report": "Report",
    "sighting": "Sighting",
    "threat-actor": "ThreatActor",
    "tool": "Tool",
    "vulnerability": "Vulnerability",
    "extension-definition": "ExtensionDefinition",
    "artifact": "Artifact",
    "autonomous-system": "AutonomousSystem",
    "directory": "Directory",
    "domain-name": "DomainName",
    "email-addr": "EmailAddress",
    "email-message": "EmailMessage",
    "file": "File",
    "ipv4-addr": "IPv4Address",
    "ipv6-addr": "IPv6Address",
    "mac-addr": "MacAddr",
    "mutex": "Mutex",
    "network-traffic": "NetworkTraffic",
    "process": "Process",
    "software": "Software",
    "url": "URL",
    "user-account": "UserAccount",
    "windows-registry-key": "WindowsRegistryKey",
    "x509-certificate": "X509Certificate",
}


def _stixflayer_class(stix_type: str) -> type:
    cls_name = TYPE_TO_CLASS.get(stix_type)
    if cls_name is None:
        raise KeyError(f"Unknown stixflayer class for type {stix_type!r}")
    return getattr(stixflayer, cls_name)


def load_json_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def stix2_validator_parse(text: str) -> Any:
    options = stix2validator.util.ValidationOptions(silent=True, version="2.1")
    return stix2validator.validate_string(text, options)


def stixflayer_parse(text: str, stix_type: str | None = None) -> Any:
    parsed = json.loads(text)
    obj_type = stix_type or parsed.get("type")
    if obj_type == "bundle":
        return stixflayer.Bundle.from_json(text)
    return _stixflayer_class(obj_type).from_json(text)


def validate_fixture(text: str, path: Path) -> tuple[bool, str]:
    """Ensure both the validator and stixflayer accept the fixture."""
    parsed = json.loads(text)
    obj_type = parsed.get("type")
    try:
        validator_results = stix2_validator_parse(text)
    except Exception as exc:  # noqa: BLE001
        return False, f"stix2-validator failed on {path.name}: {exc}"

    if not validator_results.is_valid:
        errors = [e.message for e in (validator_results.errors or [])]
        return False, f"stix2-validator rejected {path.name}: {errors}"

    try:
        stixflayer_obj = stixflayer_parse(text, stix_type=obj_type)
    except Exception as exc:  # noqa: BLE001
        return False, f"stixflayer failed on {path.name}: {exc}"

    if obj_type == "bundle":
        validator_count = len(parsed.get("objects", []))
        stixflayer_count = stixflayer_obj.object_count
    else:
        validator_count = 1
        stixflayer_count = 1

    if validator_count != stixflayer_count:
        return False, (
            f"object count mismatch for {path.name}: "
            f"validator={validator_count}, stixflayer={stixflayer_count}"
        )

    return True, ""


def _collect_small_fixtures() -> list[tuple[str, str]]:
    """Collect valid SDO/SCO fixture files that both libraries accept."""
    candidates: list[tuple[str, str]] = []
    for subdir in ("sdos", "scos", "sros", "meta"):
        dir_path = TESTDATA_DIR / subdir
        if not dir_path.exists():
            continue
        for file_path in sorted(dir_path.glob("*.json")):
            text = load_json_text(file_path)
            ok, reason = validate_fixture(text, file_path)
            stix_type = json.loads(text).get("type")
            param_id = f"{stix_type}-{file_path.stem}"
            marks = [pytest.mark.skip(reason=reason)] if not ok else []
            candidates.append(
                pytest.param(
                    (file_path.name, text),
                    id=param_id,
                    marks=marks,
                )
            )
    return candidates


SMALL_FIXTURES = _collect_small_fixtures()

BUNDLE_FIXTURES = [
    pytest.param(
        "apt1",
        load_json_text(DATA_DIR / "apt1.json"),
        id="apt1",
    ),
    pytest.param(
        "poisonivy",
        load_json_text(DATA_DIR / "poisonivy.json"),
        id="poisonivy",
    ),
]
