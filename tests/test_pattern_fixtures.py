"""Fixture-driven STIX pattern validation tests.

The corpus under ``testdata/stix/{valid,invalid}/patterns/`` is language
agnostic: the Rust suite reads the same files. Valid entries must validate,
invalid entries must fail at their declared layer, and every invalid entry's
``expected_error`` must appear in the message.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import stixflayer

PATTERNS_DIR = Path(__file__).parent.parent / "testdata" / "stix"
VALID_DIR = PATTERNS_DIR / "valid" / "patterns"
INVALID_DIR = PATTERNS_DIR / "invalid" / "patterns"


def load_entries(directory: Path) -> list[dict[str, Any]]:
    """Load every JSON array in a fixture directory."""
    entries: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        entries.extend(json.loads(path.read_text(encoding="utf-8")))
    return entries


VALID = load_entries(VALID_DIR)
INVALID = load_entries(INVALID_DIR)


def pytest_params(entries: list[dict[str, Any]]) -> list[Any]:
    """Turn fixture entries into pytest parameters keyed by fixture id."""
    return [pytest.param(entry, id=entry["id"]) for entry in entries]


def test_fixture_schema() -> None:
    """Every entry has the shared schema, with unique IDs across both sets."""
    ids: set[str] = set()
    for entry in VALID:
        assert set(entry) == {"id", "description", "pattern", "spec"}, entry["id"]
        assert all(entry[key] for key in ("id", "description", "pattern", "spec")), entry["id"]
        assert entry["id"] not in ids, f"duplicate fixture id {entry['id']}"
        ids.add(entry["id"])

    for entry in INVALID:
        assert set(entry) == {
            "id",
            "description",
            "pattern",
            "spec",
            "layer",
            "expected_error",
        }, entry["id"]
        assert all(entry[key] for key in entry), entry["id"]
        assert entry["layer"] in {"grammar", "semantic"}, entry["id"]
        assert entry["id"] not in ids, f"duplicate fixture id {entry['id']}"
        ids.add(entry["id"])


@pytest.mark.parametrize("entry", pytest_params(VALID))
def test_valid_pattern_fixture(entry: dict[str, Any]) -> None:
    """Every valid fixture validates."""
    stixflayer.validate_pattern(entry["pattern"])


@pytest.mark.parametrize("entry", pytest_params(INVALID))
def test_invalid_pattern_fixture(entry: dict[str, Any]) -> None:
    """Every invalid fixture fails at its declared layer with the expected message."""
    with pytest.raises(stixflayer.ValidationError) as exc_info:
        stixflayer.validate_pattern(entry["pattern"])

    error = exc_info.value
    grammar_rejected = any(entry_.get("kind") == "invalid_pattern" for entry_ in error.errors)
    if entry["layer"] == "grammar":
        assert grammar_rejected, f"{entry['id']}: expected a grammar rejection: {error}"
    else:
        assert not grammar_rejected, f"{entry['id']}: expected a semantic rejection: {error}"

    assert entry["expected_error"] in str(error), f"{entry['id']}: {error}"
