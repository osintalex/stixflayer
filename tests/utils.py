"""Shared test utilities for stixflayer Python tests."""

from pathlib import Path
import json

# Project root is one level up from tests/
DATA_DIR = Path(__file__).parent.parent / "testdata" / "stix"


def load_fixture(path: str) -> str:
    """Load a fixture file from testdata/stix/ as a string."""
    fixture_path = DATA_DIR / path
    return fixture_path.read_text()


def load_fixture_json(path: str) -> dict:
    """Load a fixture file from testdata/stix/ and parse as JSON."""
    return json.loads(load_fixture(path))
