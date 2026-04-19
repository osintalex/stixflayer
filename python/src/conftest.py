# STIX 2.1 Test Suite - Shared fixtures and helpers
from pathlib import Path
import json
from typing import Any

# Path to shared test data
DATA_DIR = Path(__file__).parent.parent.parent / "data" / "stix"


def load_stix_json(filename: str) -> Any:
    """Load a STIX JSON file from the shared test data directory."""
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Test data file not found: {path}")
    with open(path, "r") as f:
        return json.load(f)


def load_sdo_json(sdo_type: str) -> Any:
    """Load an SDO JSON file from the test data."""
    data = load_stix_json(f"sdos/{sdo_type}.json")
    if isinstance(data, list):
        return data[0]
    return data


def load_sco_json(sco_type: str) -> Any:
    """Load an SCO JSON file from the test data."""
    return load_stix_json(f"scos/{sco_type}.json")


def load_sro_json(sro_type: str) -> Any:
    """Load an SRO JSON file from the test data."""
    return load_stix_json(f"sros/{sro_type}.json")


def load_meta_json(meta_type: str) -> Any:
    """Load a meta object JSON file from the test data."""
    return load_stix_json(f"meta/{meta_type}.json")


def load_pattern_json(pattern_type: str = "basic") -> Any:
    """Load a pattern JSON file from the test data."""
    return load_stix_json(f"patterns/{pattern_type}.json")


def load_bundle_json() -> Any:
    """Load a bundle JSON file from the test data."""
    return load_stix_json("bundle.json")
