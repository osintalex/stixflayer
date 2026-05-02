"""Test utilities for loading STIX 2.1 test data"""
from pathlib import Path
import json

# Path to shared test data
DATA_DIR = Path(__file__).parent.parent.parent / "data" / "stix"

def load_stix_json(filename: str) -> dict:
    """Load a STIX JSON file from shared test data."""
    with open(DATA_DIR / filename) as f:
        return json.load(f)

def load_sdo(sdo_type: str) -> dict:
    """Load SDO test data by type name (e.g., 'attack-pattern')."""
    return load_stix_json(f"sdos/{sdo_type}.json")

def load_sco(sco_type: str) -> dict:
    """Load SCO test data by type name (e.g., 'ipv4-addr')."""
    # Handle filename mapping differences
    filename_map = {"email-addr": "email-address"}
    filename = filename_map.get(sco_type, sco_type)
    return load_stix_json(f"scos/{filename}.json")

def load_sro(sro_type: str) -> dict:
    """Load SRO test data by type name (e.g., 'relationship')."""
    return load_stix_json(f"sros/{sro_type}.json")

def load_meta(meta_type: str) -> dict:
    """Load Meta object test data by type name (e.g., 'marking-definition')."""
    return load_stix_json(f"meta/{meta_type}.json")

# STIX 2.1 type constants for parametrized testing
SDO_TYPES = [
    "attack-pattern", "campaign", "course-of-action", "grouping", "identity",
    "incident", "indicator", "infrastructure", "intrusion-set", "location",
    "malware", "malware-analysis", "note", "observed-data", "opinion",
    "report", "threat-actor", "tool", "vulnerability"
]

SCO_TYPES = [
    "artifact", "autonomous-system", "directory", "domain-name", "email-addr",
    "email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex",
    "network-traffic", "process", "software", "url", "user-account",
    "windows-registry-key", "x509-certificate"
]

SRO_TYPES = ["relationship", "sighting"]

META_TYPES = ["marking-definition", "extension-definition", "language-content", "bundle"]
