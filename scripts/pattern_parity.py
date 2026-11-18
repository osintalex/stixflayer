#!/usr/bin/env python3
"""Compare stixflayer's pattern verdicts with the ``stix2patterns`` reference.

This is a diagnostic, not a gate: it is intentionally outside ``pytest`` and
CI. It reads the shared fixture corpus, validates every pattern with both
implementations, and prints each disagreement. Known reference drifts are
labelled; anything else is reported as unexpected.

Usage:
    python scripts/pattern_parity.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import stixflayer

try:
    from stix2patterns.validator import run_validator
except ImportError:  # the parity script is optional; the package is not a project dependency
    run_validator = None

ROOT = Path(__file__).resolve().parent.parent
PATTERNS_DIR = ROOT / "testdata" / "stix"

# Fixture id -> why stixflayer intentionally disagrees with the reference.
KNOWN_DIVERGENCES = {
    "V31": "bracket pre-scan rejects a leading block comment; the grammar skips comments",
    "V38": "reference inspector crashes on a negative list index; the grammar allows it",
    "V43": "REPEATS 0: the specification requires a positive integer",
    "V44": "WITHIN 0: the specification requires a positive value",
    "V45": "AND across different SCO types: the specification requires the same SCO",
    "V46": "hash inspector: pattern validation does not inspect hash formats",
    "V54": "hash inspector: pattern validation does not inspect hash formats",
    "I29": "object-path semantic check rejects a non-lowercase custom SCO type",
}


def fixture_entries() -> list[dict]:
    """Load every fixture entry from the valid and invalid directories."""
    entries: list[dict] = []
    for directory in ("valid", "invalid"):
        for path in sorted((PATTERNS_DIR / directory / "patterns").glob("*.json")):
            entries.extend(json.loads(path.read_text(encoding="utf-8")))
    return entries


def stixflayer_verdict(pattern: str) -> str:
    """Return stixflayer's verdict for a pattern."""
    try:
        stixflayer.validate_pattern(pattern)
    except stixflayer.ValidationError:
        return "reject"
    return "accept"


def reference_verdict(pattern: str) -> str:
    """Return the reference validator's verdict, or its crash type."""
    assert run_validator is not None
    try:
        return "accept" if not run_validator(pattern) else "reject"
    except Exception as exc:
        return f"crash:{type(exc).__name__}"


def main() -> int:
    """Run the comparison and report divergences."""
    if run_validator is None:
        print("stix2patterns is not installed; skipping parity comparison")
        return 0

    divergences = 0
    unexpected = 0

    for entry in fixture_entries():
        ours = stixflayer_verdict(entry["pattern"])
        reference = reference_verdict(entry["pattern"])
        if ours == reference:
            continue

        divergences += 1
        reason = KNOWN_DIVERGENCES.get(entry["id"])
        if reason is None:
            unexpected += 1
            print(f"UNEXPECTED {entry['id']:4} stixflayer={ours:6} reference={reference:20}")
        else:
            print(f"known      {entry['id']:4} stixflayer={ours:6} reference={reference:20} {reason}")
        print(f"           {entry['pattern']}")

    print(f"\n{divergences} divergences ({unexpected} unexpected)")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
