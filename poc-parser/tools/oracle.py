#!/usr/bin/env python3
"""Build and verify the STIX pattern corpus.

The corpus records the *grammar-layer* verdict for every case, because the
front-end PoCs only implement the grammar. `basis` records why a verdict is
authoritative; `semantic` flags grammar-valid cases whose verdict differs once
the semantic layer (shipped `stix_check` or the reference inspector) runs.

Usage:
    python3 tools/oracle.py --write   # regenerate corpus/*.jsonl
    python3 tools/oracle.py           # verify corpus is current and correct
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stix2patterns.v21.pattern import Pattern
from stix2patterns.validator import run_validator

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
SPEC_EXAMPLES = CORPUS / "spec_examples.txt"

# Extra valid patterns. The reference validator's own 23 examples are loaded
# from spec_examples.txt and numbered V01..V23; these continue at V24.
EXTRA_VALID = [
    ("V24", "[file:name='x']", False, "whitespace is optional between tokens; shipped parser rejects"),
    ("V25", "[file:name == 'x']", False, "EQ allows '=' or '=='"),
    ("V26", "[file:name <> 'x']", False, "NEQ allows '!=' or '<>'"),
    ("V27", "[file:name IN ()]", False, "setLiteral allows an empty set; shipped parser rejects"),
    ("V28", "[file:name NOT = 'x']", False, "NOT sits between the object path and the operator"),
    ("V29", "[NOT EXISTS file:name]", False, "NOT is allowed before EXISTS"),
    ("V30", "[file:name = 'x'] // trailing", False, "LINE_COMMENT is skipped"),
    ("V31", "/* leading */ [file:name = 'x']", False, "COMMENT is skipped; reference rejects via brackets_check (reference bug)"),
    ("V32", "[\u00a0file:name = 'x']", False, "U+00A0 is in the grammar WS set"),
    ("V33", "[file:name = 'a\\'b\\\\c']", False, "StringLiteral allows \\' and \\\\ escapes"),
    ("V34", "[file:name = b'YWJjZA==']", False, "BinaryLiteral with '==' padding"),
    ("V35", "[file:size >= 1000]", False, "GE is a single token; shipped parser rejects"),
    ("V36", "[file:size <= 1000]", False, "LE is a single token; shipped parser rejects"),
    ("V37", "[file:name = 'x'] START t'2025-01-01T00:00:00Z' STOP t'2025-02-01T00:00:00Z'", False, "qualifier keywords are START/STOP; shipped parser uses STARTS/STOPS"),
    ("V38", "[email-message:body_multipart[-1].body_raw_ref.name = 'x']", False, "indexPathStep allows IntNegLiteral; reference inspector crashes (reference bug)"),
    ("V39", "[file:created = t'2016-12-31T23:59:60Z']", False, "TimestampLiteral allows a leap second"),
    ("V40", "[file:name = 'x'] WITHIN 600.5 SECONDS", False, "FloatPosLiteral is allowed for WITHIN"),
    ("V41", "[file:size = +5]", False, "IntPosLiteral allows a leading '+'"),
    ("V42", "[file:size = .5]", False, "FloatPosLiteral allows an empty integer part"),
    ("V43", "[file:name = 'x'] REPEATS 0 TIMES", True, "brief case I16: grammar and reference accept; spec requires a positive integer; shipped semantics reject"),
    ("V44", "[file:name = 'x'] WITHIN 0 SECONDS", True, "grammar and reference accept zero; spec requires x > 0; shipped semantics reject"),
    ("V45", "[ipv4-addr:value = '1.1.1.1' AND ipv6-addr:value = '::1']", True, "spec requires the same SCO; reference accepts; shipped semantics reject"),
    ("V46", "[file:hashes.'SHA-256' = 'x']", True, "reference hash inspector rejects a non-hash value; grammar accepts"),
    ("V47", "([file:name = 'a'] AND [file:name = 'b']) WITHIN 300 SECONDS", False, "qualifier applies to a parenthesised group"),
    ("V48", "[file:name = 'x'] WITHIN 600 SECONDS REPEATS 5 TIMES", False, "qualifiers may chain"),
    ("V49", "[file:name NOT IN ('a','b')]", False, "NOT also applies to IN"),
    ("V50", "[file:name = 'x'] REPEATS 5 TIMES", False, "standalone REPEATS qualifier"),
    ("V51", "[file:name = 'x'] WITHIN 600 SECONDS WITHIN 300 SECONDS", True, "duplicate qualifier: grammar accepts; reference and shipped semantics reject"),
]

INVALID = [
    ("I01", "[file:name = ]", "missing value; expected set should list the literal kinds"),
    ("I02", "[file:name ~= 'evil']", "'~' is InvalidCharacter; lexer versus parser error"),
    ("I03", "[file:name = 'x' AND]", "dangling AND; expected set should list propTest starts"),
    ("I04", "[file:name = 'x' FALLOWEDBY [domain-name:value = 'y']]", "operator typo inside the bracket; reference expected set is only ']'"),
    ("I05", "[file:name = 'x", "unterminated string literal"),
    ("I06", "[file:created = t'2025-13-01T00:00:00Z']", "invalid month; ANTLR falls back to identifier + string"),
    ("I07", "file:name = 'x'", "missing brackets"),
    ("I08", "[file:name]", "missing comparison"),
    ("I09", "[file:name IN (]", "malformed set literal"),
    ("I10", "[file:name = 'x']]", "trailing garbage; position matters"),
    ("I11", "[file:name = 'x' AND file:size > 0", "missing closing bracket at EOF"),
    ("I12", "[NOT file:name = 'x']", "NOT is not a prefix on comparisons"),
    ("I13", "[file:name = 'x'] WITHIN -5 SECONDS", "withinQualifier only accepts positive literals"),
    ("I14", "[file:name = 'x' oR file:size > 0]", "keywords are case-sensitive"),
    ("I15", "[file:name = 'x'] WITHIN 600 seconds", "qualifier keywords are uppercase"),
    ("I17", "[file:size = 007]", "IntPosLiteral forbids leading zeros; shipped parser accepts"),
    ("I18", "[file:name = 'x'] REPEATS -1 TIMES", "repeatedQualifier requires IntPosLiteral"),
    ("I19", "[file:name = 'x'] LAST 5", "LAST is a lexer keyword but unused by parser rules"),
    ("I20", "[file:name = 'x'] STARTS t'2025-01-01T00:00:00Z' STOPS t'2025-02-01T00:00:00Z'", "wrong qualifier keywords"),
    ("I21", "[]", "empty observation expression"),
    ("I22", "[file:name = 'a\\nb']", "only \\' and \\\\ are valid escapes"),
    ("I23", "AND [file:name = 'x']", "leading operator"),
    ("I25", "[file:name = 'x'] FALLOWEDBY [domain-name:value = 'y']", "same typo after the bracket; reference expected set is only EOF"),
    ("I26", "[file:name = 'x'] AND", "dangling observation operator"),
    ("I27", "[file:name = 'x'] WITHIN 600", "missing SECONDS"),
    ("I28", "[file:name = 'x'] WITHIN", "missing value and SECONDS"),
]


def grammar_verdict(pattern: str) -> str:
    try:
        Pattern(pattern)
    except Exception:
        return "reject"
    return "accept"


def reference_verdict(pattern: str) -> str:
    try:
        return "accept" if not run_validator(pattern) else "reject"
    except Exception as exc:  # reference inspector crashes on some valid input
        return f"crash:{type(exc).__name__}"


def build() -> list[dict]:
    cases: list[dict] = []

    for line_no, line in enumerate(SPEC_EXAMPLES.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        cases.append(
            {
                "id": f"V{line_no:02d}",
                "input": line,
                "expected": "accept",
                "basis": "reference",
                "semantic": False,
                "note": f"spec_examples.txt line {line_no} (reference validator fixture)",
            }
        )

    for case_id, pattern, semantic, note in EXTRA_VALID:
        cases.append(
            {
                "id": case_id,
                "input": pattern,
                "expected": "accept",
                "basis": "grammar",
                "semantic": semantic,
                "note": note,
            }
        )

    for case_id, pattern, note in INVALID:
        cases.append(
            {
                "id": case_id,
                "input": pattern,
                "expected": "reject",
                "basis": "grammar",
                "semantic": False,
                "note": note,
            }
        )

    seen: set[str] = set()
    for case in cases:
        if case["id"] in seen:
            raise SystemExit(f"duplicate id: {case['id']}")
        seen.add(case["id"])
        actual = grammar_verdict(case["input"])
        if actual != case["expected"]:
            raise SystemExit(
                f"{case['id']}: expected {case['expected']} but grammar says {actual}: {case['input']!r}"
            )

    return sorted(cases, key=lambda c: c["id"])


def render(cases: list[dict]) -> dict[str, str]:
    valid = [c for c in cases if c["expected"] == "accept"]
    invalid = [c for c in cases if c["expected"] == "reject"]

    def dump(rows: list[dict]) -> str:
        return "".join(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows
        )

    return {"valid.jsonl": dump(valid), "invalid.jsonl": dump(invalid)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate corpus files")
    parser.add_argument("--report", action="store_true", help="print reference divergences")
    args = parser.parse_args()

    cases = build()
    files = render(cases)

    if args.report:
        for case in cases:
            ref = reference_verdict(case["input"])
            if ref != case["expected"]:
                print(f"{case['id']:4s} grammar={case['expected']:6s} reference={ref:22s} {case['input'][:60]}")

    if args.write:
        for name, content in files.items():
            (CORPUS / name).write_text(content, encoding="utf-8")
        print(f"wrote {sum(len(v.splitlines()) for v in files.values())} cases")
        return 0

    failures = 0
    for name, content in files.items():
        path = CORPUS / name
        if not path.exists():
            print(f"MISSING {path}")
            failures += 1
        elif path.read_text(encoding="utf-8") != content:
            print(f"STALE   {path} (run --write)")
            failures += 1
    if failures:
        return 1
    print(f"corpus OK: {len(cases)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
