#!/usr/bin/env python3
"""Release gate: decide whether a package's manifest version advanced.

Compares the version in a manifest (``pyproject.tom`` or ``Cargo.toml``)
against the latest release tag of that package (``py-v*`` / ``rust-v*``).
A release is due if and only if the manifest version is strictly greater
than the version in the latest matching tag, or no matching tag exists yet
(first release). Prints GitHub Actions output assignments:

    <prefix>release=<true|false>
    <prefix>version=<x.y.z>

Standalone use (no git repository needed):

    check_release_gate.py --manifest pyproject.toml --tag-prefix py-v \
        --version 0.2.0 --output-prefix py_ --tags "py-v0.1.0 py-v0.2.10"

In the release workflow, ``--version`` and ``--tags`` are omitted: the
version comes from the manifest and the tags come from
``git tag --list '<prefix>*'``.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import tomllib
from pathlib import Path


def read_manifest_version(path: Path) -> str:
    """Read the package version from a pyproject.toml or Cargo.toml manifest."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if "project" in data and "version" in data["project"]:  # pyproject.toml
        return str(data["project"]["version"])
    if "package" in data and "version" in data["package"]:  # Cargo.toml
        return str(data["package"]["version"])
    raise SystemExit(f"no package version found in {path}")


def parse_version(text: str) -> tuple[int, ...]:
    """Parse a dotted numeric version like 0.2.10 into a comparable tuple."""
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)", text.strip())
    if not match:
        raise SystemExit(f"cannot parse version: {text!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def list_tags(prefix: str) -> list[str]:
    """List the repository's tags starting with the given prefix."""
    result = subprocess.run(
        ["git", "tag", "--list", f"{prefix}*"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.split()


def main() -> None:
    """Parse arguments, compare the manifest version against release tags, print the verdict."""
    parser = argparse.ArgumentParser(description="Decide whether a release is due.")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--tag-prefix", required=True)
    parser.add_argument("--version", help="override the manifest version (for testing)")
    parser.add_argument("--tags", help="space-separated tag list (for testing; default: git)")
    parser.add_argument("--output-prefix", default="", help="prefix for printed output keys")
    args = parser.parse_args()

    version = args.version if args.version else read_manifest_version(args.manifest)
    current = parse_version(version)

    tags = args.tags.split() if args.tags is not None else list_tags(args.tag_prefix)
    latest: tuple[int, ...] | None = None
    for tag in tags:
        if not tag.startswith(args.tag_prefix):
            continue
        candidate = parse_version(tag[len(args.tag_prefix) :])
        if latest is None or candidate > latest:
            latest = candidate

    release = latest is None or current > latest
    print(f"{args.output_prefix}release={'true' if release else 'false'}")
    print(f"{args.output_prefix}version={version}")


if __name__ == "__main__":
    main()
