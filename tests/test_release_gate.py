"""Tests for the release gate script in ``.github/scripts``.

The gate decides whether a package version advanced beyond its latest
release tag. Its Rust channel reads the effective version through
``cargo metadata`` so that a workspace-inherited ``version.workspace =
true`` resolves to the number cargo would publish.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check_release_gate.py"
CARGO = shutil.which("cargo")


def load_gate() -> ModuleType:
    """Import the gate script as a module."""
    spec = importlib.util.spec_from_file_location("check_release_gate", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_gate(*args: str) -> dict[str, str]:
    """Run the gate script as a subprocess and parse its key=value output."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


@pytest.mark.parametrize(
    ("version", "expected_release"),
    [("0.2.11", "true"), ("0.2.10", "false"), ("0.1.0", "false")],
)
def test_version_override_compares_against_tags(version: str, expected_release: str) -> None:
    """``--version`` still overrides the manifest for tag comparison."""
    outputs = run_gate(
        "--manifest",
        str(REPO_ROOT / "pyproject.toml"),
        "--tag-prefix",
        "py-v",
        "--version",
        version,
        "--tags",
        "py-v0.1.0 py-v0.2.10",
        "--output-prefix",
        "py_",
    )
    assert outputs == {"py_release": expected_release, "py_version": version}


def test_pyproject_version_is_read_directly(tmp_path: Path) -> None:
    """The Python channel still reads its version from ``pyproject.toml``."""
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[project]\nname = "fixture"\nversion = "1.2.3"\n', encoding="utf-8")
    assert load_gate().read_manifest_version(manifest) == "1.2.3"


@pytest.mark.skipif(CARGO is None, reason="cargo is required to resolve workspace versions")
def test_workspace_inherited_version_is_resolved(tmp_path: Path) -> None:
    """A ``version.workspace = true`` package reports the workspace version."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("", encoding="utf-8")
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(
        "[package]\n"
        'name = "fixture"\n'
        "version.workspace = true\n"
        'edition = "2021"\n'
        "\n"
        "[workspace]\n"
        'members = ["."]\n'
        "\n"
        "[workspace.package]\n"
        'version = "0.1.1"\n'
        'edition = "2021"\n',
        encoding="utf-8",
    )
    assert load_gate().read_manifest_version(manifest) == "0.1.1"
