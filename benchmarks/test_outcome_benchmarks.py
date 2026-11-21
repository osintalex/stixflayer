"""Benchmarks for the single-pass constructor and parse paths."""

from __future__ import annotations

import json
from typing import Any

import pytest

import stixflayer
from benchmarks.fixtures import DATA_DIR, gc_setup, load_json_text

IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--550e8400-e29b-41d4-a716-446655440000",
    "created": "2019-04-24T15:12:36.609Z",
    "modified": "2023-03-24T15:14:15.637Z",
    "name": "Acme",
    "identity_class": "organization",
}
IDENTITY_JSON = json.dumps(IDENTITY)


def constructor_path() -> Any:
    return stixflayer.Identity(
        id=IDENTITY["id"],
        name="Acme",
        identity_class="organization",
        created=IDENTITY["created"],
        modified=IDENTITY["modified"],
    )


def from_json_path() -> Any:
    return stixflayer.Identity.from_json(IDENTITY_JSON)


def bundle_path() -> Any:
    return stixflayer.Bundle.from_json(load_json_text(DATA_DIR / "apt1.json"))


@pytest.mark.parametrize(
    "target",
    [constructor_path, from_json_path],
    ids=["constructor", "from_json"],
)
def test_single_object_paths(benchmark: Any, target: Any) -> None:
    """Compare the constructor and parse paths."""
    benchmark.group = "single_object_paths"
    benchmark.extra_info["path"] = target.__name__
    benchmark.pedantic(target, setup=gc_setup, rounds=100, warmup_rounds=10)


def test_bundle_parse(benchmark: Any) -> None:
    """Full bundle parse through the single-pass validation pipeline."""
    benchmark.group = "bundle_parse"
    benchmark.pedantic(bundle_path, setup=gc_setup, rounds=20, warmup_rounds=5)
