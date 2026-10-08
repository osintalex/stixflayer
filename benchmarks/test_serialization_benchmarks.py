"""Serialization benchmarks: convert a parsed bundle back to JSON."""

from __future__ import annotations

import json
from typing import Any

import pytest
import stixflayer

from benchmarks.fixtures import BUNDLE_FIXTURES, gc_setup


@pytest.mark.parametrize("name,text", BUNDLE_FIXTURES)
def test_serialize_bundle(benchmark: Any, name: str, text: str) -> None:
    """Serialize a parsed bundle back to a JSON string."""
    parsed = stixflayer.Bundle.from_json(text)

    def target() -> str:
        return parsed.to_json()

    benchmark.group = "serialize_bundle"
    benchmark.extra_info.update({
        "library": "stixflayer",
        "fixture": name,
        "objects": len(json.loads(text)["objects"]),
    })
    benchmark.pedantic(target, setup=gc_setup, rounds=30, warmup_rounds=5)
