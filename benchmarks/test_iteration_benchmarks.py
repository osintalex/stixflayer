"""Iteration benchmarks: walk a parsed bundle and touch common properties."""

from __future__ import annotations

import json
from typing import Any

import pytest
import stixflayer

from benchmarks.fixtures import BUNDLE_FIXTURES, gc_setup


@pytest.mark.parametrize("name,text", BUNDLE_FIXTURES)
def test_iterate_bundle(benchmark: Any, name: str, text: str) -> None:
    """Touch .type and .id on every object in a parsed bundle."""
    parsed = stixflayer.Bundle.from_json(text)
    items = parsed.objects

    def target() -> None:
        for item in items:
            _ = item.type
            _ = item.id

    benchmark.group = "iterate_bundle"
    benchmark.extra_info.update({
        "library": "stixflayer",
        "fixture": name,
        "objects": len(json.loads(text)["objects"]),
    })
    benchmark.pedantic(target, setup=gc_setup, rounds=100, warmup_rounds=5)
