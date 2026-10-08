"""Parse benchmarks: single objects and full bundles."""

from __future__ import annotations

import json
from typing import Any

import pytest

from benchmarks.fixtures import (
    BUNDLE_FIXTURES,
    SMALL_FIXTURES,
    gc_setup,
    stix2_validator_parse,
    stixflayer_parse,
)


@pytest.mark.parametrize("library", ["stix2-validator", "stixflayer"])
@pytest.mark.parametrize("fixture", SMALL_FIXTURES)
def test_parse_single_object(benchmark: Any, library: str, fixture: tuple[str, str]) -> None:
    """Parse / validate a single SDO/SCO/meta/SRO fixture."""
    name, text = fixture
    stix_type = json.loads(text)["type"]

    benchmark.group = "parse_single_object"
    benchmark.extra_info.update({
        "library": library,
        "fixture": name,
        "type": stix_type,
    })

    if library == "stix2-validator":
        target = stix2_validator_parse
        args = (text,)
    else:
        target = stixflayer_parse
        args = (text, stix_type)

    benchmark.pedantic(target, args=args, setup=gc_setup, rounds=50, warmup_rounds=5)


@pytest.mark.parametrize("library", ["stix2-validator", "stixflayer"])
@pytest.mark.parametrize("name,text", BUNDLE_FIXTURES)
def test_parse_bundle(benchmark: Any, library: str, name: str, text: str) -> None:
    """Parse / validate a full STIX bundle."""
    benchmark.group = "parse_bundle"
    benchmark.extra_info.update({
        "library": library,
        "fixture": name,
        "objects": len(json.loads(text)["objects"]),
    })

    if library == "stix2-validator":
        target = stix2_validator_parse
    else:
        target = stixflayer_parse
    args = (text,)

    benchmark.pedantic(target, args=args, setup=gc_setup, rounds=30, warmup_rounds=5)
