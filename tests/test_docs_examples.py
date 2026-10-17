"""Test that documentation examples actually run.

Collects every Python code example from the docs pages, the README, and
docstrings under ``src/``. Each example must: lint cleanly with ruff,
execute, and produce exactly the output shown inline in the docs (the
pydantic-style "no example that doesn't compile and run" guarantee).

Examples that must not run are marked explicitly in the fence, e.g.
`` ```python test="skip" ```. Unmarked Python examples always run.

To reformat examples and rewrite their printed output in place, run
``uv run pytest tests/test_docs_examples.py --update-examples``.
"""

import sys
from pathlib import Path

import pytest
from pytest_examples import CodeExample, EvalExample, find_examples

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Docs pages, the README (front door of PyPI/GitHub/docs.rs), and docstrings.
EXAMPLE_ROOTS = (
    PROJECT_ROOT / "docs",
    PROJECT_ROOT / "README.md",
    PROJECT_ROOT / "src",
)
LINE_LENGTH = 120  # matches [tool.ruff] line-length


@pytest.mark.parametrize("example", list(find_examples(*EXAMPLE_ROOTS)), ids=str)
def test_docs_examples(example: CodeExample, eval_example: EvalExample) -> None:
    eval_example.set_config(
        line_length=LINE_LENGTH,
        quotes="double",
        # pytest-examples 0.0.18's own annotation is stale: the Literal in
        # eval_example.py duplicates 'py310' where 'py311' belongs (config.py
        # has the correct list). Runtime honors py311; black accepts it too.
        # Tracked upstream: https://github.com/pydantic/pytest-examples/issues/63
        # (also https://github.com/pydantic/pytest-examples/issues/64)
        # pyrefly: ignore [bad-argument-type]
        target_version="py311",
        # Snippets are linted with the project's ruff (config is auto-discovered),
        # but rules that only make sense for real modules are relaxed here:
        # docstrings and annotations would clutter concise docs examples.
        ruff_ignore=["D", "ANN", "PL", "SIM", "RET", "PERF", "C4", "B", "S"],
    )

    prefixes = example.prefix_settings()
    requires = prefixes.get("requires")
    if requires:
        major, minor = (int(part) for part in requires.split("."))
        if sys.version_info < (major, minor):
            pytest.skip(f"requires python {requires}")

    if prefixes.get("lint", "").startswith("skip"):
        if prefixes.get("test", "").startswith("skip"):
            pytest.skip("example marked skip")
    else:
        eval_example.lint(example)

    if prefixes.get("test", "").startswith("skip"):
        pytest.skip("example marked skip")

    if eval_example.update_examples:
        eval_example.format(example)
        eval_example.run_print_update(example)
    else:
        eval_example.run_print_check(example)
