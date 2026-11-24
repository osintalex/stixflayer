---
hide:
  - navigation
  - toc
---

# 🧠 Stixflayer 🦑

The fastest, most spec-correct STIX 2.1 library for Python, powered by a Rust engine, with a native CLI.

Parse, validate, and serialize at **~30–43× the speed** of the industry-standard
Python validator, with stricter spec enforcement.

<div class="grid cards" markdown>

-   🚀 **Quickstart**

    ---

    Parse a document, build an object, handle errors — in five minutes.

    [:material-arrow-right: Get started](quickstart.md)

-   📖 **Guides**

    ---

    Parsing, building, validation modes, vocabularies, patterns, errors, and
    conformance.

    [:material-book-open: Browse the guides](guides/parsing.md)

-   📚 **API reference**

    ---

    Curated reference for every public class and function.

    [:material-api: Open the reference](api/overview.md)

-   🖥️ **CLI**

    ---

    Validate files, directories, and standard input with the native binary.

    [:material-console: Read the CLI reference](cli.md)

-   🦀 **Rust crate**

    ---

    The native engine, documented where Rust users expect it.

    [:simple-rust: docs.rs/stixflayer](https://docs.rs/stixflayer)

</div>

## Why stixflayer? 🤔

- ⚙️ **One engine, no validation gaps** — the same Rust engine powers the
  Python package and the CLI, so a document gets the same verdict through
  every interface.
- ⚔️ **Spec-first, not tool-first** — follows the OASIS STIX 2.1
  specification, including its MUST/SHOULD distinction. MUST violations fail;
  SHOULD findings are reported as warnings.
- 🧐 **Complete structural validation** — rejects empty bundles, malformed
  identifiers, closed-enumeration violations, and incorrect SCO UUIDv5
  hashes.

## Performance 🚀

| Operation                           | Baseline | stixflayer | speedup |
| ----------------------------------- | -------- | ---------- | ------- |
| Parse + validate `apt1` bundle      | ~47 ms   | ~1.6 ms    | **~30×** |
| Parse + validate `poisonivy` bundle | ~99 ms   | ~2.3 ms    | **~43×** |

See [`benchmarks/BENCHMARKING.md`](https://github.com/osintalex/stixflayer/blob/main/benchmarks/BENCHMARKING.md)
for the harness, fixtures, and how to reproduce the numbers.

## Install ⚡

```console
pip install stixflayer
```

The CLI is a standalone binary:

```console
curl -LsSf https://github.com/osintalex/stixflayer/releases/latest/download/install.sh | sh
```

Requires Python 3.11+. Rust users can `cargo add stixflayer`; API docs are at
[docs.rs/stixflayer](https://docs.rs/stixflayer).

## Credits 🙏

Built on [OASIS CTI's `cti-rust-stix`](https://github.com/oasis-open/cti-rust-stix),
the official STIX 2.1 reference implementation in Rust.
