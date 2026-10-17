---
hide:
  - navigation
  - toc
---

# stixflayer

Fast STIX 2.1 parsing, validation, and serialization — a single Rust engine,
consumed by every supported language, so the same document validates the same
way everywhere.

- **One engine, no validation gaps** — most STIX libraries are reimplemented
  per language, which creates subtle interoperability bugs. stixflayer ships
  one Rust core into each language instead.
- **Battle-tested, but faster** — built from OASIS's reference
  implementation, with full parity against the industry-standard Python
  validator, at 10–40× the speed.
- **Stricter where it matters** — enforces rules other validators skip:
  empty bundles, invalid vocabulary values, incorrect SCO UUIDv5 hashes.

## Install

```console
pip install stixflayer
```

Requires Python 3.11+.

<div class="grid cards" markdown>

-   **Quickstart**

    ---

    Parse a document, build an object, handle errors — in five minutes.

    [:arrow_forward: Get started](quickstart.md)

-   **Guides**

    ---

    Parsing, building, validation modes, vocabularies, patterns, errors.

    :book: [Browse the guides](guides/parsing.md)

-   **API reference**

    ---

    Curated reference for every public class and function.

    :material-api: [Open the reference](api/overview.md)

-   **Rust**

    ---

    The native crate, documented where Rust users expect it.

    :simple-rust: [docs.rs/stixflayer](https://docs.rs/stixflayer)

</div>
