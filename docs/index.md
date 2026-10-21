---
hide:
  - navigation
  - toc
---

# 🧠 Stixflayer 🦑

**Rust-native STIX 2.1. One spec-compliant core, consumed by many.** ⚡

Parse, validate, and serialize at **10–40× the speed** of the
industry-standard Python validator — with *stricter* spec enforcement.

<div class="grid cards" markdown>

-   🚀 **Quickstart**

    ---

    Parse a document, build an object, handle errors — in five minutes.

    [:material-arrow-right: Get started](quickstart.md)

-   📖 **Guides**

    ---

    Parsing, building, validation modes, vocabularies, patterns, errors.

    [:material-book-open: Browse the guides](guides/parsing.md)

-   📚 **API reference**

    ---

    Curated reference for every public class and function.

    [:material-api: Open the reference](api/overview.md)

-   🦀 **Rust**

    ---

    The native crate, documented where Rust users expect it.

    [:simple-rust: docs.rs/stixflayer](https://docs.rs/stixflayer)

</div>

## Why another STIX library? 🤔

- 🌍 **One engine, no validation gaps** — most STIX libraries are
  reimplemented per language, so the same document can be valid in one and
  rejected in another. stixflayer ships a single Rust core into every
  language, so data validates the same way everywhere.
- ⚔️ **Battle-tested, but faster** — built from OASIS's reference
  implementation, with full parity against the industry-standard validator,
  at 10–40× the speed.
- 🧐 **Stricter where it matters** — rejects empty bundles, invalid
  vocabulary values, and incorrect SCO UUIDv5 hashes that other validators
  skip.

## Performance 🚀

| Operation                          | stix2-validator | stixflayer | speedup   |
| ---------------------------------- | --------------- | ---------- | --------- |
| Parse + validate `apt1` bundle     | ~47 ms          | ~1.6 ms    | **~30×** 🏎️ |
| Parse + validate `poisonivy` bundle | ~99 ms         | ~2.3 ms    | **~40×** 🏎️ |
| Serialize `apt1` bundle            | ~0.6 ms         | ~0.06 ms   | **~10×** 🏎️ |
| Serialize `poisonivy` bundle       | ~1.0 ms         | ~0.09 ms   | **~12×** 🏎️ |

## Install ⚡

```console
pip install stixflayer
```

Requires Python 3.11+. Rust users: `cargo add stixflayer` 🦀 — API docs at
[docs.rs/stixflayer](https://docs.rs/stixflayer).

## Credits 🙏

Built on [OASIS CTI's `cti-rust-stix`](https://github.com/oasis-open/cti-rust-stix),
the official STIX 2.1 reference implementation in Rust, and benchmarked
against [`cti-stix-validator`](https://github.com/oasis-open/cti-stix-validator).
