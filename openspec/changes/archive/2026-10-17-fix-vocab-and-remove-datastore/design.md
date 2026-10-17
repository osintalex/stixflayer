# Design

## Context

See proposal.md — Why. Relevant current state: the vocabulary error message is produced by the `make_vocab_enum!` macro in `python_bindings/vocab.rs`, which formats `stringify!($enum_type)` where the macro's second argument is the full type path (`crate::domain_objects::vocab::ThreatActorType`). The macro's first argument (`$name`) is already the clean class name. The wrong vocabulary values live in `strum(serialize = "...")` attributes on enum variants; the `imcp` typo also appears in the `PROTOCOLS_MAP` in `sco.rs`. The `datastore` module is entirely self-contained: zero references from outside (verified by grep across `src/` and `tests/`), carries its own `#![allow(dead_code)]`, and six `StixError` variants exist solely for it.

## Goals / Non-Goals

**Goals:**
- Spec-exact vocabulary values, no compatibility shims.
- Error messages that name things the way users see them.
- Delete dead surface rather than complete or maintain it.

**Non-Goals:**
- No replacement storage/query layer (revisit when a Python-facing need exists).
- No deprecation aliases or value migration helpers.
- No new datastore backend work.

## Decisions

- **Vocabulary error name: use the macro's clean first argument.** Change `stringify!($enum_type)` to `stringify!($name)` in `make_vocab_enum!`. Alternative: pass explicit STIX open-vocabulary names (`threat-actor-type-ov`) — rejected because the Python surface is the vocabulary *class*, and the Rust-side validation path already uses the `-ov` names correctly.
- **Vocabulary values: direct rename.** `RegDword` → serialize `REG_DWORD` (rename variant for consistency), `REG_RESOURCEL_REQUIREMENTS_LIST` → `REG_RESOURCE_REQUIREMENTS_LIST`, `Imcp` → `Icmp`, `EmergencyServicesSanitation` → `EmergencyServices`, plus `PROTOCOLS_MAP` `"imcp-ext"`/`"imcp"` → `"icmp-ext"`/`"icmp"`. Alternative: keep variant names and only change serialized strings — rejected; the names should match what they emit. Confirmed against the local spec copy: `REG_QWORD` and `REG_INVALID_TYPE` and `SERVICE_SYSTEM_ALERT` ARE spec values and stay.
- **Datastore: full removal.** Delete `src/datastore/` (614 lines), the six orphaned `StixError` variants, their arms in `envelope_category`/`to_entry`/Python exception mapping, and any matching kinds in docs. Alternative: keep the working filesystem store — rejected; nothing consumes it and the filter model it would need is itself dead code. History preserves the module if a storage feature is ever designed.
- **pytest-examples: keep suppression.** 0.0.18 is the latest release; the annotation (`Literal['py37','py38','py39','py310','py310']`) is upstream's bug. Keep the `# pyrefly: ignore [bad-argument-type]` with its justification comment and file/link an upstream issue in the change notes.

## Risks / Trade-offs

- [Serialized values change] → Breaking by explicit decision (pre-1.0, no known consumers); the change notes list old→new mappings for release notes.
- [Error kinds disappear from the cross-language contract] → Same breaking rationale; update `docs/guides/errors.md` kind list in the same change.
- [A future storage feature starts from scratch] → Accepted; git history retains the removed module.

## Migration Plan

1. Fix macro message and vocabulary values; update affected tests.
2. Delete datastore module, error variants, Python mapping arms.
3. Update docs (errors guide kinds, vocabulary examples) and run the full quality gate.
4. Rollback: revert the single commit.

## Open Questions

None.
