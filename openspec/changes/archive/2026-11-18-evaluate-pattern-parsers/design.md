# Design

## Context

See `proposal.md` - Why for the motivation. This document fixes the experimental design only.

Current state that constrains the approach:

- `rust/src/pattern/mod.rs` is a nom front end that produces the AST in `rust/src/pattern/expr.rs`.
  `ObservationExpression::stix_check()` (via the public `Stix` trait) applies semantic rules.
  `validate_pattern` maps parse failure to `StixError::ParsePatternError`, which the Python layer
  raises as `ValidationError` with an `invalid_pattern` entry (`error-reporting` spec).
- `pub mod pattern`, `pub mod expr`, and `Stix::stix_check` are public, so an external crate can build
  the real AST and run the real semantic layer. The front end is replaceable without changing the
  contract.
- The authoritative grammar is the 237-line `STIXPattern.g4` on `cti-stix2-json-schemas` `master`.
  STIX 2.1 is still current (no 2.2 spec or branch exists), and the repo targets 2.1 only.
- The reference validator is ANTLR 4.13.2 plus a Python inspector. It is a comparison point, not an
  oracle: it crashes on `[-1]`, rejects a leading `/* */` via a naive bracket pre-check, and applies
  hash-format semantics the grammar does not.
- This is a Python extension module, so dependency weight, compile time, and MSRV are shipping costs,
  not just developer costs.

## Goals / Non-Goals

**Goals**

- Produce comparable accept/reject and diagnostic evidence for five front ends: nom, pest,
  antlr-rust, chumsky, and the shipped baseline.
- Make every front end pass the same must-pass set before its diagnostics are ranked.
- Answer the antlr expected-set hypothesis with evidence, early.
- Prove the winning front end can populate the existing AST and survive `stix_check()`.
- Leave a `RESULTS.md` that a follow-up change can act on without re-deriving anything.

**Non-Goals**

- Adopting a parser, changing semantics, or touching `rust/`, `src/`, `tests/`, or `testdata/`.
- Throughput or memory benchmarking; any timing recorded is a by-product, not a criterion.
- Exhaustive grammar conformance. The corpus is a decision sample, not a compliance suite.
- Improving the reference validator or filing upstream issues.

## Decisions

### D1. Five-member workspace, including the shipped baseline

`poc-parser/` is its own workspace with `harness`, `nom-poc`, `pest-poc`, `antlr-poc`,
`chumsky-poc`, and `baseline-poc`. The brief specifies four; the fifth runs
`stixflayer::pattern::validate_pattern` via a path dependency.

Alternatives: four members only (the brief); compare against the Python reference instead.
A baseline makes every result relative to what we ship, and doubles as a harness self-test: if it
does not reproduce the known failures, the harness is wrong.

### D2. JSONL corpus with provenance, not line-based text

Each case is `{"id","input","expected","basis","semantic","note"}`. `basis` is one of `grammar`,
`reference`, `spec`, `shipped`; `semantic` marks grammar-valid cases that our semantic layer rejects.

Alternatives: the brief's `valid.txt`/`invalid.txt`; a TOML file.
Line-based files cannot represent patterns containing `/* */` or `//`, cannot carry an expected
verdict, and cannot record why a verdict is authoritative. JSONL keeps one case per line and stays
diffable.

### D3. Grammar-only front ends, then a single winner spike

The four PoCs map to `()` and are scored on accept/reject plus errors. After ranking, only the winner
(and the runner-up if the margin is thin) is wired to the real `expr` AST and `stix_check()`.

Alternatives: every PoC builds the AST (better migration signal, roughly +1h each, and AST plumbing
would contaminate error-quality comparisons); no spike (leaves the migration question unanswered).
The AST is public, so the spike is cheap and does not require editing `rust/`.

### D4. Curated expected verdicts, never blindly generated

Verdicts start from `stix2patterns.run_validator` and are then curated, with disagreements recorded
rather than resolved silently. Known conflicts: `REPEATS 0`, `WITHIN 0`, and `AND` across SCO types
are accepted by the reference, rejected by the spec and by `stix_check`, and accepted by the grammar.

Alternatives: reference-only (inherits its bugs and inspector semantics); spec-only (no executable
oracle). The `basis` field is the mitigation: every expectation names its authority.

### D5. Score diagnostics twice: raw and formatted

For each case, record the library's verbatim output and the best message reachable with a small
formatter (target <=50 LOC per library). The formatter is not optional in the product: the
`error-reporting` spec forbids parser internals in user-facing messages.

Alternatives: raw only (rewards libraries whose debug output happens to look nice); formatted only
(hides how much work the formatter had to do). Reporting both shows what the structured error data
actually buys.

### D6. antlr first, as a kill gate

The brief sequences antlr last with the largest box, justified by expected-set-driven suggestions.
The official ANTLR reference already reports `expecting ']'` for the flagship typo, and `expecting
<EOF>` when the typo follows the bracket, because operator loops have already exited by the time the
error is reported.

Alternatives: follow the brief's order. Running antlr first caps the downside: if it reproduces the
reference behavior, the 6h box collapses and the remaining work is unaffected.

### D7. Coverage gate before diagnostic ranking

A front end must pass the must-pass set (all 23 `spec_examples.txt` lines plus curated valid cases)
before its errors are scored. Otherwise a parser that supports less grammar produces cleaner errors.

Alternatives: score everything and note coverage separately. That confounds the criterion the brief
makes decisive, so it is rejected.

### D8. Spike through a read-only path dependency

`baseline-poc` and the spike depend on `../rust` with `default-features = false` (pyo3 is
feature-gated), then build `stixflayer::pattern::expr` values and call `Stix::stix_check()`.

Alternatives: copy `expr.rs` into the PoC (drifts immediately); modify `rust/` in place (out of
scope, and would contaminate the branch). The path dependency keeps one source of truth and touches
nothing.

### D9. Cost metrics instead of hours

Record LOC per PoC, direct dependency count, clean-build wall time, generated-source size, release
binary delta, MSRV, and grammar-drift risk. Hours are recorded only as an effort note, because
human-hours and agent wall-clock are not comparable.

Alternatives: the brief's hours table. Hours answer "how long did this take us", not "what will this
cost to maintain and ship".

### D10. Incremental commits on `poc-parser-exploration`

The brief says leave everything untracked. This change overrides that: each task ends in a commit,
and `poc-parser/` is committed rather than ignored.

Alternatives: untracked PoC (no review trail, and the branch becomes a label with no content).
Rollback remains trivial: delete the directory.

## Risks / Trade-offs

- **Corpus overfits reference bugs** → every case carries `basis`; known reference bugs get explicit
  `note` fields and are curated, not copied.
- **Front ends differ in coverage, flattering weak parsers** → D7 coverage gate; incomplete coverage
  is reported, not scored.
- **antlr codegen friction or MSRV 1.95** → pinned at 0.34.0, gated first, timeboxed; pest is the
  standing fallback.
- **Generated ANTLR source inflates build time or wheel size** → measured under D9; if it dominates,
  that is a verdict input, not a surprise.
- **The 50-LOC formatter cap biases toward libraries with structured errors** → raw output is always
  reported alongside; the cap is stated, not hidden.
- **PoC leaks into `rust/`** → only a path dependency is used; `git status` is checked before every
  commit and only `poc-parser/` paths are staged.
- **Chumsky API drift** (0.14.1, not the brief's 0.9) → pinned in `poc-parser/Cargo.lock`; API churn
  is recorded as a cost.
- **Timebox overrun** → cut chumsky first, then the fresh nom PoC. Never cut the corpus freeze, the
  baseline column, or the antlr gate.

## Migration Plan

This change does not deploy anything. It ends at `poc-parser/RESULTS.md` plus a verdict.

- The follow-up change replaces `rust/src/pattern/mod.rs` behind the existing AST, keeps `stix_check`
  as the semantic layer, and amends `error-reporting` while adding a pattern-validation capability.
- `RESULTS.md` supplies the front end choice, the diagnostics baseline, and the cost evidence for that
  change's proposal.
- Rollback for this change is deleting `poc-parser/`; no production path is touched.
- The `pest-poc` and `antlr-poc` directories stay in place as phase-2 seeds even if the other PoCs are
  deleted.

## Open Questions

- The exact formatter budget (50 LOC) may be tuned after the first two PoCs. It does not change the
  task breakdown or the corpus.
- Whether to record throughput is optional; if the schedule allows, one measurement per front end is
  enough.
