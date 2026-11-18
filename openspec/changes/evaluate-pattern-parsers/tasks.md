# Tasks

## 1. Workspace and corpus freeze

- [x] 1.1 Create `poc-parser/` as an independent Cargo workspace with members `harness`, `nom-poc`,
  `pest-poc`, `antlr-poc`, `chumsky-poc`, `baseline-poc`, plus `grammar/`, `corpus/`, `results/`;
  verify with `cargo metadata --no-deps` from `poc-parser/` and record the SHA-256 of the unmodified
  `grammar/STIXPattern.g4`.
- [x] 1.2 Write `corpus/valid.jsonl` and `corpus/invalid.jsonl` with
  `{id,input,expected,basis,semantic,note}`; include all 23 `spec_examples.txt` lines, the 14 valid
  constructs the shipped parser rejects, the reference-bug cases (`[-1]` index, leading `/* */`,
  hash-format), and the grammar-vs-semantics cases; verify a `corpus-check` test passes (unique ids,
  known `basis` values, every `semantic: true` case also `expected: "accept"`).
- [x] 1.3 Add `tools/oracle.py` that regenerates reference verdicts from `stix2patterns` and reports
  unexplained divergence; verify running it twice leaves the corpus unchanged and exits non-zero if a
  case's verdict differs from its recorded `expected` without a `note`.

## 2. Harness and baseline column

- [x] 2.1 Implement `harness` with `Case`/`Outcome` serde types, corpus loading, and JSONL emission;
  verify a unit test round-trips a case and an outcome without loss.
- [x] 2.2 Implement `harness`'s `compare` binary that renders the correctness matrix and the verbatim
  showcase from `results/*.jsonl`; verify against a checked-in fixture results file with a snapshot
  test.
- [x] 2.3 Implement `baseline-poc` with a `../rust` path dependency (`default-features = false`)
  calling `validate_pattern`; verify it reproduces the five known `spec_examples.txt` failures and the
  shipped-behavior cases recorded in the corpus.

## 3. antlr gate

- [x] 3.1 Generate the lexer and parser from the unmodified grammar with `antlr-rust-codegen 0.34.0`
  in `build.rs`; verify `cargo build -p antlr-poc` succeeds and record whether the combined grammar
  needed a lexer/parser split.
- [x] 3.2 Implement the antlr runner using the validated-parse surface plus a custom `ErrorListener`;
  verify verdicts come from syntax-error count (not `parse().is_ok()`) and that each error emits
  line/column, offending token text/type, and expected set.
- [x] 3.3 Run the gate experiment on `I04` and its after-bracket sibling and record the expected sets;
  verify the gate conclusion and raw output are written into the `RESULTS.md` draft.
- [x] 3.4 Add the <=50 LOC formatter and record LOC, dependency count, clean-build time, generated
  source size, release binary delta, and MSRV; verify formatted showcase messages contain no parser
  internals and pass the same no-debug-text assertion used by the `error-reporting` tests.

## 4. pest

- [x] 4.1 Port the full grammar to `pest` with atomic literal rules, `WHITESPACE`/`COMMENT`, keyword
  boundaries, and left-associative folds; verify the PoC accepts every must-pass corpus case.
- [x] 4.2 Implement the pest runner with raw `to_string()` and `renamed_rules` display modes; verify
  `results/pest.jsonl` is emitted with both modes for every showcase case.
- [x] 4.3 Add the formatter and cost metrics; verify formatted output contains no parser internals and
  that LOC/dependency/build numbers are recorded.

## 5. chumsky

- [x] 5.1 Implement the chumsky 0.14 parser with `Rich` errors and labels on every major rule; verify
  it accepts every must-pass corpus case.
- [x] 5.2 Add the runner, formatter, and cost metrics; verify `results/chumsky.jsonl` exists, multi-
  error output is captured where produced, and the LOC/API-version note is recorded.

## 6. Fresh nom

- [x] 6.1 Implement the nom 8 parser with `VerboseError` and `context()` on every rule; verify it
  accepts every must-pass corpus case.
- [x] 6.2 Add `convert_error` display, the formatter, and cost metrics; verify `results/nom.jsonl`
  exists and the formatted messages contain no parser internals.

## 7. Winner spike

- [x] 7.1 Build the real `stixflayer::pattern::expr` AST from the winning front end's output for
  every must-pass corpus case; report unrepresentable shapes as gaps rather than dropping them
  (the baseline exposes no AST, and its AST is lossy, so equality against it is not a valid check).
- [x] 7.2 Run `Stix::stix_check()` on the spike ASTs; verify semantic verdicts match the baseline on
  the `semantic: true` cases and that the `REPEATS 0` / `WITHIN 0` divergence is recorded.
- [x] 7.3 Verify lossless AST population (`Like`, `Hex`, `Binary`, `Neq` distinct rather than collapsed
  to `Eq`/`String`); verify with assertions on the corpus cases that exercise each variant.

## 8. Verdict

- [x] 8.1 Assemble `poc-parser/RESULTS.md` with environment, verbatim showcase, correctness matrix,
  diagnostics assessment, cost table, and the three verdict questions; verify every claim cites a
  `results/*.jsonl` entry and all showcase cases are present.
- [x] 8.2 Run the final checks: `cargo build --workspace` in `poc-parser/`, `git status` shows only
  `poc-parser/` and change artifacts, and no file under `rust/`, `src/`, `tests/`, or `testdata/`
  changed; verify with `git diff --stat c00f095..HEAD -- rust src tests testdata` returning empty.

## Workflow follow-up

- Archive the change with `/opsx-archive` once review is complete.
- Keep `pest-poc/` and `antlr-poc/` as phase-2 seeds even if the other PoCs are deleted.
