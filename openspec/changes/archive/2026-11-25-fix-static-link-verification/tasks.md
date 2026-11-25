# Tasks

## 1. Release workflow verification

- [x] 1.1 Replace the `file`/`ldd` static-link step in `.github/workflows/release.yml` with a `readelf` assertion that rejects `PT_INTERP` and `DT_NEEDED` while keeping `file` output as an informational log line. Verify by running the step's shell block against a dynamically linked ELF (must fail) and against a static musl CLI build (must pass), and confirm the workflow still parses as YAML.
- [x] 1.2 Confirm the release assertion only runs for Linux matrix targets and fails with a message naming the offending property. Verify by inspecting the step's `if:` condition and reading the failure messages for both the `PT_INTERP` and `DT_NEEDED` branches.

## 2. Pull request CI verification

- [x] 2.1 Add the same static-linkage assertion to the `rust-cross` job in `.github/workflows/ci.yml`, inspecting the musl CLI debug binary and running only for the musl target. Verify by running the block against a musl CLI debug build (static PIE) and the existing `x86_64-unknown-linux-musl` static PIE artifact (must pass), and confirming the workflow parses as YAML.

## 3. Integration verification

- [x] 3.1 Run `openspec validate fix-static-link-verification --strict` and confirm both delta specs validate without issues.
- [x] 3.2 Compare the assertion blocks in `.github/workflows/release.yml` and `.github/workflows/ci.yml` and confirm both test the same two ELF properties (`PT_INTERP` and `DT_NEEDED`) and neither uses `file`/`ldd` text as the pass/fail decision.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Confirm the `cli-v0.1.0` release and `lockstep-crate-versions` task 5.4 are unblocked after the change is merged.
