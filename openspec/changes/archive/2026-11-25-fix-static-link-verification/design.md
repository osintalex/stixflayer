# Design

## Context

See `proposal.md` — Why. The current release step in `.github/workflows/release.yml` treats `file` output containing `statically linked` or `ldd` output containing `not a dynamic executable` as proof of a self-contained binary. Both strings describe one ELF *shape*. Rust now emits static PIE (`file`: `static-pie linked`) on x86_64 musl and classic `ET_EXEC` (`file`: `statically linked`) on aarch64 musl, so a shape-based match cannot cover both.

The build already sets `-C target-feature=+crt-static` for both musl targets, so no build-flag change is needed. The CI `rust-cross` job builds the workspace for `x86_64-unknown-linux-musl` in debug mode and is the natural place to assert the same property on pull requests. Linux runners provide `readelf` through the preinstalled `binutils` package.

## Goals / Non-Goals

**Goals:**

- Decide the binary's self-containedness from ELF structure, independent of `file`/`ldd` wording and of PIE vs non-PIE layout.
- Make the release and pull-request checks use the same predicate so they cannot disagree.
- Fail with a message that names the property found, keeping `file` output as diagnostic context only.

**Non-Goals:**

- Changing musl linker flags, adding `-no-pie`, or influencing which ELF shape rustc emits.
- Executing the binary or validating it in a chroot.
- Sharing code with any non-Linux job; macOS artifacts are unaffected.

## Decisions

### Assert on `PT_INTERP` and `DT_NEEDED`

A binary is self-contained when it has no `PT_INTERP` program header (it needs no loader) and no `DT_NEEDED` entries in its dynamic section (it needs no shared libraries). This is true for both static PIE (`ET_DYN` with no interpreter) and classic static (`ET_EXEC`) binaries, so the predicate is stable across the rustc change.

Implementation shape, repeated in the release build step and the CI cross-compile job:

```sh
binary=...
readelf -lW "$binary" | grep -q 'INTERP' && { echo "has PT_INTERP" >&2; exit 1; }
dynamic="$(readelf -dW "$binary" 2>/dev/null || true)"
printf '%s\n' "$dynamic" | grep -q '(NEEDED)' && { echo "has DT_NEEDED" >&2; exit 1; }
```

`readelf -lW` is expected to succeed for any ELF; a parse failure is allowed to fail the job. `readelf -dW` exits non-zero for a file with no dynamic section, which is the success case here, so its failure is tolerated and only `(NEEDED)` entries are treated as a violation. `file "$binary"` remains as an informational log line.

### Keep the check inline in both workflows rather than adding a shared script

A checked-in helper script would remove duplication, but the proposal scopes the change to the two workflow files and the specs. Inline steps keep the change reviewable and avoid introducing a new executable artifact that must be maintained and invoked from two jobs. The duplication is limited to four shell lines, and both copies implement the same two-property predicate stated in the specs.

### Run the CI assertion only on the musl leg

The existing `rust-cross` matrix has one musl target (`x86_64-unknown-linux-musl`) and one glibc target (`aarch64-unknown-linux-gnu`). Only musl builds are intended to be static, so the step is conditioned on `contains(matrix.target, 'musl')`. The debug binary at `rust/target/<target>/debug/stixflayer` is inspected; the release profile is not needed to observe linkage.

## Risks / Trade-offs

- [`readelf` missing or a different binutils version changes output] → `readelf` is preinstalled on the Ubuntu runners; the predicate greps stable header/entry names (`INTERP`, `(NEEDED)`) rather than prose, and a parse failure fails the job rather than passing it.
- [A future toolchain emits a new dynamic tag that still implies a dependency] → `DT_NEEDED` is the ELF mechanism for shared-library dependencies; other tags such as `DT_RPATH` do not by themselves introduce one.
- [The CI debug binary and the release binary differ in linkage] → Both are built from the same crate and target with the same `+crt-static` configuration; the CI check catches configuration regressions before the release profile is built.
- [Inline duplication drifts between the two workflows] → Both blocks implement the two properties named in `cli-distribution` and `ci-cd` specs; reviewers compare them, and either failing job blocks its pipeline.
