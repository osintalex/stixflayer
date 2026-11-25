# Proposal

## Why

The CLI release job decides whether the Linux binary is static by matching
human-readable output from `file` and `ldd`. Those strings describe the ELF's
*shape*, and the shape differs per target and per libc: Rust 1.100 builds
`x86_64-unknown-linux-musl` as a static PIE (`file`: "static-pie linked";
glibc `ldd`: "statically linked"), but `aarch64-unknown-linux-musl` as a
classic static `ET_EXEC` (`file`: "statically linked"). The x86_64 leg
therefore fails on a binary that is genuinely static, while the aarch64 leg
passes by accident. Rust has already merged static PIE for all musl targets
(rust-lang/rust@d1b11ade, 2026-11-19), so the aarch64 leg will start failing
too as soon as that reaches stable. This currently blocks the `cli-v0.1.0`
release that `lockstep-crate-versions` task 5.4 is waiting on.

## What Changes

- Replace the `file`/`ldd` string matching in the CLI release job with an
  assertion on the two ELF properties that make the binary self-contained:
  no `PT_INTERP` program header and no `DT_NEEDED` dynamic entries, read with
  `readelf`. `file` output stays in the log as context, not as the assertion.
- Run the same assertion in the pull-request pipeline (`ci.yml`'s
  `rust-cross` musl legs), so a linkage regression fails on the PR instead of
  during a release.
- Leave the musl build flags unchanged. Static PIE is the rustc default and is
  desirable (it enables ASLR); the fix is to accept it, not to force
  `-no-pie`.
- Put the invariant in the specs so the check is backed by a requirement
  rather than a literal string that drifts with toolchain output.

Out of scope (considered and deliberately not done):

- Forcing classic non-PIE static binaries (`-C link-arg=-no-pie`) or otherwise
  changing musl build flags.
- Adding a chroot or execution smoke test of the published archives.
- Windows CLI artifacts, which are not published.
- The version and release-pipeline changes owned by `lockstep-crate-versions`;
  this change only unblocks that change's final verification task.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cli-distribution`: add a requirement that Linux release binaries are
  self-contained -- no ELF interpreter and no shared-library dependencies --
  and that the release pipeline verifies this before packaging the archives.
- `ci-cd`: extend the Rust cross-compile verification so the musl CLI binary's
  static linkage is asserted on every pull request, not only at release time.

## Impact

- `.github/workflows/release.yml` -- replace the static-link verification step.
- `.github/workflows/ci.yml` -- assert the same property in `rust-cross`.
- `openspec/specs/cli-distribution/spec.md` and `openspec/specs/ci-cd/spec.md`
  -- via delta specs, not edited directly by this change.
- No Rust source, Python API, wheel, or build-flag changes.
- Unblocks `cli-v0.1.0` publication and `lockstep-crate-versions` task 5.4.
