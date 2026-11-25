# Spec Delta

## ADDED Requirements

### Requirement: Linux CLI release binaries are self-contained

Before packaging a Linux CLI archive, the release pipeline SHALL verify that the binary has no ELF interpreter (`PT_INTERP`) and no shared-library dependencies (`DT_NEEDED`). The verification MUST inspect the ELF program headers and dynamic section rather than match human-readable `file` or `ldd` output, so that both static PIE and classic static executables are accepted.

#### Scenario: Static PIE binary is accepted

- **WHEN** a musl binary has no `PT_INTERP` header and no `DT_NEEDED` entries because the toolchain produced a static PIE
- **THEN** the verification passes and the release archive is produced

#### Scenario: Classic static binary is accepted

- **WHEN** a musl binary is a classic static `ET_EXEC` with no `PT_INTERP` header and no `DT_NEEDED` entries
- **THEN** the verification passes and the release archive is produced

#### Scenario: Dynamically linked binary is rejected

- **WHEN** a Linux CLI binary declares an ELF interpreter or lists shared-library dependencies
- **THEN** the release job fails with a message naming the offending property and no archive is published

#### Scenario: ELF shape is logged for diagnosis

- **WHEN** the verification runs
- **THEN** the `file` description of the binary is written to the job log as context, without being used as the pass/fail assertion
