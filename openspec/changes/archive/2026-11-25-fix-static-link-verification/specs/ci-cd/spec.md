# Spec Delta

## ADDED Requirements

### Requirement: Pull request cross-compile asserts musl CLI linkage

The pull-request pipeline SHALL assert that each Linux musl CLI binary built by the Rust cross-compile job is self-contained — no ELF interpreter and no shared-library dependencies — using the ELF program headers and dynamic section, so a linkage regression fails on the pull request instead of at release time.

#### Scenario: Musl CLI binary is checked on every pull request

- **WHEN** the Rust cross-compile job builds the `x86_64-unknown-linux-musl` target for a pull request
- **THEN** the CLI binary is inspected and the job fails if it declares an ELF interpreter or shared-library dependencies

#### Scenario: Linkage regression fails the pull request

- **WHEN** a change causes the musl CLI binary to link dynamically
- **THEN** the cross-compile job fails and reports which ELF property was present
