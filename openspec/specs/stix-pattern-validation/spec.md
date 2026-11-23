# stix-pattern-validation Specification

## Purpose
Defines what `stixflayer` must do when validating STIX 2.1 patterning expressions: accept the full
grammar, preserve the structure the semantic checks depend on, reject invalid input with positional
plain-language diagnostics, and keep the behavior testable from every language binding.

## Requirements

### Requirement: The full STIX 2.1 patterning grammar is accepted

The validator SHALL accept every pattern that conforms to the STIX 2.1 STIXPattern grammar,
including comparison and observation operators, `NOT` in both permitted positions, parenthesised
comparison and observation groups, qualifiers, all literal forms, comments, and the grammar's Unicode
whitespace set.

#### Scenario: Official specification examples validate

- **WHEN** any pattern from the reference validator's `spec_examples.txt` is validated
- **THEN** validation succeeds

#### Scenario: Grammar edge constructs validate

- **WHEN** a pattern uses `==`, `<>`, an empty set, a leading block comment, a trailing line comment,
  a non-breaking space, an escaped quote, a binary literal, a hexadecimal literal, a leap-second
  timestamp, a signed number, or no whitespace between tokens
- **THEN** validation succeeds

#### Scenario: Qualifiers validate

- **WHEN** a pattern uses `REPEATS`, `WITHIN`, or `START`/`STOP`, alone or chained, on an observation
  or a parenthesised group
- **THEN** validation succeeds

### Requirement: Invalid patterns are rejected

The validator SHALL reject input that does not conform to the grammar, including malformed literals,
unknown or misspelled operators, missing delimiters, misplaced `NOT`, wrong keyword case, and
malformed qualifiers.

#### Scenario: Malformed literals are rejected

- **WHEN** a timestamp has an invalid month, a string is unterminated, a string contains an invalid
  escape, a binary literal has invalid padding, or a number has a leading zero
- **THEN** validation fails

#### Scenario: Structural errors are rejected

- **WHEN** brackets are missing or unbalanced, a comparison lacks an operator or value, a boolean or
  observation operator is dangling, or `NOT` appears before an object path
- **THEN** validation fails

#### Scenario: Keyword errors are rejected

- **WHEN** a keyword is misspelled or lowercased, or the wrong qualifier keyword is used
- **THEN** validation fails

### Requirement: Parsed patterns preserve their structure

The parsed representation SHALL retain negation, grouping on either side of an operator, the
specific comparison operator, and the specific literal kind, so that semantic checks can inspect
them rather than seeing a lossy approximation.

#### Scenario: Negation is preserved

- **WHEN** a pattern uses `NOT` before a comparison operator or before `EXISTS`
- **THEN** the parsed comparison records that it is negated and retains the underlying operator

#### Scenario: Groups are preserved

- **WHEN** a comparison group appears on the left or the right of a boolean operator
- **THEN** the parsed representation keeps the group as a nested structure

#### Scenario: Operators and literals are not collapsed

- **WHEN** a pattern uses `LIKE`, `!=`, a hexadecimal literal, or a binary literal
- **THEN** the parsed representation distinguishes it from `=`, `Eq`, or a plain string

### Requirement: Pattern semantic rules are enforced

Validation SHALL reject patterns that are grammatically valid but violate the patterning semantic
rules: comparisons joined by `AND` that target different SCO types, duplicate qualifier types,
non-positive `REPEATS` or `WITHIN` values, operators applied to incompatible literal kinds, and
invalid object paths.

#### Scenario: AND across SCO types is rejected

- **WHEN** a pattern joins comparisons on different SCO types with `AND`
- **THEN** validation fails with a message naming the different-object problem

#### Scenario: Qualifier values must be positive

- **WHEN** a pattern uses `REPEATS 0 TIMES` or `WITHIN 0 SECONDS`
- **THEN** validation fails

#### Scenario: Qualifier types must be unique

- **WHEN** a pattern applies two qualifiers of the same type to the same observation
- **THEN** validation fails

#### Scenario: Empty START/STOP ranges are accepted

- **WHEN** a pattern uses `START` and `STOP` timestamps where the stop is not after the start
- **THEN** validation succeeds, because the specification defines the range but does not prohibit an
  empty one

#### Scenario: Operator and literal kinds must agree

- **WHEN** `IN` is applied to a non-set, or `LIKE`, `MATCHES`, `ISSUBSET`, or `ISSUPERSET` is applied
  to a non-string
- **THEN** validation fails

### Requirement: Diagnostics identify the position and the expected construct

A rejected pattern SHALL produce a message that states the line and column of the failure, describes
what was expected in plain language, and does not contain parser-internal debug structures or Rust
type paths.

#### Scenario: Position is reported

- **WHEN** a pattern is rejected
- **THEN** the message contains the line and column of the offending input

#### Scenario: Expected construct is reported

- **WHEN** a value, closing delimiter, operator, or keyword is missing
- **THEN** the message names the kind of construct that was expected

#### Scenario: No parser internals leak

- **WHEN** any pattern is rejected
- **THEN** the message contains no debug struct syntax, parser error kinds, or Rust module paths

### Requirement: The STIX 2.1 specification is authoritative

Where the reference validator disagrees with the STIX 2.1 specification, validation SHALL follow the
specification, and the project SHALL document the divergence.

#### Scenario: Reference drift is not copied

- **WHEN** the reference validator accepts `REPEATS 0` or `WITHIN 0` but the specification requires a
  positive value
- **THEN** validation rejects the pattern

#### Scenario: Known divergences are documented

- **WHEN** a divergence from the reference validator is known
- **THEN** `README.md` lists it

### Requirement: Pattern fixtures are language-agnostic and cover the grammar

The project SHALL provide JSON fixtures for valid and invalid patterns that every language binding
can consume, each carrying a description and a reference to the grammar or specification section it
covers; invalid cases SHALL record whether the grammar or the semantic layer rejects them. A coverage check SHALL verify that every grammar rule is exercised by at least one case.

#### Scenario: Valid fixtures are consumed

- **WHEN** the Rust or Python test suite runs
- **THEN** every valid pattern fixture is validated and expected to succeed

#### Scenario: Invalid fixtures are consumed

- **WHEN** the Rust or Python test suite runs
- **THEN** every invalid pattern fixture is validated and expected to fail

#### Scenario: Grammar coverage is enforced

- **WHEN** a parser rule has no corresponding fixture
- **THEN** the coverage check fails

### Requirement: The parser builds with the standard Rust toolchain only

The pattern parser SHALL build using only the Rust toolchain, with no external grammar generator,
JVM, or runtime files, and SHALL be statically linkable into every language binding.

#### Scenario: Clean build needs no extra tooling

- **WHEN** the crate is built in a clean environment with only Rust installed
- **THEN** the build succeeds without invoking an external generator or runtime

#### Scenario: Binding builds inherit the parser

- **WHEN** the Python extension is built
- **THEN** it contains the pattern parser with no additional runtime dependency
