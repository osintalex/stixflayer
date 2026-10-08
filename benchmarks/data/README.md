# Benchmark fixtures

These STIX 2.1 bundles are taken from the OASIS `cti-stix2-json-schemas` open
repository and are used as realistic workload inputs for the benchmark suite.

- `apt1.json` — APT1 threat report bundle (76 objects)
- `poisonivy.json` — Poison Ivy threat report bundle (155 objects)

## Normalization

Both files were lightly edited so that both `stix2` and `stixflayer` accept them
as valid STIX 2.1. The edits do not change object topology or semantics.

- Added placeholder hashes to external references that contain a `url` but
  omitted the optional `hashes` property.
- Fixed one invalid STIX pattern in `poisonivy.json` (`'domain autuo.xicp.net'`
  → `'autuo.xicp.net'`).

These changes are required because `stixflayer` currently treats the optional
`hashes` on a URL external reference as mandatory (a spec bug; see
`benchmarking.md` known issues).

Source: https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/examples/threat-reports
License: BSD-3-Clause
