# Review notes

## Task 10.2 — MITRE ATT&CK `enterprise-attack.json`

- Source: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- Size: 52.7 MB (not committed; downloaded to `/tmp/attack/`)
- Command: `stixflayer --allow-custom --json enterprise-attack.json`
- Result: exit `1`, 1 file, 26,699 objects, 4,220 errors, 38,964 warnings
- Wall clock: 2.63 s
- Peak RSS: 364,180 KiB (~356 MiB)
- Error kinds: `custom_missing_extension` (2,645), `invalid_nested_object` (1,575)
- Warning kinds: `external_reference_url_without_hashes` (38,326),
  `relationship_type_not_suggested` (638)

The run completes and uses object-level parallelism as intended, but the
bundle is **not valid** under `--allow-custom` alone. ATT&CK carries custom
object types (`x-mitre-analytic`, `x-mitre-tactic`, `x-mitre-collection`, and
others) without `extension-definition` objects, and its nested objects also
trigger `invalid_nested_object`. `--allow-custom` is specified to accept
custom *properties*; it does not relax the engine's custom-object extension
requirement.

With `--allow-custom --no-strict` the same bundle exits `0` with 26,699
objects and zero errors or warnings. The task wording expects a valid document
from `--allow-custom` alone, which would require an engine behavior change
outside this change's "no engine behavior changes" scope.

### STIX 2.1 spec check

The local OASIS copy (`stix-2.1-spec.html`) says custom objects **SHOULD** be
defined with the extension mechanism (§11.2, `_7f3c4jgkyhl3`), not MUST. The
requirements in that section do not require an `extensions` property, and the
section's own example has none. The engine's `custom_missing_extension` error is
therefore stricter than the normative text: those 2,645 errors are likely false
positives.

The relationship errors are a different question. §5.1 (`_e2e1szrqfoan`) says a
Relationship links two SDOs or SCOs. A custom object without a `new-sdo` /
`new-sco` extension is not declared as an SDO or SCO, so ATT&CK's
`x-mitre-*` -> SDO relationships are invalid under a strict reading. The
Attack Pattern relationship table (§4.1, `_axjijf603msy`) also does not list
`tool -> attack-pattern` for `uses`; undefined pairs are supposed to use
`related-to` or a user-defined relationship name. ATT&CK's `tool uses
attack-pattern` edges are therefore non-conformant under the same strict
reading.

Conclusion: ATT&CK is not cleanly valid per strict STIX 2.1, but our validator
is also not fully correct because of `custom_missing_extension`. Fixing only
that rule would leave the relationship errors. Making ATT&CK validate would
require a deliberate leniency policy for custom-object relationship endpoints,
not just a bug fix.

The reference `stix2-validator` also rejects a minimal custom object without an
extension (it cannot locate a base schema), so ecosystem behavior is mixed.

## Task 10.3 — Public feeds

- Amnesty: `https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2`
  - exit `0`; 4,375 objects; 0 errors; 0 warnings
- MVT: `https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2`
  - exit `0`; 3 objects; 0 errors; 1 warning (`identifier_uuid_not_v4`)
  - exit `1` only when `--fail-on-warnings` is set

## Task 8.4 — Static Linux artifact

Built locally for `x86_64-unknown-linux-musl` with the target-specific
`-C target-feature=+crt-static` flag and rust-lld:

- `file`: `ELF 64-bit LSB pie executable, x86-64 ... static-pie linked`
- `readelf -d`: 0 `NEEDED` entries

The release workflow applies the same target-specific flags and verifies the
result with `file`/`ldd`.

## Task 8.2 — Workflow validation

`actionlint` parses `.github/workflows/release.yml` and reports only two
pre-existing shellcheck findings in the gate and Python publish jobs. The new
CLI jobs are clean.

## Task 9.1 — Docs

`zensical build --strict --clean` succeeds with `No issues found`.
