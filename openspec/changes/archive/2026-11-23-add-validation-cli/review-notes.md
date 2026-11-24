# Review notes

## Task 10.2 — MITRE ATT&CK `enterprise-attack.json`

- Source: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- Size: 52.7 MB (not committed; downloaded to `/tmp/attack/`)
- Command: `stixflayer --json enterprise-attack.json`
- Result: exit `1`, 1 file, 26,699 objects, 1,575 errors, 41,609 warnings
- Wall clock: 2.79 s
- Peak RSS: 404,672 KiB (~395 MiB)
- Error kinds: `invalid_nested_object` (1,575)
- Warning kinds: `external_reference_url_without_hashes` (38,326),
  `custom_missing_extension` (2,645), `relationship_type_not_suggested` (638)

The extension-less `x-mitre-*` custom objects are valid and produce
`custom_missing_extension` warnings after the follow-up fix.

The remaining errors are intentional strict STIX 2.1 behavior. §5.1
(`_e2e1szrqfoan`) says a Relationship links two SDOs or SCOs; ATT&CK's
`x-mitre-*` objects do not declare a `new-sdo` extension. §4.1
(`_axjijf603msy`) does not list `tool -> attack-pattern` for `uses`; undefined
pairs should use `related-to` or a user-defined relationship name. The CLI has
no flag to accept those non-conformant shapes.

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
