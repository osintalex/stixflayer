# Review notes

## ATT&CK verification

Source: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
(52.7 MB, downloaded to `/tmp/attack/`, not committed).

Command:

```console
stixflayer --json enterprise-attack.json
```

- Exit: `1`
- Files: 1; objects: 26,699; valid: 0; invalid: 1; skipped: 0
- Errors: 1,575, all `invalid_nested_object`
- Warnings: 41,609
  - `external_reference_url_without_hashes`: 38,326
  - `custom_missing_extension`: 2,645
  - `relationship_type_not_suggested`: 638
- Wall clock: 2.79 s
- Peak RSS: 404,672 KiB (~395 MiB)

The extension-less `x-mitre-*` custom objects are valid and produce
`custom_missing_extension` warnings. The relationship errors are intentional:
ATT&CK uses extension-less custom objects as relationship endpoints and uses
`tool -> attack-pattern` for `uses`, neither of which STIX 2.1 §5.1 and the
relationship tables allow. There is no leniency flag; strict validation
reports them as errors.
