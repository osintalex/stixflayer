# STIX patterns

Validate STIX patterns without building any object.

## Validate a pattern

`validate_pattern` returns silently for a valid pattern.

```python
import stixflayer

stixflayer.validate_pattern("[ipv4-addr:value = '203.0.113.7']")
```

## Invalid patterns raise

Syntactically invalid patterns raise `ValidationError` with an
`invalid_pattern` entry — the pattern itself plus a plain-language parse
failure.

```python
import stixflayer

try:
    stixflayer.validate_pattern("[ipv4-addr:value = 203.0.113.7]")
except Exception as e:
    entry = e.errors[0]
    print(entry["kind"])
    #> invalid_pattern
    print(entry["got"])
    #> expected a specific character near '[ipv4-addr:value = 203.0.113.7]'
```

## Composite patterns

Comparisons, AND/OR/NOT, and multiple observations are all supported.

```python
import stixflayer

stixflayer.validate_pattern("[network-traffic:src_port = 22 AND network-traffic:dst_port = 443]")
```
