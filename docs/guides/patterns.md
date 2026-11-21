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
`invalid_pattern` entry. The message names the line and column of the failure,
the construct that was expected, and the token that was found.

```python
import stixflayer

try:
    stixflayer.validate_pattern("[ipv4-addr:value = ]")
except Exception as e:
    entry = e.errors[0]
    print(entry["kind"])
    #> invalid_pattern
    print("expected a value" in entry["message"])
    #> True
```

## Semantic errors raise too

A pattern can follow the grammar and still break a patterning rule. Those
failures also raise `ValidationError`, with a plain-language message instead of
a parse position.

```python
import stixflayer

try:
    stixflayer.validate_pattern("[file:name = 'x'] REPEATS 0 TIMES")
except Exception as e:
    print(e.errors[0]["kind"])
    #> validation_error
```

## Composite patterns

Comparisons, AND/OR/NOT, and multiple observations are all supported.

```python
import stixflayer

stixflayer.validate_pattern("[network-traffic:src_port = 22 AND network-traffic:dst_port = 443]")
```
