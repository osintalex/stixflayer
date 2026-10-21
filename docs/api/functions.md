# Functions

## `validate_pattern(pattern)`

Validates a STIX pattern. Returns silently if valid; raises `ValidationError`
with an `invalid_pattern` entry if not.

```python
import stixflayer

stixflayer.validate_pattern("[ipv4-addr:value = '203.0.113.7']")

try:
    stixflayer.validate_pattern("[ipv4-addr:value = 203.0.113.7]")
except Exception as e:
    print(e.errors[0]["kind"])
    #> invalid_pattern
```

## `version()`

Returns the stixflayer version.

```python
import stixflayer

print(stixflayer.version())
#> 0.1.0
```
