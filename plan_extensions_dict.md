# Python Dict for Extensions

## Problem
Currently `extensions_json` only accepts JSON string, not Python dict:
```python
# Current (works)
obj = AttackPattern(name="x", extensions_json='{"ext--x": {...}}')

# Desired (doesn't work)
obj = AttackPattern(name="x", extensions={"ext--x": {...}})
```

## Solution
Accept both `str` and `dict` types in extension parameter.

## Changes Needed

### Python (python/src/lib.rs)

1. Create helper to detect input type:
```rust
fn parse_extensions(input: &PyAny) -> Result<StixDictionary<DictionaryValue>, PyErr> {
    if input.is_none() {
        return Ok(StixDictionary::new());
    }
    // Try dict first
    if let Ok(dict) = input.extract::<&PyDict>() {
        return pydict_to_stix_dict(dict);
    }
    // Fall back to JSON string
    if let Ok(s) = input.extract::<String>() {
        return json_to_stix_dict(&s);
    }
    Err(...)
}
```

2. Update parameter signature to accept `PyAny`:
```rust
#[pyo3(signature = (name, extensions = None))]
fn new(name: String, extensions: &PyAny) -> Result<Self, PyErr>
```

## Classes Needing Update
- All SDOs via make_sdo! macro
- 13 SCOs with extensions_json

## Test
```python
# Should both work
obj1 = AttackPattern(name="x", extensions={"ext--x": {"x": 1}})
obj2 = AttackPattern(name="x", extensions_json='{"ext--x": {"x": 1}}')
```

## Effort
~1 hour