# Language and Country Code Validation

## Problem
STIX 2.1 specifies language codes (RFC 5646) and country codes (ISO 3166-1) should be validated, but:
1. Rust crate has documentation but NOT runtime validation
2. Python bindings expose the fields without validation

## STIX 2.1 Requirements

### Language Codes (RFC 5646)
- Examples: en, es, fr, de, ja, zh, ru, ar
- 2-3 letter primary/subtag combinations
- Stored in `lang` property

### Country Codes (ISO 3166-1 alpha-2)
- Examples: US, GB, DE, FR, JP, CN, RU
- 2-letter codes
- Stored in `x_country_code` or similar

## Changes Needed

### Option 1: Rust Validation (Recommended - contributes back)
```rust
// In rust/src/types.rs or base.rs
impl StringOfMinLength<2> {
    pub fn stix_check(&self) -> Result<(), Error> {
        // Check against RFC 5646 list for lang
        // Check against ISO 3166-1 list for country
    }
}
```

### Option 2: Python Only
- Add validation in Python class setters/getters
- Less ideal - diverges from Rust

## Effort
- Rust: ~2 hours (validate, test, contribute upstream)
- Python only: ~1 hour

## Note
This is a gap in original OASIS crate - opportunity to contribute fix upstream.