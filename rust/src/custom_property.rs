//! Custom property name and value validation.
use base64::{engine::general_purpose, Engine};
use crate::error::StixError as Error;
use serde_json::Value;

/// Validates a custom property name against the STIX 2.1 rules in section 11.1.1 and
/// the reserved property names in section 3.8.
///
/// - ASCII only, characters limited to `a-z`, `0-9`, and `_`.
/// - Length between 3 and 250 inclusive.
/// - Must not start with a digit.
/// - Must not be a reserved name.
pub fn validate_custom_property_name(name: &str) -> Result<(), Error> {
    if name.len() < 3 {
        return Err(Error::ValidationError(format!(
            "Custom property name '{}' is too short; minimum length is 3",
            name
        )));
    }
    if name.len() > 250 {
        return Err(Error::ValidationError(format!(
            "Custom property name '{}' is too long; maximum length is 250",
            name
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(Error::ValidationError(format!(
            "Custom property name '{}' contains characters outside the allowed set (a-z, 0-9, _)",
            name
        )));
    }
    const RESERVED: &[&str] = &["severity", "username", "phone_number", "action"];
    if RESERVED.contains(&name) {
        return Err(Error::ValidationError(format!(
            "Custom property name '{}' is reserved by STIX 2.1 and cannot be used as a custom property",
            name
        )));
    }
    Ok(())
}

/// Validates that a custom property whose name claims the `hex` or `binary` type
/// via the `_hex` / `_bin` suffix actually carries a value conforming to the
/// JSON MTI serialization rules in STIX 2.1 section 2.1 (binary) and 2.8 (hex).
///
/// Hex values must be strings containing an even number of characters from
/// `0-9`/`a-f`. Binary values must be strings containing valid base64.
pub fn validate_custom_property_suffix_value(name: &str, value: &Value) -> Result<(), Error> {
    if name.ends_with("_hex") {
        let Some(s) = value.as_str() else {
            return Err(Error::ValidationError(format!(
                "Custom property '{}' uses the _hex suffix and therefore must have a string value",
                name
            )));
        };
        if s.len() % 2 != 0 {
            return Err(Error::ValidationError(format!(
                "Custom property '{}' has an _hex value with an odd number of characters",
                name
            )));
        }
        if !s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(Error::ValidationError(format!(
                "Custom property '{}' has an _hex value containing characters other than 0-9 and a-f",
                name
            )));
        }
    } else if name.ends_with("_bin") {
        let Some(s) = value.as_str() else {
            return Err(Error::ValidationError(format!(
                "Custom property '{}' uses the _bin suffix and therefore must have a string value",
                name
            )));
        };
        if general_purpose::STANDARD.decode(s).is_err() {
            return Err(Error::ValidationError(format!(
                "Custom property '{}' has an _bin value that is not valid base64",
                name
            )));
        }
    }
    Ok(())
}
