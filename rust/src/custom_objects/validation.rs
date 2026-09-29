use crate::error::StixError as Error;

/// Validates the name of a custom STIX object type.
///
/// Custom object type names MUST:
/// - start with a lowercase ASCII letter
/// - contain only lowercase ASCII letters, digits, and hyphens
/// - NOT contain underscores
pub fn check_custom_object_type(object_type: &str) -> Result<(), Error> {
    if object_type.is_empty() {
        return Err(Error::ValidationError(
            "Custom object type name must not be empty".to_string(),
        ));
    }

    let first = object_type.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(Error::ValidationError(format!(
            "Custom object type name '{}' must start with a lowercase letter",
            object_type
        )));
    }

    if object_type.contains('_') {
        return Err(Error::ValidationError(format!(
            "Custom object type name '{}' must not contain underscores",
            object_type
        )));
    }

    // Ensure all characters are valid (lowercase, digit, hyphen)
    if !object_type
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(Error::ValidationError(format!(
            "Custom object type name '{}' contains invalid characters",
            object_type
        )));
    }

    Ok(())
}

