//! Classification of serde errors into structured STIX error variants.
use serde_path_to_error as serde_path;

use super::StixError;

/// Maps a wrapped serde_json error to the most specific structured variant.
///
/// - Data-category errors (missing field, invalid type) become
///   `MissingProperty` / `InvalidPropertyType`, losing their line/column
///   position — which is meaningless for JSON synthesized from kwargs.
/// - Syntax/IO/EOF errors keep the full serde message (positions are real
///   and useful for user-supplied JSON).
///
/// `object_type` is the STIX type name (kebab-case) being deserialized, used
/// for the structured variants' `object_type` field.
pub fn classify_serde_error(
    error: serde_path::Error<serde_json::Error>,
    object_type: &str,
) -> StixError {
    let path = error.path().to_string();
    let inner = error.into_inner();
    let message = inner.to_string();
    if inner.classify() != serde_json::error::Category::Data {
        return StixError::DeserializationError(message);
    }

    if let Some(rest) = message.strip_prefix("missing field ") {
        // serde's missing-field message always names the field, with a
        // position suffix: `missing field \`name\` at line 1 column 2`
        let property = strip_position_suffix(rest).trim_matches('`');
        return StixError::MissingProperty {
            object_type: object_type.to_string(),
            property: property.to_string(),
        };
    }

    if let Some(rest) = message.strip_prefix("invalid type: ") {
        // Strip the position suffix before splitting: serde messages look
        // like `invalid type: integer \`1\`, expected a string at line 1 column 5`
        let rest = strip_position_suffix(rest);
        if let Some((got, expected)) = rest.split_once(", expected ") {
            // `serde_path_to_error` reports the path of flattened struct errors
            // as ".", which is not actionable. Fall back to a generic
            // deserialization error in that case.
            if path != "." {
                return StixError::InvalidPropertyType {
                    object_type: object_type.to_string(),
                    property: path,
                    expected: expected.to_string(),
                    got: got.to_string(),
                };
            }
        }
    }

    StixError::DeserializationError(message)
}

/// Removes serde's ` at line N column M` suffix from an error message.
fn strip_position_suffix(message: &str) -> &str {
    match message.find(" at line ") {
        Some(pos) => &message[..pos],
        None => message,
    }
}
