//! Classification of serde errors into structured STIX error variants.
use serde_path_to_error as serde_path;

use super::StixError;

/// Names the JSON kind of a value the way users would.
pub fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Message for valid-JSON input that is not a JSON object.
///
/// STIX objects are JSON objects; this states that plainly and names the kind
/// received, without referencing internal Rust type names.
pub fn non_object_json_message(received: &str) -> String {
    format!("Expected a STIX object (JSON object), got {received}.")
}

/// Maps serde's "invalid type" descriptor (e.g. `sequence`, `integer \`1\``)
/// to the JSON kind a user would recognize.
fn json_kind_from_serde_got(got: &str) -> &'static str {
    if got.starts_with("sequence") {
        "array"
    } else if got.starts_with("map") {
        "object"
    } else if got.starts_with("integer")
        || got.starts_with("floating point")
        || got.starts_with("number")
    {
        "number"
    } else if got.starts_with("string") {
        "string"
    } else if got.starts_with("boolean") {
        "boolean"
    } else if got == "null" {
        "null"
    } else {
        "unexpected input"
    }
}

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
            // A struct-expected failure at the root means the input is valid
            // JSON but not a JSON object (STIX objects are JSON objects).
            // Report that plainly instead of leaking serde's internal struct
            // name. Nested struct-typed properties report a real path, so
            // they keep the property classification below.
            if path == "." && expected.starts_with("struct") {
                return StixError::DeserializationError(non_object_json_message(
                    json_kind_from_serde_got(got),
                ));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn classify_root(json: &str) -> StixError {
        // Probe a struct with flattened fields, mirroring the SDO/SCO/SRO
        // shape so top-level non-object inputs produce the same serde error.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Probe {
            #[serde(flatten)]
            #[expect(dead_code)]
            common: crate::base::CommonProperties,
        }
        let result: Result<Probe, _> =
            serde_path::deserialize(&mut serde_json::Deserializer::from_str(json));
        match result {
            Ok(_) => panic!("probe should not deserialize"),
            Err(e) => classify_serde_error(e, "attack-pattern"),
        }
    }

    #[test]
    fn non_object_input_is_reported_plainly() {
        for (json, kind) in [
            ("[1,2,3]", "array"),
            ("42", "number"),
            ("\"hello\"", "string"),
            ("true", "boolean"),
            ("null", "null"),
        ] {
            let error = classify_root(json);
            match error {
                StixError::DeserializationError(message) => {
                    assert_eq!(
                        message,
                        format!("Expected a STIX object (JSON object), got {kind}."),
                        "input: {json}"
                    );
                }
                other => panic!("expected DeserializationError for {json}, got {other:?}"),
            }
        }
    }

    #[test]
    fn object_input_with_bad_property_keeps_property_classification() {
        // A JSON object with a mistyped common property is NOT a non-object
        // case; it should classify as a property error (or fall back), never
        // as the non-object message.
        let error = classify_root(
            r#"{"id": "attack-pattern--12345678-1234-5678-1234-567812345678", "created": 123}"#,
        );
        match error {
            StixError::DeserializationError(message) => {
                assert!(
                    !message.starts_with("Expected a STIX object"),
                    "object input misclassified: {message}"
                );
            }
            other => match other {
                StixError::InvalidPropertyType { .. } | StixError::MissingProperty { .. } => {}
                other => panic!("unexpected variant: {other:?}"),
            },
        }
    }
}
