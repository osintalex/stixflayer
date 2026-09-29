//! A custom STIX Error type, with its associated functions.
use std::num::ParseIntError;

use jiff::Error as JiffError;
use strum::ParseError;
use thiserror::Error;

use crate::types::Identifier;

pub mod classify;
pub mod envelope;
pub mod helpers;

pub use classify::classify_serde_error;
pub use envelope::{ErrorEntry, ErrorEnvelope};
pub use helpers::{add_error, return_multiple_errors};

/// Custom Error type for rust-stix
#[derive(Debug, Clone, Error)]
pub enum StixError {
    // For retunning multiple errors at once, e.g. during validation
    #[error("Validation errors: {0:?}")]
    ValidationErrors(Vec<StixError>),
    // Basic parsing or validation errors
    #[error("DateTime error: {0}")]
    DateTimeError(JiffError),
    #[error("Empty Lists and dictionaries are prohibted in STIX")]
    EmptyList,
    #[error("The corresponding hash string for this value MUST be a valid {hash_type} message, and it is: {hash_identity} {hash_string}")]
    InvalidHash {
        hash_type: String,
        hash_identity: String,
        hash_string: String,
    },
    #[error("Invalid UUID in object id: {message}")]
    InvalidUuid { message: String },
    #[error("{object} of type {object_type} do not have a '{field}' field.")]
    IllegalBuilderProperty {
        object: String,
        object_type: String,
        field: String,
    },
    #[error("A Relationship Object of type {relationship} cannot exist from a {source_type} to a {target_type}")]
    InvalidRelationship {
        relationship: String,
        source_type: String,
        target_type: String,
    },
    #[error("Object of type {object_type} must have the '{property}' property set.")]
    MissingBuilderProperty {
        object_type: String,
        property: String,
    },
    #[error("Could not parse String {0} as a valid hex")]
    ParseHexError(String),
    #[error("Could not parse String {0} as a valid STIX 2.1 Identifier")]
    ParseIdentifierError(String),
    #[error("Error parsing integer: {0}")]
    ParseIntegerError(ParseIntError),
    #[error("Could not parse timestamp {0} as a valid STIX 2.1 Timestamp")]
    ParseTimestampError(String),
    #[error("Failed to parse STIX Pattern {0}: {1}")]
    ParsePatternError(String, String),
    // General validation error
    #[error("STIX validation error: {0}")]
    ValidationError(String),
    // Extension errors
    #[error("Extension key is not a known predefined extension")]
    UnknownExtension,
    #[error("Wrong extension type for object")]
    WrongExtension,
    // Versioning errors
    #[error("Cannot version this object: {0}")]
    UnableToVersion(String),
    #[error("{0} is not valid version timestamp: {1}")]
    BadVersion(String, JiffError),
    // Customization errors
    #[error("Custom objects must have an extension with an appropriate new_object extension type")]
    CustomMissingExtension,
    // (De)serialization and JSON parsing related errors
    #[error("JSON nulls are not allowed in STIX 2.1")]
    JsonNull,
    #[error("Unexpected JSON format")]
    UnexpectedJsonFormat,
    #[error("Unknown fields in JSON: {0:?}")]
    UnknownFields(Vec<String>),
    #[error("Unrecognized STIX Object or Object Type")]
    UnrecognizedObject(ParseError),
    // `serde_json:Error`s are converted to Strings during error mapping because that Error type does not `impl Clone`
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    // Structured (de)serialization errors, produced by classify_serde_error
    // and the collect-all validation flow. These carry the STIX object type
    // so bindings can render actionable messages without re-parsing strings.
    #[error("`{object_type}` is missing required property '{property}'")]
    MissingProperty {
        object_type: String,
        property: String,
    },
    #[error("`{object_type}` has unknown properties: {fields:?}")]
    UnknownProperties {
        object_type: String,
        fields: Vec<String>,
    },
    #[error("`{object_type}` has an invalid value for property '{property}': expected {expected}, got {got}")]
    InvalidPropertyType {
        object_type: String,
        property: String,
        expected: String,
        got: String,
    },
    // Datastore errors
    #[error("Data source not found")]
    MissingDataSource,
    #[error("Data sink not found")]
    MissingDataSink,
    #[error("Data type {0} is not supported in rust-stix")]
    UnsupportedDataType(String),
    // Filesystem access errors
    #[error("File I/O error: {0}")]
    IoError(String),
    #[error("File {0} not found")]
    PathNotFound(String),
    #[error("Object {0} not in filesystem")]
    ObjectNotFound(Identifier),
}

impl StixError {
    /// Returns the envelope category for this error.
    ///
    /// Categories are: `validation`, `deserialization`, `stix`.
    pub fn envelope_category(&self) -> &'static str {
        match self {
            StixError::ValidationErrors(_)
            | StixError::MissingProperty { .. }
            | StixError::UnknownProperties { .. }
            | StixError::InvalidPropertyType { .. }
            | StixError::ValidationError(_)
            | StixError::WrongExtension
            | StixError::CustomMissingExtension
            | StixError::UnknownExtension => "validation",
            StixError::DeserializationError(_)
            | StixError::SerializationError(_)
            | StixError::UnexpectedJsonFormat
            | StixError::JsonNull => "deserialization",
            _ => "stix",
        }
    }

    /// Converts a structured validation variant into an [`ErrorEntry`].
    fn to_entry(&self) -> Option<ErrorEntry> {
        match self {
            StixError::MissingProperty {
                object_type: _,
                property,
            } => Some(ErrorEntry {
                kind: "missing_property".to_string(),
                message: self.to_string(),
                property: Some(property.clone()),
                properties: None,
                expected: None,
                got: None,
            }),
            StixError::UnknownProperties {
                object_type: _,
                fields,
            } => Some(ErrorEntry {
                kind: "unknown_property".to_string(),
                message: self.to_string(),
                property: None,
                properties: Some(fields.clone()),
                expected: None,
                got: None,
            }),
            StixError::InvalidPropertyType {
                object_type: _,
                property,
                expected,
                got,
            } => Some(ErrorEntry {
                kind: "invalid_property_type".to_string(),
                message: self.to_string(),
                property: Some(property.clone()),
                properties: None,
                expected: Some(expected.clone()),
                got: Some(got.clone()),
            }),
            _ => None,
        }
    }

    /// Human-readable summary for the envelope top-level `message` field.
    pub fn envelope_message(&self) -> String {
        match self {
            StixError::ValidationErrors(errors) => match errors.len() {
                0 => "Validation error".to_string(),
                1 => errors[0].to_string(),
                n => format!("{n} validation errors occurred"),
            },
            _ => self.to_string(),
        }
    }

    /// Human-readable message suitable for Python exception display.
    ///
    /// Unlike [`Self::envelope_message`], multiple validation errors are joined
    /// into a single readable sentence so callers see every issue in `str(e)`.
    pub fn display_message(&self) -> String {
        match self {
            StixError::ValidationErrors(errors) => match errors.len() {
                0 => "Validation error".to_string(),
                1 => errors[0].to_string(),
                _ => errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            },
            _ => self.to_string(),
        }
    }

    /// Returns the structured error entries for this error.
    ///
    /// For `ValidationErrors`, this flattens the entries of each inner error.
    /// For errors without a structured representation, the returned vector is
    /// empty.
    pub fn errors(&self) -> Vec<ErrorEntry> {
        match self {
            StixError::ValidationErrors(errors) => {
                errors.iter().filter_map(|e| e.to_entry()).collect()
            }
            _ => self.to_entry().into_iter().collect(),
        }
    }

    /// Serializes this error as the cross-language JSON envelope.
    pub fn to_json(&self) -> serde_json::Value {
        let errors = match self {
            StixError::ValidationErrors(errors) => {
                errors.iter().filter_map(|e| e.to_entry()).collect()
            }
            _ => self.to_entry().into_iter().collect(),
        };

        serde_json::to_value(ErrorEnvelope {
            error: self.envelope_category().to_string(),
            message: self.envelope_message(),
            errors,
        })
        .expect("ErrorEnvelope serializes to JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_path_to_error as serde_path;

    #[derive(Debug, Deserialize)]
    struct Probe {
        #[serde(rename = "name")]
        _name: String,
    }

    fn classify(json: &str) -> StixError {
        let result: Result<Probe, _> =
            serde_path::deserialize(&mut serde_json::Deserializer::from_str(json));
        classify_serde_error(result.unwrap_err(), "attack-pattern")
    }

    #[test]
    fn missing_field_becomes_missing_property() {
        let error = classify("{}");
        match error {
            StixError::MissingProperty {
                object_type,
                property,
            } => {
                assert_eq!(object_type, "attack-pattern");
                assert_eq!(property, "name");
            }
            other => panic!("expected MissingProperty, got {other:?}"),
        }
    }

    #[test]
    fn invalid_type_becomes_invalid_property_type() {
        let error = classify(r#"{"name": 1}"#);
        match error {
            StixError::InvalidPropertyType {
                object_type,
                property,
                expected,
                got,
            } => {
                assert_eq!(object_type, "attack-pattern");
                assert_eq!(property, "name");
                assert_eq!(expected, "a string");
                assert_eq!(got, "integer `1`");
            }
            other => panic!("expected InvalidPropertyType, got {other:?}"),
        }
    }

    #[test]
    fn syntax_error_keeps_position_message() {
        let error = classify("not json");
        match error {
            StixError::DeserializationError(message) => {
                assert!(message.contains("expected ident"), "message: {message}");
                assert!(message.contains("line 1"), "position kept: {message}");
            }
            other => panic!("expected DeserializationError, got {other:?}"),
        }
    }

    #[test]
    fn display_renders_structured_variants() {
        let error = classify("{}");
        assert_eq!(
            error.to_string(),
            "`attack-pattern` is missing required property 'name'"
        );
    }

    #[test]
    fn return_multiple_errors_joins_into_validation_errors() {
        assert!(return_multiple_errors(vec![]).is_ok());
        let single = return_multiple_errors(vec![StixError::EmptyList]).unwrap_err();
        assert!(matches!(single, StixError::EmptyList));
        let multiple =
            return_multiple_errors(vec![StixError::EmptyList, StixError::EmptyList]).unwrap_err();
        assert!(matches!(multiple, StixError::ValidationErrors(_)));
    }

    #[test]
    fn missing_property_envelope() {
        let error = classify("{}");
        let envelope = error.to_json();
        assert_eq!(envelope["error"], "validation");
        assert_eq!(
            envelope["message"],
            "`attack-pattern` is missing required property 'name'"
        );
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "missing_property");
        assert_eq!(entries[0]["property"], "name");
        assert!(entries[0]["expected"].is_null());
    }

    #[test]
    fn invalid_property_type_envelope() {
        let error = classify(r#"{"name": 1}"#);
        let envelope = error.to_json();
        assert_eq!(envelope["error"], "validation");
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "invalid_property_type");
        assert_eq!(entries[0]["property"], "name");
        assert_eq!(entries[0]["expected"], "a string");
        assert_eq!(entries[0]["got"], "integer `1`");
    }

    #[test]
    fn syntax_deserialization_envelope_keeps_position() {
        let error = classify("not json");
        let envelope = error.to_json();
        assert_eq!(envelope["error"], "deserialization");
        assert!(
            envelope["message"].as_str().unwrap().contains("line 1"),
            "position kept: {}",
            envelope["message"]
        );
        assert!(envelope["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_errors_flatten_into_envelope() {
        let error = StixError::ValidationErrors(vec![
            StixError::MissingProperty {
                object_type: "attack-pattern".to_string(),
                property: "name".to_string(),
            },
            StixError::InvalidPropertyType {
                object_type: "attack-pattern".to_string(),
                property: "name".to_string(),
                expected: "a string".to_string(),
                got: "integer `1`".to_string(),
            },
        ]);
        let envelope = error.to_json();
        assert_eq!(envelope["error"], "validation");
        assert_eq!(envelope["message"], "2 validation errors occurred");
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["kind"], "missing_property");
        assert_eq!(entries[1]["kind"], "invalid_property_type");
    }

    #[test]
    fn unknown_properties_envelope() {
        let error = StixError::UnknownProperties {
            object_type: "attack-pattern".to_string(),
            fields: vec!["foo".to_string(), "bar".to_string()],
        };
        let envelope = error.to_json();
        assert_eq!(envelope["error"], "validation");
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "unknown_property");
        let props: Vec<String> = serde_json::from_value(entries[0]["properties"].clone()).unwrap();
        assert_eq!(props, vec!["foo", "bar"]);
    }

    #[test]
    fn generic_stix_error_envelope() {
        let error = StixError::EmptyList;
        let envelope = error.to_json();
        assert_eq!(envelope["error"], "stix");
        assert_eq!(
            envelope["message"],
            "Empty Lists and dictionaries are prohibted in STIX"
        );
        assert!(envelope["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn envelope_has_no_version_field() {
        let error = classify("{}");
        let envelope = error.to_json();
        assert!(envelope.get("v").is_none());
        assert!(envelope.get("version").is_none());
    }
}
