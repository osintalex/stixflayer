//! A custom STIX Error type, with its associated functions.
use std::num::ParseIntError;

use jiff::Error as JiffError;
use strum::ParseError;
use thiserror::Error;

pub mod classify;
pub mod envelope;
pub mod helpers;

pub use classify::{classify_serde_error, json_kind, non_object_json_message};
pub use envelope::{ErrorEntry, ErrorEnvelope};
pub use helpers::{add_error, return_multiple_errors};

/// Custom Error type for rust-stix
///
/// Every variant yields at least one structured [`ErrorEntry`] via
/// [`StixError::errors`]; variants with natural structure produce rich entries
/// (see `to_entry`), all others fall back to a catch-all entry whose `kind` is
/// the variant name in snake_case. Kind strings are cross-language API surface:
/// adding variants is additive, renaming kinds is breaking and avoided.
#[derive(Debug, Clone, Error, strum::EnumDiscriminants)]
#[strum_discriminants(derive(strum::AsRefStr))]
#[strum_discriminants(strum(serialize_all = "snake_case"))]
pub enum StixError {
    /// Multiple validation errors returned at once, e.g. by the collect-all
    /// validation flow.
    #[error("Validation errors: {0:?}")]
    ValidationErrors(Vec<StixError>),
    // Basic parsing or validation errors
    /// A timestamp could not be parsed or represented (wraps a
    /// [`jiff`](https://docs.rs/jiff) error).
    #[error("DateTime error: {0}")]
    DateTimeError(JiffError),
    /// A list or dictionary property was empty; empty collections are
    /// prohibited in STIX 2.1.
    #[error("Empty Lists and dictionaries are prohibted in STIX")]
    EmptyList,
    /// A hash value does not match the format of its declared algorithm.
    #[error("The hash value '{hash_string}' is not a valid {hash_type} hash (detected format: {hash_identity}).")]
    InvalidHash {
        /// The hash algorithm the value was checked against.
        hash_type: String,
        /// The hash algorithm the value's format actually suggests.
        hash_identity: String,
        /// The offending hash value.
        hash_string: String,
    },
    /// A `--` UUID portion of an object identifier is invalid.
    #[error("Invalid UUID in object id: {message}")]
    InvalidUuid {
        /// Details of why the UUID is invalid.
        message: String,
    },
    /// A property was set on a builder that its object type does not allow.
    #[error("{object} of type {object_type} do not have a '{field}' field.")]
    IllegalBuilderProperty {
        /// The builder or object name the property was set on.
        object: String,
        /// The STIX type of the object.
        object_type: String,
        /// The property name that is not valid for this type.
        field: String,
    },
    /// A relationship type is not valid between the given source and target
    /// object types.
    #[error("A Relationship Object of type {relationship} cannot exist from a {source_type} to a {target_type}")]
    InvalidRelationship {
        /// The relationship type that was attempted.
        relationship: String,
        /// The STIX type of the source object.
        source_type: String,
        /// The STIX type of the target object.
        target_type: String,
    },
    /// A required property was never set on a builder.
    #[error("Object of type {object_type} must have the '{property}' property set.")]
    MissingBuilderProperty {
        /// The STIX type of the object being built.
        object_type: String,
        /// The required property that was not set.
        property: String,
    },
    /// The given string could not be parsed as hexadecimal.
    #[error("Could not parse String {0} as a valid hex")]
    ParseHexError(String),
    /// The given string could not be parsed as a STIX 2.1 identifier.
    #[error("Could not parse String {0} as a valid STIX 2.1 Identifier")]
    ParseIdentifierError(String),
    /// The given string could not be parsed as an integer.
    #[error("Error parsing integer: {0}")]
    ParseIntegerError(ParseIntError),
    /// The given string could not be parsed as a STIX 2.1 timestamp.
    #[error("Could not parse timestamp {0} as a valid STIX 2.1 Timestamp")]
    ParseTimestampError(String),
    /// The given string is not a valid STIX pattern; the second field carries
    /// the parser's diagnostic.
    #[error("Failed to parse STIX Pattern {0}: {1}")]
    ParsePatternError(String, String),
    /// A validation failure with no more specific variant.
    #[error("STIX validation error: {0}")]
    ValidationError(String),
    /// An object-level check (SDO/SCO/SRO) failed because of an inner error.
    ///
    /// `context` names the object and the failed check; the display message
    /// embeds the inner message without repeating the `STIX validation error:`
    /// prefix, and the inner error's structured entries are preserved so
    /// field-level detail (e.g. vocabulary context) survives nesting.
    #[error("STIX validation error: {context}: {}", .source.embedded_message())]
    InvalidNestedObject {
        /// Names the object and the failed check.
        context: String,
        /// The inner error that caused the check to fail.
        source: Box<StixError>,
    },
    /// A value is not a member of the vocabulary it was checked against.
    #[error("STIX validation error: Value '{value}' is not a valid {vocabulary} value.")]
    InvalidVocabValue {
        /// The invalid value.
        value: String,
        /// The name of the vocabulary the value was checked against.
        vocabulary: String,
    },
    // Extension errors
    /// An extension key is not a known predefined extension.
    #[error("Extension key is not a known predefined extension")]
    UnknownExtension,
    /// An extension is not valid for the object type it is applied to.
    #[error("Wrong extension type for object")]
    WrongExtension,
    // Versioning errors
    /// The object cannot be versioned; the string explains why.
    #[error("Cannot version this object: {0}")]
    UnableToVersion(String),
    /// The given string is not a valid version timestamp.
    #[error("{0} is not valid version timestamp: {1}")]
    BadVersion(String, JiffError),
    // Customization errors
    /// A custom object must carry an extension with an appropriate
    /// `new_object` extension type.
    #[error("Custom objects must have an extension with an appropriate new_object extension type")]
    CustomMissingExtension,
    // (De)serialization and JSON parsing related errors
    /// A JSON `null` was encountered; nulls are not allowed in STIX 2.1.
    #[error("JSON nulls are not allowed in STIX 2.1")]
    JsonNull,
    /// The JSON value did not have the expected shape.
    #[error("Unexpected JSON format")]
    UnexpectedJsonFormat,
    /// The object contained fields that are not part of its STIX type.
    #[error("Unknown fields in JSON: {0:?}")]
    UnknownFields(Vec<String>),
    /// The JSON value is not a recognized STIX object type.
    #[error("Unrecognized STIX Object or Object Type")]
    UnrecognizedObject(ParseError),
    // `serde_json:Error`s are converted to Strings during error mapping because that Error type does not `impl Clone`
    /// Serializing a value to JSON failed.
    ///
    /// The message is stringified because `serde_json::Error` does not
    /// implement `Clone`.
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Deserializing a value from JSON failed.
    ///
    /// The message is stringified because `serde_json::Error` does not
    /// implement `Clone`.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    // Structured (de)serialization errors, produced by classify_serde_error
    // and the collect-all validation flow. These carry the STIX object type
    // so bindings can render actionable messages without re-parsing strings.
    /// A required property is missing from an object.
    #[error("`{object_type}` is missing required property '{property}'")]
    MissingProperty {
        /// The STIX type missing the property.
        object_type: String,
        /// The required property name.
        property: String,
    },
    /// An object contains properties that are not part of its STIX type.
    #[error("`{object_type}` has unknown properties: {fields:?}")]
    UnknownProperties {
        /// The STIX type that rejected the fields.
        object_type: String,
        /// The unrecognized property names.
        fields: Vec<String>,
    },
    /// A property has a value of the wrong JSON type.
    #[error("`{object_type}` has an invalid value for property '{property}': expected {expected}, got {got}")]
    InvalidPropertyType {
        /// The STIX type of the object.
        object_type: String,
        /// The property with the wrong value type.
        property: String,
        /// Description of the expected type.
        expected: String,
        /// Description of the value that was found.
        got: String,
    },
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
            | StixError::InvalidNestedObject { .. }
            | StixError::InvalidVocabValue { .. }
            | StixError::ParsePatternError(_, _)
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

    /// Returns this error's message without the leading `STIX validation error: `
    /// prefix, so a larger validation message can embed it without repeating
    /// the prefix. Errors that never carry the prefix are returned unchanged.
    pub fn embedded_message(&self) -> String {
        let message = self.to_string();
        message
            .strip_prefix("STIX validation error: ")
            .unwrap_or(&message)
            .to_string()
    }

    /// Converts a structured validation variant into an [`ErrorEntry`].
    fn to_entry(&self) -> Option<ErrorEntry> {
        match self {
            StixError::MissingProperty { property, .. } => Some(ErrorEntry {
                kind: "missing_property".to_string(),
                message: self.to_string(),
                property: Some(property.clone()),
                ..Default::default()
            }),
            StixError::UnknownProperties { fields, .. } => Some(ErrorEntry {
                kind: "unknown_property".to_string(),
                message: self.to_string(),
                properties: Some(fields.clone()),
                ..Default::default()
            }),
            StixError::InvalidPropertyType {
                property,
                expected,
                got,
                ..
            } => Some(ErrorEntry {
                kind: "invalid_property_type".to_string(),
                message: self.to_string(),
                property: Some(property.clone()),
                expected: Some(expected.clone()),
                got: Some(got.clone()),
                ..Default::default()
            }),
            StixError::InvalidNestedObject { source, .. } => source.to_entry().map(|mut entry| {
                // Keep the composed, context-aware message on the entry while
                // preserving the inner error's structured fields.
                entry.message = self.to_string();
                entry
            }),
            StixError::InvalidVocabValue { value, vocabulary } => Some(ErrorEntry {
                kind: "invalid_vocab_value".to_string(),
                message: self.to_string(),
                value: Some(value.clone()),
                vocabulary: Some(vocabulary.clone()),
                ..Default::default()
            }),
            StixError::InvalidHash {
                hash_type,
                hash_identity,
                hash_string,
            } => Some(ErrorEntry {
                kind: "invalid_hash".to_string(),
                message: self.to_string(),
                value: Some(hash_string.clone()),
                expected: Some(hash_type.clone()),
                got: Some(hash_identity.clone()),
                ..Default::default()
            }),
            StixError::ParseTimestampError(timestamp) => Some(ErrorEntry {
                kind: "invalid_timestamp".to_string(),
                message: self.to_string(),
                value: Some(timestamp.clone()),
                ..Default::default()
            }),
            StixError::ParseIdentifierError(identifier) => Some(ErrorEntry {
                kind: "invalid_identifier".to_string(),
                message: self.to_string(),
                value: Some(identifier.clone()),
                ..Default::default()
            }),
            StixError::ParsePatternError(pattern, detail) => Some(ErrorEntry {
                kind: "invalid_pattern".to_string(),
                message: self.to_string(),
                value: Some(pattern.clone()),
                got: Some(detail.clone()),
                ..Default::default()
            }),
            _ => None,
        }
    }

    /// Catch-all entry for variants without a rich structured form.
    ///
    /// Guarantees the total `.errors` contract: the `kind` is the variant name
    /// in snake_case and `message` is the display string.
    fn catch_all_entry(&self) -> ErrorEntry {
        ErrorEntry {
            kind: StixErrorDiscriminants::from(self).as_ref().to_string(),
            message: self.to_string(),
            ..Default::default()
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
    /// Every other error yields at least one entry: a rich entry when the
    /// variant has natural structure, otherwise a catch-all entry
    /// (`catch_all_entry`).
    pub fn errors(&self) -> Vec<ErrorEntry> {
        match self {
            StixError::ValidationErrors(errors) if !errors.is_empty() => {
                errors.iter().flat_map(|e| e.errors()).collect()
            }
            _ => {
                let mut entries: Vec<ErrorEntry> = self.to_entry().into_iter().collect();
                if entries.is_empty() {
                    entries.push(self.catch_all_entry());
                }
                entries
            }
        }
    }

    /// Serializes this error as the cross-language JSON envelope.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(ErrorEnvelope {
            error: self.envelope_category().to_string(),
            message: self.envelope_message(),
            errors: self.errors(),
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
        // Total contract: even syntax failures carry a catch-all entry.
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "deserialization_error");
        assert!(entries[0]["message"].as_str().unwrap().contains("line 1"));
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
        // Total contract: every variant yields at least one entry.
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "empty_list");
        assert_eq!(entries[0]["message"], envelope["message"]);
    }

    /// Constructs every `StixError` variant so the total `.errors` contract can
    /// be asserted exhaustively. A new variant must be added here, keeping the
    /// contract honest.
    fn all_variants() -> Vec<StixError> {
        vec![
            StixError::ValidationErrors(vec![StixError::EmptyList]),
            StixError::ValidationErrors(vec![]),
            StixError::DateTimeError("bad".parse::<jiff::Timestamp>().unwrap_err()),
            StixError::EmptyList,
            StixError::InvalidHash {
                hash_type: "MD5".to_string(),
                hash_identity: "unknown".to_string(),
                hash_string: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            },
            StixError::InvalidUuid {
                message: "bad".to_string(),
            },
            StixError::IllegalBuilderProperty {
                object: "AttackPattern".to_string(),
                object_type: "attack-pattern".to_string(),
                field: "bogus".to_string(),
            },
            StixError::InvalidRelationship {
                relationship: "indicates".to_string(),
                source_type: "identity".to_string(),
                target_type: "identity".to_string(),
            },
            StixError::MissingBuilderProperty {
                object_type: "attack-pattern".to_string(),
                property: "name".to_string(),
            },
            StixError::ParseHexError("zz".to_string()),
            StixError::ParseIdentifierError("nope".to_string()),
            StixError::ParseIntegerError("x".parse::<u32>().unwrap_err()),
            StixError::ParseTimestampError("not-a-time".to_string()),
            StixError::ParsePatternError("AND OR".to_string(), "syntax error".to_string()),
            StixError::ValidationError("bad value".to_string()),
            StixError::InvalidNestedObject {
                context: "Domain Object x is not a valid y".to_string(),
                source: Box::new(StixError::EmptyList),
            },
            StixError::InvalidVocabValue {
                value: "unknown".to_string(),
                vocabulary: "test-vocab".to_string(),
            },
            StixError::UnknownExtension,
            StixError::WrongExtension,
            StixError::UnableToVersion("no timestamps".to_string()),
            StixError::BadVersion(
                "attack-pattern--12345678-1234-5678-1234-567812345678".to_string(),
                "bad".parse::<jiff::Timestamp>().unwrap_err(),
            ),
            StixError::CustomMissingExtension,
            StixError::JsonNull,
            StixError::UnexpectedJsonFormat,
            StixError::UnknownFields(vec!["bogus".to_string()]),
            StixError::UnrecognizedObject(strum::ParseError::VariantNotFound),
            StixError::SerializationError("cannot serialize".to_string()),
            StixError::DeserializationError("cannot deserialize".to_string()),
            StixError::MissingProperty {
                object_type: "attack-pattern".to_string(),
                property: "name".to_string(),
            },
            StixError::UnknownProperties {
                object_type: "attack-pattern".to_string(),
                fields: vec!["bogus".to_string()],
            },
            StixError::InvalidPropertyType {
                object_type: "attack-pattern".to_string(),
                property: "name".to_string(),
                expected: "a string".to_string(),
                got: "integer `1`".to_string(),
            },
        ]
    }

    #[test]
    fn every_variant_yields_at_least_one_entry() {
        for error in all_variants() {
            let entries = error.errors();
            assert!(
                !entries.is_empty(),
                "variant {:?} produced no entries",
                error
            );
            for entry in &entries {
                assert!(!entry.kind.is_empty(), "empty kind for {error:?}");
                assert!(!entry.message.is_empty(), "empty message for {error:?}");
            }
        }
    }

    #[test]
    fn catch_all_kinds_are_snake_case_variant_names() {
        assert_eq!(StixError::EmptyList.errors()[0].kind, "empty_list");
        assert_eq!(
            StixError::ParseHexError("zz".to_string()).errors()[0].kind,
            "parse_hex_error"
        );
        assert_eq!(StixError::JsonNull.errors()[0].kind, "json_null");
        // Rich variants keep their documented kinds.
        assert_eq!(
            StixError::InvalidVocabValue {
                value: "x".to_string(),
                vocabulary: "v".to_string(),
            }
            .errors()[0]
                .kind,
            "invalid_vocab_value"
        );
    }

    #[test]
    fn rich_entries_carry_natural_structure() {
        // InvalidHash: value/expected/got mirror declared vs detected type.
        let hash = StixError::InvalidHash {
            hash_type: "MD5".to_string(),
            hash_identity: "unknown".to_string(),
            hash_string: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        };
        let entry = &hash.errors()[0];
        assert_eq!(entry.kind, "invalid_hash");
        assert_eq!(
            entry.value.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(entry.expected.as_deref(), Some("MD5"));
        assert_eq!(entry.got.as_deref(), Some("unknown"));
        assert!(
            !hash.to_string().contains("and it is:"),
            "old wording removed: {}",
            hash
        );
        assert!(hash.to_string().contains("is not a valid MD5 hash"));

        let timestamp = StixError::ParseTimestampError("not-a-time".to_string());
        let entry = &timestamp.errors()[0];
        assert_eq!(entry.kind, "invalid_timestamp");
        assert_eq!(entry.value.as_deref(), Some("not-a-time"));

        let identifier = StixError::ParseIdentifierError("nope".to_string());
        let entry = &identifier.errors()[0];
        assert_eq!(entry.kind, "invalid_identifier");
        assert_eq!(entry.value.as_deref(), Some("nope"));

        let pattern = StixError::ParsePatternError("AND OR".to_string(), "syntax".to_string());
        let entry = &pattern.errors()[0];
        assert_eq!(entry.kind, "invalid_pattern");
        assert_eq!(entry.value.as_deref(), Some("AND OR"));
        assert_eq!(entry.got.as_deref(), Some("syntax"));
    }

    #[test]
    fn envelope_has_no_version_field() {
        let error = classify("{}");
        let envelope = error.to_json();
        assert!(envelope.get("v").is_none());
        assert!(envelope.get("version").is_none());
    }
}
