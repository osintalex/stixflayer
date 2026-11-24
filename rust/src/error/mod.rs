//! A custom STIX Error type, with its associated functions.
use jiff::Error as JiffError;
use strum::ParseError;
use thiserror::Error;

pub mod classify;
pub mod envelope;
pub mod helpers;

pub use classify::{classify_serde_error, json_kind, non_object_json_message};
pub use envelope::{CheckContext, Entry, Outcome};
pub use helpers::{add_error, return_multiple_errors};

/// Every error `kind` the engine can currently produce.
///
/// This is the machine-readable contract; the docs catalog and the
/// `all_variants` drift test keep it in sync with the implementation.
pub const KNOWN_ERROR_KINDS: &[&str] = &[
    "deserialization_error",
    "empty_list",
    "illegal_builder_property",
    "invalid_hash",
    "invalid_hex",
    "invalid_identifier",
    "invalid_nested_object",
    "invalid_pattern",
    "invalid_property_type",
    "invalid_relationship",
    "invalid_timestamp",
    "invalid_uuid",
    "invalid_vocab_value",
    "json_null",
    "missing_property",
    "serialization_error",
    "unable_to_version",
    "unexpected_json_format",
    "unknown_extension",
    "unknown_property",
    "unrecognized_object",
    "validation_error",
    "validation_errors",
    "wrong_extension",
];

/// Every warning `kind` the engine can currently produce.
pub const KNOWN_WARNING_KINDS: &[&str] = &[
    "custom_missing_extension",
    "dictionary_key_not_lowercase",
    "extension_key_not_extension_definition",
    "external_reference_url_without_hashes",
    "hash_not_sha256",
    "identifier_uuid_not_v4",
    "marking_definition_type_not_suggested",
    "network_traffic_missing_port",
    "observed_data_no_recognized_sco",
    "observed_data_unrecognized_ref",
    "open_vocab_value_not_suggested",
    "protocol_missing_from_protocols",
    "relationship_type_not_suggested",
    "value_not_lowercase_hyphenated",
];

/// Custom Error type for rust-stix
///
/// Every variant yields at least one structured [`Entry`] via
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
    /// An error attributed to a specific STIX object.
    ///
    /// Wraps an object-scoped failure so its structured entries carry
    /// `object_id`. `Display` delegates to the inner error, so human messages
    /// are unchanged.
    #[error("{error}")]
    Located {
        /// The identifier of the object the error applies to.
        object_id: String,
        /// The inner error.
        #[source]
        error: Box<StixError>,
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
    // (De)serialization and JSON parsing related errors
    /// A JSON `null` was encountered; nulls are not allowed in STIX 2.1.
    #[error("JSON nulls are not allowed in STIX 2.1")]
    JsonNull,
    /// The JSON value did not have the expected shape.
    #[error("Unexpected JSON format")]
    UnexpectedJsonFormat,
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
            | StixError::UnknownExtension => "validation",
            StixError::DeserializationError(_)
            | StixError::SerializationError(_)
            | StixError::UnexpectedJsonFormat
            | StixError::JsonNull => "deserialization",
            StixError::Located { error, .. } => error.envelope_category(),
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

    /// Converts a structured validation variant into one or more [`Entry`]s.
    ///
    /// Entries are sparse: one entry per property, with the message carrying
    /// the detail that older envelopes split into `expected`/`got`/`properties`.
    fn to_entries(&self) -> Vec<Entry> {
        match self {
            StixError::MissingProperty { property, .. }
            | StixError::MissingBuilderProperty { property, .. } => {
                vec![Entry::new("missing_property", self.to_string()).property(property.clone())]
            }
            StixError::UnknownProperties { fields, .. } => fields
                .iter()
                .map(|field| {
                    Entry::new("unknown_property", self.to_string()).property(field.clone())
                })
                .collect(),
            StixError::InvalidPropertyType { property, .. } => {
                vec![Entry::new("invalid_property_type", self.to_string())
                    .property(property.clone())]
            }
            StixError::InvalidNestedObject { source, .. } => source
                .to_entries()
                .into_iter()
                .map(|mut entry| {
                    // Keep the composed, context-aware message on the entry while
                    // preserving the inner error's structured fields.
                    entry.message = self.to_string();
                    entry
                })
                .collect(),
            StixError::InvalidVocabValue { value, vocabulary } => {
                vec![Entry::new("invalid_vocab_value", self.to_string())
                    .value(value.clone())
                    .vocabulary(vocabulary.clone())]
            }
            StixError::InvalidHash { hash_string, .. } => {
                vec![Entry::new("invalid_hash", self.to_string()).value(hash_string.clone())]
            }
            StixError::ParseTimestampError(timestamp) => {
                vec![Entry::new("invalid_timestamp", self.to_string()).value(timestamp.clone())]
            }
            StixError::DateTimeError(_) => {
                vec![Entry::new("invalid_timestamp", self.to_string())]
            }
            StixError::ParseIdentifierError(identifier) => {
                vec![Entry::new("invalid_identifier", self.to_string()).value(identifier.clone())]
            }
            StixError::ParsePatternError(pattern, _detail) => {
                vec![Entry::new("invalid_pattern", self.to_string()).value(pattern.clone())]
            }
            StixError::ParseHexError(value) => {
                vec![Entry::new("invalid_hex", self.to_string()).value(value.clone())]
            }
            _ => Vec::new(),
        }
    }

    /// Catch-all entry for variants without a rich structured form.
    ///
    /// Guarantees the total `.errors` contract: the `kind` is the variant name
    /// in snake_case and `message` is the display string.
    fn catch_all_entry(&self) -> Entry {
        Entry::new(
            StixErrorDiscriminants::from(self).as_ref(),
            self.to_string(),
        )
    }

    /// Human-readable summary for the envelope top-level `message` field.
    pub fn envelope_message(&self) -> String {
        match self {
            StixError::ValidationErrors(errors) => match errors.len() {
                0 => "Validation error".to_string(),
                1 => errors[0].to_string(),
                n => format!("{n} validation errors occurred"),
            },
            StixError::Located { error, .. } => error.envelope_message(),
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
            StixError::Located { error, .. } => error.display_message(),
            _ => self.to_string(),
        }
    }

    /// Returns the structured error entries for this error.
    ///
    /// For `ValidationErrors`, this flattens the entries of each inner error.
    /// Every other error yields at least one entry: a rich entry when the
    /// variant has natural structure, otherwise a catch-all entry
    /// (`catch_all_entry`).
    pub fn errors(&self) -> Vec<Entry> {
        match self {
            StixError::ValidationErrors(errors) if !errors.is_empty() => {
                errors.iter().flat_map(|e| e.errors()).collect()
            }
            StixError::Located { object_id, error } => {
                let mut entries = error.errors();
                for entry in &mut entries {
                    if entry.object_id.is_none() {
                        entry.object_id = Some(object_id.clone());
                    }
                }
                entries
            }
            _ => {
                let mut entries = self.to_entries();
                if entries.is_empty() {
                    entries.push(self.catch_all_entry());
                }
                entries
            }
        }
    }

    /// Serializes this error as a failed [`Outcome`] JSON object.
    ///
    /// The shape is `{ "valid": false, "errors": [...], "warnings": [] }`.
    pub fn to_json(&self) -> serde_json::Value {
        Outcome::<()>::err(self.clone(), Vec::new()).to_json()
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
        assert_eq!(envelope["valid"], false);
        assert!(envelope["warnings"].as_array().unwrap().is_empty());
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "missing_property");
        assert_eq!(entries[0]["property"], "name");
        assert!(entries[0].get("expected").is_none());
        assert!(entries[0].get("got").is_none());
        assert!(entries[0].get("properties").is_none());
        assert!(entries[0].get("level").is_none());
    }

    #[test]
    fn invalid_property_type_envelope() {
        let error = classify(r#"{"name": 1}"#);
        let envelope = error.to_json();
        assert_eq!(envelope["valid"], false);
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "invalid_property_type");
        assert_eq!(entries[0]["property"], "name");
        // Detail lives in the message now.
        let message = entries[0]["message"].as_str().unwrap();
        assert!(message.contains("a string"), "message: {message}");
        assert!(message.contains("integer `1`"), "message: {message}");
    }

    #[test]
    fn syntax_deserialization_envelope_keeps_position() {
        let error = classify("not json");
        let envelope = error.to_json();
        assert_eq!(envelope["valid"], false);
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
        assert_eq!(envelope["valid"], false);
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
        assert_eq!(envelope["valid"], false);
        let entries = envelope["errors"].as_array().unwrap();
        // One entry per property, with no `properties` list.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["kind"], "unknown_property");
        assert_eq!(entries[0]["property"], "foo");
        assert_eq!(entries[1]["kind"], "unknown_property");
        assert_eq!(entries[1]["property"], "bar");
        assert!(entries[0].get("properties").is_none());
    }

    #[test]
    fn generic_stix_error_envelope() {
        let error = StixError::EmptyList;
        let envelope = error.to_json();
        assert_eq!(envelope["valid"], false);
        // Total contract: every variant yields at least one entry.
        let entries = envelope["errors"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["kind"], "empty_list");
        assert_eq!(
            entries[0]["message"],
            "Empty Lists and dictionaries are prohibted in STIX"
        );
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
            StixError::JsonNull,
            StixError::UnexpectedJsonFormat,
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
            StixError::Located {
                object_id: "attack-pattern--12345678-1234-5678-1234-567812345678".to_string(),
                error: Box::new(StixError::MissingProperty {
                    object_type: "attack-pattern".to_string(),
                    property: "name".to_string(),
                }),
            },
        ]
    }

    #[test]
    fn every_reachable_kind_is_in_the_catalog() {
        let mut reachable = std::collections::BTreeSet::new();
        for error in all_variants() {
            for entry in error.errors() {
                reachable.insert(entry.kind);
            }
        }
        for kind in &reachable {
            assert!(
                KNOWN_ERROR_KINDS.contains(&kind.as_str()),
                "reachable kind '{kind}' is missing from KNOWN_ERROR_KINDS"
            );
        }
        for kind in KNOWN_ERROR_KINDS {
            assert!(
                reachable.contains(*kind),
                "catalog kind '{kind}' is not reachable from any variant"
            );
        }
    }

    #[test]
    fn warning_kinds_are_stable_snake_case() {
        for kind in KNOWN_WARNING_KINDS {
            assert!(
                !kind.is_empty()
                    && kind
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "warning kind '{kind}' is not snake_case"
            );
        }
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
            "invalid_hex"
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
        // InvalidHash: the value is structured and the detail lives in the message.
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
        assert!(entry.message.contains("MD5"));
        assert!(entry.message.contains("unknown"));
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
        assert!(entry.message.contains("syntax"));
    }

    #[test]
    fn envelope_has_no_version_field() {
        let error = classify("{}");
        let envelope = error.to_json();
        assert!(envelope.get("v").is_none());
        assert!(envelope.get("version").is_none());
    }

    #[test]
    fn located_stamps_object_id_without_changing_the_message() {
        let inner = StixError::MissingProperty {
            object_type: "attack-pattern".to_string(),
            property: "name".to_string(),
        };
        let message = inner.to_string();
        let located = StixError::Located {
            object_id: "attack-pattern--12345678-1234-5678-1234-567812345678".to_string(),
            error: Box::new(inner),
        };

        assert_eq!(located.to_string(), message);
        assert_eq!(located.display_message(), message);
        assert_eq!(located.envelope_category(), "validation");

        let entries = located.errors();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].object_id.as_deref(),
            Some("attack-pattern--12345678-1234-5678-1234-567812345678")
        );
        assert_eq!(entries[0].message, message);
    }

    #[test]
    fn located_preserves_an_existing_object_id() {
        let inner = StixError::Located {
            object_id: "indicator--inner".to_string(),
            error: Box::new(StixError::EmptyList),
        };
        let outer = StixError::Located {
            object_id: "indicator--outer".to_string(),
            error: Box::new(inner),
        };
        assert_eq!(
            outer.errors()[0].object_id.as_deref(),
            Some("indicator--inner")
        );
    }
}
