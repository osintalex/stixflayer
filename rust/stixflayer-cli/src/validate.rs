//! Document classification and validation.
//!
//! Classification happens before validation so skips never depend on the
//! engine's verdict: unparseable `.json` files are `not_json`, JSON without a
//! STIX `type` is `not_stix`, and documents declaring a different
//! `spec_version` are `unsupported_spec_version`.

use std::path::Path;
use std::str::FromStr;

use rayon::prelude::*;
use serde_json::Value;
use stixflayer::bundles::Bundle;
use stixflayer::error::Entry;
use stixflayer::object::StixObject;
use stixflayer::types::Identifier;

/// Engine parsing options exposed by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Accept `x_`-prefixed custom properties.
    pub allow_custom: bool,
    /// Run semantic (`SHOULD`-level) checks in addition to structural checks.
    pub strict: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            allow_custom: false,
            strict: true,
        }
    }
}

/// The outcome of classifying and validating one input document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Document {
    /// The document is not STIX 2.1 and was skipped for the given reason.
    Skipped { reason: String },
    /// The document was validated; `valid` is false when `errors` is non-empty.
    Result {
        valid: bool,
        errors: Vec<Entry>,
        warnings: Vec<Entry>,
        /// The number of STIX objects that were validated.
        objects: usize,
    },
}

impl Document {
    fn invalid(errors: Vec<Entry>, warnings: Vec<Entry>, objects: usize) -> Self {
        Self::Result {
            valid: false,
            errors,
            warnings,
            objects,
        }
    }
}

/// Classifies and validates one document.
pub fn validate_document(path: &str, text: &str, options: &Options) -> Document {
    if is_jsonl_extension(path) {
        return validate_jsonl(text, options);
    }

    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            if is_json_extension(path) {
                return Document::Skipped {
                    reason: "not_json".to_string(),
                };
            }
            return Document::invalid(
                vec![Entry::new("deserialization_error", error.to_string())],
                Vec::new(),
                0,
            );
        }
    };

    classify_value(value, options)
}

/// Validates a JSON Lines file as one JSON document per non-empty line.
///
/// Each line is classified independently. Parse or validation failures make
/// the file invalid and name the line; a file whose lines are all non-STIX is
/// skipped as `not_stix`. Lines that are skipped do not affect the exit code.
fn validate_jsonl(text: &str, options: &Options) -> Document {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut objects = 0;
    let mut validated_lines = 0;
    let mut skipped_reason: Option<String> = None;
    let mut valid = true;

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                valid = false;
                errors.push(Entry::new(
                    "deserialization_error",
                    format!("line {line_number}: {error}"),
                ));
                continue;
            }
        };

        match classify_value(value, options) {
            Document::Skipped { reason } => {
                skipped_reason.get_or_insert(reason);
            }
            Document::Result {
                valid: line_valid,
                errors: line_errors,
                warnings: line_warnings,
                objects: line_objects,
            } => {
                validated_lines += 1;
                objects += line_objects;
                valid &= line_valid;
                errors.extend(prefix_line(line_errors, line_number));
                warnings.extend(prefix_line(line_warnings, line_number));
            }
        }
    }

    if validated_lines == 0 && valid {
        return Document::Skipped {
            reason: skipped_reason.unwrap_or_else(|| "not_stix".to_string()),
        };
    }

    Document::Result {
        valid: valid && errors.is_empty(),
        errors,
        warnings,
        objects,
    }
}

fn prefix_line(mut entries: Vec<Entry>, line_number: usize) -> Vec<Entry> {
    for entry in &mut entries {
        entry.message = format!("line {line_number}: {}", entry.message);
    }
    entries
}

fn classify_value(value: Value, options: &Options) -> Document {
    let Some(object_type) = value.get("type").and_then(Value::as_str) else {
        return Document::Skipped {
            reason: "not_stix".to_string(),
        };
    };

    if let Some(spec_version) = value.get("spec_version").and_then(Value::as_str) {
        if spec_version != "2.1" {
            return Document::Skipped {
                reason: "unsupported_spec_version".to_string(),
            };
        }
    }

    if object_type == "bundle" {
        validate_bundle(value, options)
    } else {
        let outcome = StixObject::from_value_outcome(value, options.allow_custom, options.strict);
        Document::Result {
            valid: outcome.valid,
            errors: outcome.errors,
            warnings: outcome.warnings,
            objects: 1,
        }
    }
}

fn validate_bundle(value: Value, options: &Options) -> Document {
    let object_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let Some(raw_id) = value.get("id").and_then(Value::as_str) else {
        return Document::invalid(
            vec![Entry::new(
                "deserialization_error",
                "missing field `id` in bundle",
            )],
            Vec::new(),
            0,
        );
    };
    let id = match Identifier::from_str(raw_id) {
        Ok(id) => id,
        Err(error) => {
            return Document::invalid(
                vec![Entry::new("deserialization_error", error.to_string())],
                Vec::new(),
                0,
            )
        }
    };

    let Some(raw_objects) = value.get("objects").and_then(Value::as_array) else {
        return Document::invalid(
            vec![Entry::new(
                "deserialization_error",
                "missing or invalid field `objects` in bundle",
            )],
            Vec::new(),
            0,
        );
    };

    let object_count = raw_objects.len();
    let outcomes: Vec<_> = raw_objects
        .par_iter()
        .map(|value| {
            StixObject::from_value_outcome(value.clone(), options.allow_custom, options.strict)
        })
        .collect();

    let mut objects = Vec::with_capacity(object_count);
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for outcome in outcomes {
        warnings.extend(outcome.warnings);
        match (outcome.valid, outcome.value) {
            (true, Some(object)) => objects.push(object),
            _ => errors.extend(outcome.errors),
        }
    }

    let bundle = Bundle {
        object_type,
        id,
        objects,
    };

    // Bundle invariants only run once every object parsed, matching
    // `Bundle::from_json_outcome`.
    if errors.is_empty() {
        if let Err(error) = bundle.check_invariants() {
            errors.extend(error.errors());
        }
    }

    Document::Result {
        valid: errors.is_empty(),
        errors,
        warnings,
        objects: object_count,
    }
}

fn is_json_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn is_jsonl_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.eq_ignore_ascii_case("jsonl"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options::default()
    }

    fn valid_bundle() -> &'static str {
        r#"{
            "type": "bundle",
            "id": "bundle--44580eb5-a924-475f-970c-8b47ee07f641",
            "objects": [
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": "attack-pattern--089a0ad8-367a-4326-ba2e-35b506fa4c29",
                    "created": "2016-05-12T08:17:27.000Z",
                    "modified": "2016-05-12T08:17:27.000Z",
                    "name": "Spear Phishing"
                }
            ]
        }"#
    }

    fn valid_object() -> &'static str {
        r#"{
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--550e8400-e29b-41d4-a716-446655440000",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "name": "Acme"
        }"#
    }

    fn valid_identity_line() -> &'static str {
        r#"{"type":"identity","spec_version":"2.1","id":"identity--550e8400-e29b-41d4-a716-446655440000","created":"2016-05-12T08:17:27Z","modified":"2016-05-12T08:17:27Z","name":"Acme"}"#
    }

    #[test]
    fn jsonl_validates_each_non_empty_line() {
        let text = format!("{}\n\n{}\n", valid_identity_line(), valid_identity_line());
        assert_eq!(
            validate_document("objects.jsonl", &text, &options()),
            Document::Result {
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
                objects: 2,
            }
        );
    }

    #[test]
    fn jsonl_invalid_line_names_the_line_number() {
        let text = format!("{}\n{{not json\n", valid_identity_line());
        match validate_document("objects.jsonl", &text, &options()) {
            Document::Result {
                valid,
                errors,
                objects,
                ..
            } => {
                assert!(!valid);
                assert_eq!(objects, 1);
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].kind, "deserialization_error");
                assert!(errors[0].message.contains("line 2"), "{:?}", errors[0]);
            }
            other => panic!("expected invalid result, got {other:?}"),
        }
    }

    #[test]
    fn jsonl_with_only_non_stix_lines_is_skipped() {
        assert_eq!(
            validate_document("objects.jsonl", "{\"hello\":\"world\"}\n", &options()),
            Document::Skipped {
                reason: "not_stix".to_string()
            }
        );
    }

    #[test]
    fn jsonl_ignores_non_stix_lines_when_stix_is_present() {
        let text = format!("{}\n{{\"hello\":\"world\"}}\n", valid_identity_line());
        match validate_document("objects.jsonl", &text, &options()) {
            Document::Result {
                valid,
                errors,
                objects,
                ..
            } => {
                assert!(valid);
                assert!(errors.is_empty());
                assert_eq!(objects, 1);
            }
            other => panic!("expected result, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_json_file_is_skipped() {
        assert_eq!(
            validate_document("feed.json", "{not json", &options()),
            Document::Skipped {
                reason: "not_json".to_string()
            }
        );
    }

    #[test]
    fn json_without_a_stix_type_is_skipped() {
        assert_eq!(
            validate_document("config.json", r#"{"name":"not stix"}"#, &options()),
            Document::Skipped {
                reason: "not_stix".to_string()
            }
        );
    }

    #[test]
    fn non_string_type_is_skipped_as_not_stix() {
        assert_eq!(
            validate_document("config.json", r#"{"type":42}"#, &options()),
            Document::Skipped {
                reason: "not_stix".to_string()
            }
        );
    }

    #[test]
    fn stix_20_is_skipped() {
        assert_eq!(
            validate_document(
                "old.json",
                r#"{"type":"identity","spec_version":"2.0"}"#,
                &options()
            ),
            Document::Skipped {
                reason: "unsupported_spec_version".to_string()
            }
        );
    }

    #[test]
    fn unparseable_stix_extension_is_invalid() {
        let document = validate_document("feed.stix2", "{not json", &options());
        match document {
            Document::Result {
                valid,
                errors,
                objects,
                ..
            } => {
                assert!(!valid);
                assert_eq!(objects, 0);
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].kind, "deserialization_error");
            }
            other => panic!("expected invalid result, got {other:?}"),
        }
    }

    #[test]
    fn explicit_non_json_extension_parse_failure_is_invalid() {
        let document = validate_document("notes.txt", "{not json", &options());
        assert!(matches!(document, Document::Result { valid: false, .. }));
    }

    #[test]
    fn valid_object_is_valid() {
        assert_eq!(
            validate_document("identity.json", valid_object(), &options()),
            Document::Result {
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
                objects: 1,
            }
        );
    }

    #[test]
    fn valid_bundle_is_valid_and_counts_objects() {
        let document = validate_document("bundle.json", valid_bundle(), &options());
        match document {
            Document::Result {
                valid,
                errors,
                objects,
                ..
            } => {
                assert!(valid);
                assert!(errors.is_empty());
                assert_eq!(objects, 1);
            }
            other => panic!("expected result, got {other:?}"),
        }
    }

    #[test]
    fn empty_bundle_is_invalid() {
        let text =
            r#"{"type":"bundle","id":"bundle--44580eb5-a924-475f-970c-8b47ee07f641","objects":[]}"#;
        let document = validate_document("bundle.json", text, &options());
        assert!(matches!(document, Document::Result { valid: false, .. }));
    }

    #[test]
    fn bundle_duplicate_ids_are_invalid() {
        let text = r#"{
            "type": "bundle",
            "id": "bundle--44580eb5-a924-475f-970c-8b47ee07f641",
            "objects": [
                {"type":"identity","spec_version":"2.1","id":"identity--550e8400-e29b-41d4-a716-446655440000","created":"2016-05-12T08:17:27Z","modified":"2016-05-12T08:17:27Z","name":"Acme"},
                {"type":"identity","spec_version":"2.1","id":"identity--550e8400-e29b-41d4-a716-446655440000","created":"2016-05-12T08:17:27Z","modified":"2016-05-12T08:17:27Z","name":"Acme"}
            ]
        }"#;
        let document = validate_document("bundle.json", text, &options());
        match document {
            Document::Result { valid, errors, .. } => {
                assert!(!valid);
                assert!(errors
                    .iter()
                    .any(|entry| entry.message.contains("duplicate object id")));
            }
            other => panic!("expected result, got {other:?}"),
        }
    }

    #[test]
    fn custom_properties_require_allow_custom() {
        let text = r#"{
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--550e8400-e29b-41d4-a716-446655440000",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "name": "Acme",
            "x_mitre_version": "1.0"
        }"#;
        assert!(matches!(
            validate_document("identity.json", text, &options()),
            Document::Result { valid: false, .. }
        ));
        assert!(matches!(
            validate_document(
                "identity.json",
                text,
                &Options {
                    allow_custom: true,
                    strict: true
                }
            ),
            Document::Result { valid: true, .. }
        ));
    }

    #[test]
    fn strict_off_skips_semantic_checks() {
        let text = r#"{
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--4bd68344-9327-4487-89b3-a52f1bd86e37",
            "created": "2016-04-06T08:17:27Z",
            "modified": "2016-04-06T08:17:27Z",
            "pattern": "[file:hashes.'SHA-256' = ",
            "pattern_type": "stix",
            "valid_from": "2016-04-06T08:17:27Z"
        }"#;
        assert!(matches!(
            validate_document("indicator.json", text, &options()),
            Document::Result { valid: false, .. }
        ));
        assert!(matches!(
            validate_document(
                "indicator.json",
                text,
                &Options {
                    allow_custom: false,
                    strict: false
                }
            ),
            Document::Result { valid: true, .. }
        ));
    }
}
