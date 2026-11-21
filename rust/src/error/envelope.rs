//! Cross-language result contract for STIX validation.
//!
//! Validation produces an [`Outcome`] carrying the validated value (when
//! successful), MUST-level errors, and SHOULD-level warnings. Both lists use the
//! same sparse [`Entry`] shape so bindings parse one structure.
use serde::{Deserialize, Serialize};

use super::StixError;

/// A single structured error or warning entry.
///
/// Fields are sparse. There is no `level`/`severity`: the containing list is the
/// MUST/SHOULD distinction. There is no `properties` (one entry per property)
/// and no `expected`/`got` (the message carries the detail).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Machine-readable kind, e.g. `missing_property` or `hash_not_sha256`.
    /// Kind strings are cross-language API surface: they are stable and
    /// additions are additive.
    pub kind: String,
    /// Human-readable message for this entry.
    pub message: String,
    /// The property this entry refers to, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub property: Option<String>,
    /// The offending value, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<String>,
    /// The vocabulary a value was checked against, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vocabulary: Option<String>,
    /// The STIX object identifier this entry applies to, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub object_id: Option<String>,
}

impl Entry {
    /// Creates an entry with a kind and message.
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            ..Default::default()
        }
    }

    /// Sets the `property` field.
    pub fn property(mut self, property: impl Into<String>) -> Self {
        self.property = Some(property.into());
        self
    }

    /// Sets the `value` field.
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Sets the `vocabulary` field.
    pub fn vocabulary(mut self, vocabulary: impl Into<String>) -> Self {
        self.vocabulary = Some(vocabulary.into());
        self
    }

    /// Sets the `object_id` field.
    pub fn object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }

    /// The dedupe key `(object_id, kind, property, value)`.
    fn dedupe_key(&self) -> (Option<&str>, &str, Option<&str>, Option<&str>) {
        (
            self.object_id.as_deref(),
            self.kind.as_str(),
            self.property.as_deref(),
            self.value.as_deref(),
        )
    }
}

/// The result of a validation pass.
///
/// A result with no errors is valid and carries the value; a result with errors
/// is invalid and carries no value. Warnings never make an outcome invalid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome<T = ()> {
    /// Whether validation succeeded (no errors).
    pub valid: bool,
    /// The validated value; present only when `valid` is true.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<T>,
    /// MUST-level findings.
    pub errors: Vec<Entry>,
    /// SHOULD-level findings.
    pub warnings: Vec<Entry>,
}

impl<T> Outcome<T> {
    /// Builds an outcome from a result and the warnings collected during the
    /// pass. `valid` is derived from whether errors were produced.
    pub fn from_result(result: Result<T, StixError>, warnings: Vec<Entry>) -> Self {
        match result {
            Ok(value) => Self {
                valid: true,
                value: Some(value),
                errors: Vec::new(),
                warnings,
            },
            Err(error) => Self {
                valid: false,
                value: None,
                errors: error.errors(),
                warnings,
            },
        }
    }

    /// Builds a successful outcome carrying `value`.
    pub fn ok(value: T, warnings: Vec<Entry>) -> Self {
        Self {
            valid: true,
            value: Some(value),
            errors: Vec::new(),
            warnings,
        }
    }

    /// Builds a successful outcome with no value.
    pub fn valid(warnings: Vec<Entry>) -> Outcome<()> {
        Outcome {
            valid: true,
            value: Some(()),
            errors: Vec::new(),
            warnings,
        }
    }

    /// Maps the value of a successful outcome, preserving errors and warnings.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U> {
        Outcome {
            valid: self.valid,
            value: self.value.map(f),
            errors: self.errors,
            warnings: self.warnings,
        }
    }

    /// Converts the outcome into a `Result`, flattening errors into a
    /// [`StixError::ValidationErrors`] when there is more than one.
    pub fn into_result(self) -> Result<T, StixError> {
        match self.value {
            Some(value) if self.valid => Ok(value),
            _ => {
                let errors = self
                    .errors
                    .into_iter()
                    .map(|entry| StixError::ValidationError(entry.message))
                    .collect::<Vec<_>>();
                Err(if errors.len() == 1 {
                    errors.into_iter().next().expect("one error")
                } else {
                    StixError::ValidationErrors(errors)
                })
            }
        }
    }

    /// Builds a failed outcome from a single error.
    pub fn err(error: StixError, warnings: Vec<Entry>) -> Self {
        Self {
            valid: false,
            value: None,
            errors: error.errors(),
            warnings,
        }
    }
}

impl<T: Serialize> Outcome<T> {
    /// Serializes the outcome to the language-agnostic JSON object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("Outcome serializes to JSON")
    }
}

/// Explicit warning sink threaded through a single validation pass.
///
/// The context is stack-local: it is created per entry-point call and dropped
/// afterwards, so warnings cannot leak between calls. The optional current
/// object id is stamped onto entries that do not already carry one.
#[derive(Debug, Default, Clone)]
pub struct CheckContext {
    warnings: Vec<Entry>,
    object_id: Option<String>,
}

impl CheckContext {
    /// Creates an empty validation context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a context whose warnings are discarded by the caller.
    pub fn discard() -> Self {
        Self::default()
    }

    /// Sets the current object id, returning the previous value.
    pub fn set_object_id(&mut self, object_id: Option<String>) -> Option<String> {
        std::mem::replace(&mut self.object_id, object_id)
    }

    /// Records a warning, stamping the current object id when the entry has none.
    ///
    /// Entries are deduplicated by `(object_id, kind, property, value)` so a
    /// repeated rule cannot produce duplicate findings.
    pub fn warn(&mut self, mut entry: Entry) {
        if entry.object_id.is_none() {
            entry.object_id = self.object_id.clone();
        }
        let key = entry.dedupe_key();
        let duplicate = self.warnings.iter().any(|existing| {
            let existing_key = existing.dedupe_key();
            existing_key == key
        });
        if !duplicate {
            self.warnings.push(entry);
        }
    }

    /// Returns the warnings collected so far.
    pub fn warnings(&self) -> &[Entry] {
        &self.warnings
    }

    /// Consumes the context and returns its warnings.
    pub fn into_warnings(self) -> Vec<Entry> {
        self.warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_serializes_expected_shape() {
        let outcome = Outcome::ok(
            "value".to_string(),
            vec![Entry::new("hash_not_sha256", "use sha-256").property("hashes")],
        );
        let json = outcome.to_json();
        assert_eq!(json["valid"], true);
        assert_eq!(json["value"], "value");
        assert!(json["errors"].as_array().unwrap().is_empty());
        assert_eq!(json["warnings"].as_array().unwrap().len(), 1);
        assert_eq!(json["warnings"][0]["kind"], "hash_not_sha256");
        assert_eq!(json["warnings"][0]["property"], "hashes");
        assert!(json.get("level").is_none());
        assert!(json.get("severity").is_none());
    }

    #[test]
    fn optional_fields_are_omitted() {
        let entry = Entry::new("some_kind", "message");
        let json = serde_json::to_value(&entry).unwrap();
        for key in ["property", "value", "vocabulary", "object_id"] {
            assert!(json.get(key).is_none(), "{key} should be omitted: {json}");
        }
        assert!(json.get("properties").is_none());
        assert!(json.get("expected").is_none());
        assert!(json.get("got").is_none());
    }

    #[test]
    fn outcome_with_no_findings_is_valid() {
        let outcome = Outcome::<()>::valid(Vec::new());
        assert!(outcome.valid);
        assert!(outcome.errors.is_empty());
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn outcome_with_warnings_is_valid() {
        let mut ctx = CheckContext::new();
        ctx.warn(Entry::new("hash_not_sha256", "use sha-256"));
        let outcome = Outcome::<()>::valid(ctx.into_warnings());
        assert!(outcome.valid);
        assert!(outcome.errors.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
    }

    #[test]
    fn outcome_from_error_is_invalid_without_value() {
        let outcome: Outcome<()> = Outcome::from_result(Err(StixError::EmptyList), Vec::new());
        assert!(!outcome.valid);
        assert!(outcome.value.is_none());
        assert_eq!(outcome.errors.len(), 1);
    }

    #[test]
    fn context_stamps_object_id() {
        let mut ctx = CheckContext::new();
        ctx.set_object_id(Some("identity--123".to_string()));
        ctx.warn(Entry::new("open_vocab_value_not_suggested", "message"));
        assert_eq!(
            ctx.warnings()[0].object_id.as_deref(),
            Some("identity--123")
        );
    }

    #[test]
    fn contexts_do_not_leak() {
        let mut first = CheckContext::new();
        first.warn(Entry::new("hash_not_sha256", "message"));
        let second = CheckContext::new();
        assert_eq!(first.into_warnings().len(), 1);
        assert!(second.into_warnings().is_empty());
    }

    #[test]
    fn duplicate_warnings_are_dropped() {
        let mut ctx = CheckContext::new();
        ctx.set_object_id(Some("identity--123".to_string()));
        ctx.warn(Entry::new("hash_not_sha256", "first").property("hashes"));
        ctx.warn(Entry::new("hash_not_sha256", "second").property("hashes"));
        assert_eq!(ctx.warnings().len(), 1);
        // A different property is a distinct finding.
        ctx.warn(Entry::new("hash_not_sha256", "third").property("other"));
        assert_eq!(ctx.warnings().len(), 2);
    }
}
