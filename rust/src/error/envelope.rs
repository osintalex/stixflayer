//! Cross-language JSON envelope for STIX errors.
use serde::Serialize;

/// Cross-language JSON envelope for every STIX error.
///
/// This is the only contract exposed to non-Rust bindings. The `error` field
/// is the major category. The `errors` array carries per-field entries for
/// validation-style failures.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorEnvelope {
    /// Major error category: `validation`, `deserialization`, or `stix`.
    pub error: String,
    /// Human-readable summary of the error.
    pub message: String,
    /// Per-field entries for validation-style failures.
    pub errors: Vec<ErrorEntry>,
}

/// A single structured error entry inside an [`ErrorEnvelope`].
///
/// Fields are sparse. `property` is a single JSON property name; `properties`
/// is provided for entries that name a list of unknown fields. Entries are
/// built with `..Default::default()` so each variant only names the fields it
/// carries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ErrorEntry {
    /// Machine-readable error kind, e.g. `missing_property`. Kind strings are
    /// cross-language API surface: they are stable and additions are additive.
    pub kind: String,
    /// Human-readable message for this entry.
    pub message: String,
    /// The single property this entry refers to, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub property: Option<String>,
    /// The properties this entry refers to, for entries naming a list of
    /// unknown fields.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<Vec<String>>,
    /// What the property was expected to contain.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected: Option<String>,
    /// What was actually found for the property.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub got: Option<String>,
    /// The offending value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<String>,
    /// The vocabulary a rejected value was checked against.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vocabulary: Option<String>,
}
