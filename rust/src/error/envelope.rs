//! Cross-language JSON envelope for STIX errors.
use serde::Serialize;

/// Cross-language JSON envelope for every STIX error.
///
/// This is the only contract exposed to non-Rust bindings. The `error` field
/// is the major category. The `errors` array carries per-field entries for
/// validation-style failures and is omitted when empty.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorEnvelope {
    pub error: String,
    pub message: String,
    pub errors: Vec<ErrorEntry>,
}

/// A single structured error entry inside an [`ErrorEnvelope`].
///
/// Fields are sparse. `property` is a single JSON property name; `properties`
/// is provided for entries that name a list of unknown fields.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorEntry {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub property: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub got: Option<String>,
}
