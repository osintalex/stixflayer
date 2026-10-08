//! Shared, stateless validation helpers used across STIX objects and extensions.

use crate::{
    error::StixError as Error,
    types::{stix_case, Identifier},
};
use regex::Regex;
use std::{
    any::TypeId,
    collections::{HashMap, HashSet},
    sync::{Mutex, OnceLock},
};
use strum::IntoEnumIterator;

/// Checks whether `value` is a syntactically valid top-level MIME type of the
/// form `{application|audio|font|image|message|model|multipart|text|video}/{token}`.
pub fn is_valid_mime_type(value: &str) -> bool {
    static MIME_RE: OnceLock<Regex> = OnceLock::new();
    let re = MIME_RE.get_or_init(|| {
        Regex::new(
            r"^(application|audio|font|image|message|model|multipart|text|video)/[a-zA-Z0-9.+_-]+$",
        )
        .expect("hard-coded MIME regex is valid")
    });
    re.is_match(value)
}

/// Checks whether `value` is a valid IANA character set name as used by the
/// STIX `path_enc` and `name_enc` properties.
pub fn is_valid_charset_name(value: &str) -> bool {
    static CHARSET_RE: OnceLock<Regex> = OnceLock::new();
    let re = CHARSET_RE.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9_\(\)-]+$").expect("hard-coded charset regex is valid")
    });
    re.is_match(value)
}

/// Checks whether `value` is a valid hexadecimal string.
pub fn is_valid_hex(value: &str) -> bool {
    hex::decode(value).is_ok()
}

/// Generic cache of pre-built vocabulary membership sets.
///
/// Each enum is built once via its [`IntoEnumIterator`] implementation and
/// stored under its [`TypeId`] to give O(1) lookups on repeated validations.
fn vocab_membership_set<V>() -> &'static HashSet<String>
where
    V: IntoEnumIterator + AsRef<str> + 'static,
{
    static CACHE: OnceLock<Mutex<HashMap<TypeId, &'static HashSet<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("vocab membership cache lock poisoned");
    *cache
        .entry(TypeId::of::<V>())
        .or_insert_with(|| {
            let set: HashSet<String> = V::iter().map(|v| v.as_ref().to_string()).collect();
            Box::leak(Box::new(set))
        })
}

/// Returns true when `value` is a member of the vocabulary `V`.
///
/// The value is normalised with [`stix_case`] before comparison, matching the
/// behaviour of [`validate_vocab_value`].
pub fn is_vocab_value<V, S>(value: S) -> bool
where
    V: IntoEnumIterator + AsRef<str> + 'static,
    S: AsRef<str>,
{
    let normalized = stix_case(value.as_ref());
    vocab_membership_set::<V>().contains(normalized.as_str())
}

/// Returns true when `value` matches a vocabulary member exactly (no case
/// normalisation). Use this for enums whose values are fixed-case constants
/// such as `AF_INET` or `REG_DWORD`.
pub fn is_exact_vocab_value<V, S>(value: S) -> bool
where
    V: IntoEnumIterator + AsRef<str> + 'static,
    S: AsRef<str>,
{
    vocab_membership_set::<V>().contains(value.as_ref())
}

/// Validates that a single string value is a member of the provided
/// STIX open-vocabulary enum.
///
/// The value is normalised with [`stix_case`] before comparison.
pub fn validate_vocab_value<V, S>(value: S, enum_display_name: &str) -> Result<(), Error>
where
    V: IntoEnumIterator + AsRef<str> + 'static,
    S: AsRef<str>,
{
    let normalized = stix_case(value.as_ref());
    if is_vocab_value::<V, _>(normalized.as_str()) {
        Ok(())
    } else {
        Err(Error::ValidationError(format!(
            "Value '{}' is not a valid {} value.",
            normalized, enum_display_name
        )))
    }
}

/// Validates that every string value in `values` is a member of the provided
/// STIX open-vocabulary enum.
///
/// Each value is normalised with [`stix_case`] before comparison.
pub fn validate_vocab_list<V, S>(values: &[S], enum_display_name: &str) -> Result<(), Error>
where
    V: IntoEnumIterator + AsRef<str> + 'static,
    S: AsRef<str>,
{
    for value in values {
        validate_vocab_value::<V, _>(value, enum_display_name)?;
    }
    Ok(())
}

/// Validates that every identifier in `refs` is one of the expected STIX object
/// types.
pub fn validate_refs_are_type(
    refs: &[Identifier],
    expected_types: &[&str],
    field_name: &str,
) -> Result<(), Error> {
    for id in refs {
        let t = id.get_type();
        if !expected_types.contains(&t) {
            let allowed = expected_types.join(", ");
            return Err(Error::ValidationError(format!(
                "The '{}' field must reference objects of type {}. Found '{}'.",
                field_name, allowed, t
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_mime_types() {
        assert!(is_valid_mime_type("text/plain"));
        assert!(is_valid_mime_type("application/msword"));
        assert!(is_valid_mime_type("image/jpeg"));
        assert!(!is_valid_mime_type("not/a/mime/type"));
        assert!(!is_valid_mime_type("textplain"));
        assert!(!is_valid_mime_type(""));
    }

    #[test]
    fn valid_charset_names() {
        assert!(is_valid_charset_name("utf-8"));
        assert!(is_valid_charset_name("ISO_8859-1"));
        assert!(is_valid_charset_name("Windows-1252"));
        assert!(!is_valid_charset_name("utf 8"));
        assert!(!is_valid_charset_name(""));
    }

    #[test]
    fn valid_hex_strings() {
        assert!(is_valid_hex("deadbeef"));
        assert!(is_valid_hex("DEADBEEF"));
        assert!(is_valid_hex("08"));
        assert!(!is_valid_hex("0g"));
        // hex::decode accepts an empty string as valid
        assert!(is_valid_hex(""));
    }

    #[derive(Debug, Clone, Copy, strum::AsRefStr, strum::EnumIter)]
    #[strum(serialize_all = "kebab-case")]
    enum TestVocab {
        FooBar,
        BazQux,
    }

    #[test]
    fn validate_vocab_accepts_known_and_normalised_values() {
        assert!(validate_vocab_value::<TestVocab, _>("foo-bar", "test-vocab").is_ok());
        assert!(validate_vocab_value::<TestVocab, _>("Foo Bar", "test-vocab").is_ok());
        assert!(validate_vocab_value::<TestVocab, _>("BAZ_QUX", "test-vocab").is_ok());
    }

    #[test]
    fn validate_vocab_rejects_unknown_values() {
        let err = validate_vocab_value::<TestVocab, _>("unknown", "test-vocab").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown"));
        assert!(msg.contains("test-vocab"));
    }

    #[test]
    fn validate_vocab_list_checks_every_member() {
        assert!(validate_vocab_list::<TestVocab, _>(&["foo-bar", "baz-qux"], "test-vocab").is_ok());
        assert!(
            validate_vocab_list::<TestVocab, _>(&["foo-bar", "not-in-list"], "test-vocab").is_err()
        );
    }

    #[test]
    fn validate_refs_are_type_accepts_matching_refs() {
        let refs = [Identifier::new_test("file")];
        assert!(validate_refs_are_type(&refs, &["file", "directory"], "contains_refs").is_ok());
    }

    #[test]
    fn validate_refs_are_type_rejects_mismatch() {
        let refs = [
            Identifier::new_test("directory"),
            Identifier::new_test("ipv4-addr"),
        ];
        let err =
            validate_refs_are_type(&refs, &["file", "directory"], "contains_refs").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ipv4-addr"));
        assert!(msg.contains("file"));
        assert!(msg.contains("directory"));
    }
}
