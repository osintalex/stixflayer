//! Shared, stateless validation helpers used across STIX objects and extensions.

use crate::{
    error::{CheckContext, Entry, StixError as Error},
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
    cache.entry(TypeId::of::<V>()).or_insert_with(|| {
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
        Err(Error::InvalidVocabValue {
            value: normalized,
            vocabulary: enum_display_name.to_string(),
        })
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

/// Returns true when `value` is formatted the way open-vocabulary terms SHOULD
/// be: all lowercase, with hyphens as word separators (no spaces or underscores,
/// no empty hyphen-delimited segments).
pub fn is_lowercase_hyphenated(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(' ')
        && !value.contains('_')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Records a SHOULD-level warning when an open-vocabulary value is not one of
/// the suggested terms, and a formatting warning when it is not lowercase and
/// hyphenated. Never fails validation.
pub fn warn_vocab_value<V, S>(ctx: &mut CheckContext, value: S, vocabulary: &str, property: &str)
where
    V: IntoEnumIterator + AsRef<str> + 'static,
    S: AsRef<str>,
{
    let raw = value.as_ref();
    let normalized = stix_case(raw);
    if !is_vocab_value::<V, _>(normalized.as_str()) {
        ctx.warn(
            Entry::new(
                "open_vocab_value_not_suggested",
                format!(
                    "'{}' is not a suggested {} value. Open-vocabulary values MAY be any string.",
                    raw, vocabulary
                ),
            )
            .property(property)
            .value(normalized.clone())
            .vocabulary(vocabulary),
        );
    }
    if !is_lowercase_hyphenated(raw) {
        ctx.warn(
            Entry::new(
                "value_not_lowercase_hyphenated",
                format!(
                    "Open vocabulary value '{}' should be all lowercase and use hyphens instead of spaces or underscores as word separators.",
                    raw
                ),
            )
            .property(property)
            .value(raw.to_string()),
        );
    }
}

/// Records [`warn_vocab_value`] warnings for every value in `values`.
pub fn warn_vocab_list<V, S>(ctx: &mut CheckContext, values: &[S], vocabulary: &str, property: &str)
where
    V: IntoEnumIterator + AsRef<str> + 'static,
    S: AsRef<str>,
{
    for value in values {
        warn_vocab_value::<V, _>(ctx, value, vocabulary, property);
    }
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
        // The message keeps a single validation-error prefix.
        assert!(msg.starts_with("STIX validation error: "));
        assert_eq!(msg.matches("STIX validation error:").count(), 1);
    }

    #[test]
    fn invalid_vocab_value_entry_carries_value_and_vocabulary() {
        let err = validate_vocab_value::<TestVocab, _>("unknown", "test-vocab").unwrap_err();
        let entries = err.errors();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.kind, "invalid_vocab_value");
        assert_eq!(entry.value.as_deref(), Some("unknown"));
        assert_eq!(entry.vocabulary.as_deref(), Some("test-vocab"));
        assert!(entry.message.contains("unknown"));
        assert!(entry.message.contains("test-vocab"));
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
