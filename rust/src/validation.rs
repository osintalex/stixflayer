//! Value-based collect-all validation for STIX objects.
//!
//! This module provides the central deserialization gate used by every typed
//! `from_json` path. It operates on a single [`serde_json::Value`] (the JSON is
//! parsed once at the top level) and tries to surface as many independent errors
//! as possible instead of stopping at the first serde failure.
//!
//! The flow is:
//!
//! 1. Structural checks from the property registry:
//!    - unknown properties (unless `allow_custom` is true)
//!    - missing required properties
//! 2. Typed deserialization; `serde_path_to_error` turns data errors into
//!    structured
//!    [`StixError::MissingProperty`](crate::error::StixError::MissingProperty) /
//!    [`StixError::InvalidPropertyType`](crate::error::StixError::InvalidPropertyType).
//! 3. Object-specific `stix_check` logic when `strict` is true.

use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_path_to_error as serde_path;

use crate::{
    base::{validate_custom_property_name, CustomPropertiesHolder, Stix},
    error::{
        add_error, classify_serde_error, return_multiple_errors, CheckContext, Entry, Outcome,
        StixError as Error,
    },
    properties::type_properties,
};

/// Validates a STIX object from a JSON value and returns the typed struct.
///
/// - `allow_custom: false` rejects unknown properties against the registry.
/// - `allow_custom: true` permits unknown properties, strips them out into the
///   object's [`CommonProperties::custom_properties`][crate::base::CommonProperties::custom_properties]
///   bag, and validates their names against the STIX 2.1 custom-property rules.
/// - `strict: true` adds required-property checks and runs the object-specific
///   `stix_check`. `strict: false` just deserializes and optionally checks unknown
///   properties.
///
/// Multiple independent errors are returned as a single
/// [`StixError::ValidationErrors`](crate::error::StixError::ValidationErrors).
pub fn validate_value<T: DeserializeOwned + Stix + CustomPropertiesHolder>(
    value: Value,
    allow_custom: bool,
    strict: bool,
) -> Result<T, Error> {
    validate_value_from_object(value, allow_custom, strict)
}

/// Outcome-returning variant of [`validate_value`].
pub fn validate_value_outcome<T: DeserializeOwned + Stix + CustomPropertiesHolder>(
    value: Value,
    allow_custom: bool,
    strict: bool,
) -> Outcome<T> {
    validate_value_from_object_outcome(value, allow_custom, strict)
}

/// Validates a STIX object from its raw object [`Value`] without re-serializing.
///
/// This is the optimized implementation. The API-compatible [`validate_value`]
/// wrapper delegates here.
pub fn validate_value_from_object<T: DeserializeOwned + Stix + CustomPropertiesHolder>(
    value: Value,
    allow_custom: bool,
    strict: bool,
) -> Result<T, Error> {
    validate_value_from_object_parts(value, allow_custom, strict).0
}

/// Outcome-returning variant of [`validate_value_from_object`].
///
/// The outcome carries the typed value on success and the collected SHOULD
/// warnings whether or not validation succeeded.
pub fn validate_value_from_object_outcome<T: DeserializeOwned + Stix + CustomPropertiesHolder>(
    value: Value,
    allow_custom: bool,
    strict: bool,
) -> Outcome<T> {
    let (result, warnings) = validate_value_from_object_parts(value, allow_custom, strict);
    Outcome::from_result(result, warnings)
}

/// Wraps an object-scoped error with the object's identifier.
///
/// Errors already attributed by an inner layer are returned unchanged so the
/// identifier is stamped once.
fn attach_object_id(object_id: Option<&str>, error: Error) -> Error {
    match object_id {
        Some(id) if !matches!(&error, Error::Located { .. }) => Error::Located {
            object_id: id.to_string(),
            error: Box::new(error),
        },
        _ => error,
    }
}

/// Shared implementation behind the `Result` and `Outcome` entry points.
///
/// Returns the typed value (or structured error) together with the warnings
/// collected during the same validation pass.
pub fn validate_value_from_object_parts<T: DeserializeOwned + Stix + CustomPropertiesHolder>(
    mut value: Value,
    allow_custom: bool,
    strict: bool,
) -> (Result<T, Error>, Vec<Entry>) {
    // Read the id before `value` is moved so object-scoped findings can be
    // attributed to the object they concern.
    let object_id = value.get("id").and_then(Value::as_str).map(str::to_owned);
    let type_name = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let props = type_properties(&type_name);
    let mut errors: Vec<Error> = Vec::new();

    let mut custom_properties: Option<std::collections::BTreeMap<String, Value>> = None;

    if let Some(props) = props {
        if let Some(map) = value.as_object() {
            let keys: std::collections::HashSet<&str> = map.keys().map(|s| s.as_str()).collect();
            let known: std::collections::HashSet<&str> = props.known.iter().copied().collect();

            let unknown: Vec<&str> = keys.difference(&known).copied().collect();

            if !unknown.is_empty() {
                if !allow_custom {
                    errors.push(Error::UnknownProperties {
                        object_type: type_name.to_string(),
                        fields: unknown.into_iter().map(|k| k.to_string()).collect(),
                    });
                } else {
                    // Validate custom property names immediately, regardless of `strict`.
                    for key in &unknown {
                        add_error(&mut errors, validate_custom_property_name(key));
                    }

                    if errors.is_empty() {
                        let mut bag = std::collections::BTreeMap::new();
                        for key in unknown {
                            if let Some(val) = map.get(key) {
                                bag.insert(key.to_string(), val.clone());
                            }
                        }
                        if !bag.is_empty() {
                            custom_properties = Some(bag);
                        }
                    }
                }
            }

            for req in props.required.iter() {
                if !keys.contains(*req) {
                    errors.push(Error::MissingProperty {
                        object_type: type_name.to_string(),
                        property: req.to_string(),
                    });
                }
            }
        }
    }

    // If we found custom properties, strip them from the value before passing it
    // to serde so the flattened `custom_properties` field cannot accidentally
    // capture known keys.
    if let Some(bag) = custom_properties.as_ref() {
        if let Some(map) = value.as_object_mut() {
            for key in bag.keys() {
                map.remove(key);
            }
        }
    }

    let mut typed: T = match serde_path::deserialize(value) {
        Ok(t) => t,
        Err(e) => {
            let classified = classify_serde_error(e, &type_name);
            // Avoid reporting a missing field that the registry already listed.
            if let Error::MissingProperty { property, .. } = &classified {
                if errors.iter().any(|err| {
                    matches!(
                        err,
                        Error::MissingProperty {
                            property: p,
                            ..
                        } if p == property
                    )
                }) {
                    return (
                        Err(attach_object_id(
                            object_id.as_deref(),
                            return_multiple_errors(errors).unwrap_err(),
                        )),
                        Vec::new(),
                    );
                }
            }
            errors.push(classified);
            return (
                Err(attach_object_id(
                    object_id.as_deref(),
                    return_multiple_errors(errors).unwrap_err(),
                )),
                Vec::new(),
            );
        }
    };

    // Attach the custom-property bag explicitly, overriding the serde-default None.
    typed.set_custom_properties(custom_properties);

    let mut ctx = CheckContext::new();
    if strict {
        add_error(&mut errors, typed.check(&mut ctx));
    }
    let warnings = ctx.into_warnings();

    let result = match return_multiple_errors(errors) {
        Ok(()) => Ok(typed),
        Err(error) => Err(attach_object_id(object_id.as_deref(), error)),
    };
    (result, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_objects::sdo::DomainObject;
    use std::collections::BTreeMap;

    /// Strips the object-attribution wrapper so tests can inspect the variant.
    fn inner(error: Error) -> Error {
        match error {
            Error::Located { error, .. } => *error,
            other => other,
        }
    }

    #[test]
    fn valid_sdo_deserializes() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing"
        });
        assert!(validate_value::<DomainObject>(value, false, true).is_ok());
    }

    #[test]
    fn unknown_property_rejected_when_allow_custom_false() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "junk": "value"
        });
        let err = inner(validate_value::<DomainObject>(value, false, true).unwrap_err());
        assert!(
            matches!(err, Error::UnknownProperties { .. }),
            "expected UnknownProperties, got {err:?}"
        );
    }

    #[test]
    fn unknown_property_allowed_when_allow_custom_true() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "junk": "value"
        });
        assert!(validate_value::<DomainObject>(value, true, true).is_ok());
    }

    #[test]
    fn multiple_validation_errors_collected() {
        // Both errors are independent: the object deserializes fine, but
        // `spec_version` is wrong per `stix_check` and `junk` is unknown.
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "3.0",
            "name": "Spear Phishing",
            "junk": "value"
        });
        let err = inner(validate_value::<DomainObject>(value, false, true).unwrap_err());
        match err {
            Error::ValidationErrors(errors) => {
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, Error::UnknownProperties { .. })),
                    "missing unknown property error"
                );
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, Error::ValidationError(_))),
                    "missing validation error"
                );
            }
            other => panic!("expected ValidationErrors, got {other:?}"),
        }
    }

    #[test]
    fn missing_required_property_reported() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1"
        });
        let err = validate_value::<DomainObject>(value, false, true).unwrap_err();
        let entries = err.errors();
        assert_eq!(entries.len(), 1, "entries: {entries:?}");
        assert_eq!(entries[0].kind, "missing_property");
        assert_eq!(entries[0].property.as_deref(), Some("name"));
        assert_eq!(
            entries[0].object_id.as_deref(),
            Some("attack-pattern--12345678-1234-5678-1234-567812345678")
        );
    }

    #[test]
    fn invalid_top_level_type_reported_as_deserialization_error() {
        // Top-level properties are flattened into the object structs, so
        // `serde_path_to_error` cannot report the property name for an invalid
        // type at the root. The error should still be surfaced, not lost.
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": 2.1,
            "name": "Spear Phishing"
        });
        let err = inner(validate_value::<DomainObject>(value, false, true).unwrap_err());
        assert!(
            matches!(err, Error::DeserializationError(_)),
            "expected DeserializationError, got {err:?}"
        );
    }

    #[test]
    fn non_strict_skips_validation() {
        // missing required `name`, invalid timestamp, unknown property
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "junk": "value"
        });
        // Non-strict still fails because the required `name` field cannot be deserialized.
        assert!(validate_value::<DomainObject>(value.clone(), true, false).is_err());
        // When allow_custom is true the unknown field is ignored; but `name` is still required.
        let err = inner(validate_value::<DomainObject>(value, true, false).unwrap_err());
        assert!(
            !matches!(err, Error::UnknownProperties { .. }),
            "unknown property should not be reported in non-strict mode: {err:?}"
        );
    }

    #[test]
    fn allow_custom_true_preserves_custom_property() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_vendor_severity": 5
        });
        let obj = validate_value::<DomainObject>(value, true, true).unwrap();
        assert_eq!(
            obj.common_properties.custom_properties,
            Some(BTreeMap::from([(
                "x_vendor_severity".to_string(),
                serde_json::json!(5)
            )]))
        );

        let json = serde_json::to_string(&obj).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["x_vendor_severity"], 5);
    }

    #[test]
    fn allow_custom_false_rejects_custom_property() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_vendor_severity": 5
        });
        let err = inner(validate_value::<DomainObject>(value, false, true).unwrap_err());
        assert!(
            matches!(err, Error::UnknownProperties { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn custom_property_name_may_start_with_digit() {
        let value = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "1digit_custom": "allowed"
        });
        let obj = validate_value::<DomainObject>(value, true, true).unwrap();
        assert!(obj
            .common_properties
            .custom_properties
            .as_ref()
            .unwrap()
            .contains_key("1digit_custom"));
    }

    #[test]
    fn invalid_custom_property_name_is_rejected() {
        let cases = [
            ("bad-key", "characters outside the allowed set"),
            ("AB", "too short"),
            ("severity", "reserved"),
        ];
        for (key, _msg) in cases {
            let value = serde_json::json!({
                "type": "attack-pattern",
                "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
                "created": "2016-05-12T08:17:27Z",
                "modified": "2016-05-12T08:17:27Z",
                "spec_version": "2.1",
                "name": "Spear Phishing",
                key: "value"
            });
            let err = inner(validate_value::<DomainObject>(value, true, true).unwrap_err());
            assert!(
                matches!(err, Error::ValidationError(_) | Error::ValidationErrors(_)),
                "{key}: expected ValidationError, got {err:?}"
            );
        }
    }

    #[test]
    fn custom_property_suffix_value_validation() {
        let valid_hex = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_bytes_hex": "deadbeef"
        });
        assert!(validate_value::<DomainObject>(valid_hex, true, true).is_ok());

        let invalid_hex_odd = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_bytes_hex": "deadbee"
        });
        assert!(validate_value::<DomainObject>(invalid_hex_odd, true, true).is_err());

        let invalid_hex_upper = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_bytes_hex": "DEADBEEF"
        });
        assert!(validate_value::<DomainObject>(invalid_hex_upper, true, true).is_err());

        let valid_bin = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_payload_bin": "aGVsbG8gd29ybGQ="
        });
        assert!(validate_value::<DomainObject>(valid_bin, true, true).is_ok());

        let invalid_bin = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_payload_bin": "not-valid-base64!!!"
        });
        assert!(validate_value::<DomainObject>(invalid_bin, true, true).is_err());

        // Non-string values with a _hex suffix are rejected.
        let non_string_hex = serde_json::json!({
            "type": "attack-pattern",
            "id": "attack-pattern--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "name": "Spear Phishing",
            "x_bytes_hex": 12345
        });
        assert!(validate_value::<DomainObject>(non_string_hex, true, true).is_err());
    }

    #[test]
    fn custom_object_custom_property_validation() {
        use crate::custom_objects::CustomObject;

        let valid = serde_json::json!({
            "type": "x-custom",
            "id": "x-custom--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "extensions": {
                "extension-definition--12345678-1234-5678-1234-567812345678": {
                    "extension_type": "new-sdo"
                }
            },
            "x_bytes_hex": "deadbeef"
        });
        assert!(validate_value::<CustomObject>(valid, true, true).is_ok());

        let invalid = serde_json::json!({
            "type": "x-custom",
            "id": "x-custom--12345678-1234-5678-1234-567812345678",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "spec_version": "2.1",
            "extensions": {
                "extension-definition--12345678-1234-5678-1234-567812345678": {
                    "extension_type": "new-sdo"
                }
            },
            "x_bytes_hex": "not-hex"
        });
        assert!(validate_value::<CustomObject>(invalid, true, true).is_err());
    }
}
