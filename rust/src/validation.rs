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
//!    structured [`StixError::MissingProperty`] / [`StixError::InvalidPropertyType`].
//! 3. Object-specific `stix_check` logic when `strict` is true.

use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_path_to_error as serde_path;

use crate::{
    base::{validate_custom_property_name, CustomPropertiesHolder, Stix},
    error::{add_error, classify_serde_error, return_multiple_errors, StixError as Error},
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
/// [`StixError::ValidationErrors`].
pub fn validate_value<T: DeserializeOwned + Stix + CustomPropertiesHolder>(
    value: Value,
    allow_custom: bool,
    strict: bool,
) -> Result<T, Error> {
    let type_name = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let props = type_properties(type_name);
    let mut errors: Vec<Error> = Vec::new();

    let mut custom_properties: Option<std::collections::BTreeMap<String, Value>> = None;

    if let Some(props) = props {
        if let Some(map) = value.as_object() {
            let keys: std::collections::HashSet<&str> = map.keys().map(|s| s.as_str()).collect();
            let known: std::collections::HashSet<&str> = props.known.iter().copied().collect();

            let unknown: Vec<&str> = keys.difference(&known).map(|k| *k).collect();

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

    // If we found custom properties, ensure they are not passed to serde so the
    // flattened `custom_properties` field cannot accidentally capture known keys.
    let mut value_to_deserialize = value.clone();
    if let (Some(ref bag), Some(map)) = (&custom_properties, value_to_deserialize.as_object_mut()) {
        for key in bag.keys() {
            map.remove(key);
        }
    }

    // For path-aware deserialization we need a textual form. This serializes the
    // value once instead of the previous N-pass parse/serialize dance.
    let json = serde_json::to_string(&value_to_deserialize)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    let mut typed: T = match serde_path::deserialize(&mut serde_json::Deserializer::from_str(&json)) {
        Ok(t) => t,
        Err(e) => {
            let classified = classify_serde_error(e, type_name);
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
                    return Err(return_multiple_errors(errors).unwrap_err());
                }
            }
            errors.push(classified);
            return Err(return_multiple_errors(errors).unwrap_err());
        }
    };

    // Attach the custom-property bag explicitly, overriding the serde-default None.
    typed.set_custom_properties(custom_properties);

    if strict {
        add_error(&mut errors, typed.stix_check());
    }

    return_multiple_errors(errors)?;
    Ok(typed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_objects::sdo::DomainObject;
    use std::collections::BTreeMap;

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
        let err = validate_value::<DomainObject>(value, false, true).unwrap_err();
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
        let err = validate_value::<DomainObject>(value, false, true).unwrap_err();
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
        assert!(
            matches!(err, Error::MissingProperty { ref property, .. } if property == "name"),
            "expected MissingProperty name, got {err:?}"
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
        let err = validate_value::<DomainObject>(value, false, true).unwrap_err();
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
        let err = validate_value::<DomainObject>(value, true, false).unwrap_err();
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
        let err = validate_value::<DomainObject>(value, false, true).unwrap_err();
        assert!(matches!(err, Error::UnknownProperties { .. }), "got {err:?}");
    }

    #[test]
    fn invalid_custom_property_name_is_rejected() {
        let cases = [
            ("1_starts_digit", "must not start with a digit"),
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
            let err = validate_value::<DomainObject>(value, true, true).unwrap_err();
            assert!(
                matches!(err, Error::ValidationError(_) | Error::ValidationErrors(_)),
                "{key}: expected ValidationError, got {err:?}"
            );
        }
    }
}
