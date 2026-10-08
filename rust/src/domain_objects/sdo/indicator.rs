//! Indicator SDO
//!
//! Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v>

use crate::{
    base::{check_timestamp_ordering, Stix},
    common::validation::{is_vocab_value, validate_vocab_list},
    domain_objects::vocab::{IndicatorPatternType, IndicatorType},
    error::{add_error, return_multiple_errors, StixError as Error},
    pattern::validate_pattern,
    types::{stix_case, KillChainPhase, Timestamp},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Indicator {
    /// An optional name used to identify the Indicator.
    pub name: Option<String>,
    /// An optional description that provides more details and context about the Indicator.
    pub description: Option<String>,
    /// An optional list of open-vocab types that specify categorizations for this indicator.
    pub indicator_types: Option<Vec<String>>,
    /// A required string that represents the detection pattern for this Indicator.
    pub pattern: String,
    /// A required open-vocab type that indicates the type of pattern used in this indicator.
    pub pattern_type: String,
    /// The optional version of the pattern language that is used for the data in the pattern property.
    pub pattern_version: Option<String>,
    /// A required timestamp indicating when this Indicator is considered valid.
    pub valid_from: Timestamp,
    /// An optional timestamp indicating when this Indicator is no longer considered valid.
    pub valid_until: Option<Timestamp>,
    /// An optional list of kill chain phases corresponding to this Indicator.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

impl Stix for Indicator {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }

        // name is required for Indicator
        if self.name.is_none() || self.name.as_ref().unwrap().trim().is_empty() {
            errors.push(Error::ValidationError(
                "Indicator is missing required property 'name'".to_string(),
            ));
        }

        // If the pattern is a STIX Pattern, validate it using the Rust implemtation of STIX Patterning
        if stix_case(&self.pattern_type) == "stix" {
            add_error(&mut errors, validate_pattern(&self.pattern));
        } else if !is_vocab_value::<IndicatorPatternType, _>(&self.pattern_type) {
            errors.push(Error::ValidationError(format!(
                "pattern type should come from the STIX pattern type open vocabulary; '{}' is not valid",
                self.pattern_type
            )));
        }
        if let Some(indicator_types) = &self.indicator_types {
            add_error(&mut errors, indicator_types.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<IndicatorType, _>(indicator_types, "indicator-type-ov"),
            );
        }

        if let Some(valid_until) = &self.valid_until {
            add_error(
                &mut errors,
                check_timestamp_ordering(
                    &self.valid_from,
                    valid_until,
                    "valid_from",
                    "valid_until",
                    "Indicator",
                ),
            );
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        types::{DictionaryValue, ExternalReference, StixDictionary},
    };
    use serde_json::Value;

    fn build_indicator() -> DomainObject {
        let mut general_extension = StixDictionary::new();
        general_extension
            .insert(
                "extension_type",
                DictionaryValue::String("property-extension".to_string()),
            )
            .unwrap();
        general_extension
            .insert("rank", DictionaryValue::Int(5))
            .unwrap();
        general_extension
            .insert("toxicity", DictionaryValue::Int(8))
            .unwrap();

        DomainObjectBuilder::new("indicator")
            .unwrap()
            .name("Indicator".to_string())
            .unwrap()
            .description(
                "This indicator detects connections to a known malicious IP address".to_string(),
            )
            .unwrap()
            .indicator_types(vec!["malicious-activity".to_string()])
            .unwrap()
            .pattern("[domain-name:value = 'example.com']".to_string())
            .unwrap()
            .pattern_type("stix".to_string())
            .unwrap()
            .valid_from("2016-05-12T08:17:27.000Z")
            .unwrap()
            .valid_until("2023-10-05T10:00:00.000Z")
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_indicator() {
        let indicator = build_indicator();
        let result = serde_json::to_value(&indicator).unwrap();

        let expected = r#"{
    "type": "indicator",
    "name": "Indicator",
    "description": "This indicator detects connections to a known malicious IP address",
    "indicator_types": [
            "malicious-activity"
        ],
    "pattern": "[domain-name:value = 'example.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2016-05-12T08:17:27Z",
    "valid_until":"2023-10-05T10:00:00Z",
    "spec_version": "2.1",
    "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
    "created": "2016-05-12T08:17:27Z",
    "modified": "2016-05-12T08:17:27Z",
    "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ],
    "extensions": {
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e" : {
            "extension_type": "property-extension",
            "rank": 5,
            "toxicity": 8
        }
    }
    }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_indicator() {
        let json = r#"{
    "type": "indicator",
    "name": "Indicator",
    "description": "This indicator detects connections to a known malicious IP address",
    "indicator_types": [
            "malicious-activity"
        ],
    "pattern": "[domain-name:value = 'example.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2016-05-12T08:17:27Z",
    "valid_until":"2023-10-05T10:00:00Z",
    "spec_version": "2.1",
    "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
    "created": "2016-05-12T08:17:27Z",
    "modified": "2016-05-12T08:17:27Z",
    "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ],
    "extensions": {
        "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e" : {
            "extension_type": "property-extension",
            "rank": 5,
            "toxicity": 8
        }
    }
    }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, build_indicator());
    }

    #[test]
    fn deserialize_indicator_invalid() {
        let json = r#"{
    "type": "indicator",
    "name": "Indicator",
    "description": "This indicator detects connections to a known malicious IP address",
    "indicator_types": [
            "malicious-activity"
        ],
    "pattern": "[type=domain-name,value='example.com']",
    "pattern_type": "stix",
    "pattern_version": "2.1",
    "valid_from": "2016-05-12T08:17:27Z",
    "valid_until":"2023-10-05T10:00:00Z",
    "spec_version": "2.1",
    "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
    "created": "2016-05-12T08:17:27Z",
    "modified": "2016-05-12T08:17:27Z",
    "junk":"junk",
    "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ]
    }"#;

        let result = DomainObject::from_json(json, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_property_rejected_when_allow_custom_false() {
        let json_str_invalid = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[domain-name:value = 'example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "junk":"junk",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let err = DomainObject::from_json(json_str_invalid, false).unwrap_err();
        assert!(
            matches!(err, crate::error::StixError::UnknownProperties { .. }),
            "expected UnknownProperties, got {err:?}"
        );
    }

    #[test]
    fn test_unknown_property_allowed_when_allow_custom_true() {
        let json_str_invalid = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[domain-name:value = 'example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "junk":"junk",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        assert!(DomainObject::from_json(json_str_invalid, true).is_ok());
    }

    #[test]
    fn test_valid_indicator_deserializes_with_allow_custom_false() {
        let json_str_valid = r#"{
        "type": "indicator",
        "name": "Indicator",
        "description": "This indicator detects connections to a known malicious IP address",
        "indicator_types": [
                "malicious-activity"
            ],
        "pattern": "[domain-name:value = 'example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2016-05-12T08:17:27Z",
        "valid_until":"2023-10-05T10:00:00Z",
        "spec_version": "2.1",
        "id": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        assert!(DomainObject::from_json(json_str_valid, false).is_ok());
    }
}
