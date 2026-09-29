//! Intrusion Set SDO
//!
//! An Intrusion Set is a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_5ol9xlbbnrdn>

use crate::{
    base::Stix,
    common::validation::{validate_vocab_list, validate_vocab_value},
    domain_objects::vocab::{AttackMotivation, AttackResourceLevel},
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct IntrusionSet {
    /// A name used to identify this Intrusion Set.
    pub name: String,
    /// A description that provides more details and context about the Intrusion Set.
    pub description: Option<String>,
    /// Alternative names used to identify this Intrusion Set.
    pub aliases: Option<Vec<String>>,
    /// The time that this Intrusion Set was first seen.
    pub first_seen: Option<Timestamp>,
    /// The time that this Intrusion Set was last seen.
    pub last_seen: Option<Timestamp>,
    /// The high-level goals of this Intrusion Set.
    pub goals: Option<Vec<String>>,
    /// This property specifies the organizational level at which this Intrusion Set typically works.
    pub resource_level: Option<String>,
    /// The primary reason, motivation, or purpose behind this Intrusion Set.
    pub primary_motivation: Option<String>,
    /// The secondary reasons, motivations, or purposes behind this Intrusion Set.
    pub secondary_motivations: Option<Vec<String>>,
}

impl Stix for IntrusionSet {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(primary_motivation) = self.primary_motivation.as_deref() {
            add_error(
                &mut errors,
                validate_vocab_value::<AttackMotivation, _>(
                    primary_motivation,
                    "attack-motivation-ov",
                ),
            );
        }

        if let Some(secondary_motivations) = &self.secondary_motivations {
            add_error(&mut errors, secondary_motivations.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<AttackMotivation, _>(
                    secondary_motivations,
                    "attack-motivation-ov",
                ),
            );
        }

        if let Some(resource_level) = self.resource_level.as_deref() {
            add_error(
                &mut errors,
                validate_vocab_value::<AttackResourceLevel, _>(
                    resource_level,
                    "attack-resource-level-ov",
                ),
            );
        }

        if let Some(goals) = &self.goals {
            add_error(&mut errors, goals.stix_check());
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    
    use crate::{
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        types::ExternalReference,
    };
    use serde_json::Value;

    fn expected_intrusion_set() -> DomainObject {
        DomainObjectBuilder::new("intrusion-set")
            .unwrap()
            .name("APT28".to_string())
            .unwrap()
            .description("Fancy Bear".to_string())
            .unwrap()
            .aliases(vec!["Sofacy, Sednit".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .goals(vec!["disrupt communications".to_string()])
            .unwrap()
            .resource_level("team".to_string())
            .unwrap()
            .primary_motivation("organizational-gain".to_string())
            .unwrap()
            .secondary_motivations(vec!["organizational-gain".to_string()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_intrusion_set() {
        let intrusion_set = expected_intrusion_set();
        let result = serde_json::to_value(&intrusion_set).unwrap();

        let expected = r#"{
            "type": "intrusion-set",
            "name" : "APT28",
            "description": "Fancy Bear",
            "aliases": ["Sofacy, Sednit"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "goals" : ["disrupt communications"],
            "resource_level" : "team",
            "primary_motivation": "organizational-gain",
            "secondary_motivations": ["organizational-gain"],
            "spec_version": "2.1",
            "id": "intrusion-set--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
   }"#;

        let expected_value: Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(result, expected_value);
    }

    #[test]
    fn deserialize_intrusion_set() {
        let json = r#"{
            "type": "intrusion-set",
            "name" : "APT28",
            "description": "Fancy Bear",
            "aliases": ["Sofacy, Sednit"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "goals" : ["disrupt communications"],
            "resource_level" : "team",
            "primary_motivation": "organizational-gain",
            "secondary_motivations": ["organizational-gain"],
            "spec_version": "2.1",
            "id": "intrusion-set--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_intrusion_set());
    }
}
