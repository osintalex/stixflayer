//! Campaign SDO
//!
//! A Campaign is a grouping of adversarial behaviors that describes a set of malicious activities or attacks (sometimes called waves) that occur over a period of time against a specific
//! set of targets. Campaigns usually have well defined objectives and may be part of an Intrusion Set.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_pcpvfz4ik6d6>

use crate::{
    base::{check_timestamp_ordering, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Campaign {
    /// A name used to identify the Campaign.
    pub name: String,
    /// A description that provides more details and context about the Campaign, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// Alternative names, if any, used to identify this Campaign.
    pub aliases: Option<Vec<String>>,
    /// The time that this Campaign was first seen.
    pub first_seen: Option<Timestamp>,
    /// The time that this Campaign was last seen.
    pub last_seen: Option<Timestamp>,
    /// The Campaign’s primary goal, objective, desired outcome, or intended effect.
    pub objective: Option<String>,
}

impl Stix for Campaign {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            add_error(
                &mut errors,
                check_timestamp_ordering(start, stop, "first_seen", "last_seen", "Campaign"),
            );
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {

    use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};

    fn expected_campaign() -> DomainObject {
        DomainObjectBuilder::new("campaign")
            .unwrap()
            .name("Test_Campaign".to_string())
            .unwrap()
            .objective("Test_objective_property".to_string())
            .unwrap()
            .first_seen("2024-11-14T21:05:36.309596Z".to_string())
            .unwrap()
            .last_seen("2024-11-14T21:05:36.309596Z".to_string())
            .unwrap()
            .aliases(vec!["Test_Campaign2".to_string()])
            .unwrap()
            .description("description_test".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2024-11-14T21:05:36.309596Z")
            .modified("2024-11-14T21:05:36.309596Z")
    }

    #[test]
    fn serialize_campaign() {
        let campaign = expected_campaign();
        let mut result = serde_json::to_string_pretty(&campaign).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type": "campaign",
        "name": "Test_Campaign",
        "description": "description_test",
        "aliases":["Test_Campaign2"],
        "first_seen":"2024-11-14T21:05:36.309596Z",
        "last_seen":"2024-11-14T21:05:36.309596Z",
        "objective": "Test_objective_property",
        "spec_version": "2.1",
        "id": "campaign--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2024-11-14T21:05:36.309596Z",
        "modified": "2024-11-14T21:05:36.309596Z"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn deserialize_campaign() {
        let json = r#"{
        "type": "campaign",
        "name": "Test_Campaign",
        "description": "description_test",
        "aliases":["Test_Campaign2"],
        "first_seen":"2024-11-14T21:05:36.309596Z",
        "last_seen":"2024-11-14T21:05:36.309596Z",
        "objective": "Test_objective_property",
        "spec_version": "2.1",
        "id": "campaign--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2024-11-14T21:05:36.309596Z",
        "modified": "2024-11-14T21:05:36.309596Z"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_campaign());
    }

    #[test]
    fn deserialize_campaign_invalid() {
        let json = r#"{
        "type": "campaign",
        "name": "Test_Campaign",
        "first_seen":"2024-11-14T21:05:36.309596Z",
        "last_seen":"2023-11-14T21:05:36.309596Z",
        "spec_version": "2.1",
        "id": "campaign--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2024-11-14T21:05:36.309596Z",
        "modified": "2024-11-14T21:05:36.309596Z"
        }"#;

        let result = DomainObject::from_json(json, false);
        assert!(result.is_err());
    }
}
