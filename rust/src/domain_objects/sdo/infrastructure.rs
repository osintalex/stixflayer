//! Infrastructure SDO
//!
//! The Infrastructure SDO represents a type of TTP and describes any systems, software services and any associated physical or virtual resources intended to support some purpose.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_jo3k1o6lr9>

use crate::{
    base::{check_timestamp_ordering, Stix},
    common::validation::validate_vocab_list,
    domain_objects::vocab::InfrastructureType,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{KillChainPhase, Timestamp},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Infrastructure {
    /// A name used to identify the Infrastructure.
    pub name: String,
    /// A description that provides more details and context about the Infrastructure.
    pub description: Option<String>,
    /// The type of infrastructure being described.
    pub infrastructure_types: Option<Vec<String>>,
    /// Alternative names used to identify this Infrastructure.
    pub aliases: Option<Vec<String>>,
    /// The list of Kill Chain Phases for which this Infrastructure is used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    /// The time that this Infrastructure was first seen performing malicious activities.
    pub first_seen: Option<Timestamp>,
    /// The time that this Infrastructure was last seen performing malicious activities.
    pub last_seen: Option<Timestamp>,
}

impl Stix for Infrastructure {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            add_error(
                &mut errors,
                check_timestamp_ordering(start, stop, "first_seen", "last_seen", "Infrastructure"),
            );
        }
        if let Some(its) = &self.infrastructure_types {
            add_error(&mut errors, its.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<InfrastructureType, _>(its, "infrastructure-type-ov"),
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
    use serde_json::Value;

    fn expected_infrastructure() -> DomainObject {
        DomainObjectBuilder::new("infrastructure")
            .unwrap()
            .name("Infrastructure test".to_string())
            .unwrap()
            .description("Infrastructure description".to_string())
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .infrastructure_types(vec!["amplification".to_string(), "botnet".to_string()])
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_infrastructure() {
        let infrastructure = expected_infrastructure();
        let result = serde_json::to_value(&infrastructure).unwrap();

        let expected = r#"{
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": "infrastructure--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Infrastructure test",
        "description": "Infrastructure description",
        "first_seen": "2023-10-01T00:00:00Z",
        "infrastructure_types": [
            "amplification","botnet"
        ]
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_infrastructure() {
        let json = r#"{
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": "infrastructure--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Infrastructure test",
        "description": "Infrastructure description",
        "first_seen": "2023-10-01T00:00:00Z",
        "infrastructure_types": [
            "amplification","botnet"
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_infrastructure());
    }
}
