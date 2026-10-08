//! Threat Actor SDO
//!
//! Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
//!
//! For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k017w16zutw>

use crate::{
    base::{check_timestamp_ordering, Stix},
    common::validation::{validate_vocab_list, validate_vocab_value},
    domain_objects::vocab::{
        AttackMotivation, AttackResourceLevel, ThreatActorRole, ThreatActorSophistication,
        ThreatActorType,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct ThreatActor {
    /// A name used to identify this Threat Actor or Threat Actor group.
    pub name: String,
    /// A description that provides more details and context about the Threat Actor.
    pub description: Option<String>,
    /// Specifies the type(s) of this threat actor.
    pub threat_actor_types: Option<Vec<String>>,
    /// A list of other names that this Threat Actor is believed to use.
    pub aliases: Option<Vec<String>>,
    /// The time that this Threat Actor was first seen.
    pub first_seen: Option<Timestamp>,
    /// The time that this Threat Actor was last seen.
    pub last_seen: Option<Timestamp>,
    /// A list of roles the Threat Actor plays.
    pub roles: Option<Vec<String>>,
    /// The high-level goals of this Threat Actor.
    pub goals: Option<Vec<String>>,
    /// The skill or expertise a Threat Actor must have to perform the attack.
    pub sophistication: Option<String>,
    /// Defines the organizational level at which this Threat Actor typically works.
    pub resource_level: Option<String>,
    /// The primary reason, motivation, or purpose behind this Threat Actor.
    pub primary_motivation: Option<String>,
    /// The secondary reasons, motivations, or purposes behind this Threat Actor.
    pub secondary_motivations: Option<Vec<String>>,
    /// The personal reasons, motivations, or purposes of the Threat Actor.
    pub personal_motivations: Option<Vec<String>>,
}

impl Stix for ThreatActor {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(actor_types) = &self.threat_actor_types {
            add_error(&mut errors, actor_types.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<ThreatActorType, _>(actor_types, "threat-actor-type-ov"),
            );
        }
        if let Some(aliases) = &self.aliases {
            add_error(&mut errors, aliases.stix_check());
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            add_error(
                &mut errors,
                check_timestamp_ordering(start, stop, "first_seen", "last_seen", "ThreatActor"),
            );
        }
        if let Some(roles) = &self.roles {
            add_error(&mut errors, roles.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<ThreatActorRole, _>(roles, "threat-actor-role-ov"),
            );
        }
        if let Some(goals) = &self.goals {
            add_error(&mut errors, goals.stix_check());
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

        if let Some(sophistication) = self.sophistication.as_deref() {
            add_error(
                &mut errors,
                validate_vocab_value::<ThreatActorSophistication, _>(
                    sophistication,
                    "threat-actor-sophistication-ov",
                ),
            );
        }
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
        if let Some(personal_motivations) = &self.personal_motivations {
            add_error(&mut errors, personal_motivations.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<AttackMotivation, _>(
                    personal_motivations,
                    "attack-motivation-ov",
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
        types::ExternalReference,
    };

    fn expected_threat_actor() -> DomainObject {
        DomainObjectBuilder::new("threat-actor")
            .unwrap()
            .name("Threat Actor Group".to_string())
            .unwrap()
            .description("A group known for cyber espionage".to_string())
            .unwrap()
            .threat_actor_types(vec!["activist".to_string(), "crime-syndicate".to_string()])
            .unwrap()
            .aliases(vec!["TA123, Cyber Espionage Group".to_string()])
            .unwrap()
            .first_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .last_seen("2023-10-01T00:00:00.000Z".to_string())
            .unwrap()
            .roles(vec!["agent".to_string(), "malware author".to_string()])
            .unwrap()
            .goals(vec!["disrupt communications".to_string()])
            .unwrap()
            .sophistication("advanced".to_string())
            .unwrap()
            .resource_level("government".to_string())
            .unwrap()
            .primary_motivation("ideology".to_string())
            .unwrap()
            .secondary_motivations(vec!["organizational-gain".to_string()])
            .unwrap()
            .personal_motivations(vec!["personal-gain".to_string()])
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
    fn serialize_threat_actor() {
        let threat_actor = expected_threat_actor();
        let mut result = serde_json::to_string_pretty(&threat_actor).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected_value = r#"{
            "type": "threat-actor",
            "name" : "Threat Actor Group",
            "description": "A group known for cyber espionage",
            "threat_actor_types": ["activist","crime-syndicate"],
            "aliases": ["TA123, Cyber Espionage Group"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "roles": ["agent", "malware author"],
            "goals" : ["disrupt communications"],
            "sophistication": "advanced",
            "resource_level" : "government",
            "primary_motivation": "ideology",
            "secondary_motivations": ["organizational-gain"],
            "personal_motivations": ["personal-gain"],
            "spec_version": "2.1",
            "id": "threat-actor--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
   }"#
        .to_string();
        expected_value.retain(|c| !c.is_whitespace());

        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_threat_actor() {
        let json = r#"{
            "type": "threat-actor",
            "name" : "Threat Actor Group",
            "description": "A group known for cyber espionage",
            "threat_actor_types": ["activist","crime-syndicate"],
            "aliases": ["TA123, Cyber Espionage Group"],
            "first_seen": "2023-10-01T00:00:00Z",
            "last_seen": "2023-10-01T00:00:00Z",
            "roles": ["agent", "malware author"],
            "goals" : ["disrupt communications"],
            "sophistication": "advanced",
            "resource_level" : "government",
            "primary_motivation": "ideology",
           "secondary_motivations": ["organizational-gain"],
            "personal_motivations": ["personal-gain"],
            "spec_version": "2.1",
            "id": "threat-actor--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                "source_name": "capec",
                 "external_id": "CAPEC-163"
                }
            ]
        }"#
        .to_string();

        let result = DomainObject::from_json(&json, false).unwrap();
        assert_eq!(result, expected_threat_actor());
    }
}
