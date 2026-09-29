//! Attack Pattern SDO
//!
//! Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
//! These are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed
//!
//! An Attack Pattern SDO contains textual descriptions of the pattern along with references to externally-defined taxonomies of attacks (e.g. CAPEC)
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_axjijf603msy>

use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::KillChainPhase,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct AttackPattern {
    /// A name used to identify the Attack Pattern.
    pub name: String,
    /// Provides more details and context about the Attack Pattern, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
    /// Alternative names, if any, used to identify this Attack Pattern.
    pub aliases: Option<Vec<String>>,
    /// The list of Kill Chain Phases, if any, for which this Attack Pattern is used.
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
}

impl Stix for AttackPattern {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(kill_chain_phases) = &self.kill_chain_phases {
            add_error(&mut errors, kill_chain_phases.stix_check());
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
        types::{ExternalReference, Hashes, ReferenceUrl},
    };
    

    fn expected_attack_pattern() -> DomainObject {
        DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("Spear Phishing".to_string())
            .unwrap()
            .description("...".to_string())
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
    fn serialize_attack_pattern() {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("Spear Phishing".to_string())
            .unwrap()
            .description("...".to_string())
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "capec",
                None,
                Some(ReferenceUrl::new(
                    "https://foo-bar.com/foo",
                    Some(
                        Hashes::new(
                            "SHA-256",
                            "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                        )
                        .unwrap(),
                    ),
                ).unwrap()),
                Some("CAPEC-163".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let mut result = serde_json::to_string_pretty(&attack_pattern).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type": "attack-pattern",
        "name": "Spear Phishing",
        "description": "...",
        "spec_version": "2.1",
        "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
        {
        "source_name": "capec",
        "url": "https://foo-bar.com/foo",
        "hashes": {
            "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
        },
        "external_id": "CAPEC-163"
        }
        ]
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn deserialize_attack_pattern() {
        let json = r#"{
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27.000Z",
        "modified": "2016-05-12T08:17:27.000Z",
        "name": "Spear Phishing",
        "description": "...",
        "external_references": [
            {
            "source_name": "capec",
            "external_id": "CAPEC-163"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_attack_pattern());
    }
}
