//! Identity SDO
//!
//! Identities can represent actual individuals, organizations, or groups as well as classes of individuals, organizations, systems or groups.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wh296fiwpklp>

use crate::{
    base::Stix,
    common::validation::{validate_vocab_list, validate_vocab_value},
    domain_objects::vocab::{IdentityClass, IdentitySectors},
    error::{add_error, return_multiple_errors, StixError as Error},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Identity {
    /// The name of the Identity.
    pub name: String,
    /// An optional description providing more details about the Identity.
    pub description: Option<String>,
    /// An optional list of roles that this Identity performs.
    pub roles: Option<Vec<String>>,
    /// The optional type of entity, e.g., individual or organization.
    pub identity_class: Option<String>,
    /// An optional list of industry sectors this Identity belongs to.
    pub sectors: Option<Vec<String>>,
    /// The optional contact information for this Identity.
    pub contact_information: Option<String>,
}

impl Stix for Identity {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(identity_class) = &self.identity_class {
            add_error(
                &mut errors,
                validate_vocab_value::<IdentityClass, _>(identity_class, "identity-class-ov"),
            );
        }
        if let Some(sectors) = &self.sectors {
            add_error(&mut errors, sectors.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<IdentitySectors, _>(sectors, "industry-sector-ov"),
            );
        }
        if let Some(roles) = &self.roles {
            add_error(&mut errors, roles.stix_check());
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

    fn expected_identity() -> DomainObject {
        DomainObjectBuilder::new("identity")
            .unwrap()
            .name("Identity".to_string())
            .unwrap()
            .identity_class("individual".to_string())
            .unwrap()
            .description("Responsible for managing personal digital identity".to_string())
            .unwrap()
            .roles(vec!["User".to_string(), "Administrator".to_string()])
            .unwrap()
            .sectors(vec!["Technology".to_string(), "Aerospace".to_string()])
            .unwrap()
            .contact_information("alex.johnson@example.com".to_string())
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
    fn serialize_identity() {
        let identity = expected_identity();
        let result = serde_json::to_value(&identity).unwrap();

        let expected = r#"{
        "type": "identity",
        "name": "Identity",
        "identity_class": "individual",
        "description": "Responsible for managing personal digital identity",
        "roles": ["User", "Administrator"],
        "sectors": ["Technology","Aerospace"],
        "spec_version": "2.1",
        "contact_information": "alex.johnson@example.com",
        "id": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
        {
        "source_name": "capec",
        "external_id": "CAPEC-163"
        }
    ]
    }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value)
    }

    #[test]
    fn deserialize_identity() {
        let json = r#"{
        "type": "identity",
        "name": "Identity",
        "identity_class": "individual",
        "description": "Responsible for managing personal digital identity",
        "roles": ["User", "Administrator"],
        "sectors": ["Technology","Aerospace"],
        "spec_version": "2.1",
        "contact_information": "alex.johnson@example.com",
        "id": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
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
        assert_eq!(result, expected_identity());
    }
}
