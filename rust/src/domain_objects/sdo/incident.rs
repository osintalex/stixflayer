//! Incident SDO (**stub**)
//!
//! The Incident object in STIX 2.1 is a stub.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_sczfhw64pjxt>

use crate::{base::Stix, error::StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Incident {
    /// The name of the Incident.
    pub name: String,
    /// An optional description providing more details about the Incident.
    pub description: Option<String>,
}

impl Stix for Incident {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        types::ExternalReference,
    };

    #[test]
    fn serialize_incident() {
        let result = DomainObjectBuilder::new("incident")
            .unwrap()
            .name("incident".to_string())
            .unwrap()
            .description("incident desc".to_string())
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
            .modified("2016-05-12T08:17:27.000Z");

        let expected = DomainObjectBuilder::new("incident")
            .unwrap()
            .name("incident".to_string())
            .unwrap()
            .description("incident desc".to_string())
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
            .modified("2016-05-12T08:17:27.000Z");

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_incident() {
        let json = r#"{
            "type": "incident",
            "name": "incident",
            "description": "incident desc",
            "spec_version": "2.1",
            "id": "incident--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
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
        assert_eq!(
            result.common_properties.id.to_string(),
            "incident--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        );
    }
}
