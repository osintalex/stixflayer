//! Opinion SDO
//!
//! An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity.
//!
//! For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ht1vtzfbtzda>

use crate::{
    base::Stix,
    common::validation::validate_vocab_value,
    domain_objects::vocab::OpinionType,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Identifier,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Opinion {
    /// An optional abstract providing a summary of the note.
    pub explanation: Option<String>,
    /// The name of the author(s) of this Opinion.
    pub authors: Option<Vec<String>>,
    /// A required string that provides the content of the note.
    pub opinion: OpinionType,
    /// A list of references to other STIX objects.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Opinion {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        add_error(
            &mut errors,
            validate_vocab_value::<OpinionType, _>(self.opinion.as_ref(), "opinion-enum"),
        );
        if let Some(authors) = &self.authors {
            add_error(&mut errors, authors.stix_check());
        }

        add_error(&mut errors, self.object_refs.stix_check());
        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        domain_objects::{
            sdo::{DomainObject, DomainObjectBuilder},
            vocab::OpinionType,
        },
        types::{ExternalReference, Identifier},
    };
    use serde_json::Value;
    use std::str::FromStr;

    fn expected_opinion() -> DomainObject {
        DomainObjectBuilder::new("opinion")
            .unwrap()
            .explanation("The analyst team believes this campaign is related to previous malicious activity based on identified patterns.".to_string())
            .unwrap()
            .authors(vec!["Jane Smith".to_string()])
            .unwrap()
            .opinion(OpinionType::StronglyAgree)
            .unwrap()
            .object_refs(vec![Identifier::from_str("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "incident-reporter",
                None,
                None,
                Some("incident-id-5678".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_opinion() {
        let opinion = expected_opinion();
        let result = serde_json::to_value(&opinion).unwrap();

        let expected = r#"{
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "object_refs": [
            "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        ],
        "opinion": "strongly-agree",
        "explanation": "The analyst team believes this campaign is related to previous malicious activity based on identified patterns.",
        "authors": ["Jane Smith"],
        "external_references": [
            {
                "source_name": "incident-reporter",
                "external_id": "incident-id-5678"
            }
        ]
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn opinion_enum_fail() {
        let expected = r#"{
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "object_refs": [
            "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        ],
        "opinion": "strongly-agreeXX",
        "explanation": "The analyst team believes this campaign is related to previous malicious activity based on identified patterns.",
        "authors": ["Jane Smith"],
        "external_references": [
            {
                "source_name": "incident-reporter",
                "external_id": "incident-id-5678"
            }
        ]
        }"#;

        let expected_value = DomainObject::from_json(expected, false);
        assert!(expected_value.is_err());
    }

    #[test]
    fn deserialize_opinion() {
        let json = r#"{
        "type": "opinion",
        "spec_version": "2.1",
        "id": "opinion--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "object_refs": [
            "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
        ],
        "opinion": "strongly-agree",
        "explanation": "The analyst team believes this campaign is related to previous malicious activity based on identified patterns.",
        "authors": ["Jane Smith"],
        "external_references": [
            {
                "source_name": "incident-reporter",
                "external_id": "incident-id-5678"
            }
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_opinion());
    }
}
