//! Note SDO
//!
//! A Note is intended to convey informative text to provide further context and/or to provide additional analysis not contained in the STIX Objects.
//!
//! For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gudodcg1sbb9>

use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Identifier,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Note {
    /// An optional abstract providing a summary of the note.
    #[serde(rename = "abstract")]
    pub set_abstract: Option<String>,
    /// A required string that provides the content of the note.
    pub content: String,
    /// An optional list of authors of the note.
    pub authors: Option<Vec<String>>,
    /// A list of references to other STIX objects.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Note {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

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
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        types::{ExternalReference, Identifier},
    };
    use serde_json::Value;
    use std::str::FromStr;

    fn expected_note() -> DomainObject {
        DomainObjectBuilder::new("note")
            .unwrap()
            .set_abstract("Tracking Team Note#1".to_string())
            .unwrap()
            .content("This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc".to_string())
            .unwrap()
            .authors(vec!["John Doe".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f").unwrap()])
            .unwrap()
            .external_references(vec![ExternalReference::new(
                "job-tracker",
                None,
                None,
                Some("job-id-1234".to_string()),
            )
            .unwrap()])
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_note() {
        let note = expected_note();
        let result = serde_json::to_value(&note).unwrap();

        let expected = r#"{
        "type": "note",
        "spec_version": "2.1",
        "id": "note--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
            {
            "source_name": "job-tracker",
            "external_id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_note() {
        let json = r#"{
        "type": "note",
        "spec_version": "2.1",
        "id": "note--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "external_references": [
            {
            "source_name": "job-tracker",
            "external_id": "job-id-1234"
            }
        ],
        "abstract": "Tracking Team Note#1",
        "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
        "authors": ["John Doe"],
        "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_note());
    }
}
