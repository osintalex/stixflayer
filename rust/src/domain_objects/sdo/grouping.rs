//! Grouping SDO
//!
//! A Grouping object explicitly asserts that the referenced STIX Objects have a shared context, unlike a STIX Bundle (which explicitly conveys no context).
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_t56pn7elv6u7>

use crate::{
    base::Stix,
    common::validation::validate_vocab_value,
    domain_objects::vocab::ContextType,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::Identifier,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Grouping {
    /// A name used to identify the Grouping.
    pub name: Option<String>,
    /// A description that provides more details and context about the Grouping.
    pub description: Option<String>,
    /// A short descriptor of the particular context shared by the content referenced by the Grouping.
    pub context: String,
    /// Specifies the STIX Objects that are referred to by this Grouping.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Grouping {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        add_error(
            &mut errors,
            validate_vocab_value::<ContextType, _>(&self.context, "grouping-context-ov"),
        );

        add_error(&mut errors, self.object_refs.stix_check());
        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};
    use serde_json::Value;
    use std::str::FromStr;

    fn expected_grouping() -> DomainObject {
        DomainObjectBuilder::new("grouping")
            .unwrap()
            .name("Suspicious Activity Group".to_string())
            .unwrap()
            .description(
                "Grouping of related suspicious indicators identified in recent activity."
                    .to_string(),
            )
            .unwrap()
            .context("suspicious-activity".to_string())
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            )
            .unwrap()])
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_grouping() {
        let grouping = expected_grouping();
        let result = serde_json::to_value(&grouping).unwrap();

        let expected = r#"{
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Suspicious Activity Group",
        "description": "Grouping of related suspicious indicators identified in recent activity.",
        "object_refs": [
            "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        ],
        "context": "suspicious-activity"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_grouping() {
        let json = r#"{
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Suspicious Activity Group",
        "description": "Grouping of related suspicious indicators identified in recent activity.",
        "object_refs": [
            "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        ],
        "context": "suspicious-activity"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_grouping());
    }
}
