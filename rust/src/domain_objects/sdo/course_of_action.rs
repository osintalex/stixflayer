//! Course of Action SDO
//!
//! A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_a925mpw39txn>

use crate::{base::Stix, error::StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct CourseOfAction {
    /// A name used to identify the Course of Action.
    pub name: String,
    /// A description that provides more details and context about the Course of Action.
    pub description: Option<String>,
}

impl Stix for CourseOfAction {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};
    use serde_json::Value;

    fn expected_course_of_action() -> DomainObject {
        DomainObjectBuilder::new("course-of-action")
            .unwrap()
            .name("Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter".to_string())
            .unwrap()
            .description("This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ...".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z")
    }

    #[test]
    fn serialize_course_of_action() {
        let course_of_action = expected_course_of_action();
        let result = serde_json::to_value(course_of_action).unwrap();

        let expected = r#"{
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_course_of_action() {
        let json = r#"{
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": "course-of-action--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_course_of_action());
    }
}
