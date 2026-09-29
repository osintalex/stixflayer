//! Report SDO
//!
//! Reports are collections of threat intelligence focused on one or more topics.
//!
//! For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_n8bjzg1ysgdq>

use crate::{
    base::Stix,
    common::validation::validate_vocab_list,
    domain_objects::vocab::ReportType,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{stix_case, Identifier, ScoTypes, SroTypes, StixMetaTypes, Timestamp},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use strum::IntoEnumIterator;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Report {
    /// A name used to identify the Report.
    pub name: String,
    /// A description that provides more details and context about the Report.
    pub description: Option<String>,
    /// This property is an open vocabulary that specifies the primary subject(s) of this report.
    pub report_types: Option<Vec<String>>,
    /// The date that this Report object was officially published by the creator of this report.
    pub published: Timestamp,
    /// Specifies the STIX Objects that are referred to by this Report.
    pub object_refs: Vec<Identifier>,
}

impl Stix for Report {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(report_types) = &self.report_types {
            add_error(&mut errors, report_types.stix_check());
            add_error(
                &mut errors,
                validate_vocab_list::<ReportType, _>(report_types, "report-type-ov"),
            );
            for report_type in report_types {
                if !ScoTypes::iter().all(|x| x.as_ref() != stix_case(&report_type))
                    || !SroTypes::iter().all(|x| x.as_ref() != stix_case(&report_type))
                    || !StixMetaTypes::iter().all(|x| x.as_ref() != stix_case(&report_type))
                {
                    errors.push(Error::ValidationError(format!(
                        "A report type must be an SDO. Report is type {}.",
                        report_type,
                    )));
                }
            }
            add_error(&mut errors, self.object_refs.stix_check());
        }
        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        types::Identifier,
    };
    use serde_json::Value;
    use std::str::FromStr;

    fn expected_report() -> DomainObject {
        DomainObjectBuilder::new("report")
            .unwrap()
            .name("The Black Vine Cyberespionage Group".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .report_types(vec!["campaign".to_string(), "attack-pattern".to_string()])
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2").unwrap(),
                Identifier::from_str("campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c").unwrap(),
                Identifier::from_str("relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    // test that if report_type is either in known STIX language as an SDO or unknown from STIX language, object passes
    #[test]
    fn try_ok_report_types() {
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["attack-pattern".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_ok());
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["threat-report".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_ok());
    }

    // test that if report_type is in language, but not a report, gives an error
    #[test]
    fn try_error_report_types() {
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["artifact".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_err());
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["sighting".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_err());
        let report = DomainObjectBuilder::new("report")
            .unwrap()
            .name("Test_Report".to_string())
            .unwrap()
            .description("A simple report with an indicator and campaign".to_string())
            .unwrap()
            .published(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .created_by_ref(Identifier::new_test("identity"))
            .unwrap()
            .report_types(vec!["language-content".to_string()])
            .unwrap()
            .object_refs(vec![Identifier::from_str(
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
            )
            .unwrap()])
            .unwrap()
            .build();
        assert!(report.is_err());
    }

    #[test]
    fn serialize_report() {
        let report = expected_report();
        let result = serde_json::to_value(&report).unwrap();

        let expected = r#"{
            "type": "report",
            "name": "The Black Vine Cyberespionage Group",
            "description": "A simple report with an indicator and campaign",
            "created_by_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "published": "2016-05-12T08:17:27Z",
            "report_types": ["campaign","attack-pattern"],
            "object_refs": [
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
                "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
                "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
             ],
            "spec_version": "2.1",
            "id": "report--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
           }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(result, expected_value);
    }

    #[test]
    fn deserialize_report() {
        let json = r#"{
            "type": "report",
            "name": "The Black Vine Cyberespionage Group",
            "description": "A simple report with an indicator and campaign",
            "created_by_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "published": "2016-05-12T08:17:27Z",
            "report_types": ["campaign","attack-pattern"],
            "object_refs": [
                "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
                "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
                "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
             ],
            "spec_version": "2.1",
            "id": "report--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
           }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_report());
    }
}
