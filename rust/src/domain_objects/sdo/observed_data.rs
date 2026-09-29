//! Observed Data SDO
//!
//! Observed Data conveys information about cyber security related entities such as files, systems, and networks using the STIX Cyber-observable Objects (SCOs).
//!
//! For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc>

use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{Identifier, ScoTypes, SdoTypes, SroTypes, StixMetaTypes, Timestamp},
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use strum::IntoEnumIterator;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct ObservedData {
    /// The beginning of the time window during which the data was seen.
    pub first_observed: Timestamp,
    /// The end of the time window during which the data was seen.
    pub last_observed: Timestamp,
    /// The number of times that each Cyber-observable object represented in the objects or object_ref property was seen.
    #[serde(default, deserialize_with = "as_u64")]
    pub number_observed: u64,
    /// A list of SCOs and SROs representing the observation.
    pub object_refs: Vec<Identifier>,
}

impl Stix for ObservedData {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        add_error(&mut errors, self.number_observed.stix_check());
        if self.last_observed < self.first_observed {
            errors.push(Error::ValidationError(format!(
                "The last_observed timestamp {} cannot be earlier than the first_observed timestamp {}.",
                self.last_observed,
                self.first_observed
            )));
        }

        if self.number_observed < 1 || self.number_observed > 999_999_999 {
            errors.push(Error::ValidationError(format!(
                "The number_observed {} must be an integer between 1 and 999,999,999 inclusive.",
                self.number_observed
            )));
        }

        let mut has_sco = false;
        let mut has_custom = false;
        for object_ref in self.object_refs.iter() {
            add_error(&mut errors, self.object_refs.stix_check());
            if SdoTypes::iter().any(|s| s.as_ref() == object_ref.get_type())
                || StixMetaTypes::iter().any(|s| s.as_ref() == object_ref.get_type())
            {
                errors.push(Error::ValidationError(format!(
                    "The `object_refs` list must contain only SCO and SRO types. {} is neither.",
                    object_ref.get_type()
                )));
            } else if ScoTypes::iter().any(|s| s.as_ref() == object_ref.get_type()) {
                has_sco = true;
            } else if !SroTypes::iter().any(|s| s.as_ref() == object_ref.get_type()) {
                warn!(
                    "The `object_refs` list must contain only SCO and SRO types. Confirm that {} is one of those types.",
                    object_ref.get_type()
                );
                has_custom = true;
            }
        }

        if !has_sco {
            if has_custom {
                warn!(
                    "The `object_refs` list must contain at least one SCO type. Confirm that at least one of the included custom types is an SCO."
                );
            } else {
                errors.push(Error::ValidationError(
                    "The `object_refs` list must contain at least one SCO type.".to_string(),
                ));
            }
        }
        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};
    use serde_json::Value;
    use std::str::FromStr;

    fn expected_observed_data() -> DomainObject {
        DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("ipv4-addr--efcd5e80-570d-5131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("domain-name--ecb120bf-2694-5902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-04-06T20:03:48.000Z")
            .modified("2016-04-06T20:03:48.000Z")
    }

    #[test]
    fn serialize_observed_data() {
        let observed_data = expected_observed_data();
        let result = serde_json::to_value(&observed_data).unwrap();

        let expected = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50,
        "object_refs": [
            "ipv4-addr--efcd5e80-570d-5131-b213-62cb18eaa6a8",
            "domain-name--ecb120bf-2694-5902-a737-62b74539a41b"
        ]
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn observed_data_test_number_observed_as_json_string() {
        let observed_data = expected_observed_data();

        let json = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": "50",
        "object_refs": [
            "ipv4-addr--efcd5e80-570d-5131-b213-62cb18eaa6a8",
            "domain-name--ecb120bf-2694-5902-a737-62b74539a41b"
        ]
        }"#;

        let expected_value = DomainObject::from_json(json, false).unwrap();
        assert_eq!(&observed_data, &expected_value);
    }

    #[test]
    fn deserialize_observed_data() {
        let json = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50,
        "object_refs": [
            "ipv4-addr--efcd5e80-570d-5131-b213-62cb18eaa6a8",
            "domain-name--ecb120bf-2694-5902-a737-62b74539a41b"
        ]
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_observed_data());
    }

    #[test]
    fn observed_data_sdo_fail() {
        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("ipv4-addr--efcd5e80-570d-5131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("note--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build();

        assert!(expected.is_err());
    }

    #[test]
    fn observed_data_no_sco_fail() {
        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("relationship--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("relationship--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build();

        assert!(expected.is_err());
    }

    #[test]
    fn observed_data_custom_pass() {
        let expected = DomainObjectBuilder::new("observed-data")
            .unwrap()
            .first_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .last_observed("2015-12-21T19:00:00Z".to_string())
            .unwrap()
            .number_observed(50)
            .unwrap()
            .object_refs(vec![
                Identifier::from_str("relationship--efcd5e80-570d-4131-b213-62cb18eaa6a8").unwrap(),
                Identifier::from_str("foo--ecb120bf-2694-4902-a737-62b74539a41b").unwrap(),
            ])
            .unwrap()
            .build();

        assert!(expected.is_ok());
    }

    #[test]
    fn observed_data_none_fail() {
        let json = r#"{
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2016-04-06T20:03:48Z",
        "modified": "2016-04-06T20:03:48Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50
        }"#;

        let result = DomainObject::from_json(json, false);
        assert!(result.is_err());
    }
}
