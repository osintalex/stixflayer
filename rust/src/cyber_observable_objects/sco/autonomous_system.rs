use crate::base::Stix;
use crate::error::StixError as Error;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Autonomous System
///
/// This object represents the properties of an Autonomous System (AS).
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_27gux0aol9e3>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct AutonomousSystem {
    ///Specifies the number assigned to the AS.
    #[serde(default, deserialize_with = "as_u64")]
    pub number: u64,
    ///Specifies the name of the AS
    pub name: Option<String>,
    ///Specifies the name of the Regional Internet Registry (RIR) that assigned the number to the AS.
    pub rir: Option<String>,
}
impl Stix for AutonomousSystem {
    fn stix_check(&self) -> Result<(), Error> {
        self.number.stix_check()
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder};
    use crate::extensions::{
        ArchiveExtension, FileExtensions, HttpRequestExtension, IcmpExtension,
        NetworkTrafficExtensions, ProcessExtensions, SocketExtenion, SpecialExtensions,
        UnixAccountExtension, UserAccountExtensions, WindowsProcessExtension,
    };
    use crate::types::{DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp};
    use log::warn;
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};
    use test_log::test;

    #[test]
    fn deserialize_autonomous_system() {
        let json = r#"{
        "type":"autonomous-system",
        "number":50,
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, autonomous_system)
    }

    #[test]
    fn serialize_autonomous_system() {
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let mut result = serde_json::to_string_pretty(&autonomous_system).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type":"autonomous-system",
        "number":50,
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn deserialize_autonomous_system_number_quote_test() {
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let json = r#"{
        "type":"autonomous-system",
        "number":"50",
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        let expected = CyberObject::from_json(&json, false).unwrap();

        assert_eq!(autonomous_system, expected)
    }

    #[test]
    fn deserialize_autonomous_system_number_no_quote_test() {
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .name("Slime Industries".to_string())
            .unwrap()
            .rir("ARIN".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let json = r#"{
        "type":"autonomous-system",
        "number":50,
        "name":"Slime Industries",
        "rir":"ARIN",
        "spec_version":"2.1",
        "id":"autonomous-system--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        let expected = CyberObject::from_json(&json, false).unwrap();

        assert_eq!(autonomous_system, expected)
    }
}
