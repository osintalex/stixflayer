use crate::base::Stix;
use crate::error::{StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Mutex
///
/// The MAC Address object represents a single Media Access Control (MAC) address.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_84hwlkdmev1w>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Mutex {
    /// Specifies the name of the mutex object.
    pub name: String,
}
impl Stix for Mutex {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
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
    fn golden_mutex_id_matches_normative_uuidv5_algorithm() {
        // STIX 2.1 spec section 2.9 (normative): the UUIDv5 name is the RFC 8785
        // canonical JSON of the ID contributing properties - for a Mutex with
        // name "__CLEANSWEEP__" that is `{"name":"__CLEANSWEEP__"}`.
        //
        // NOTE: the example identifier shown in the spec's Mutex section
        // (mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300) does not match the
        // spec's own normative algorithm under the defined namespace - no
        // serialization of {name: value} reproduces it. The normative
        // algorithm wins; this golden value was computed independently of
        // this codebase (python uuid5 over the canonical JSON).
        let mutex = CyberObjectBuilder::new("mutex")
            .unwrap()
            .name("__CLEANSWEEP__".to_string())
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            mutex.common_properties.id.to_string(),
            "mutex--f93fe911-e545-5239-b9b0-597840d0c871"
        );
        assert_eq!(mutex.common_properties.id.get_uuid_version(), "UUIDv5");
    }

    #[test]
    fn serialize_mutex() {
        let mutex = CyberObjectBuilder::new("mutex")
            .unwrap()
            .name("mutex name foo bar object name here".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result_value = serde_json::to_value(&mutex).unwrap();

        let expected = r#"{
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "name": "mutex name foo bar object name here"
        }"#;
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_mutex() {
        let json = r#"{
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "name": "mutex name foo bar object name here"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let expected = CyberObjectBuilder::new("mutex")
            .unwrap()
            .name("mutex name foo bar object name here".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, expected);
    }
}
