use crate::base::Stix;
use crate::error::{StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use regex::Regex;

/// MAC Address
///
/// The MAC Address object represents a single Media Access Control (MAC) address.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f92nr9plf58y>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct MacAddr {
    /// Specifies the value of a single MAC address.
    pub value: String,
}

impl Stix for MacAddr {
    fn stix_check(&self) -> Result<(), Error> {
        // Check if the MAC address is in the correct format
        // Panic: Safe to unwrap as this is a valid regex string
        let mac_regex = Regex::new(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$").unwrap();
        if !mac_regex.is_match(&self.value) {
            return Err(Error::ValidationError(
                "MAC address must be a valid colon-delimited, lowercase MAC-48 address with leading zeros".to_string(),
            ));
        }
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
    fn serialize_macaddress() {
        let mac_address = CyberObjectBuilder::new("mac-addr")
            .unwrap()
            .value("d2:fb:49:24:37:18".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&mac_address).unwrap();

        let expected = r#"{
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "d2:fb:49:24:37:18"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_macaddress() {
        let json = r#"{
            "type": "mac-addr",
            "spec_version": "2.1",
            "id": "mac-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "d2:fb:49:24:37:18"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let mac_address = CyberObjectBuilder::new("mac-addr")
            .unwrap()
            .value("d2:fb:49:24:37:18".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, mac_address)
    }

    #[test]
    fn try_mac_without_leading_zeros() {
        let test_addresses = vec![
            "00:1A:2B:3C:4D:5E", // uppercase letters
            "0:fb:49:24:37:18",  // no leading zeroes
            "00-1A-2B-3C-4D-5E", // incorrect delimiter
            "001A.2B3C.4D5E",    // This format and delimiter won't match
            "00:1A:2B:3C:4D:5G", // Invalid character
        ];

        let mut all_invalid = true;

        for address in test_addresses {
            let mac_address = CyberObjectBuilder::new("mac-addr")
                .unwrap()
                .value(address.to_string())
                .unwrap()
                .build();
            if mac_address.is_ok() {
                all_invalid = false;
                eprintln!("Address '{}' should be invalid but passed", address);
            }
        }

        assert!(all_invalid, "Not all addresses were invalid");
    }
}
