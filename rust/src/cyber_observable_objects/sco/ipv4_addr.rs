use crate::base::Stix;
use crate::common::validation::validate_refs_are_type;
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::Identifier;
use iptools;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// IPv4 Address
///
/// The IPv4 Address object represents one or more IPv4 addresses expressed using CIDR notation.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ki1ufj1ku8s0>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Ipv4Addr {
    /// Specifies the values of one or more IPv4 addresses expressed using CIDR notation.
    pub value: String,
    /// Specifies a list of references to one or more Layer 2 Media Access Control (MAC) addresses that the IPv4 address resolves to.
    pub resolves_to_refs: Option<Vec<Identifier>>,
    /// Specifies a list of references to one or more autonomous systems (AS) that the IPv4 address belongs to.
    pub belongs_to_refs: Option<Vec<Identifier>>,
}

impl Stix for Ipv4Addr {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the IPv4 address is in the correct format, with or without a CIDR
        if !(iptools::ipv4::validate_cidr(&self.value) || iptools::ipv4::validate_ip(&self.value)) {
            errors.push(Error::ValidationError(
                "IPv4 address must be a valid dotted-decimal format with optional CIDR notation"
                    .to_string(),
            ));
        }

        // Check for leading zeros in CIDR prefix (e.g., "/01" instead of "/1")
        if let Some(cidr_part) = self.value.split('/').nth(1) {
            if !cidr_part.is_empty() && cidr_part.len() > 1 && cidr_part.starts_with('0') {
                errors.push(Error::ValidationError(
                    "IPv4 address CIDR prefix must not have leading zeros".to_string(),
                ));
            }
        }

        // Validate resolves_to_refs if present
        if let Some(resolves_to_refs) = &self.resolves_to_refs {
            resolves_to_refs.stix_check()?;
            add_error(
                &mut errors,
                validate_refs_are_type(resolves_to_refs, &["mac-addr"], "resolves_to_refs"),
            );
        }

        // Validate belongs_to_refs if present
        if let Some(belongs_to_refs) = &self.belongs_to_refs {
            belongs_to_refs.stix_check()?;
            add_error(
                &mut errors,
                validate_refs_are_type(belongs_to_refs, &["autonomous-system"], "belongs_to_refs"),
            );
        }

        return_multiple_errors(errors)
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
    fn serialize_ipv4address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv4_address = CyberObjectBuilder::new("ipv4-addr")
            .unwrap()
            .value("198.51.100.3".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv4_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "198.51.100.3",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_ipv4address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let json = format!(
            r#"{{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "198.51.100.3",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );

        let result = CyberObject::from_json(&json, false).unwrap();

        let ipv4_address = CyberObjectBuilder::new("ipv4-addr")
            .unwrap()
            .value("198.51.100.3".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, ipv4_address);
    }

    #[test]
    fn ipv4_cidr() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv4_address = CyberObjectBuilder::new("ipv4-addr")
            .unwrap()
            .value("198.51.100.0/24".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv4_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "198.51.100.0/24",
            "resolves_to_refs": [
                "{}",
                "{}"
            ],
            "belongs_to_refs": [
                "{}"
            ]
        }}"#,
            mac_addr1, mac_addr2, autonomous_system
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn invalid_ipv4s() {
        let test_ips = vec![
            "198.51.100.x",    // invalid ipv4
            "xC6.51.100.0",    // invalid ipv4
            "198.51.100.0/50", // invalid CIDR
        ];

        let mut all_invalid = true;

        for ip in test_ips {
            let ipv4 = CyberObjectBuilder::new("ipv4-addr")
                .unwrap()
                .value(ip.to_string())
                .unwrap()
                .build();
            if ipv4.is_ok() {
                all_invalid = false;
                warn!("Ipv4Address '{}' should be invalid but passed", ip);
            }
        }
        assert!(all_invalid, "Not all ipvv4 addresses were invalid");
    }
}
