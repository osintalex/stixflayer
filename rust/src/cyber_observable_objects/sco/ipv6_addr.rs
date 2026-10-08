use crate::base::Stix;
use crate::common::validation::validate_refs_are_type;
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::Identifier;
use iptools;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// IPv6 Address
///
/// The IPv6 Address object represents one or more IPv6 addresses expressed using CIDR notation.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oeggeryskriq>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Ipv6Addr {
    /// Specifies the values of one or more IPv6 addresses expressed using CIDR notation.
    pub value: String,
    /// Specifies a list of references to one or more Layer 2 Media Access Control (MAC) addresses that the IPv6 address resolves to.
    pub resolves_to_refs: Option<Vec<Identifier>>,
    /// Specifies a list of references to one or more autonomous systems (AS) that the IPv6 address belongs to.
    pub belongs_to_refs: Option<Vec<Identifier>>,
}
impl Stix for Ipv6Addr {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the IPv6 address is in the correct format, with or without a CIDR
        if !(iptools::ipv6::validate_cidr(&self.value) || iptools::ipv6::validate_ip(&self.value)) {
            errors.push(Error::ValidationError(
                "IPv6 address must be a valid hexadecimal format with optional CIDR notation"
                    .to_string(),
            ));
        }

        // Check for leading zeros in CIDR prefix (e.g., "/03" instead of "/3")
        if let Some(cidr_part) = self.value.split('/').nth(1) {
            if !cidr_part.is_empty() && cidr_part.len() > 1 && cidr_part.starts_with('0') {
                errors.push(Error::ValidationError(
                    "IPv6 address CIDR prefix must not have leading zeros".to_string(),
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
    fn serialize_ipv6address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv6_address = CyberObjectBuilder::new("ipv6-addr")
            .unwrap()
            .value("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv6_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
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
    fn deserialize_ipv6address() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let json = format!(
            r#"{{
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
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

        let ipv6_address = CyberObjectBuilder::new("ipv6-addr")
            .unwrap()
            .value("2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, ipv6_address);
    }

    #[test]
    fn ipv6_cidr() {
        let mac_addr1 = Identifier::new("mac-addr").unwrap();
        let mac_addr2 = Identifier::new("mac-addr").unwrap();
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let ipv6_address = CyberObjectBuilder::new("ipv6-addr")
            .unwrap()
            .value("2001:0db8::/96".to_string())
            .unwrap()
            .resolves_to_refs(vec![mac_addr1.clone(), mac_addr2.clone()])
            .unwrap()
            .belongs_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&ipv6_address).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": "ipv6-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "2001:0db8::/96",
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
    fn invalid_ipv6s() {
        let test_ips = vec![
            "::ffff:192.0.2.300", // invalid ipv6
            "2001:0dh8::",        // invalid ipv6
            "2001:0db8::/150",    // invalid CIDR
        ];

        let mut all_invalid = true;

        for ip in test_ips {
            let ipv6 = CyberObjectBuilder::new("ipv6-addr")
                .unwrap()
                .value(ip.to_string())
                .unwrap()
                .build();
            if ipv6.is_ok() {
                all_invalid = false;
                warn!("Ipv6Address '{}' should be invalid but passed", ip);
            }
        }
        assert!(all_invalid, "Not all ipvv4 addresses were invalid");
    }
}
