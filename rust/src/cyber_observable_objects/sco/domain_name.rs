use crate::base::Stix;
use crate::common::validation::validate_refs_are_type;
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::Identifier;
use addr::parse_domain_name;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Domain Name
///
/// The Domain Name object represents the properties of a network domain name.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_prhhksbxbg87>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct DomainName {
    /// Specifies the value of the domain name.
    pub value: String,
    /// Specifies a list of references to one or more IP addresses or domain names that the domain name resolves to.
    pub resolves_to_refs: Option<Vec<Identifier>>,
}
impl Stix for DomainName {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the domain name is in the correct format using the `addr` crate
        if parse_domain_name(&self.value).is_err() {
            errors.push(Error::ValidationError(
                "Domain name must conform to RFC1034 and RFC5890".to_string(),
            ));
        }

        // Validate resolves_to_refs if present
        if let Some(resolves_to_refs) = &self.resolves_to_refs {
            resolves_to_refs.stix_check()?;
            add_error(
                &mut errors,
                validate_refs_are_type(
                    resolves_to_refs,
                    &["ipv4-addr", "ipv6-addr", "domain-name"],
                    "resolves_to_refs",
                ),
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
    fn serialize_domain_name() {
        let ipv4_addr = Identifier::new("ipv4-addr").unwrap();

        let domain_name_obj = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("example.com".to_string())
            .unwrap()
            .resolves_to_refs(vec![ipv4_addr.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let result = serde_json::to_string_pretty(&domain_name_obj).unwrap();
        let result_value: serde_json::Value = serde_json::from_str(&result).unwrap();

        let expected = format!(
            r#"{{
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "example.com",
            "resolves_to_refs": [
                "{}"
            ]
        }}"#,
            ipv4_addr
        );
        let expected_value: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(result_value, expected_value);
    }

    #[test]
    fn deserialize_domain_name() {
        let ipv4_addr = Identifier::new("ipv4-addr").unwrap();

        let json = format!(
            r#"{{
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "example.com",
            "resolves_to_refs": [
                "{}"
            ]
        }}"#,
            ipv4_addr
        );

        let result = CyberObject::from_json(&json, false).unwrap();

        let domain_name_obj = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("example.com".to_string())
            .unwrap()
            .resolves_to_refs(vec![ipv4_addr.clone()])
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, domain_name_obj);
    }

    #[test]
    fn invalid_domain_name() {
        let result = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("invalid_domain_name".to_string())
            .unwrap()
            .build();

        assert!(
            result.is_err(),
            "Invalid domain name should result in an error"
        );
    }

    #[test]
    fn incorrect_reference_type() {
        let autonomous_system = Identifier::new("autonomous-system").unwrap();

        let result = CyberObjectBuilder::new("domain-name")
            .unwrap()
            .value("example.com".to_string())
            .unwrap()
            .resolves_to_refs(vec![autonomous_system.clone()])
            .unwrap()
            .build();

        assert!(
            result.is_err(),
            "Incorrect reference type should result in an error"
        );
    }
}
