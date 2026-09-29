use crate::base::Stix;
use crate::types::{Identifier};
use crate::error::{return_multiple_errors, StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use email_address::{EmailAddress as validate_email, Options};

/// Email Address
///
/// The Email Address object represents a single email address.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_wmenahkvqmgj>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct EmailAddress {
    /// Specifies the value of the email address. This MUST NOT include the display name.
    pub value: String,
    /// Specifies a single email display name, i.e., the name that is displayed to the human user of a mail application.
    pub display_name: Option<String>,
    /// Specifies the user account that the email address belongs to, as a reference to a User Account object.
    pub belongs_to_ref: Option<Identifier>,
}
impl Stix for EmailAddress {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check if the Email address is in the correct format
        let value = &self.value.to_string();
        let options = Options {
            minimum_sub_domains: 2,
            ..Options::default()
        };
        if validate_email::parse_with_options(value, options).is_err() {
            errors.push(Error::ValidationError(format!(
                "Email address {} is not a valid e-mail address.",
                value
            )));
        }
        if let Some(display_name) = &self.display_name {
            if value.contains(&display_name.to_string()) {
                errors.push(Error::ValidationError(format!(
                    "Email address {} must not include the display name {}.",
                    value, display_name
                )));
            }
        }
        if let Some(belongs_to_ref) = &self.belongs_to_ref {
            belongs_to_ref.stix_check()?;
            let belongs_to_ref_type = belongs_to_ref.get_type();
            if belongs_to_ref_type != "user-account" {
                errors.push(Error::ValidationError(format!(
                    "Email address belongs_to_ref type {} must be 'user-account'.",
                    belongs_to_ref_type
                )));
            }
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
    fn email_addr_id_is_stable_across_builds() {
        let build = || {
            CyberObjectBuilder::new("email-addr")
                .unwrap()
                .value("user@example.com".to_string())
                .unwrap()
                .build()
                .unwrap()
        };
        let first = build();
        let second = build();

        assert_eq!(first.common_properties.id, second.common_properties.id);
        assert_eq!(first.common_properties.id.get_uuid_version(), "UUIDv5");
    }

    #[test]
    fn serialize_emailaddress() {
        let email_address = CyberObjectBuilder::new("email-addr")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&email_address).unwrap();

        let expected = r#"{
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "john@example.com"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_emailaddress() {
        let json = r#"{
            "type": "email-addr",
            "spec_version": "2.1",
            "id": "email-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "john@example.com"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let email_address = CyberObjectBuilder::new("email-addr")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, email_address)
    }

    #[test]
    fn email_display_nameinvalid() {
        let email_address = CyberObjectBuilder::new("email-addr")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .display_name("john@example.com".to_string())
            .unwrap()
            .build();
        assert!(email_address.is_err());
    }

    #[test]
    fn email_belongs_to_ref() {
        let email_address = CyberObjectBuilder::new("email-addr")
            .unwrap()
            .value("john@example.com".to_string())
            .unwrap()
            .display_name("john doe".to_string())
            .unwrap()
            .belongs_to_ref(Identifier::new("user-account").unwrap())
            .unwrap()
            .build();
        assert!(email_address.is_ok());
    }

    #[test]
    fn try_email_invalid() {
        let test_addresses = vec![
            "foobar",       // invalid email
            "john@example", // invalid email
            "foo-bar.com",  // invalid email
        ];

        let mut all_invalid = true;

        for address in test_addresses {
            let email_address = CyberObjectBuilder::new("email-addr")
                .unwrap()
                .value(address.to_string())
                .unwrap()
                .build();
            if email_address.is_ok() {
                all_invalid = false;
                warn!("Email Address '{}' should be invalid but passed", address);
            }
        }
        assert!(all_invalid, "Not all email addresses were invalid");
    }

    #[test]
    fn try_email_valid() {
        let test_addresses = vec![
            "foobar@foobar.edu",        // valid email
            "john.doe@example.com",     // valid email
            "username-test@foo-bar.au", // valid email
        ];

        let mut all_valid = true;

        for address in test_addresses {
            let email_address = CyberObjectBuilder::new("email-addr")
                .unwrap()
                .value(address.to_string())
                .unwrap()
                .build();
            if email_address.is_err() {
                all_valid = false;
                warn!("Email Address '{}' should be valid but failed", address);
            }
        }
        assert!(all_valid, "All email addresses were valid");
    }
}
