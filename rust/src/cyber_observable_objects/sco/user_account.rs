use crate::base::Stix;
use crate::common::validation::is_vocab_value;
use crate::cyber_observable_objects::vocab::AccountTypeVocabulary;
use crate::error::{return_multiple_errors, StixError as Error};
use crate::types::Timestamp;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// User Account
///
/// The User Account object represents an instance of any type of user account, including but not limited to
/// operating system, device, messaging service, and social media platform accounts. As all properties of this
/// object are optional, at least one of the properties defined below **MUST** be included when using this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_azo70vgj1vm2>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct UserAccount {
    // The identifier of the account.
    pub user_id: Option<String>,
    // Specifies a cleartext credential
    pub credential: Option<String>,
    // Specifies the type of credential
    pub credential_type: Option<String>,
    //Specifies the account login string,
    pub account_login: Option<String>,
    //pecifies the type of the account.
    pub account_type: Option<String>,
    //Specifies the display name of the account
    pub display_name: Option<String>,
    //Indicates that the account is associated with a network service
    pub is_service_account: Option<bool>,
    //Specifies that the account has elevated privileges
    pub is_privileged: Option<bool>,
    //Specifies that the account has the ability to escalate privileges
    pub can_escalate_privs: Option<bool>,
    //Specifies if the account is disabled.
    pub is_disabled: Option<bool>,
    //Specifies when the account was created.
    pub account_created: Option<Timestamp>,
    //Specifies the expiration date of the account.
    pub account_expires: Option<Timestamp>,
    //Specifies when the account credential was last changed.
    pub credential_last_changed: Option<Timestamp>,
    //Specifies when the account was first accessed.
    pub account_first_login: Option<Timestamp>,
    //Specifies when the account was last accessed.
    pub account_last_login: Option<Timestamp>,
}

impl Stix for UserAccount {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(account_type_str) = &self.account_type {
            if !is_vocab_value::<AccountTypeVocabulary, _>(account_type_str) {
                errors.push(Error::ValidationError(format!(
                    "The account_type property should come from the `account-type-ov` open vocabulary. Account type '{}' is not in the vocabulary.",
                    account_type_str
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
    fn serialize_user_account() {
        let unix_extension = UnixAccountExtension {
            gid: Some(1000.into()),
            groups: Some(vec!["users".to_string(), "admins".to_string()]),
            home_dir: Some("/home/user".to_string()),
            shell: None,
        };

        let user_extension = SpecialExtensions::UserAccountExtensions(
            UserAccountExtensions::UnixAccountExt(unix_extension),
        );

        let mut general_extension = StixDictionary::new();
        general_extension
            .insert(
                "extension_type",
                DictionaryValue::String("property-extension".to_string()),
            )
            .unwrap();
        general_extension
            .insert("rank", DictionaryValue::Int(5))
            .unwrap();
        general_extension
            .insert("toxicity", DictionaryValue::Int(8))
            .unwrap();

        let user_account = CyberObjectBuilder::new("user-account")
            .unwrap()
            .user_id("1001".to_string())
            .unwrap()
            .account_login("jdoe".to_string())
            .unwrap()
            .account_type("unix".to_string())
            .unwrap()
            .display_name("John Doe".to_string())
            .unwrap()
            .is_service_account(false)
            .unwrap()
            .is_privileged(false)
            .unwrap()
            .can_escalate_privs(true)
            .unwrap()
            .is_disabled(true)
            .unwrap()
            .account_created("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .credential_last_changed("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_first_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_last_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .add_extension(
                "unix-account-ext",
                user_extension.extension_to_dict().unwrap(),
            )
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&user_account).unwrap();

        let expected = r#"{
        "user_id": "1001",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": false,
        "is_privileged": false,
        "can_escalate_privs": true,
        "is_disabled": true,
        "account_created": "2023-10-01T00:00:00Z",
        "credential_last_changed": "2023-10-01T00:00:00Z",
        "account_first_login": "2023-10-01T00:00:00Z",
        "account_last_login": "2023-10-01T00:00:00Z",
        "id": "user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
        "spec_version": "2.1",
        "type": "user-account",
        "extensions": 
        {
            "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
             },
            "unix-account-ext": {
                "gid": 1000,
                "groups": ["users", "admins"],
                "home_dir": "/home/user"
            }
        }
    }"#;
        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_user_account() {
        let json = r#"{
        "user_id": "1001",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": false,
        "is_privileged": false,
        "can_escalate_privs": true,
        "is_disabled": true,
        "account_created": "2023-10-01T00:00:00Z",
        "credential_last_changed": "2023-10-01T00:00:00Z",
        "account_first_login": "2023-10-01T00:00:00Z",
        "account_last_login": "2023-10-01T00:00:00Z",
        "id": "user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
        "spec_version": "2.1",
        "type": "user-account",
        "extensions":
        {
            "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
             },
            "unix-account-ext": {
                "gid": 1000,
                "groups": ["users", "admins"],
                "home_dir": "/home/user"
            }
        }
    }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let unix_extension = UnixAccountExtension {
            gid: Some(1000.into()),
            groups: Some(vec!["users".to_string(), "admins".to_string()]),
            home_dir: Some("/home/user".to_string()),
            shell: None,
        };

        let user_extension = SpecialExtensions::UserAccountExtensions(
            UserAccountExtensions::UnixAccountExt(unix_extension),
        );

        let mut general_extension = StixDictionary::new();
        general_extension
            .insert(
                "extension_type",
                DictionaryValue::String("property-extension".to_string()),
            )
            .unwrap();
        general_extension
            .insert("rank", DictionaryValue::Int(5))
            .unwrap();
        general_extension
            .insert("toxicity", DictionaryValue::Int(8))
            .unwrap();

        let user_account = CyberObjectBuilder::new("user-account")
            .unwrap()
            .user_id("1001".to_string())
            .unwrap()
            .account_login("jdoe".to_string())
            .unwrap()
            .account_type("unix".to_string())
            .unwrap()
            .display_name("John Doe".to_string())
            .unwrap()
            .is_service_account(false)
            .unwrap()
            .is_privileged(false)
            .unwrap()
            .can_escalate_privs(true)
            .unwrap()
            .is_disabled(true)
            .unwrap()
            .account_created("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .credential_last_changed("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_first_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .account_last_login("2023-10-01T00:00:00.00Z".to_string())
            .unwrap()
            .add_extension(
                "unix-account-ext",
                user_extension.extension_to_dict().unwrap(),
            )
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, user_account);
    }
}
