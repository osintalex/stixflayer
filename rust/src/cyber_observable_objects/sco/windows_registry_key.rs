use crate::base::Stix;
use crate::common::validation::is_exact_vocab_value;
use crate::cyber_observable_objects::vocab::WindowsRegistryDataTypeEnum;
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::{Identifier, Timestamp};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_i64;
use serde_with::skip_serializing_none;
use std::sync::OnceLock;
use stix_derive::StixProperties;

fn windows_registry_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(\\[a-zA-Z0-9_]+)*$")
            .expect("Windows registry key regex is valid")
    })
}

/// Windows Regsitry Key Open
///
/// The Registry Key object represents the properties of a Windows registry key. As all properties of this object are optional,
/// at least one of the properties defined below **MUST** be included when using this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_luvw8wjlfo3y>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct WindowsRegistryKey {
    /// Specifies the full registry key including the hive.
    pub key: Option<String>,
    /// list of type windows-registry-value-type
    pub values: Option<Vec<WindowsRegistryKeyType>>,
    /// Specifies the last date/time that the registry key was modified.
    pub modified_time: Option<Timestamp>,
    /// Specifies a reference to the user account that created the registry key.
    pub creator_user_ref: Option<Identifier>,
    /// Specifies the number of subkeys contained under the registry key.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub number_of_subkeys: Option<i64>,
}
impl Stix for WindowsRegistryKey {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(creator_user_ref) = &self.creator_user_ref {
            creator_user_ref.stix_check()?;
            if creator_user_ref.get_type() != "user-account" {
                errors.push(Error::ValidationError(
                    "creator_user_ref must be of type 'user-account'.".to_string(),
                ));
            }
        }
        if let Some(key) = &self.key {
            if !windows_registry_key_re().is_match(key) {
                errors.push(Error::ValidationError(
                    "Registry key must begin with HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, or HKEY_CURRENT_CONFIG.".to_string(),
                ));
            }
        }
        if let Some(number_of_subkeys) = &self.number_of_subkeys {
            number_of_subkeys.stix_check()?;
        }
        if let Some(values) = &self.values {
            add_error(&mut errors, values.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Windows Registry Value Type
///
/// The Windows Registry Value type captures the properties of a Windows Registry Key Value.
/// As all properties of this type are optional, at least one of the properties defined below MUST be included when using this type.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_u7n4ndghs3qq>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct WindowsRegistryKeyType {
    /// Specifies the name of the registry value. For specifying the default value in a registry key, an empty string MUST be used.
    pub name: Option<String>,
    /// Specifies the data contained in the registry value.
    pub data: Option<String>,
    /// Specifies the registry (REG_*) data type used in the registry value.
    pub data_type: Option<String>,
}
impl Stix for WindowsRegistryKeyType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(data_type) = &self.data_type {
            if !is_exact_vocab_value::<WindowsRegistryDataTypeEnum, _>(data_type) {
                return Err(Error::ValidationError(
                    "data_type must come from the 'windows-registry-datatype-enum' enumeration."
                        .to_string(),
                ));
            }
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
    fn serialize_windows_registry_key() {
        let windows_registry_key = CyberObjectBuilder::new("windows-registry-key")
            .unwrap()
            .key("HKEY_LOCAL_MACHINE".to_string())
            .unwrap()
            .number_of_subkeys(10000000.into())
            .unwrap()
            .creator_user_ref(
                Identifier::from_str("user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5").unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&windows_registry_key).unwrap();

        let expected = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "number_of_subkeys": 10000000,
            "creator_user_ref": "user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_windows_registry_key() {
        let json = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "number_of_subkeys": 10000000,
            "creator_user_ref": "user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let windows_registry_key = CyberObjectBuilder::new("windows-registry-key")
            .unwrap()
            .key("HKEY_LOCAL_MACHINE".to_string())
            .unwrap()
            .number_of_subkeys(10000000.into())
            .unwrap()
            .creator_user_ref(
                Identifier::from_str("user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5").unwrap(),
            )
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, windows_registry_key)
    }

    #[test]
    fn windows_registry_key_i64_invalid1() {
        // using subkey value 1 num out of 2^53 ramge
        let json = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "number_of_subkeys": -9007199254740992,
            "creator_user_ref": "user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let result = CyberObject::from_json(json, false);

        assert!(result.is_err())
    }

    #[test]
    fn windows_registry_key_i64_valid() {
        // using subkey value at -1 value from max
        let json = r#"{
            "key":"HKEY_LOCAL_MACHINE",
            "id": "windows-registry-key--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "number_of_subkeys": 9007199254740990,
            "creator_user_ref": "user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
             "type": "windows-registry-key"
        }"#;

        let result = CyberObject::from_json(json, false);
        assert!(result.is_ok());
    }

    #[test]
    fn windows_registry_key_invalid() {
        let windows_registry_key = CyberObjectBuilder::new("windows-registry-key")
            .unwrap()
            .key("HKEY_LOCAL_MACHINExx\\foo\\bar".to_string())
            .unwrap()
            .number_of_subkeys(10000000.into())
            .unwrap()
            .creator_user_ref(
                Identifier::from_str("user-account--cc7fa653-c35f-53db-afdd-dce4c3a241d5").unwrap(),
            )
            .unwrap()
            .build();

        assert!(windows_registry_key.is_err())
    }
}
