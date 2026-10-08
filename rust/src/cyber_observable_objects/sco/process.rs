use crate::base::Stix;
use crate::common::validation::validate_refs_are_type;
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::{Identifier, StixDictionary, Timestamp};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_i64;
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Process
///
/// The Process object represents common properties of an instance of a computer program as executed
/// on an operating system. A Process object **MUST** contain at least one property (other than type) from
/// this object (or one of its extensions).
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hpppnm86a1jm>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Process {
    /// Specifies the name of the process.
    pub name: Option<String>,
    /// Specifies whether the process is hidden.
    pub is_hidden: Option<bool>,
    /// Specifies the Process ID, or PID, of the process.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub pid: Option<i64>,
    /// Specifies the date/time at which the process was created.
    pub created_time: Option<Timestamp>,
    /// Specifies the current working directory of the process.
    pub cwd: Option<String>,
    /// Specifies the full command line used in executing the process, including the process name (which may be specified individually via the image_ref.name property) and any arguments.
    pub command_line: Option<String>,
    /// Specifies the list of environment variables associated with the process as a dictionary.
    pub environment_variables: Option<StixDictionary<Vec<String>>>,
    /// Specifies the list of network connections opened by the process, as a reference to one or more Network Traffic objects.
    pub opened_connection_refs: Option<Vec<Identifier>>,
    /// Specifies the user that created the process, as a reference to a User Account object.
    pub creator_user_ref: Option<Identifier>,
    /// Specifies the executable binary that was executed as the process image, as a reference to a File object.
    pub image_ref: Option<Identifier>,
    /// Specifies the other process that spawned (i.e. is the parent of) this one, as a reference to a Process object.
    pub parent_ref: Option<Identifier>,
    /// Specifies the other processes that were spawned by (i.e. children of) this process, as a reference to one or more other Process objects.
    pub child_refs: Option<Vec<Identifier>>,
}
impl Stix for Process {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(child_refs) = &self.child_refs {
            add_error(
                &mut errors,
                validate_refs_are_type(child_refs, &["process"], "child_refs"),
            );
        }
        if let Some(creator_user_ref) = &self.creator_user_ref {
            creator_user_ref.stix_check()?;
            if creator_user_ref.get_type() != "user-account" {
                errors.push(Error::ValidationError(
                    "creator_user_ref must be of type 'user-account'.".to_string(),
                ));
            }
        }
        if let Some(image_ref) = &self.image_ref {
            image_ref.stix_check()?;
            if image_ref.get_type() != "file" {
                errors.push(Error::ValidationError(
                    "image_ref must be of type 'file'.".to_string(),
                ));
            }
        }
        if let Some(opened_connection_refs) = &self.opened_connection_refs {
            opened_connection_refs.stix_check()?;
            add_error(
                &mut errors,
                validate_refs_are_type(
                    opened_connection_refs,
                    &["network-traffic"],
                    "opened_connection_refs",
                ),
            );
        }
        if let Some(parent_ref) = &self.parent_ref {
            parent_ref.stix_check()?;
            if parent_ref.get_type() != "process" {
                errors.push(Error::ValidationError(
                    "parent_ref must be of type 'process'.".to_string(),
                ));
            }
        }
        if let Some(pid) = &self.pid {
            add_error(&mut errors, pid.stix_check());
        }
        if let Some(child_refs) = &self.child_refs {
            add_error(&mut errors, child_refs.stix_check());
        }

        if let Some(environment_variables) = &self.environment_variables {
            add_error(&mut errors, environment_variables.stix_check());
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
    fn process_uses_spec_sanctioned_uuidv4() {
        // STIX 2.1 spec section 6.14 (Process): all properties are optional,
        // so a UUIDv4 MUST be used for the identifier.
        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .command_line("evil.exe --flag".to_string())
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(process.common_properties.id.get_uuid_version(), "UUIDv4");
    }

    #[test]
    fn deserialize_process() {
        let json = r#"{
            "type": "process",
            "pid": 314,
            "spec_version": "2.1",
            "id": "process--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "extensions": {
                "windows-process-ext": {
                "aslr_enabled": true,
                "dep_enabled": true,                
                "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309",
                "priority": "HIGH_PRIORITY_CLASS"
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: None,
            },
        ));

        let expected = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_process() {
        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: None,
            },
        ));

        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();
        let mut result = serde_json::to_string_pretty(&process).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "process",
            "pid": 314,
            "spec_version": "2.1",
            "id": "process--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "extensions": {
                "windows-process-ext": {
                "aslr_enabled": true,
                "dep_enabled": true,                
                "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309",
                "priority": "HIGH_PRIORITY_CLASS"
                }
            }
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }

    #[test]
    fn serialize_process_invalid_integrity() {
        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: Some("FOO".to_string()),
            },
        ));

        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build();

        assert!(process.is_err());
    }

    #[test]
    fn serialize_process_valid_integrity() {
        let wpe = SpecialExtensions::ProcessExtensions(ProcessExtensions::WindowsProcessExt(
            WindowsProcessExtension {
                aslr_enabled: Some(true),
                dep_enabled: Some(true),
                priority: Some("HIGH_PRIORITY_CLASS".to_string()),
                owner_sid: Some("S-1-5-21-186985262-1144665072-74031268-1309".to_string()),
                window_title: None,
                startup_info: None,
                integrity_level: Some("high".to_string()),
            },
        ));

        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .add_extension("windows-process-ext", wpe.extension_to_dict().unwrap())
            .unwrap()
            .build();

        assert!(process.is_ok());
    }

    #[test]
    fn serialize_process_invalid_image_ref() {
        //image ref shuold be of type file
        let process = CyberObjectBuilder::new("process")
            .unwrap()
            .pid(314.into())
            .unwrap()
            .image_ref(Identifier::new_test("FOO"))
            .unwrap()
            .build();

        assert!(process.is_err());
    }
}
