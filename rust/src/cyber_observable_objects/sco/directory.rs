use crate::base::Stix;
use crate::common::validation::{is_valid_charset_name, validate_refs_are_type};
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::{Identifier, Timestamp};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Directory
///
/// The Directory object represents the properties common to a file system directory.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lyvpga5hlw52>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Directory {
    pub path: String, // if not USCII path_enc must be set: not sure how we can determine
    pub path_enc: Option<String>, //supposed to be from charcter set list
    pub ctime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
    pub atime: Option<Timestamp>,
    pub contains_refs: Option<Vec<Identifier>>,
}
impl Stix for Directory {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(path_enc) = &self.path_enc {
            if !is_valid_charset_name(path_enc) {
                errors.push(Error::ValidationError(format!(
                    "path_enc '{}' is not a valid IANA character set name.",
                    path_enc,
                )));
            }
        }

        if let Some(cr) = &self.contains_refs {
            cr.stix_check()?;
            add_error(
                &mut errors,
                validate_refs_are_type(cr, &["file", "directory"], "contains_refs"),
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
    fn deserialize_directory() {
        let json = r#"{
            "type": "directory",
            "spec_version": "2.1",  
            "id": "directory--cc7fa653-c35f-53db-afdd-dce4c3a241d5", 
            "path": "C:\\Windows\\System32"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let directory = CyberObjectBuilder::new("directory")
            .unwrap()
            .path("C:\\Windows\\System32".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, directory)
    }

    #[test]
    fn serialize_directory() {
        let directory = CyberObjectBuilder::new("directory")
            .unwrap()
            .path("C:\\Windows\\System32".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        let mut result = serde_json::to_string_pretty(&directory).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "directory",
            "path": "C:\\Windows\\System32",
            "spec_version": "2.1",
            "id": "directory--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }
}
