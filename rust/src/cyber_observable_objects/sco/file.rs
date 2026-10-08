use crate::base::Stix;
use crate::common::validation::{is_valid_charset_name, is_valid_hex, is_valid_mime_type};
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::{Hashes, Identifier, Timestamp};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_u64;
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// File
///
/// The File object represents the properties of a file. A File object **MUST** contain at least one of hashes or name.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_99bl2dibcztv>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct File {
    /// Specifies a dictionary of hashes for the file.
    pub hashes: Option<Hashes>,
    /// Specifies the size of the file, in bytes. The value of this property MUST NOT be negative.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size: Option<u64>,
    /// Specifies the name of the file.
    pub name: Option<String>,
    /// Specifies the observed encoding for the name of the file.
    pub name_enc: Option<String>,
    /// Specifies the hexadecimal constant ("magic number") associated with a specific file format that corresponds to the file, if applicable.
    pub magic_number_hex: Option<String>,
    /// Specifies the MIME type name specified for the file, e.g., application/msword.
    pub mime_type: Option<String>,
    /// Specifies the date/time the file was created.
    pub ctime: Option<Timestamp>,
    /// Specifies the date/time the file was last written to/modified.
    pub mtime: Option<Timestamp>,
    /// Specifies the date/time the file was last accessed.
    pub atime: Option<Timestamp>,
    /// Specifies the parent directory of the file, as a reference to a Directory object.
    pub parent_directory_ref: Option<Identifier>,
    /// Specifies a list of references to other Cyber-observable Objects contained within the file, such as another file that is appended to the end of the file, or an IP address that is contained somewhere in the file.
    pub contains_refs: Option<Vec<Identifier>>,
    /// Specifies the content of the file, represented as an Artifact object.
    pub content_ref: Option<Identifier>,
}
impl Stix for File {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        let mut errors = Vec::new();

        if let Some(mime_type) = &self.mime_type {
            if !is_valid_mime_type(mime_type) {
                errors.push(Error::ValidationError(format!(
                    "mime_type '{}' is not a valid MIME type.",
                    mime_type,
                )));
            }
        }

        if let Some(name_enc) = &self.name_enc {
            if !is_valid_charset_name(name_enc) {
                errors.push(Error::ValidationError(format!(
                    "name_enc '{}' is not a valid IANA character set name.",
                    name_enc,
                )));
            }
        }

        if let Some(size) = &self.size {
            add_error(&mut errors, size.stix_check());
        }
        if let Some(magic_number_hex) = &self.magic_number_hex {
            if !is_valid_hex(magic_number_hex) {
                errors.push(Error::ParseHexError(
                    "magic_number_hex -- ".to_string() + magic_number_hex,
                ))
            }
        }
        if let Some(parent_directory_ref) = &self.parent_directory_ref {
            parent_directory_ref.stix_check()?;
            if parent_directory_ref.get_type() != "directory" {
                errors.push(Error::ValidationError(
                    "parent_directory_ref must be of type directory".to_string(),
                ));
            }
        }
        if let Some(contains_refs) = &self.contains_refs {
            add_error(&mut errors, contains_refs.stix_check());
        }

        if let Some(content_ref) = &self.content_ref {
            content_ref.stix_check()?;
            if content_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(
                    "content_ref must be of type artifact".to_string(),
                ));
            }
        }
        if self.name.is_none() && self.hashes.is_none() {
            errors.push(Error::ValidationError(
                "One of name or hashes muste be set".to_string(),
            ));
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
    fn deserialize_file() {
        let json = r#"{
            "type": "file",
            "spec_version": "2.1",
            "id": "file--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "name": "foo.zip",
            "hashes": {
              "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "extensions": {
              "archive-ext": {
                "contains_refs": [
                  "file--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
                ],
                "comment": "test"
              },
              "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
              }
            }
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let archive =
            SpecialExtensions::FileExtensions(FileExtensions::ArchiveExt(ArchiveExtension {
                contains_refs: [Identifier::new_test("file")].to_vec(),
                comment: Some("test".to_string()),
            }));
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
        let file = CyberObjectBuilder::new("file")
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f",
                )
                .unwrap(),
            )
            .unwrap()
            .name("foo.zip".to_string())
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .add_extension("archive-ext", archive.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, file)
    }

    #[test]
    fn serialize_file() {
        let archive =
            SpecialExtensions::FileExtensions(FileExtensions::ArchiveExt(ArchiveExtension {
                contains_refs: [Identifier::new_test("file")].to_vec(),
                comment: Some("test".to_string()),
            }));
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
        let file = CyberObjectBuilder::new("file")
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA3-256",
                    "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
                )
                .unwrap(),
            )
            .unwrap()
            .name("foo.zip".to_string())
            .unwrap()
            .add_extension(
                "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
                general_extension,
            )
            .unwrap()
            .add_extension("archive-ext", archive.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        let mut result = serde_json::to_string_pretty(&file).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "file",
            "hashes": {
              "SHA3-256": "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
            },
            "name": "foo.zip",
            "spec_version": "2.1",
            "id": "file--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "extensions": {
              "archive-ext": {
                "comment": "test",
                "contains_refs": [
                  "file--cc7fa653-c35f-53db-afdd-dce4c3a241d5"
                ]
              },
              "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
                "extension_type": "property-extension",
                "rank": 5,
                "toxicity": 8
              }
            }
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected)
    }
}
