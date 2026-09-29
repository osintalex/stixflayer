use crate::base::Stix;
use crate::cyber_observable_objects::lang_codes::{is_iso639_2_code, is_valid_language_code};
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Software
///
/// The Software object represents high-level properties associated with software, including software products.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_7rkyhtkdthok>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Software {
    // name of the software.
    pub name: String,
    // Common Platform Enumeration (CPE) entry for the software
    pub cpe: Option<String>,
    // The Software Identification (SWID) Tags [SWID] entry for the software
    pub swid: Option<String>,
    //languages supported by the software.
    pub languages: Option<Vec<String>>,
    // The name of the vendor of the software.
    pub vendor: Option<String>,
    // The version of the software.
    pub version: Option<String>,
}

impl Stix for Software {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(cpe) = &self.cpe {
            // CPE v2.3 format: cpe:2.3:<part>:<vendor>:<product>:...
            if !cpe.starts_with("cpe:2.3:") {
                errors.push(Error::ValidationError(format!(
                    "cpe '{}' is not a valid CPE v2.3 identifier. Must start with 'cpe:2.3:'.",
                    cpe,
                )));
            }
        }

        if let Some(languages) = &self.languages {
            add_error(&mut errors, languages.stix_check());
            for language in languages {
                if !is_valid_language_code(language) {
                    errors.push(Error::ValidationError(format!(
                        "Object {:?}'s `language` is '{}'. A `language` must conform to RFC5646.",
                        self, language,
                    )));
                } else if is_iso639_2_code(language) {
                    errors.push(Error::ValidationError(format!(
                        "Object {:?}'s `language` is '{}'. ISO 639-2 three-letter codes are not valid in STIX 2.1 strict mode; use the RFC 5646 equivalent instead.",
                        self, language,
                    )));
                }
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
    fn serialize_software() {
        let software = CyberObjectBuilder::new("software")
            .unwrap()
            .name("Word".to_string())
            .unwrap()
            .cpe("cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*".to_string())
            .unwrap()
            .swid("com.example.software-1.0.0".to_string())
            .unwrap()
            .languages(vec!["en-US".to_string(), "ja-JP".to_string()])
            .unwrap()
            .vendor("Microsoft".to_string())
            .unwrap()
            .version("Word for Microsoft 365".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&software).unwrap();

        let expected = r#"{
            "name": "Word",
            "cpe":"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "id": "software--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "swid": "com.example.software-1.0.0",
            "languages": ["en-US","ja-JP"],
            "vendor": "Microsoft",
            "version": "Word for Microsoft 365",
            "spec_version": "2.1",
             "type": "software"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_software() {
        let json = r#"{
            "name": "Word",
            "cpe":"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
            "id": "software--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "swid": "com.example.software-1.0.0",
            "languages": ["en-US","ja-JP"],
            "vendor": "Microsoft",
            "version": "Word for Microsoft 365",
            "spec_version": "2.1",
             "type": "software"
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let software = CyberObjectBuilder::new("software")
            .unwrap()
            .name("Word".to_string())
            .unwrap()
            .cpe("cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*".to_string())
            .unwrap()
            .swid("com.example.software-1.0.0".to_string())
            .unwrap()
            .languages(vec!["en-US".to_string(), "ja-JP".to_string()])
            .unwrap()
            .vendor("Microsoft".to_string())
            .unwrap()
            .version("Word for Microsoft 365".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        assert_eq!(result, software)
    }
}
