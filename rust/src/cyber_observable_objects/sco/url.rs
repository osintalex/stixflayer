use crate::base::Stix;
use crate::error::StixError as Error;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use url::Url as RustUrl;

/// URL
///
/// The User Account object represents an instance of any type of user account, including but not limited to
/// operating system, device, messaging service, and social media platform accounts. As all properties of this
/// object are optional, at least one of the properties defined below **MUST** be included when using this object.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ah3hict2dez0>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Url {
    pub value: RustUrl,
}
impl Stix for Url {
    fn stix_check(&self) -> Result<(), Error> {
        // We do not need to validate the `value` field, because a `url::Url` cannot be empty or an invalid URL.
        Ok(())
    }
}

impl Default for Url {
    fn default() -> Self {
        Url {
            // Panic: Safe to unwrap as this is a valid URL string
            value: RustUrl::parse("http://example.com").unwrap(),
        }
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
    fn serialize_url() {
        let url = CyberObjectBuilder::new("url")
            .unwrap()
            .value(String::from("https://new-url.com/"))
            .unwrap()
            .build()
            .unwrap()
            .test_id();

        //Serialization (to_value): Converts Rust data into a JSON-compatible format.
        let result = serde_json::to_value(&url).unwrap();

        let expected = r#"{
            "type": "url",
            "spec_version": "2.1",
            "id": "url--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "https://new-url.com/"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();

        assert_eq!(&result, &expected_value);
    }

    #[test]
    fn deserialize_url() {
        let json = r#"{
            "type": "url",
            "spec_version": "2.1",
            "id": "url--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "value": "https://new-url.com/"
        }"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let url = CyberObjectBuilder::new("url")
            .unwrap()
            .value(String::from("https://new-url.com/"))
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, url)
    }
}
