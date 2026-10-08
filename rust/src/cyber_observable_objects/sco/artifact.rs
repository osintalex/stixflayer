use crate::base::Stix;
use crate::common::validation::is_valid_mime_type;
use crate::cyber_observable_objects::vocab::EncryptionAlgorithm;
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use crate::types::Hashes;
use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use url::Url as RustUrl;

/// Artifact Object
///
/// The Artifact object permits capturing an array of bytes (8-bits),
/// as a base64-encoded string, or linking to a file-like payload.
///  
/// One of payload_bin or url **MUST** be provided. It is incumbent on object
/// creators to ensure that the URL is accessible for downstream consumers.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_4jegwl6ojbes>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Artifact {
    pub mime_type: Option<String>,
    pub payload_bin: Option<String>,
    pub url: Option<RustUrl>,
    pub hashes: Option<Hashes>,
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    pub decryption_key: Option<String>,
}
impl Stix for Artifact {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(hashes) = &self.hashes {
            add_error(&mut errors, hashes.stix_check());
        }
        if let Some(mime_type) = &self.mime_type {
            if !is_valid_mime_type(mime_type) {
                errors.push(Error::ValidationError(format!(
                    "mime_type '{}' is not a valid MIME type.",
                    mime_type,
                )));
            }
        }
        if self.payload_bin.is_none() && self.url.is_none() {
            errors.push(Error::ValidationError(
                "One of the optional fields, url or payload_bin, must be set".to_string(),
            ));
        }
        if self.payload_bin.is_some() && self.url.is_some() {
            errors.push(Error::ValidationError(
                "Only one of payload_bin and url may be set".to_string(),
            ));
        }
        if self.decryption_key.is_some() && self.encryption_algorithm.is_none() {
            errors.push(Error::ValidationError(
                "Encrytpion algorithm must be set when when decryption key is present".to_string(),
            ));
        }
        if let Some(payload_bin) = &self.payload_bin {
            // Try to decode the payload bin as a base-64 encoded string
            // We do not care about the value, just that it *can* be decoded
            let bytes = general_purpose::STANDARD.decode(payload_bin);
            if bytes.is_err() {
                errors.push(Error::ValidationError(
                    "A payload_bin must be a valid base-64 encoded string".to_string(),
                ));
            }
        }
        if self.url.is_some() && self.hashes.is_none() {
            errors.push(Error::ValidationError(
                "Hashes field must be present when url is set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder};
    use crate::cyber_observable_objects::vocab::EncryptionAlgorithm;
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
    fn artifact_hash_valid() {
        // test hash values that are intentionally correct
        let mut test_strings = HashMap::new();
        test_strings.insert("d41d8cd98f00b204e9800998ecf8427e", "MD5");
        test_strings.insert("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1");
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256",
        );
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA3-256",
        );
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-512");
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA3-512");
        // using hash example from https://ssdeep-project.github.io/ssdeep/usage.html
        test_strings.insert("96:s4Ud1Lj96tHHlZDrwciQmA+4uy1I0G4HYuL8N3TzS8QsO/wqWXLcMSx:sF1LjEtHHlZDrJzrhuyZvHYm8tKp/RWO", "SSDEEP");
        test_strings.insert(
            "dd0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
            "TLSH",
        );

        let mut all_valid = true;

        for (hash, hash_type) in test_strings {
            let artifact = CyberObjectBuilder::new("artifact")
                .unwrap()
                .payload_bin("aGVsbG8gd29ybGR+Cg==".to_string())
                .unwrap()
                .hashes(Hashes::new(hash_type, hash).unwrap())
                .unwrap()
                .build();
            if artifact.is_err() {
                all_valid = false;
                eprintln!(
                    "Artifiact hashes '{}' should be valid but failed as invalid {}",
                    hash, hash_type
                );
            }
        }

        assert!(all_valid, "Not all hashes were valid");
    }

    #[test]
    fn artifact_hash_invalid() {
        // test hash values that are intentionally incorrect
        let mut test_strings = HashMap::new();
        test_strings.insert("d41d8cd98f00b204e9800998ecf8427e", "SHA-1");
        test_strings.insert("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "MD5");
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-512",
        );
        test_strings.insert(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA3-512",
        );
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA-256");
        test_strings.insert("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "SHA3-256");
        test_strings.insert("3:abc:def", "TLSH");
        test_strings.insert(
            "dd0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
            "SSDEEP",
        );

        let mut all_invalid = true;

        for (hash, hash_type) in test_strings {
            let artifact = CyberObjectBuilder::new("artifact")
                .unwrap()
                .payload_bin("VBORw0KGgoAAAANSUhEUgAAADI== ...".to_string())
                .unwrap()
                .hashes(Hashes::new(hash_type, hash).unwrap())
                .unwrap()
                .build();
            if artifact.is_ok() {
                all_invalid = false;
                eprintln!(
                    "Artifiact hashes '{}' should be invalid but passed as valid {}",
                    hash, hash_type
                );
            }
        }

        assert!(all_invalid, "Not all hashes were valid");
    }

    #[test]
    fn deserialize_artifact() {
        let json = r#"{"type":"artifact","mime_type":"text/plain","url":"https://www.test.com","hashes":{"SHA-256":"6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"},"encryption_algorithm":"mime-type-indicated","decryption_key":"test","spec_version":"2.1","id":"artifact--cc7fa653-c35f-53db-afdd-dce4c3a241d5"}"#;
        let result = CyberObject::from_json(json, false).unwrap();
        let artifact = CyberObjectBuilder::new("artifact")
            .unwrap()
            .mime_type("text/plain".to_string())
            .unwrap()
            .url("https://www.test.com".to_string())
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                )
                .unwrap(),
            )
            .unwrap()
            .encryption_algorithm(EncryptionAlgorithm::MimeTypeIndicated)
            .unwrap()
            .decryption_key("test".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id();
        assert_eq!(result, artifact)
    }
}
