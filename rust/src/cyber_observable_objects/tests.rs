#[cfg(test)]
mod test {
    #![allow(unused_imports)]
    use crate::{
        cyber_observable_objects::{
            sco::{CyberObject, CyberObjectBuilder},
            sco_types::{EmailMimeCompomentType, X509V3Extensions},
            vocab::EncryptionAlgorithm,
        },
        extensions::{
            ArchiveExtension, FileExtensions, HttpRequestExtension, IcmpExtension,
            NetworkTrafficExtensions, ProcessExtensions, SocketExtenion, SpecialExtensions,
            UnixAccountExtension, UserAccountExtensions, WindowsProcessExtension,
        },
        types::{DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp},
    };
    use log::warn;
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};
    use test_log::test;
    impl CyberObject {
        pub(crate) fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }
    }

    #[test]
    fn try_build_with_required_field() {
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
            .build();
        assert!(artifact.is_ok());
    }

    #[test]
    fn try_build_without_required_field() {
        let artifact = CyberObjectBuilder::new("artifact").unwrap().build();
        assert!(artifact.is_err());
    }

    #[test]
    fn create_uuidv5_with_required_field() {
        // `number` is a required ID contributing property for an AutonomuousSystem SCO
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(50)
            .unwrap()
            .build()
            .unwrap();

        let uuid_version = autonomous_system.common_properties.id.get_uuid_version();

        assert_eq!(uuid_version, "UUIDv5");
    }

    #[test]
    fn from_parsed_preserves_parsed_identifier() {
        // Parsing is not versioning: a parsed SCO keeps its exact identifier,
        // including the spec-sanctioned UUIDv4 case (Process).
        let json = r#"{
            "type": "process",
            "spec_version": "2.1",
            "id": "process--ffa353d6-8ee4-48a0-a17c-c394d0fc56ac",
            "pid": 4135,
            "command_line": "evil.exe --flag"
        }"#;
        let parsed = CyberObject::from_json(json, false).unwrap();
        let rebuilt = CyberObjectBuilder::from_parsed(&parsed)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            parsed.common_properties.id.to_string(),
            rebuilt.common_properties.id.to_string()
        );
        assert_eq!(rebuilt.common_properties.id.get_uuid_version(), "UUIDv4");
    }

    #[test]
    fn u64_max_test() {
        let limit: u64 = 1 << 53;
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(limit)
            .unwrap()
            .build();
        assert!(autonomous_system.is_err());
        let autonomous_system = CyberObjectBuilder::new("autonomous-system")
            .unwrap()
            .number(limit - 1)
            .unwrap()
            .build();
        assert!(autonomous_system.is_ok());
    }

    #[test]
    fn create_uuidv5_with_optional_fields() {
        // `payload_bin` and `hashes` are both optional ID contributing properties for an Artifact SCO
        let artifact = CyberObjectBuilder::new("artifact")
            .unwrap()
            .payload_bin("aGVsbG8gd29ybGR+Cg==".to_string())
            .unwrap()
            .hashes(
                Hashes::new(
                    "SHA-256",
                    "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
                )
                .unwrap(),
            )
            .unwrap()
            .build()
            .unwrap();

        let uuid_version = artifact.common_properties.id.get_uuid_version();

        assert_eq!(uuid_version, "UUIDv5");
    }

    #[test]
    fn create_uuidv4_with_missing_optional_fields() {
        let multipart = EmailMimeCompomentType {
            body: Some("Cats are funny!".to_string()),
            body_raw_ref: None,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_disposition: Some("inline".to_string()),
        };

        // `from_ref`, `subject`, and `body` are the only ID contributing properties to an EmailMessage SCO
        // Because they are all optinonal, it is possible to have such an SCO with no properties to generate a UUIDv5
        let email_message = CyberObjectBuilder::new("email-message")
            .unwrap()
            .is_multipart()
            .unwrap()
            .body_multipart(vec![multipart.clone()])
            .unwrap()
            .build()
            .unwrap();

        let uuid_version = email_message.common_properties.id.get_uuid_version();

        // Per STIX 2.1 spec section 2.9, when no contributing properties are present,
        // a UUIDv4 MUST be used. email-message optional contributing props are
        // from_ref, subject, body; body_multipart is not ID contributing.
        assert_eq!(uuid_version, "UUIDv4");
    }

    #[test]
    fn cyber_object_builder_from_cyber_object() {
        let json = r#"{
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--d5f9c7a3-5f4e-5a1b-9c8d-7e6f5a4b3c2d",
            "value": "192.168.1.100"
        }"#;

        let cyber_object = CyberObject::from_json(json, false).unwrap();
        let builder = CyberObjectBuilder::from(&cyber_object).unwrap();
        let rebuilt = builder.build().unwrap();

        assert_eq!(rebuilt.object_type.to_string(), "ipv4-addr");
    }
}
