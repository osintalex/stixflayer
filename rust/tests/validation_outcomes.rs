//! Cross-language outcome contract: warnings never fail, each finding is
//! reported once, and every catalog warning kind is reachable.

use stixflayer::base::Stix;
use stixflayer::cyber_observable_objects::sco::CyberObject;
use stixflayer::domain_objects::sdo::DomainObject;
use stixflayer::error::{Entry, Outcome};
use stixflayer::external_reference::{ExternalReference, ReferenceUrl};
use stixflayer::relationship_objects::RelationshipObject;
use stixflayer::types::Hashes;
use stixflayer::validation::validate_value_outcome;

const IDENTITY_ID: &str = "identity--550e8400-e29b-41d4-a716-446655440000";
const RELATIONSHIP_ID: &str = "relationship--550e8400-e29b-41d4-a716-446655440001";

fn kinds(outcome: &Outcome<impl std::fmt::Debug>) -> Vec<String> {
    outcome.warnings.iter().map(|w| w.kind.clone()).collect()
}

fn count(outcome: &Outcome<impl std::fmt::Debug>, kind: &str) -> usize {
    outcome.warnings.iter().filter(|w| w.kind == kind).count()
}

fn identity_json(extra: serde_json::Value) -> serde_json::Value {
    let mut base = serde_json::json!({
        "type": "identity",
        "id": IDENTITY_ID,
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": "Acme",
    });
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    base
}

#[test]
fn valid_object_without_findings_has_no_warnings() {
    let outcome: Outcome<DomainObject> =
        validate_value_outcome(identity_json(serde_json::json!({})), false, true);
    assert!(outcome.valid);
    assert!(outcome.value.is_some());
    assert!(outcome.errors.is_empty());
    assert!(outcome.warnings.is_empty());
}

#[test]
fn open_vocab_value_warns_and_does_not_fail() {
    let outcome: Outcome<DomainObject> = validate_value_outcome(
        identity_json(serde_json::json!({"identity_class": "bogus-class"})),
        false,
        true,
    );
    assert!(outcome.valid, "warnings must not fail validation");
    assert_eq!(count(&outcome, "open_vocab_value_not_suggested"), 1);
    let warning = outcome
        .warnings
        .iter()
        .find(|w| w.kind == "open_vocab_value_not_suggested")
        .unwrap();
    assert_eq!(warning.property.as_deref(), Some("identity_class"));
    assert_eq!(warning.value.as_deref(), Some("bogus-class"));
    assert_eq!(warning.vocabulary.as_deref(), Some("identity-class-ov"));
    assert_eq!(warning.object_id.as_deref(), Some(IDENTITY_ID));
    assert!(warning.message.contains("bogus-class"));
}

#[test]
fn non_lowercase_open_vocab_value_warns() {
    let outcome: Outcome<DomainObject> = validate_value_outcome(
        identity_json(serde_json::json!({"identity_class": "Bogus_Class"})),
        false,
        true,
    );
    assert!(outcome.valid);
    assert!(kinds(&outcome).contains(&"value_not_lowercase_hyphenated".to_string()));
}

#[test]
fn hash_algorithm_other_than_sha256_warns_once() {
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "file",
            "id": "file--550e8400-e29b-41d4-a716-446655440003",
            "spec_version": "2.1",
            "hashes": {"MD5": "d41d8cd98f00b204e9800998ecf8427e"}
        }),
        false,
        true,
    );
    assert!(outcome.valid);
    assert_eq!(count(&outcome, "hash_not_sha256"), 1);
    let warning = outcome
        .warnings
        .iter()
        .find(|w| w.kind == "hash_not_sha256")
        .unwrap();
    assert_eq!(warning.property.as_deref(), Some("hashes"));
    assert_eq!(
        warning.object_id.as_deref(),
        Some("file--550e8400-e29b-41d4-a716-446655440003")
    );
}

#[test]
fn sha256_in_any_case_does_not_warn() {
    for key in ["sha-256", "SHA-256", "Sha-256"] {
        let outcome: Outcome<CyberObject> = validate_value_outcome(
            serde_json::json!({
                "type": "file",
                "id": "file--550e8400-e29b-41d4-a716-446655440003",
                "spec_version": "2.1",
                "hashes": {key: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            }),
            false,
            true,
        );
        assert!(outcome.valid, "{key}: {:?}", outcome.errors);
        assert!(
            !kinds(&outcome).contains(&"hash_not_sha256".to_string()),
            "{key} should not warn: {:?}",
            outcome.warnings
        );
    }
}

#[test]
fn unknown_hash_algorithm_key_is_an_error() {
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "file",
            "id": "file--550e8400-e29b-41d4-a716-446655440003",
            "spec_version": "2.1",
            "hashes": {"not-a-hash-algorithm": "abc"}
        }),
        false,
        true,
    );
    assert!(!outcome.valid);
    assert!(outcome
        .errors
        .iter()
        .any(|e| e.kind == "invalid_vocab_value"
            && e.vocabulary.as_deref() == Some("hash-algorithm-ov")));
}

#[test]
fn extension_key_warns_without_failing() {
    let outcome: Outcome<DomainObject> = validate_value_outcome(
        identity_json(serde_json::json!({
            "extensions": {"custom-ext": {"extension_type": "new-sdo"}}
        })),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(kinds(&outcome).contains(&"extension_key_not_extension_definition".to_string()));
}

#[test]
fn uppercase_extensions_key_warns() {
    let outcome: Outcome<DomainObject> = validate_value_outcome(
        identity_json(serde_json::json!({
            "extensions": {"Custom_Ext": {"extension_type": "new-sdo"}}
        })),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert_eq!(count(&outcome, "dictionary_key_not_lowercase"), 1);
}

#[test]
fn external_reference_without_hashes_warns() {
    let reference = ExternalReference::new(
        "example",
        None,
        Some(ReferenceUrl::new("https://example.com/report", None).unwrap()),
        None,
    )
    .unwrap();
    let builder = stixflayer::DomainObjectBuilder::new("identity")
        .unwrap()
        .name("Acme".to_string())
        .unwrap()
        .identity_class("organization".to_string())
        .unwrap()
        .external_references(vec![reference]);
    let object = builder.build().unwrap();
    let outcome = object.outcome();
    assert!(outcome.valid);
    assert_eq!(count(&outcome, "external_reference_url_without_hashes"), 1);
}

#[test]
fn network_traffic_missing_ports_warns_once_each() {
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "network-traffic",
            "id": "network-traffic--550e8400-e29b-41d4-a716-446655440004",
            "spec_version": "2.1",
            "protocols": ["tcp"],
            "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
            "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012"
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert_eq!(count(&outcome, "network_traffic_missing_port"), 2);
    let props: Vec<_> = outcome
        .warnings
        .iter()
        .filter(|w| w.kind == "network_traffic_missing_port")
        .filter_map(|w| w.property.clone())
        .collect();
    assert!(props.contains(&"src_port".to_string()));
    assert!(props.contains(&"dst_port".to_string()));
}

#[test]
fn protocol_missing_from_protocols_warns() {
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "network-traffic",
            "id": "network-traffic--550e8400-e29b-41d4-a716-446655440004",
            "spec_version": "2.1",
            "protocols": ["udp"],
            "src_port": 80,
            "dst_port": 443,
            "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
            "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012",
            "extensions": {"tcp-ext": {"src_flags_hex": "00"}}
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    let warning = outcome
        .warnings
        .iter()
        .find(|w| w.kind == "protocol_missing_from_protocols")
        .expect("protocol warning");
    assert_eq!(warning.value.as_deref(), Some("tcp"));
    assert_eq!(warning.property.as_deref(), Some("protocols"));
}

#[test]
fn custom_relationship_type_warns() {
    let outcome: Outcome<RelationshipObject> = validate_value_outcome(
        serde_json::json!({
            "type": "relationship",
            "id": RELATIONSHIP_ID,
            "spec_version": "2.1",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "relationship_type": "custom-relationship",
            "source_ref": IDENTITY_ID,
            "target_ref": "identity--550e8400-e29b-41d4-a716-446655440002"
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    let warning = outcome
        .warnings
        .iter()
        .find(|w| w.kind == "relationship_type_not_suggested")
        .expect("relationship warning");
    assert_eq!(warning.value.as_deref(), Some("custom-relationship"));
    assert_eq!(warning.object_id.as_deref(), Some(RELATIONSHIP_ID));
}

#[test]
fn marking_definition_type_warns() {
    let outcome: Outcome<stixflayer::meta_objects::marking_definition::MarkingDefinition> =
        validate_value_outcome(
            serde_json::json!({
                "type": "marking-definition",
                "id": "marking-definition--550e8400-e29b-41d4-a716-446655440009",
                "spec_version": "2.1",
                "created": "2016-05-12T08:17:27Z",
                "definition_type": "custom",
                "definition": {"statement": "custom marking"}
            }),
            false,
            true,
        );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(kinds(&outcome).contains(&"marking_definition_type_not_suggested".to_string()));
}

#[test]
fn observed_data_custom_ref_warns_and_known_sdo_ref_errors() {
    let custom: Outcome<DomainObject> = validate_value_outcome(
        serde_json::json!({
            "type": "observed-data",
            "id": "observed-data--550e8400-e29b-41d4-a716-446655440005",
            "spec_version": "2.1",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "first_observed": "2016-05-12T08:17:27Z",
            "last_observed": "2016-05-12T08:17:27Z",
            "number_observed": 1,
            "object_refs": ["foo--550e8400-e29b-41d4-a716-446655440006"]
        }),
        false,
        true,
    );
    assert!(custom.valid, "{:?}", custom.errors);
    assert!(kinds(&custom).contains(&"observed_data_unrecognized_ref".to_string()));
    assert!(kinds(&custom).contains(&"observed_data_no_recognized_sco".to_string()));

    let known_sdo: Outcome<DomainObject> = validate_value_outcome(
        serde_json::json!({
            "type": "observed-data",
            "id": "observed-data--550e8400-e29b-41d4-a716-446655440005",
            "spec_version": "2.1",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "first_observed": "2016-05-12T08:17:27Z",
            "last_observed": "2016-05-12T08:17:27Z",
            "number_observed": 1,
            "object_refs": [IDENTITY_ID]
        }),
        false,
        true,
    );
    assert!(!known_sdo.valid);
    assert!(!known_sdo.errors.is_empty());
}

#[test]
fn hash_keys_allow_250_characters() {
    let key31 = format!("x_{}", "a".repeat(29));
    assert_eq!(key31.len(), 31);
    let hashes = Hashes::new(&key31, "abc").expect("31-character key is accepted");
    let outcome = hashes.outcome();
    assert!(outcome.valid);

    let key251 = format!("x_{}", "a".repeat(249));
    assert_eq!(key251.len(), 251);
    assert!(Hashes::new(&key251, "abc").is_err());
}

#[test]
fn language_tags_accept_well_formed_values() {
    for language in ["eng", "en", "en-US", "zh-Hant-TW"] {
        let outcome: Outcome<DomainObject> = validate_value_outcome(
            identity_json(serde_json::json!({"lang": language})),
            false,
            true,
        );
        assert!(outcome.valid, "{language}: {:?}", outcome.errors);
    }

    let outcome: Outcome<DomainObject> = validate_value_outcome(
        identity_json(serde_json::json!({"lang": "not a language tag!"})),
        false,
        true,
    );
    assert!(!outcome.valid);
}

#[test]
fn software_languages_accept_iso639_2() {
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "software",
            "id": "software--550e8400-e29b-41d4-a716-446655440008",
            "spec_version": "2.1",
            "name": "Example",
            "languages": ["eng", "en-US", "zh-Hant-TW"]
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
}

#[test]
fn http_request_headers_accept_custom_names() {
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "network-traffic",
            "id": "network-traffic--550e8400-e29b-41d4-a716-446655440004",
            "spec_version": "2.1",
            "protocols": ["http"],
            "src_port": 80,
            "dst_port": 80,
            "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
            "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012",
            "extensions": {
                "http-request-ext": {
                    "request_method": "get",
                    "request_value": "/index.html",
                    "request_header": {"X-Custom-Header": "value"}
                }
            }
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(!kinds(&outcome).contains(&"dictionary_key_not_lowercase".to_string()));
}

#[test]
fn outcome_serializes_with_shared_entry_shape() {
    let outcome: Outcome<DomainObject> = validate_value_outcome(
        identity_json(serde_json::json!({"identity_class": "bogus-class"})),
        false,
        true,
    );
    let json = outcome.to_json();
    assert_eq!(json["valid"], true);
    assert!(json["errors"].as_array().unwrap().is_empty());
    let warning = &json["warnings"][0];
    assert_eq!(warning["kind"], "open_vocab_value_not_suggested");
    assert!(warning.get("level").is_none());
    assert!(warning.get("severity").is_none());
    assert!(warning.get("properties").is_none());
    assert!(warning.get("expected").is_none());
    assert!(warning.get("got").is_none());
}

#[test]
fn entry_constructor_is_sparse() {
    let entry = Entry::new("example_kind", "message");
    let json = serde_json::to_value(entry).unwrap();
    assert_eq!(json["kind"], "example_kind");
    assert_eq!(json["message"], "message");
    assert!(json.get("property").is_none());
    assert!(json.get("object_id").is_none());
}

#[test]
fn empty_required_name_is_identical_for_constructor_and_from_json() {
    let json = serde_json::json!({
        "type": "attack-pattern",
        "id": "attack-pattern--550e8400-e29b-41d4-a716-446655440010",
        "spec_version": "2.1",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "name": ""
    });
    let from_json = DomainObject::from_json(&json.to_string(), false).unwrap_err();

    let from_constructor = stixflayer::DomainObjectBuilder::new("attack-pattern")
        .unwrap()
        .name(String::new())
        .unwrap()
        .build()
        .unwrap_err();

    assert_eq!(from_json.errors()[0].kind, "missing_property");
    assert_eq!(from_constructor.errors()[0].kind, "missing_property");
    assert_eq!(from_json.to_string(), from_constructor.to_string());
}

#[test]
fn serialization_does_not_recheck() {
    let object = stixflayer::DomainObjectBuilder::new("attack-pattern")
        .unwrap()
        .name(String::new())
        .unwrap()
        .build_no_validate()
        .unwrap();
    // Serializing an assembled-but-invalid object must not raise.
    let json = serde_json::to_string(&object).unwrap();
    assert!(json.contains("\"name\":\"\""));
}

#[test]
fn case_preserved_dictionaries_do_not_warn() {
    // IPFIX keys preserve case.
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "network-traffic",
            "id": "network-traffic--550e8400-e29b-51d4-a716-446655440030",
            "spec_version": "2.1",
            "protocols": ["tcp"],
            "src_port": 80,
            "dst_port": 80,
            "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
            "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012",
            "ipfix": {"octetDeltaCount": 1}
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(!kinds(&outcome).contains(&"dictionary_key_not_lowercase".to_string()));

    // Email header field names preserve case.
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "email-message",
            "id": "email-message--550e8400-e29b-51d4-a716-446655440031",
            "spec_version": "2.1",
            "is_multipart": false,
            "body": "hello",
            "additional_header_fields": {"X-Mailer": ["Example Mailer"]}
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(!kinds(&outcome).contains(&"dictionary_key_not_lowercase".to_string()));

    // PDF document information dictionary keys preserve case.
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "file",
            "id": "file--550e8400-e29b-51d4-a716-446655440032",
            "spec_version": "2.1",
            "name": "report.pdf",
            "extensions": {"pdf-ext": {"document_info_dict": {"Title": "Report"}}}
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(!kinds(&outcome).contains(&"dictionary_key_not_lowercase".to_string()));

    // Socket option names preserve case.
    let outcome: Outcome<CyberObject> = validate_value_outcome(
        serde_json::json!({
            "type": "network-traffic",
            "id": "network-traffic--550e8400-e29b-51d4-a716-446655440033",
            "spec_version": "2.1",
            "protocols": ["tcp"],
            "src_port": 80,
            "dst_port": 80,
            "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
            "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012",
            "extensions": {"socket-ext": {"address_family": "AF_INET", "options": {"SO_LINGER": 1}}}
        }),
        false,
        true,
    );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(!kinds(&outcome).contains(&"dictionary_key_not_lowercase".to_string()));
}

#[test]
fn language_content_keys_do_not_warn() {
    let outcome: Outcome<stixflayer::meta_objects::language_content::LanguageContent> =
        validate_value_outcome(
            serde_json::json!({
                "type": "language-content",
                "id": "language-content--550e8400-e29b-41d4-a716-446655440034",
                "spec_version": "2.1",
                "created": "2016-05-12T08:17:27Z",
                "modified": "2016-05-12T08:17:27Z",
                "object_ref": "identity--550e8400-e29b-41d4-a716-446655440000",
                "object_modified": "2016-05-12T08:17:27Z",
                "contents": {"en-US": {"name": "Acme"}}
            }),
            false,
            true,
        );
    assert!(outcome.valid, "{:?}", outcome.errors);
    assert!(!kinds(&outcome).contains(&"dictionary_key_not_lowercase".to_string()));
}
