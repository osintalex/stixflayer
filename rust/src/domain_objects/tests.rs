#[cfg(test)]
mod test {
    use crate::{
        domain_objects::sdo::{DomainObject, DomainObjectBuilder},
        error::StixError as Error,
        relationship_objects::{Related, RelationshipObject},
        types::Identified,
    };
    
    

    #[test]
    fn try_build_with_required_field() {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("name".to_string())
            .unwrap()
            .build();

        assert!(attack_pattern.is_ok());
    }

    #[test]
    fn try_build_without_required_field() {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern").unwrap().build();

        assert!(attack_pattern.is_err());
    }

    #[test]
    fn try_build_with_correct_creator_type() {
        let identity = DomainObjectBuilder::new("identity")
            .unwrap()
            .name("identity".to_string())
            .unwrap()
            .build()
            .unwrap();

        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("pattern".to_string())
            .unwrap()
            .created_by_ref(identity.get_id().clone())
            .unwrap()
            .build();

        assert!(attack_pattern.is_ok());
    }

    #[test]
    fn try_build_with_wrong_creator_type() {
        let attack_pattern_1 = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("pattern 1".to_string())
            .unwrap()
            .build()
            .unwrap();

        let attack_pattern_2 = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("pattern 2".to_string())
            .unwrap()
            .created_by_ref(attack_pattern_1.get_id().clone())
            .unwrap()
            .build();

        assert!(attack_pattern_2.is_err());
    }

    #[test]
    fn kebab_case_test() {
        // This should not generate a warning that "Advanced" is not in the sophistication open-vocab
        let threat_actor_result = DomainObjectBuilder::new("threatActor")
            .unwrap()
            .name("Threat Actor Group".to_string())
            .unwrap()
            .sophistication("Advanced".to_string())
            .unwrap()
            .build();
        assert!(threat_actor_result.is_ok());
        let threat_actor = threat_actor_result.unwrap();
        let threat_actor_types = threat_actor.get_id().get_type();
        assert_eq!(threat_actor_types, "threat-actor");
    }

    #[test]
    fn version() {
        let attack_pattern_1 = DomainObjectBuilder::new("attack-pattern")
            .unwrap()
            .name("name".to_string())
            .unwrap()
            .build()
            .unwrap();

        let attack_pattern_2 = DomainObjectBuilder::version(&attack_pattern_1)
            .unwrap()
            .build()
            .unwrap();

        assert_ne!(
            attack_pattern_1.common_properties.modified,
            attack_pattern_2.common_properties.modified
        );
    }

    #[test]
    fn from_parsed_preserves_versioning_properties() {
        // Parsing a STIX object is not versioning it: id/created/modified must survive exactly.
        let json = r#"{
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-13T09:22:01.000Z",
            "name": "Spear Phishing"
        }"#;
        let parsed = DomainObject::from_json(json, false).unwrap();
        let rebuilt = DomainObjectBuilder::from_parsed(&parsed)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(parsed.common_properties.id, rebuilt.common_properties.id);
        assert_eq!(
            parsed.common_properties.created,
            rebuilt.common_properties.created
        );
        assert_eq!(
            parsed.common_properties.modified,
            rebuilt.common_properties.modified
        );
    }

    #[test]
    fn version_rejects_revoked_object() {
        // STIX 2.1 3.3: once an object is revoked, later versions MUST NOT be created.
        let json = r#"{
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-13T09:22:01.000Z",
            "revoked": true,
            "name": "Spear Phishing"
        }"#;
        let parsed = DomainObject::from_json(json, false).unwrap();
        assert!(matches!(
            DomainObjectBuilder::version(&parsed),
            Err(Error::UnableToVersion(_))
        ));
    }

    #[test]
    fn from_parsed_accepts_revoked_object_and_preserves_state() {
        // Revoked objects are valid STIX objects; reconstructing one must keep its state.
        let json = r#"{
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-13T09:22:01.000Z",
            "revoked": true,
            "name": "Spear Phishing"
        }"#;
        let parsed = DomainObject::from_json(json, false).unwrap();
        let rebuilt = DomainObjectBuilder::from_parsed(&parsed)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(rebuilt.common_properties.revoked, Some(true));
        assert_eq!(parsed.common_properties.id, rebuilt.common_properties.id);
        assert_eq!(
            parsed.common_properties.created,
            rebuilt.common_properties.created
        );
        assert_eq!(
            parsed.common_properties.modified,
            rebuilt.common_properties.modified
        );
    }

    #[test]
    fn deserialize_with_excluded_common_property() {
        let json = r#"{
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "name": "Spear Phishing",
            "description": "...",
            "external_references": [
                {
                "source_name": "capec",
                "external_id": "CAPEC-163"
                }
            ],
            "defanged": "true",
            }"#;

        let result = DomainObject::from_json(json, false);

        assert!(result.is_err());
    }

    fn relationship(relationship_type: String) -> Result<RelationshipObject, Error> {
        let attack_pattern = DomainObjectBuilder::new("attack-pattern")
            ?
            .name("Spear Phishing as Practiced by Adversary X".to_string())
            ?
            .description("A particular form of spear phishing where the attacker claims that the target had won a contest, including personal details, to get them to click on a link.".to_string())
            ?
            .external_references(vec![crate::types::ExternalReference::new(
                "capec",
                None,
                None,
                Some("CAPEC-163".to_string()),
            )
            ?])
            .build()
            ?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let identity = DomainObjectBuilder::new("identity")?
            .name("John Smith".to_string())?
            .identity_class("individual".to_string())?
            .description("An employee who might click on a link".to_string())?
            .contact_information("john.smith@example.com".to_string())?
            .build()?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-03-15T09:00:00.000Z")
            .modified("2016-03-15T09:00:00.000Z");

        let relationship = attack_pattern
            .add_relationship(identity, relationship_type)?
            .description("The employee targeted by the spear phishing attempt".to_string())
            .build()?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-07-01T11:35:00.000Z")
            .modified("2016-07-01T11:35:00.000Z");

        Ok(relationship)
    }

    #[test]
    fn create_relationship() {
        let relationship = relationship("targets".to_string()).unwrap();

        assert_eq!(relationship.get_id().get_type(), "relationship");
        assert_eq!(relationship.get_relationship_type(), "targets");
    }

    #[test]
    fn prohibited_relationship() {
        let relationship = relationship("uses".to_string());
        assert!(relationship.is_err());
    }

    #[test]
    fn serialize_relationship() {
        let relationship = relationship("targets".to_string()).unwrap();

        let mut result = serde_json::to_string_pretty(&relationship).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "relationship",            
            "relationship_type": "targets",
            "source_ref": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "The employee targeted by the spear phishing attempt"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_relationship() {
        let json = r#"{
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "relationship_type": "targets",
            "description": "The employee targeted by the spear phishing attempt",
            "source_ref": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#;
        let result = RelationshipObject::from_json(json, false).unwrap();

        let expected = relationship("targets".to_string()).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_invalid_relationship() {
        let json = r#"{
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "relationship_type": "targets",
            "description": "The employee targeted by the spear phishing attempt",
            "source_ref": "attack-pattern--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "malware--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#;
        let result = RelationshipObject::from_json(json, false);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_invalid_relationship_type_pattern() {
        let json = r#"{
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "relationship_type": "SOMETHING",
            "source_ref": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "target_ref": "malware--cc7fa653-c35f-43db-afdd-dce4c3a241d5"
        }"#;
        let result = RelationshipObject::from_json(json, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SOMETHING"));
        assert!(err.contains("invalid characters"));
    }

    fn sighting() -> Result<RelationshipObject, Error> {
        let indicator = DomainObjectBuilder::new("indicator")
            .unwrap()
            .name("Indicator".to_string())
            .unwrap()
            .description(
                "This indicator detects connections to a known malicious IP address".to_string(),
            )
            .unwrap()
            .indicator_types(vec!["malicious-activity".to_string()])
            .unwrap()
            .pattern("[domain-name:value = 'example.com']".to_string())
            .unwrap()
            .pattern_type("stix".to_string())
            .unwrap()
            .valid_from("2016-05-12T08:17:27.000Z")
            .unwrap()
            .valid_until("2023-10-05T10:00:00.000Z")
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z");

        let sighting = indicator
            .add_sighting()?
            .description("Sighting of malicious IP indicator".to_string())
            .last_seen("2016-08-15T14:00:00.000Z")
            .unwrap()
            .build()?
            // Change id, created, and modified fields for test matching
            .test_id()
            .created("2016-07-01T11:35:00.000Z")
            .modified("2016-07-01T11:35:00.000Z");

        Ok(sighting)
    }

    #[test]
    fn serialize_sighting() {
        let sighting = sighting().unwrap();

        let mut result = serde_json::to_string_pretty(&sighting).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
            "type": "sighting",            
            "last_seen": "2016-08-15T14:00:00Z",
            "sighting_of_ref": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "sighting--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "Sighting of malicious IP indicator"
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_sighting() {
        let json = r#"{
            "type": "sighting",            
            "last_seen": "2016-08-15T14:00:00Z",
            "sighting_of_ref": "indicator--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "sighting--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "Sighting of malicious IP indicator"
        }"#;
        let result = RelationshipObject::from_json(json, false).unwrap();

        let expected = sighting().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_invalid_sighting() {
        let json = r#"{
            "type": "sighting",            
            "last_seen": "2016-08-15T14:00:00Z",
            "sighting_of_ref": "file--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "spec_version": "2.1",
            "id": "sighting--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-07-01T11:35:00Z",
            "modified": "2016-07-01T11:35:00Z",
            "description": "Sighting of malicious IP indicator"
        }"#;
        let result = RelationshipObject::from_json(json, false);

        assert!(result.is_err());
    }
}
