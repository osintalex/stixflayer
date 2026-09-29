mod test {
    use crate::{
        bundles::Bundle,
        domain_objects::sdo::{DomainObjectBuilder, DomainObjectType},
        object::StixObject,
    };

    #[test]
    fn deserialize_bundle() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
            "objects": [
                {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
                "created": "2016-04-29T14:09:00.000Z",
                "modified": "2016-04-29T14:09:00.000Z",
                "object_marking_refs": ["marking-definition--089a6ecb-cc15-43cc-9494-767639779123"],
                "name": "Poison Ivy Malware",
                "description": "This file is part of Poison Ivy",
                "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
                "pattern_type": "stix",
                "valid_from": "2016-01-01T00:00:00Z"
                }
            ]
        }"#;

        let bundle = Bundle::from_json(json).unwrap();
        let objects = bundle.get_objects();
        let object = &objects[0];

        assert_eq!(object.get_type(), "indicator");

        let StixObject::Sdo(sdo) = object else {
            panic!()
        };
        let DomainObjectType::Indicator(indicator) = &sdo.object_type else {
            panic!()
        };
        assert_eq!(indicator.name.as_ref().unwrap(), "Poison Ivy Malware");
    }

    #[test]
    fn construct_bundle() {
        let sdo = DomainObjectBuilder::new("indicator")
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
            .unwrap();

        let bundle = Bundle::new(StixObject::Sdo(sdo));

        let object = &bundle.get_objects()[0];
        let StixObject::Sdo(sdo) = object else {
            panic!()
        };
        let DomainObjectType::Indicator(indicator) = &sdo.object_type else {
            panic!()
        };
        assert_eq!(indicator.name.as_ref().unwrap(), "Indicator");
    }

    #[test]
    fn enforce_refs_invalid() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
            "objects": [
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
                    "created": "2014-02-20T09:16:08.989Z",
                    "modified": "2014-02-20T09:16:08.989Z",
                    "name": "Poison Ivy",
                    "is_family": false
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
                    "created": "2014-02-20T09:16:08.989Z",
                    "modified": "2014-02-20T09:16:08.989Z",
                    "relationship_type": "indicates",
                    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
                }
            ]
        }"#;

        let result = Bundle::from_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"));
    }

    #[test]
    fn enforce_refs_valid() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "created": "2014-02-20T09:16:08.989Z",
                    "modified": "2014-02-20T09:16:08.989Z",
                    "name": "Bad IP",
                    "description": "This indicator detects a bad IP",
                    "pattern": "[ipv4-addr:value = '192.0.2.1']",
                    "pattern_type": "stix",
                    "valid_from": "2014-02-20T09:16:08.989Z"
                },
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
                    "created": "2014-02-20T09:16:08.989Z",
                    "modified": "2014-02-20T09:16:08.989Z",
                    "name": "Poison Ivy",
                    "is_family": false
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
                    "created": "2014-02-20T09:16:08.989Z",
                    "modified": "2014-02-20T09:16:08.989Z",
                    "relationship_type": "indicates",
                    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
                }
            ]
        }"#;

        let result = Bundle::from_json(json);
        assert!(result.is_ok());
    }
}
