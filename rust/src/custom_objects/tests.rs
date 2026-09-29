//! Contains the implementation logic for unrecognized custom STIX Objects.


#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use serde_json::{Number, Value};

    use crate::{
        custom_objects::{CustomObject, CustomObjectBuilder},
        types::{Identifier, Timestamp},
    };

    // Functions for editing otherwise un-editable fields, for testing only
    impl CustomObject {
        fn test_id(mut self) -> Self {
            let object_type = self.object_type.as_ref();
            self.common_properties.id = Identifier::new_test(object_type);
            self
        }

        fn created(mut self, datetime: &str) -> Self {
            self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
            self
        }

        fn modified(mut self, datetime: &str) -> Self {
            self.common_properties.modified = Some(Timestamp(datetime.parse().unwrap()));
            self
        }
    }

    #[test]
    fn deserialize_custom() {
        let json = r#"{
        "type": "my-favorite-sdo",
        "spec_version": "2.1",
        "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2014-02-20T09:16:08.989000Z",
        "modified": "2014-02-20T09:16:08.989000Z",
        "name": "This is the name of my favorite",
        "some_property_name1": "value1",
        "some_property_name2": 3,
        "extensions": {
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62" : {
                "extension_type" : "new-sdo"
            }
        }
        }"#;

        let result = CustomObject::from_json(json).unwrap();

        let mut custom_properties = BTreeMap::new();

        custom_properties.insert(
            "name".to_string(),
            Value::String("This is the name of my favorite".to_string()),
        );
        custom_properties.insert(
            "some_property_name1".to_string(),
            Value::String("value1".to_string()),
        );
        custom_properties.insert(
            "some_property_name2".to_string(),
            Value::Number(Number::from_u128(3).unwrap()),
        );

        let expected = CustomObjectBuilder::new_sdo(
            "my-favorite-sdo",
            custom_properties,
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
        )
        .unwrap()
        .build()
        .unwrap()
        .created("2014-02-20T09:16:08.989Z")
        .modified("2014-02-20T09:16:08.989Z")
        .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_custom_wrong_ext() {
        let json = r#"{
            "type": "my-favorite-sdo",
            "spec_version": "2.1",
            "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2014-02-20T09:16:08.989000Z",
            "modified": "2014-02-20T09:16:08.989000Z",
            "name": "This is the name of my favorite",
            "some_property_name1": "value1",
            "some_property_name2": 3,
            "extensions": {
                "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62" : {
                    "extension_type" : "property-extension"
                }
            }
            }"#;

        let result = CustomObject::from_json(json);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_custom_no_ext() {
        let json = r#"{
            "type": "my-favorite-sdo",
            "spec_version": "2.1",
            "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2014-02-20T09:16:08.989000Z",
            "modified": "2014-02-20T09:16:08.989000Z",
            "name": "This is the name of my favorite",
            "some_property_name1": "value1",
            "some_property_name2": 3
            }"#;

        let result = CustomObject::from_json(json);

        assert!(result.is_err());
    }

    #[test]
    fn serialize_custom() {
        let mut custom_properties = BTreeMap::new();

        custom_properties.insert(
            "name".to_string(),
            Value::String("This is the name of my favorite".to_string()),
        );
        custom_properties.insert(
            "some_property_name1".to_string(),
            Value::String("value1".to_string()),
        );
        custom_properties.insert(
            "some_property_name2".to_string(),
            Value::Number(Number::from_u128(3).unwrap()),
        );

        let custom_object = CustomObjectBuilder::new_sdo(
            "my-favorite-sdo",
            custom_properties,
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
        )
        .unwrap()
        .build()
        .unwrap()
        .created("2014-02-20T09:16:08.989Z")
        .modified("2014-02-20T09:16:08.989Z")
        .test_id();

        let mut result = serde_json::to_string_pretty(&custom_object).unwrap();
        result.retain(|c| !c.is_whitespace());

        let mut expected = r#"{
        "type": "my-favorite-sdo",
        "spec_version": "2.1",
        "id": "my-favorite-sdo--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
        "created": "2014-02-20T09:16:08.989Z",
        "modified": "2014-02-20T09:16:08.989Z",
        "extensions": {
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62" : {
                "extension_type" : "new-sdo"
            }
        },
        "name": "This is the name of my favorite",
        "some_property_name1": "value1",
        "some_property_name2": 3
        }"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());

        assert_eq!(result, expected);
    }

    #[test]
    fn custom_type_name_underscore_rejected() {
        let json = r#"{
            "type": "corpo_ration",
            "spec_version": "2.1",
            "id": "corpo_ration--4527e5de-8572-446a-a57a-706f15467461",
            "created": "2021-02-20T09:16:08.989000Z",
            "modified": "2021-02-20T09:16:08.989000Z",
            "extensions": {
                "extension-definition--1bba6c39-7ac1-40a2-819a-f33f8ea81a25": {
                    "extension_type": "new-sdo"
                }
            }
        }"#;

        let result = CustomObject::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn custom_type_name_uppercase_start_rejected() {
        let json = r#"{
            "type": "X-example-com-customobject",
            "spec_version": "2.1",
            "id": "X-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
            "created": "2021-02-20T09:16:08.989000Z",
            "modified": "2021-02-20T09:16:08.989000Z",
            "extensions": {
                "extension-definition--1bba6c39-7ac1-40a2-819a-f33f8ea81a25": {
                    "extension_type": "new-sdo"
                }
            }
        }"#;

        let result = CustomObject::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn custom_property_starting_with_digit_accepted() {
        let json = r#"{
            "type": "x-example-com-customobject",
            "spec_version": "2.1",
            "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
            "created": "2021-02-20T09:16:08.989000Z",
            "modified": "2021-02-20T09:16:08.989000Z",
            "9ome_custom_stuff": 14,
            "extensions": {
                "extension-definition--1bba6c39-7ac1-40a2-819a-f33f8ea81a25": {
                    "extension_type": "new-sdo"
                }
            }
        }"#;

        let result = CustomObject::from_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn custom_object_rejects_invalid_custom_property_names() {
        let json = r#"{
            "type": "x-example-com-customobject",
            "spec_version": "2.1",
            "id": "x-example-com-customobject--4527e5de-8572-446a-a57a-706f15467461",
            "created": "2021-02-20T09:16:08.989000Z",
            "modified": "2021-02-20T09:16:08.989000Z",
            "bad-key": 14,
            "extensions": {
                "extension-definition--1bba6c39-7ac1-40a2-819a-f33f8ea81a25": {
                    "extension_type": "new-sdo"
                }
            }
        }"#;

        let result = CustomObject::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn valid_custom_type_and_properties_accepted() {
        let mut custom_properties = BTreeMap::new();
        custom_properties.insert(
            "some_custom_stuff".to_string(),
            Value::Number(Number::from(14)),
        );
        custom_properties.insert(
            "other_custom_stuff".to_string(),
            Value::String("hello".to_string()),
        );

        let result = CustomObjectBuilder::new_sdo(
            "x-example-com-customobject",
            custom_properties,
            "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
        );

        assert!(result.is_ok());
    }
}
