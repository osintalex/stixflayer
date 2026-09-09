//! Functions for deserializing STIX objects from JSON strings.

use crate::{error::StixError as Error, types::get_object_type};
use serde_json::Value;

/// Function to get the STIX object type from a generic STIX object JSON by matching the given type
///
/// If the type is not recognized, the object is considered to be a "custom" STIX object, with any number of possible unrecognized fields
pub fn get_object_type_from_json(json_str: &str) -> Result<String, Error> {
    // Deserialize the JSON string to a generic JSON value
    let json_value: Value =
        serde_json::from_str(json_str).map_err(|e| Error::DeserializationError(e.to_string()))?;

    // Confirm that the JSON has "type" and "id" fields
    let (Some(sub_type), true) = (json_value.get("type"), json_value.get("id").is_some()) else {
        return Err(Error::UnexpectedJsonFormat);
    };

    // Return the STIX Object type associated with the "type" value, or return "custom" if the type is not recognized
    Ok(get_object_type(sub_type.to_string().trim_matches('\"')))
}

#[cfg(test)]
mod tests {
    use crate::json::*;

    #[test]
    fn get_sdo_from_json() {
        let json_str = r#"{
            "type": "identity",
            "name": "Identity",
            "identity_class": "individual",
            "description": "Responsible for managing personal digital identity",
            "roles": ["User", "Administrator"],
            "sectors": ["Technology","Aerospace"],
            "spec_version": "2.1",
            "contact_information": "alex.johnson@example.com",
            "id": "identity--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z",
            "external_references": [
                {
                    "source_name": "capec",
                    "external_id": "CAPEC-163"
                }
            ]
        }"#;
        let result = get_object_type_from_json(json_str).unwrap();

        assert_eq!(&result, "sdo");
    }
}
