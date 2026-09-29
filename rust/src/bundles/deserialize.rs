//! Custom deserializer for the bundle `objects` array.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::object::StixObject;

/// Custom deserializer function for a `Vec<StixObject>` to make sure each StixObject is deserialized into the correct object type
pub fn deserialize_bundle_objects<'de, D>(deserializer: D) -> Result<Vec<StixObject>, D::Error>
where
    D: Deserializer<'de>,
{
    let values: Vec<Value> = Vec::deserialize(deserializer)?;

    let mut objects = Vec::new();

    for raw_object in values {
        let object = StixObject::from_json(
            &serde_json::to_string(&raw_object).map_err(serde::de::Error::custom)?,
            true,
        )
        .map_err(serde::de::Error::custom)?;
        objects.push(object);
    }

    Ok(objects)
}
