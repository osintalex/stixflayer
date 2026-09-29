//! Reflection helper to access a struct field by name via serde.
use crate::error::StixError as Error;
use serde::{de::DeserializeOwned, Serialize};
use serde_value::Value;

/// Function to get the value of a struct's field given the field name as a &str
/// by serializing the struct then looking for the field name as a key.
///
/// Requires that the struct being checked be serializable and the field
/// property be deserializable.
///
/// Taken from an idea originated by David Tolnay (dtolnay@gmail.com) at
/// <https://users.rust-lang.org/t/access-struct-attributes-by-string/17520/2>
pub fn get_field_by_name<T, R>(data: T, field: &str) -> Result<Option<R>, Error>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut map = match serde_value::to_value(data) {
        Ok(Value::Map(map)) => map,
        _ => {
            return Err(Error::SerializationError(
                "Could not serialize struct for field checking".to_string(),
            ))
        }
    };

    let key = Value::String(field.to_owned());
    let value = match map.remove(&key) {
        Some(value) => value,
        // Key not found in struct
        None => return Ok(None),
    };

    match R::deserialize(value) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(Error::DeserializationError(format!(
            "Could not deserialize value of field checked to correct type: {}",
            e
        ))),
    }
}
