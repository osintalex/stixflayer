//! STIX 2.1 dictionaries and primitive dictionary values.
use crate::{
    base::Stix,
    common::string::stix_case,
    error::{add_error, return_multiple_errors, StixError as Error},
    taxonomy::ExtensionType,
};
use log::warn;
use ordered_float::OrderedFloat;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};

/// A STIX 2.1 compliant dictionary that captures an set of key/value pairs.
///
/// The dictionary key is a string that must satisfy certain constraints, which are checked when a new entry is added.
/// The value can be any valid STIX type. This must be checked.
///
/// Becuase the dictionary is stored as a Rust BTreeMap, the entries will always be serialized orderd by key, not by entry order
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f6e8afjdtrse>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StixDictionary<T: Stix>(BTreeMap<String, T>);

impl<T: Stix> StixDictionary<T> {
    /// Creates a new Stix 2.1 compliant dictionary
    ///
    /// Note: STIX 2.1 requires that dictionaries cannot be empty,
    /// so at least one entry must be added to the dictionary with the `insert()` method or the dictionary will not pass validation
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds a valid key/value pair to a dictionary
    pub fn insert(&mut self, key: &str, value: T) -> Result<(), Error> {
        // Make sure the key is a valid STIX Dictionary key
        if check_dictionary_key(key) {
            // We do not allow duplicate keys
            match self.0.insert(key.to_string(), value) {
                Some(_duplicate_key) => Err(Error::ValidationError(format!(
                    "Duplicate value specified for {}",
                    key
                ))),
                None => Ok(()),
            }
        } else {
            Err(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
        }
    }

    /// Retrieves the value for a given key in a dictionary
    pub fn get(&self, key: &str) -> Option<&T> {
        self.0.get(key)
    }

    /// Creates an iterator for the keys of the dictionary
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    /// Creates an iterator for the key/value pairs of the dictionary
    pub fn iter(&self) -> impl Iterator<Item = (&String, &T)> {
        self.0.iter()
    }
}

impl<T: Stix> Default for StixDictionary<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Stix> Stix for StixDictionary<T> {
    fn stix_check(&self) -> Result<(), Error> {
        // Empty dictionaries are prohibited in STIX
        if self.0.is_empty() {
            return Err(Error::EmptyList);
        }
        // If the dicitonary is non-empty, check that each key is valid.
        let mut errors = Vec::new();
        for (key, val) in self.iter() {
            if !check_dictionary_key(key) {
                errors.push(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
            }
            add_error(&mut errors, val.stix_check());
        }

        return_multiple_errors(errors)
    }
}

// Checks that the provided dictionary key is STIX 2.1 compliant and provides warnings if it compliant but against recommendations
fn check_dictionary_key(key: &str) -> bool {
    let valid = key.len() <= 250
        && (key
            .chars()
            .all(|c| c.is_ascii() && (c.is_alphanumeric() || c == '-' || c == '_')));

    if key.chars().any(|c| c.is_uppercase()) {
        warn!(
            "STIX 2.1 recommends that dictionary keys should be lowercase. Key value is {}.",
            key
        );
    }

    valid
}

/// Strict dictionary key validation for observable contexts.
///
/// This is stricter than the base STIX spec (which allows uppercase and keys up to 250 chars)
/// and aligns with stix2validator strict mode for observable dictionary keys.
///
/// Returns `Err` if the key contains uppercase characters or exceeds 30 characters.
pub fn check_observable_dictionary_key(key: &str) -> Result<(), Error> {
    if key.chars().any(|c| c.is_uppercase()) {
        return Err(Error::ValidationError(format!(
            "Observable dictionary key '{}' contains uppercase characters. Dictionary keys SHOULD be lowercase.",
            key
        )));
    }
    if key.len() > 30 {
        return Err(Error::ValidationError(format!(
            "Observable dictionary key '{}' exceeds the maximum length of 30 characters.",
            key
        )));
    }
    Ok(())
}

/// Possible primitive dictionary values
///
/// This enum is to cover the case of different primitive types being stored in the same STIX dictionary
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum DictionaryValue {
    String(String),
    Bool(bool),
    Int(u64),
    SInt(i64),
    Float(OrderedFloat<f64>),
    List(Vec<DictionaryValue>),
    Dict(StixDictionary<DictionaryValue>),
}

impl fmt::Display for DictionaryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DictionaryValue::String(string) => write!(f, "{string}"),
            DictionaryValue::Bool(bool) => write!(f, "{bool}"),
            DictionaryValue::Int(int) => write!(f, "{int}"),
            DictionaryValue::SInt(signed) => write!(f, "{signed}"),
            DictionaryValue::Float(float) => write!(f, "{float}"),
            DictionaryValue::List(list) => {
                let mut vec_string = String::new();
                vec_string.push('[');

                for item in list {
                    vec_string.push_str(&item.to_string());
                    vec_string.push_str(", ");
                }

                // Remove the space after the last item in the list
                vec_string.pop();
                vec_string.pop();
                vec_string.push(']');
                write!(f, "{vec_string}")
            }
            DictionaryValue::Dict(dict) => {
                let mut dict_string = String::new();
                dict_string.push('{');

                for (key, value) in dict.iter() {
                    dict_string.push_str(&format!("{}: {}", key, value));
                    dict_string.push_str(", ");
                }

                // Remove the space after the last item in the list
                dict_string.pop();
                dict_string.pop();
                dict_string.push('}');
                write!(f, "{dict_string}")
            }
        }
    }
}

impl Stix for DictionaryValue {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            DictionaryValue::String(string) => string.stix_check(),
            DictionaryValue::Bool(bool) => bool.stix_check(),
            DictionaryValue::Int(int) => int.stix_check(),
            DictionaryValue::SInt(_signed) => Ok(()),
            DictionaryValue::Float(float) => float.stix_check(),
            DictionaryValue::List(list) => list.stix_check(),
            DictionaryValue::Dict(dict) => dict.stix_check(),
        }
    }
}

/// Gets the extension type for a general extension
pub fn get_extension_type(extension: &StixDictionary<DictionaryValue>) -> Option<ExtensionType> {
    match extension.get("extension_type") {
        Some(DictionaryValue::String(extension_type)) => {
            ExtensionType::from_str(&stix_case(extension_type)).ok()
        }
        _ => None,
    }
}
