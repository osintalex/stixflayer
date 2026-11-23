//! Contains the implementation logic for STIX Bundles

pub mod deserialize;
#[cfg(test)]
mod tests;
pub mod validation;

pub use deserialize::deserialize_bundle_objects;

use crate::{
    error::{add_error, return_multiple_errors, Entry, Outcome, StixError as Error},
    object::StixObject,
    types::{Identified, Identifier},
    validation::ValidationOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Bundle is a collection of arbitrary STIX Objects grouped together in a single container.
///
/// A Bundle does not have any semantic meaning and the objects contained within the Bundle are not considered related by virtue of being in the same Bundle.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gms872kuzdmg>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// The type property identifies the type of object.
    ///
    /// The value of this property **MUST** be bundle.
    #[serde(rename = "type")]
    pub object_type: String,
    /// An identifier for this Bundle
    pub id: Identifier,
    /// Specifies a set of one or more STIX Objects.
    ///
    /// Objects in this list **MUST** be a STIX Object.
    #[serde(deserialize_with = "deserialize_bundle_objects")]
    pub objects: Vec<StixObject>,
}

impl Bundle {
    /// Construct a new STIX bundle, starting with an initial STIX object (because Lists in STIX 2.1 cannot be empty)
    pub fn new(object: StixObject) -> Self {
        // Panic: Safe to unwrap becuse "bundle" is valid STIX object type
        Self {
            object_type: "bundle".to_string(),
            id: Identifier::new("bundle").unwrap(),
            objects: vec![object],
        }
    }

    /// Add an additional STIX object to an existing Stix bundle
    pub fn add(&mut self, object: StixObject) {
        self.objects.push(object);
    }

    /// Add an additional STIX object to an existing Stix bundle from a raw JSON string.
    pub fn push_json(&mut self, json: &str) -> Result<(), Error> {
        let object = StixObject::from_json(json, false)?;
        self.objects.push(object);
        Ok(())
    }

    /// Deserialize a bundle from a JSON String and validate the contents of the bundle.
    ///
    /// Each object is validated exactly once through the outcome pipeline; the
    /// bundle then runs only its own invariants (type, id, non-empty, duplicate
    /// ids, and enforce-refs).
    pub fn from_json(json: &str) -> Result<Self, Error> {
        Self::from_json_parts(json).0
    }

    /// Deserialize a bundle with explicit validation options.
    pub fn from_json_with_options(json: &str, options: ValidationOptions) -> Result<Self, Error> {
        Self::from_json_parts_with_options(json, options).0
    }

    /// Deserialize a bundle and return the warnings collected from every object.
    pub fn from_json_outcome(json: &str) -> Outcome<Self> {
        Self::from_json_outcome_with_options(json, ValidationOptions::new(true, true))
    }

    /// Deserialize a bundle with explicit validation options and return warnings.
    pub fn from_json_outcome_with_options(json: &str, options: ValidationOptions) -> Outcome<Self> {
        let (result, warnings) = Self::from_json_parts_with_options(json, options);
        Outcome::from_result(result, warnings)
    }

    /// Shared implementation for [`Self::from_json`] and
    /// [`Self::from_json_outcome`].
    pub fn from_json_parts(json: &str) -> (Result<Self, Error>, Vec<Entry>) {
        Self::from_json_parts_with_options(json, ValidationOptions::new(true, true))
    }

    /// Options-aware shared implementation for bundle parsing.
    pub fn from_json_parts_with_options(
        json: &str,
        options: ValidationOptions,
    ) -> (Result<Self, Error>, Vec<Entry>) {
        #[derive(Deserialize)]
        struct RawBundle {
            #[serde(rename = "type")]
            object_type: String,
            id: Identifier,
            objects: Vec<Value>,
        }

        let raw: RawBundle = match serde_json::from_str(json) {
            Ok(raw) => raw,
            Err(e) => return (Err(Error::DeserializationError(e.to_string())), Vec::new()),
        };

        let mut objects = Vec::with_capacity(raw.objects.len());
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        for value in raw.objects {
            let (result, mut object_warnings) =
                StixObject::from_value_parts_with_options(value, options);
            warnings.append(&mut object_warnings);
            match result {
                Ok(object) => objects.push(object),
                Err(error) => errors.push(error),
            }
        }

        let bundle = Self {
            object_type: raw.object_type,
            id: raw.id,
            objects,
        };

        if errors.is_empty() {
            add_error(&mut errors, bundle.check_invariants());
        }

        (return_multiple_errors(errors).map(|()| bundle), warnings)
    }

    /// Return a list of all objects in the bundle
    pub fn get_objects(&self) -> Vec<StixObject> {
        self.objects.clone()
    }
}

impl Identified for Bundle {
    fn get_id(&self) -> &Identifier {
        &self.id
    }
}
