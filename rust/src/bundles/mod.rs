//! Contains the implementation logic for STIX Bundles

pub mod deserialize;
#[cfg(test)]
mod tests;
pub mod validation;

pub use deserialize::deserialize_bundle_objects;

use crate::{
    base::Stix,
    error::StixError as Error,
    object::StixObject,
    types::{Identified, Identifier},
};
use serde::{Deserialize, Serialize};

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

    /// Deserialize a bundle from a JSON String and validate the contents of the bundle
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let bundle: Self =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        bundle.stix_check()?;

        Ok(bundle)
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
