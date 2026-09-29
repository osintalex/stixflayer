//! Contains the implementation logic for unrecognized custom STIX Objects.

use crate::{
    base::{
        validate_custom_property_name, validate_custom_property_suffix_value, CommonProperties, Stix,
    },
    custom_objects::validation::check_custom_object_type,
    cyber_observable_objects::sco::check_sco_properties,
    domain_objects::sdo::check_sdo_properties,
    error::{add_error, return_multiple_errors, StixError as Error},
    relationship_objects::{check_sro_properties, Related, RelationshipObjectBuilder},
    types::{
        get_extension_type, ExtensionType,
        Identified, Identifier,
    },
    validation::validate_value,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use std::{collections::BTreeMap, str::FromStr};

/// A STIX object of unknown type.
///
/// This struct exists to represent custom STIX objects that do not have a recognized "type" field.
/// The object must have an `extensions` dictionary containing an extension with an `extension_type` of "new-sdo", "new-sro", or "new-sco".
///
/// The properties common to all STIX objects are accessible and validated, with the validation informed by the object type inferred from the new object extension.
///
/// Any other fields in the JSON string are stored in a flattened `custom_properties` Map, which will re-serialize back to the same fields when the object is serialized to a
/// JSON string.
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomObject {
    /// Identifies the type of STIX Object.
    #[serde(rename = "type")]
    pub object_type: String,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// Custom properties for the object
    #[serde(flatten)]
    pub custom_properties: BTreeMap<String, Value>,
}

impl CustomObject {
    /// Deserializes a custom object from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        validate_value(value, true, true)
    }

    /// Returns whether a custom STIX Object is an SDO, SRO, or SCO, as determined by its new object extension
    pub fn get_object_type(&self) -> Result<ExtensionType, Error> {
        // Custom Objects in STIX 2.1 MUST include an extension with extension_type of "new-sdo," "new-sro," or "new-sco" defining the object type
        let mut object_type = None;
        match &self.common_properties.extensions {
            Some(extensions) => {
                // Loop through all extensions looking for a custom object extension type (it is possible that there are both custom property and custom object extensions for the same object)
                for (extension_key, extension) in extensions.iter() {
                    let Ok(id) = Identifier::from_str(extension_key) else {
                        continue;
                    };
                    if id.get_type() == "extension-definition" {
                        match get_extension_type(extension).ok_or(Error::CustomMissingExtension)? {
                            // If this is a property extension, keep looking
                            ExtensionType::PropertyExtension => continue,
                            ExtensionType::ToplevelPropertyExtension => continue,
                            object_extension => {
                                object_type = Some(object_extension);
                                break;
                            }
                        }
                    }
                }
            }
            None => return Err(Error::CustomMissingExtension),
        };

        object_type.ok_or(Error::CustomMissingExtension)
    }

    /// Returns the `modified` timestamp as a String if it exists, or `None` if it does not
    pub fn get_modified(&self) -> Option<String> {
        self.common_properties
            .modified
            .as_ref()
            .map(|modified| modified.to_string())
    }

    /// Returns whether the object is revoked or not
    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    /// Adds a sighting SRO to the object
    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

impl Identified for CustomObject {
    /// Returns a reference to the identifier of the `CustomObject`.
    ///
    /// This implementation accesses the `id` field from the `common_properties`
    /// of the `CustomObject`, providing a way to retrieve the unique identifier
    /// associated with this object.
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for CustomObject {
    fn add_relationship<T: Related + Identified>(
        self,
        target: T,
        relationship_type: String,
    ) -> Result<RelationshipObjectBuilder, Error> {
        let source_id = self.get_id().to_owned();
        let target_id = target.get_id().to_owned();

        RelationshipObjectBuilder::new(source_id, target_id, &relationship_type)
    }
}

crate::impl_custom_properties_holder!(CustomObject);

impl Stix for CustomObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut common_errors = Vec::new();

        // Check common properties
        add_error(&mut common_errors, self.common_properties.stix_check());

        // Early return if the common properties are not formatted correctly.
        // We check the common properties first because this will catch any errors in `extensions` before we try to read them
        return_multiple_errors(common_errors)?;

        // Get the custom object type, returning an error if it cannot be found
        let object_type = self.get_object_type()?;

        let mut errors = Vec::new();

        // Validate custom object type name constraints
        add_error(&mut errors, check_custom_object_type(&self.object_type));

        // Check object type specific constraints on common properties
        match object_type {
            // The custom object is an SDO
            ExtensionType::NewSdo => {
                add_error(&mut errors, check_sdo_properties(&self.common_properties));
            }
            // The custom object is an SRO
            ExtensionType::NewSro => {
                add_error(&mut errors, check_sro_properties(&self.common_properties));
            }
            // The custom object is an SCO
            ExtensionType::NewSco => {
                add_error(&mut errors, check_sco_properties(&self.common_properties));
            }
            // This must be a custom object extension type
            _ => unreachable!(),
        }

        // Validate custom property names and any hex/binary suffix values.
        for (key, value) in self.custom_properties.iter() {
            add_error(&mut errors, validate_custom_property_name(key));
            add_error(
                &mut errors,
                validate_custom_property_suffix_value(key, value),
            );
        }

        // Validate custom property values generically as JSON STIX values.
        add_error(&mut errors, self.custom_properties.stix_check());

        return_multiple_errors(errors)
    }
}

