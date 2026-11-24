//! Contains the implementation logic for unrecognized custom STIX Objects.

use crate::error::CheckContext;
use crate::{
    base::{
        validate_custom_property_name, validate_custom_property_suffix_value, CommonProperties,
        Stix,
    },
    custom_objects::validation::check_custom_object_type,
    cyber_observable_objects::sco::check_sco_properties,
    domain_objects::sdo::check_sdo_properties,
    error::{add_error, return_multiple_errors, Entry, StixError as Error},
    relationship_objects::{check_sro_properties, Related, RelationshipObjectBuilder},
    types::{get_extension_type, ExtensionType, Identified, Identifier},
    validation::validate_value,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use std::{collections::BTreeMap, str::FromStr};

/// The object kind inferred for a custom object.
///
/// A custom object can declare that it is a new SDO, SCO, or SRO through an
/// `extensions` entry with the corresponding `extension_type`. Without such a
/// declaration it is a generic custom object: STIX 2.1 §11.2 says custom
/// objects **SHOULD** use the extension mechanism, not MUST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustomObjectKind {
    /// A custom object declared as a new SDO.
    Sdo,
    /// A custom object declared as a new SCO.
    Sco,
    /// A custom object declared as a new SRO.
    Sro,
    /// A custom object without a new-object extension.
    Generic,
}

impl CustomObjectKind {
    /// Returns the corresponding extension type, or `None` for a generic
    /// custom object.
    pub fn extension_type(self) -> Option<ExtensionType> {
        match self {
            Self::Sdo => Some(ExtensionType::NewSdo),
            Self::Sco => Some(ExtensionType::NewSco),
            Self::Sro => Some(ExtensionType::NewSro),
            Self::Generic => None,
        }
    }
}

/// A STIX object of unknown type.
///
/// This struct represents custom STIX objects that do not have a recognized
/// `type` field. A custom object may declare itself as a new SDO, SCO, or SRO
/// with an `extensions` entry whose `extension_type` is `new-sdo`, `new-sco`,
/// or `new-sro`. Without that declaration it is validated as a generic custom
/// object under the §11.2 custom-object rules.
///
/// The properties common to all STIX objects are accessible and validated. Any
/// other fields in the JSON string are stored in a flattened
/// `custom_properties` map, which re-serializes back to the same fields.
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

    /// Returns the kind inferred from the object's new-object extension.
    ///
    /// A custom object without a `new-sdo`, `new-sco`, or `new-sro` extension is
    /// [`CustomObjectKind::Generic`]. STIX 2.1 §11.2 makes the extension
    /// mechanism a SHOULD, so this is not an error.
    pub fn get_kind(&self) -> CustomObjectKind {
        let Some(extensions) = &self.common_properties.extensions else {
            return CustomObjectKind::Generic;
        };

        // Look through all extensions for a custom object extension type. It is
        // possible to have both property and new-object extensions on one object.
        for (extension_key, extension) in extensions.iter() {
            let Ok(id) = Identifier::from_str(extension_key) else {
                continue;
            };
            if id.get_type() != "extension-definition" {
                continue;
            }
            match get_extension_type(extension) {
                Some(ExtensionType::NewSdo) => return CustomObjectKind::Sdo,
                Some(ExtensionType::NewSco) => return CustomObjectKind::Sco,
                Some(ExtensionType::NewSro) => return CustomObjectKind::Sro,
                // Property extensions do not declare an object kind.
                Some(ExtensionType::PropertyExtension)
                | Some(ExtensionType::ToplevelPropertyExtension) => continue,
                None => continue,
            }
        }

        CustomObjectKind::Generic
    }

    /// Returns the new-object extension type, or `None` for a generic custom
    /// object.
    pub fn get_object_type(&self) -> Option<ExtensionType> {
        self.get_kind().extension_type()
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
    fn check(&self, ctx: &mut CheckContext) -> Result<(), Error> {
        ctx.set_object_id(Some(self.get_id().to_string()));
        let mut common_errors = Vec::new();

        // Check common properties
        add_error(&mut common_errors, self.common_properties.check(ctx));

        // Early return if the common properties are not formatted correctly.
        // We check the common properties first because this will catch any errors in `extensions` before we try to read them
        return_multiple_errors(common_errors)?;

        let kind = self.get_kind();

        // A missing new-object extension is a SHOULD finding, not an error.
        // §11.2 says custom objects SHOULD use the extension mechanism.
        if kind == CustomObjectKind::Generic {
            ctx.warn(
                Entry::new(
                    "custom_missing_extension",
                    format!(
                        "Custom object {} does not declare a new-sdo, new-sco, or new-sro extension; it was validated as a generic custom object",
                        self.common_properties.id
                    ),
                )
                .property("extensions"),
            );
        }

        let mut errors = Vec::new();

        // Validate custom object type name constraints
        add_error(&mut errors, check_custom_object_type(&self.object_type));

        // The identifier must use the same object type as the object.
        if self.common_properties.id.get_type() != self.object_type {
            errors.push(Error::ValidationError(format!(
                "The `id` prefix '{}' does not match the custom object type '{}'",
                self.common_properties.id.get_type(),
                self.object_type
            )));
        }
        add_error(&mut errors, self.common_properties.id.check(ctx));

        // Check object type specific constraints on common properties
        match kind {
            // The custom object is an SDO
            CustomObjectKind::Sdo => {
                add_error(&mut errors, check_sdo_properties(&self.common_properties));
            }
            // The custom object is an SRO
            CustomObjectKind::Sro => {
                add_error(&mut errors, check_sro_properties(&self.common_properties));
            }
            // The custom object is an SCO
            CustomObjectKind::Sco => {
                add_error(&mut errors, check_sco_properties(&self.common_properties));
            }
            // Generic custom objects do not have SDO/SCO/SRO-specific
            // common-property requirements.
            CustomObjectKind::Generic => {}
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
        add_error(&mut errors, self.custom_properties.check(ctx));

        return_multiple_errors(errors)
    }
}
