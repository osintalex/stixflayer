//! Contains the implementation logic for unrecognized custom STIX Objects.

use crate::{
    base::{
        CommonPropertiesBuilder, Stix,
    },
    custom_objects::object::CustomObject,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{
        stix_case, DictionaryValue, ExtensionType, ExternalReference, Identifier, StixDictionary, Timestamp,
    },
};
use serde_json::Value;
use std::{collections::BTreeMap, str::FromStr};

/// Builder struct for Custom Objects.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `CustomObject` struct.
#[derive(Clone, Debug)]
pub struct CustomObjectBuilder {
    // The object type
    object_type: String,
    // Common STIX object properties
    common_properties: CommonPropertiesBuilder,
    // The map of custom properties
    custom_properties: BTreeMap<String, Value>,
}

impl CustomObjectBuilder {
    /// Creates a new STIX 2.1 `CustomObjectBuilder` for an SDO with a given name, map of custom properties, and extension definition id for the "new-sdo" extension
    ///
    /// Automatically generates an `id`
    /// Other  fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sdo(
        type_name: &str,
        custom_properties: BTreeMap<String, Value>,
        extension_definition: &str,
    ) -> Result<CustomObjectBuilder, Error> {
        // Build the common properties with generated and default values
        let default_common_properties = CommonPropertiesBuilder::new("sdo", type_name)?;

        // Create a "new-sdo" extension
        let mut object_extension = StixDictionary::new();
        object_extension.insert(
            "extension_type",
            DictionaryValue::String("new-sdo".to_string()),
        )?;

        // Add that extension, with its extension definition id, to the common properties
        let common_properties =
            default_common_properties.add_extension(extension_definition, object_extension)?;

        Ok(CustomObjectBuilder {
            object_type: type_name.to_string(),
            common_properties,
            custom_properties,
        })
    }

    /// Creates a new STIX 2.1 `CustomObjectBuilder` for an SRO with a given name, map of custom properties, and extension definition id for the "new-sro" extension
    ///
    /// Automatically generates an `id`
    /// Other  fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sro(
        type_name: &str,
        custom_properties: BTreeMap<String, Value>,
        extension_definition: &str,
    ) -> Result<CustomObjectBuilder, Error> {
        // Build the common properties with generated and default values
        let default_common_properties = CommonPropertiesBuilder::new("sro", type_name)?;

        // Create a "new-sro" extension
        let mut object_extension = StixDictionary::new();
        object_extension.insert(
            "extension_type",
            DictionaryValue::String("new-sro".to_string()),
        )?;

        // Add that extension, with its extension definition id, to the common properties
        let common_properties =
            default_common_properties.add_extension(extension_definition, object_extension)?;

        Ok(CustomObjectBuilder {
            object_type: type_name.to_string(),
            common_properties,
            custom_properties,
        })
    }

    /// Creates a new STIX 2.1 `CustomObjectBuilder` for an SCO with a given name, map of custom properties, and extension definition id for the "new-sco" extension
    ///
    /// Automatically generates a UUIDv4-based `id`
    /// Other  fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sco(
        type_name: &str,
        custom_properties: BTreeMap<String, Value>,
        extension_definition: &str,
    ) -> Result<CustomObjectBuilder, Error> {
        // Build the common properties with generated and default values
        let default_common_properties = CommonPropertiesBuilder::new("sco", type_name)?;

        // Create a "new-sco" extension
        let mut object_extension = StixDictionary::new();
        object_extension.insert(
            "extension_type",
            DictionaryValue::String("new-sco".to_string()),
        )?;

        // Add that extension, with its extension definition id, to the common properties
        let common_properties =
            default_common_properties.add_extension(extension_definition, object_extension)?;

        Ok(CustomObjectBuilder {
            object_type: type_name.to_string(),
            common_properties,
            custom_properties,
        })
    }

    /// Create a new STIX 2.1 `CustomObjectBuilder` by cloning the fields from an already-parsed
    /// `CustomObject`, preserving its `id`, `created`, `modified`, and `revoked` properties exactly.
    /// Unlike `version()`, this does not treat the object as the basis for a new version.
    pub fn from_parsed(old: &CustomObject) -> Result<CustomObjectBuilder, Error> {
        let object_type = old.get_object_type()?;
        let object_type_name = old.object_type.clone();
        let custom_properties = old.custom_properties.clone();

        // Find the extension-definition key that declares this as a custom object.
        let ext_def_id = old
            .common_properties
            .extensions
            .as_ref()
            .and_then(|exts| {
                for (key, ext) in exts.iter() {
                    if Identifier::from_str(key)
                        .map(|id| id.get_type() == "extension-definition")
                        .unwrap_or(false)
                    {
                        if let Some(DictionaryValue::String(val)) = ext.get("extension_type") {
                            if val != "property-extension" && val != "toplevel-property-extension" {
                                return Some(key.as_str());
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or("extension-definition--00000000-0000-0000-0000-000000000000");

        let mut builder = match object_type {
            ExtensionType::NewSdo => {
                CustomObjectBuilder::new_sdo(&object_type_name, custom_properties, ext_def_id)?
            }
            ExtensionType::NewSro => {
                CustomObjectBuilder::new_sro(&object_type_name, custom_properties, ext_def_id)?
            }
            ExtensionType::NewSco => {
                CustomObjectBuilder::new_sco(&object_type_name, custom_properties, ext_def_id)?
            }
            _ => unreachable!(),
        };

        let object_name = match object_type {
            ExtensionType::NewSdo => "sdo",
            ExtensionType::NewSro => "sro",
            ExtensionType::NewSco => "sco",
            _ => unreachable!(),
        };
        builder.common_properties =
            CommonPropertiesBuilder::from_existing(object_name, &old.common_properties)?;

        Ok(builder)
    }

    /// Create a new STIX 2.1 `CustomObjectBuilder` by cloning the fields from an existing `CustomObject`
    /// When built, this will create `CustomObject` as a newer version of the original object.
    ///
    /// Only custom SDOs and SROs can be versioned
    pub fn version(old: &CustomObject) -> Result<CustomObjectBuilder, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "Custom object {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        if old.get_object_type()? == ExtensionType::NewSco {
            return Err(Error::UnableToVersion(format!(
                "Custom object {} is an SCO. SCOs cannot be versioned.",
                old.common_properties.id
            )));
        }

        let object_type = old.object_type.clone();
        let old_properties = old.common_properties.clone();
        let common_properties = CommonPropertiesBuilder::version("sdo", &old_properties)?;
        let custom_properties = old.custom_properties.clone();

        Ok(CustomObjectBuilder {
            object_type,
            common_properties,
            custom_properties,
        })
    }

    // Setter functions for optional common properties

    /// Set the optional `created_by_ref` field for a custom object under construction.
    /// This is only allowed when creating a new object, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for a custom object under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for a custom object under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `lang` field for a custom object under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.common_properties = self.common_properties.clone().lang(language);
        self
    }

    /// Set the `created` timestamp for a custom object under construction.
    pub fn created(mut self, created: Timestamp) -> Self {
        self.common_properties = self.common_properties.clone().created(created);
        self
    }

    /// Set the `modified` timestamp for a custom object under construction.
    pub fn modified(mut self, modified: Timestamp) -> Self {
        self.common_properties = self.common_properties.clone().modified(modified);
        self
    }

    /// Set the optional `external_references` field for a custom object under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for a custom object under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Add an additional extension to the `extensions` field for a custom object under construction
    pub fn add_extension(
        mut self,
        key: &str,
        extension: StixDictionary<DictionaryValue>,
    ) -> Result<Self, Error> {
        self.common_properties = self
            .common_properties
            .clone()
            .add_extension(key, extension)?;
        Ok(self)
    }

    /// Builds a new custom STIX object without running validation.
    ///
    /// This assembles the final `CustomObject` from the builder, skipping the
    /// object-specific validation. It is intended for callers that have already
    /// validated the object and only need its typed representation
    /// (e.g. serialization).
    pub fn build_no_validate(self) -> Result<CustomObject, Error> {
        let common_properties = self.common_properties.build();

        let object = CustomObject {
            object_type: self.object_type,
            common_properties,
            custom_properties: self.custom_properties,
        };

        Ok(object)
    }

    /// Builds a new custom STIX object, using the information found in the
    /// `CustomObjectBuilder`.
    ///
    /// This assembles the final `CustomObject` and runs validation on it.
    pub fn build(self) -> Result<CustomObject, Error> {
        let object = self.build_no_validate()?;
        let mut errors = Vec::new();

        // Check required and prohibited fields for the object type
        let object_type = object.get_object_type()?;

        if object_type == ExtensionType::NewSco {
            if object.common_properties.created_by_ref.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "created_by_ref".to_string(),
                });
            }

            if object.common_properties.revoked.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "revoked".to_string(),
                });
            }

            if object.common_properties.labels.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "labels".to_string(),
                });
            }

            if object.common_properties.confidence.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "confidence".to_string(),
                });
            }

            if object.common_properties.lang.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "lang".to_string(),
                });
            }

            if object.common_properties.external_references.is_some() {
                errors.push(Error::IllegalBuilderProperty {
                    object: "Custom objects".to_string(),
                    object_type: "SCO".to_string(),
                    field: "external_references".to_string(),
                });
            }
        }

        if object_type != ExtensionType::NewSco && object.common_properties.defanged.is_some() {
            errors.push(Error::IllegalBuilderProperty {
                object: "Custom objects".to_string(),
                object_type: stix_case(object_type.as_ref()),
                field: "defanged".to_string(),
            });
        }

        add_error(&mut errors, object.stix_check());

        return_multiple_errors(errors)?;

        Ok(object)
    }
}

