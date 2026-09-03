//! Data structures and functions for implementing Marking Definition SMOs

use crate::{
    base::{CommonProperties, CommonPropertiesBuilder, Stix},
    error::{return_multiple_errors, StixError as Error},
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{ExternalReference, GranularMarking, Identified, Identifier, Timestamp},
    validation::validate_value,
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

/// Type Name: marking-definition
/// The marking-definition object represents a specific marking. Data markings typically represent
/// handling or sharing requirements for data and are applied in the object_marking_refs and
///  granular_markings properties on STIX Objects, which reference a list of IDs for marking-definition objects.
///
/// Two marking definition types are defined in this specification: TLP, to capture TLP markings,
/// and Statement, to capture text marking statements. In addition, it is expected that the FIRST
/// Information Exchange Policy (IEP) will be included in a future version once a machine-usable
/// specification for it has been defined.
///
///Unlike other STIX Objects, Marking Definition objects cannot be versioned because it would allow
/// for indirect changes to the markings on a STIX Object. For example, if a Statement marking is
/// changed from "Reuse Allowed" to "Reuse Prohibited", all STIX Objects marked with that Statement
/// marking would effectively have an updated marking without being updated themselves. Instead, a
/// new Statement marking with the new text should be created and the marked objects updated to point
///  to the new marking.
///
/// The JSON MTI serialization uses the JSON Object type [RFC8259](http://www.rfc-editor.org/info/rfc8259)
/// when representing marking-definition.
///
///

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct MarkingDefinition {
    #[serde(rename = "type")]
    pub object_type: String,
    /// Common STIX object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// A name used to identify the Marking Definition.
    pub name: Option<String>,
    /// The definition_type property identifies the type of Marking Definition.
    pub definition_type: Option<String>,
    /// The definition property contains the marking object itself (e.g., the TLP marking as defined in section 7.2.1.4, the Statement marking as defined in section 7.2.1.3).
    pub definition: Option<MarkingTypes>,
}
impl MarkingDefinition {
    /// Deserializes a MarkingDefinition SMO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard.
    /// If the `allow_custom` flag is false, checks that there are no fields in the JSON String
    /// that are not in the Marking Definition SMO type definition.
    pub fn from_json(json: &str, strict: bool, allow_custom: bool) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        validate_value(value, allow_custom, strict)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

impl Identified for MarkingDefinition {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for MarkingDefinition {
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

impl Stix for MarkingDefinition {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if self.common_properties.spec_version.is_none() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs must have a `spec_version` property.".to_string(),
            ));
        }
        if self.common_properties.created.is_none() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs must have a `created` property.".to_string(),
            ));
        }
        if self.common_properties.extensions.is_none()
            && (self.definition_type.is_none() || self.definition.is_none())
        {
            errors.push(Error::ValidationError(
                "Need properties extension to be present OR definition type or definition(exclusive).".to_string(),
            ));
        }
        if let Some(definition_type) = &self.definition_type {
            if definition_type != "tlp" && definition_type != "statement" {
                warn!("defnition_type SHOULD be from open-vocab either tlp or statement")
            }
        }
        if self.common_properties.defanged.is_some() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs cannot have a `defanged` property.".to_string(),
            ));
        }
        if self.common_properties.modified.is_some() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs cannot have a `modified` property.".to_string(),
            ));
        }
        if self.common_properties.revoked.is_some() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs cannot have a `revoked` property.".to_string(),
            ));
        }
        if self.common_properties.labels.is_some() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs cannot have a `labels` property.".to_string(),
            ));
        }
        if self.common_properties.confidence.is_some() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs cannot have a `confidence` property.".to_string(),
            ));
        }
        if self.common_properties.lang.is_some() {
            errors.push(Error::ValidationError(
                "Marking Definition SMOs cannot have a `lang` property.".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

/// Builder struct for Marking Definition SMOs.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `LanguageContent` struct.
///
/// Note: Because the `schema`, `version`, and `extension_types` properties are required for Marking Definition SMOs,
/// the `build()` method will error if those fields are not set before it is called.
#[derive(Clone, Debug)]
pub struct MarkingDefinitionBuilder {
    /// Common STIX properties
    common_properties: CommonPropertiesBuilder,
    name: Option<String>,
    definition_type: Option<String>,
    definition: Option<MarkingTypes>,
}

impl MarkingDefinitionBuilder {
    // Creates a new STIX 2.1 `MarkingDefinitionBuilder` with a given name
    ///
    /// Automatically generates an `id`
    ///
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new() -> Result<Self, Error> {
        // Build the common properties with generated and default values
        let common_properties =
            CommonPropertiesBuilder::new("marking-definition", "marking-definition")?;

        Ok(Self {
            common_properties,
            name: Default::default(),
            definition_type: Default::default(),
            definition: Default::default(),
        })
    }
    // Setter functions for common properties

    /// Set the optional `created_by_ref` field for a Marking Definition SMO under construction
    /// This is only allowed when creating a new Marking Definition SMO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `external_references` field for a Marking Definition SMO under construction
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for a Marking Definition SMO under construction
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for a Marking Definition SMO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    /// Set the `created` timestamp for a Marking Definition SMO under construction.
    ///
    /// Marking definitions cannot have a `modified` timestamp, so only `created`
    /// is exposed.
    pub fn created(mut self, created: Timestamp) -> Self {
        self.common_properties = self.common_properties.clone().created(created);
        self
    }

    /// Set the optional `extension_properties` field for a Marking Definition SMO under construction
    pub fn definition_type(mut self, definition_type: String) -> Self {
        self.definition_type = Some(definition_type);
        self
    }

    /// Set the optional `extension_properties` field for a Marking Definition SMO under construction
    pub fn definition(mut self, definition: MarkingTypes) -> Self {
        self.definition = Some(definition);
        self
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Builds a new Marking Definition SMO without running `stix_check()` validation.
    ///
    /// This assembles the final `MarkingDefinition` object from the builder, but
    /// skips the object-specific `stix_check()`. It is intended for callers that
    /// have already validated the object and only need its typed representation
    /// (e.g. serialization).
    pub fn build_no_validate(self) -> Result<MarkingDefinition, Error> {
        let common_properties = self.common_properties.build();

        let name = self.name;
        let definition_type = self.definition_type;
        let definition = self.definition;

        let marking_definition = MarkingDefinition {
            object_type: "marking-definition".to_string(),
            common_properties,
            name,
            definition_type,
            definition,
        };

        Ok(marking_definition)
    }

    /// Builds a new Marking Definition SMO, using the information found in the
    /// `MarkingDefinitionBuilder`.
    ///
    /// This assembles the final `MarkingDefinition` object from the builder and
    /// then runs `stix_check()` on it.
    pub fn build(self) -> Result<MarkingDefinition, Error> {
        let marking_definition = self.build_no_validate()?;
        marking_definition.stix_check()?;
        Ok(marking_definition)
    }

    /// Create a builder from an existing MarkingDefinition
    pub fn version(old: &MarkingDefinition) -> Result<Self, Error> {
        let old_properties = old.common_properties.clone();
        let common_properties =
            CommonPropertiesBuilder::version("marking-definition", &old_properties)?;
        Ok(Self {
            common_properties,
            name: old.name.clone(),
            definition_type: old.definition_type.clone(),
            definition: old.definition.clone(),
        })
    }

    /// Create a builder from an already-parsed MarkingDefinition, preserving its
    /// `id`, `created`, `modified`, and `revoked` properties exactly. Unlike
    /// `version()`, this does not treat the object as the basis for a new version.
    pub fn from_parsed(old: &MarkingDefinition) -> Result<Self, Error> {
        let old_properties = old.common_properties.clone();
        let common_properties =
            CommonPropertiesBuilder::from_existing("marking-definition", &old_properties)?;
        Ok(Self {
            common_properties,
            name: old.name.clone(),
            definition_type: old.definition_type.clone(),
            definition: old.definition.clone(),
        })
    }
}

/// enum to for the different types in defintinition
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MarkingTypes {
    Tlp(TLP),
    Statement(Statement),
}

impl Stix for MarkingTypes {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TLP {
    pub tlp: String,
}

impl Stix for TLP {
    fn stix_check(&self) -> Result<(), Error> {
        if self.tlp != "white" && self.tlp != "red" && self.tlp != "amber" && self.tlp != "green" {
            return Err(Error::ValidationError(
                "TLP value must be one of the four TLP levels".to_string(),
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub statement: String,
}

impl Stix for Statement {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}
