use crate::{
    base::{CommonPropertiesBuilder, Stix},
    error::StixError as Error,
    relationship_objects::types::RelationshipType,
    types::{
        DictionaryValue, ExternalReference, GranularMarking, Identifier, StixDictionary, Timestamp,
    },
};
use std::str::FromStr;

use crate::relationship_objects::{
    Relationship, RelationshipObject, RelationshipObjectType, Sighting,
};

/// Creates a new STIX 2.1 `RelationshipObject` of the given type
#[derive(Clone, Debug)]
pub struct RelationshipObjectBuilder {
    object_type: RelationshipObjectType,
    common_properties: CommonPropertiesBuilder,
    description: Option<String>,
}

impl RelationshipObjectBuilder {
    /// Creates a new STIX 2.1 RelationshipObjectBuilder of the for the given relationship type between two object Identifiers
    ///
    /// The `source`, `target`, and `relationship_type` fields must be lowercase, with words separated by `-`
    ///
    /// Automatically generates an `id`
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new(
        source: Identifier,
        target: Identifier,
        relationship_type: &str,
    ) -> Result<RelationshipObjectBuilder, Error> {
        // Get the relationship type if it is in the STIX list of relationship types, or else create a custom relationship type
        let final_relationship_type =
            RelationshipType::from_str(&relationship_type.replace("-", ""))
                .unwrap_or_else(|_| RelationshipType::Custom(relationship_type.to_string()));
        // Validate that the relationship type is allowed between the source and target (this will never return an error for a custom type)
        final_relationship_type.validate(&source, &target)?;

        // Build the common properties with generated and default values
        let common_properties = CommonPropertiesBuilder::new("sro", "relationship")?;

        // The initial inner `Relationship` struct will be created with default values other than the provided relationship information
        Ok(RelationshipObjectBuilder {
            object_type: RelationshipObjectType::Relationship(Relationship {
                relationship_type: final_relationship_type,
                source_ref: source,
                target_ref: target,
                start_time: Default::default(),
                stop_time: Default::default(),
            }),
            common_properties,
            description: Default::default(),
        })
    }

    /// Creates a new STIX 2.1 RelationshipObjectBuilder for a sighting of an object Identifier
    ///
    /// The `type` field must be lowercase, with words separated by `-`
    ///
    /// Automatically generates an `id`
    /// Other fields are set to their Default (which is `None`` for optional fields)
    pub fn new_sighting(sighting_of_ref: Identifier) -> Result<RelationshipObjectBuilder, Error> {
        let common_properties = CommonPropertiesBuilder::new("sro", "sighting")?;

        // The initial inner `Sighting` struct will be created with default values other than the provided `sighting_of_ref`
        Ok(RelationshipObjectBuilder {
            object_type: RelationshipObjectType::Sighting(Sighting {
                first_seen: Default::default(),
                last_seen: Default::default(),
                count: Default::default(),
                sighting_of_ref,
                observed_data_refs: Default::default(),
                where_sighted_refs: Default::default(),
                summary: Default::default(),
            }),
            common_properties,
            description: Default::default(),
        })
    }

    /// Create a new STIX 2.1 `RelationshipObjectBuilder` by cloning the fields from an existing `RelationshipObject`
    /// When built, this will create `RelationshipObject` as a newer version of the original object.
    pub fn version(old: &RelationshipObject) -> Result<RelationshipObjectBuilder, Error> {
        if old.is_revoked() {
            return Err(Error::UnableToVersion(format!(
                "SRO {} is revoked. Versioning a revoked object is prohibited.",
                old.common_properties.id
            )));
        }

        let object_type = old.object_type.clone();
        let description = old.description.clone();
        let old_properties = old.common_properties.clone();
        let common_properties = CommonPropertiesBuilder::version("sro", &old_properties)?;

        Ok(RelationshipObjectBuilder {
            object_type,
            common_properties,
            description,
        })
    }

    /// Create a builder from an already-parsed SRO, preserving its `id`, `created`,
    /// `modified`, and `revoked` properties exactly. Unlike `version()`, this does
    /// not treat the object as the basis for a new version and does not reject
    /// revoked objects.
    pub fn from_parsed(old: &RelationshipObject) -> Result<RelationshipObjectBuilder, Error> {
        let object_type = old.object_type.clone();
        let description = old.description.clone();
        let old_properties = old.common_properties.clone();
        let common_properties = CommonPropertiesBuilder::from_existing("sro", &old_properties)?;

        Ok(RelationshipObjectBuilder {
            object_type,
            common_properties,
            description,
        })
    }

    // Setter functions for optional properties common to both SRO types

    /// Set the optional `created_by_ref` field for an SRO under construction.
    /// This is only allowed when creating a new SRO, not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        self.common_properties = self.common_properties.clone().created_by_ref(id)?;
        Ok(self)
    }

    /// Set the optional `labels` field for an SRO under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.common_properties = self.common_properties.clone().labels(labels);
        self
    }

    /// Set the optional `confidence` field for an SRO under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.common_properties = self.common_properties.clone().confidence(confidence);
        self
    }

    /// Set the optional `lang` field for an SRO under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.common_properties = self.common_properties.clone().lang(language);
        self
    }

    /// Set the optional `external_references` field for an SRO under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .external_references(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an SRO under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.common_properties = self
            .common_properties
            .clone()
            .object_marking_refs(references);
        self
    }

    /// Set the optional `granular_markings` field for an SRO under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.common_properties = self.common_properties.clone().granular_markings(markings);
        self
    }

    /// Add an optional extension to the `extensions` field for an SRO under construction, creating the field if it does not exist
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

    /// Set the optional `description` field for an SRO under construction
    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    // Setter functions for properties that exist only for generic "relationship" SROs
    // These functions will error if you try to set these properties for a "sighting"

    /// Set the optional `start time` field for a generic SRO under construction.
    pub fn start_time(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Relationship(ref mut relationship) = self.object_type {
            let start_time = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            relationship.start_time = Some(start_time);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "start time".to_string(),
        })
    }

    /// Set the optional `stop time` field for a generic SRO under construction.
    pub fn stop_time(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Relationship(ref mut relationship) = self.object_type {
            let stop_time = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            relationship.stop_time = Some(stop_time);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "stop time".to_string(),
        })
    }

    // Setter functions for properties that exist only for "sighting" SROs
    // These functions will error if you try the property for a a generic "relationship"

    /// Set the optional `first_seen` field for a sightings SRO under construction.
    pub fn first_seen(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            let first_seen = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            sighting.first_seen = Some(first_seen);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "first seen".to_string(),
        })
    }

    /// Set the optional `last_seen` field for a sightings SRO under construction.
    pub fn last_seen(mut self, datetime: &str) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            let last_seen = Timestamp(datetime.parse().map_err(Error::DateTimeError)?);
            sighting.last_seen = Some(last_seen);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "last seen".to_string(),
        })
    }

    /// Set the optional `count` field for a sightings SRO under construction.
    pub fn count(mut self, count: u64) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.count = Some(count);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "count".to_string(),
        })
    }

    /// Set the optional `observed_data_refs` field for a sightings SRO under construction.
    pub fn observed_data_refs(
        mut self,
        observed_data_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.observed_data_refs = Some(observed_data_refs);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "observed data refs".to_string(),
        })
    }

    /// Set the optional `where_sighted_refs` field for a sightings SRO under construction.
    pub fn where_sighted_refs(
        mut self,
        where_sighted_refs: Vec<Identifier>,
    ) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.where_sighted_refs = Some(where_sighted_refs);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "where_sighted_refs".to_string(),
        })
    }

    /// Set the optional `summary` field for a sightings SRO under construction to `Some(true)`.
    pub fn set_summary(mut self) -> Result<Self, Error> {
        if let RelationshipObjectType::Sighting(ref mut sighting) = self.object_type {
            sighting.summary = Some(true);
            return Ok(self);
        }

        Err(Error::IllegalBuilderProperty {
            object: "SROs".to_string(),
            object_type: self.object_type.to_string(),
            field: "summary".to_string(),
        })
    }

    /// Builds a new SRO without running `stix_check()` validation.
    ///
    /// This assembles the final `RelationshipObject` from the builder, but skips
    /// the object-specific `stix_check()`. It is intended for callers that have
    /// already validated the object and only need its typed representation
    /// (e.g. serialization).
    pub fn build_no_validate(self) -> Result<RelationshipObject, Error> {
        let common_properties = self.common_properties.build();

        let sro = RelationshipObject {
            object_type: self.object_type,
            common_properties,
            description: self.description,
        };

        Ok(sro)
    }

    /// Builds a new SRO, using the information found in the `RelationshipObjectBuilder`.
    ///
    /// This assembles the final `RelationshipObject` from the builder and then
    /// runs `stix_check()` on it.
    pub fn build(self) -> Result<RelationshipObject, Error> {
        let sro = self.build_no_validate()?;
        sro.stix_check()?;
        Ok(sro)
    }
}
