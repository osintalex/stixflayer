//! Data structures and functions for implementing STIX Relationship Objects (SROs).
#![allow(dead_code)]

pub mod builder;
pub mod relationship;
pub mod sighting;
pub mod validation;

pub use builder::RelationshipObjectBuilder;
pub use relationship::Relationship;
pub use sighting::Sighting;
pub use validation::check_sro_properties;

pub mod types;

use crate::{
    base::{CommonProperties, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{Identified, Identifier},
    validation::validate_value,
};
use stix_derive::StixProperties;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::{AsRefStr, Display as StrumDisplay};

/// A trait for all STIX Objects that can be related by SROs.
pub trait Related {
    fn add_relationship<T: Related + Identified>(
        self,
        target: T,
        relationship_type: String,
    ) -> Result<RelationshipObjectBuilder, Error>;
}

/// Represents a STIX Relationship Object (SRO).
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RelationshipObject {
    /// Identifies the type of STIX Object.
    ///
    /// For SROs, this is either "relationship" for a generic relationship or "sighting"
    #[serde(flatten)]
    pub object_type: RelationshipObjectType,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
    /// Provides more details and context about the Relationship, potentially including its purpose and its key characteristics.
    pub description: Option<String>,
}

impl RelationshipObject {
    /// Deserializes an SRO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard.
    /// If the `allow_custom` flag is false, checks that there are no fields in the JSON String
    /// that are not in the SRO type definition.
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        validate_value(value, allow_custom, true)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    /// Retunrs the relationship type for generic SROs or "sighting" if the SRO is a Sighting
    pub fn get_relationship_type(&self) -> &str {
        match &self.object_type {
            RelationshipObjectType::Relationship(relationship) => {
                relationship.relationship_type.as_ref()
            }
            RelationshipObjectType::Sighting(_) => "sighting",
        }
    }
}

/// Returns a reference to the identifier of the `RelationshipObject`.
// This implementation accesses the `id` field from the `common_properties`
// of the `RelationshipObject`, providing a way to retrieve the unique
// identifier associated with this object.
impl Identified for RelationshipObject {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Stix for RelationshipObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SRO
        add_error(&mut errors, check_sro_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check specific properties for the type of SRO
        match &self.object_type {
            RelationshipObjectType::Relationship(relationship) => add_error(
                &mut errors,
                relationship.stix_check().map_err(|e| {
                    Error::ValidationError(format!(
                        "Relationship Object {} is not a valid generic relationship: {}",
                        self.get_id(),
                        e
                    ))
                }),
            ),
            RelationshipObjectType::Sighting(sighting) => add_error(
                &mut errors,
                sighting.stix_check().map_err(|e| {
                    Error::ValidationError(format!(
                        "Relationship Object {} is not a valid sighting: {}",
                        self.get_id(),
                        e
                    ))
                }),
            ),
        }

        return_multiple_errors(errors)
    }
}

crate::impl_custom_properties_holder!(RelationshipObject);

/// Whether the SRO is a standard generic or a sighting
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AsRefStr, StrumDisplay, StixProperties,
)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum RelationshipObjectType {
    Relationship(Relationship),
    Sighting(Sighting),
}
