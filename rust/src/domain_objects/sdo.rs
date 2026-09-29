//! Contains the implementation logic for Stix Domain Objects (SDOs).

#![allow(dead_code)]

use crate::{
    base::{CommonProperties, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{Identified, Identifier},
    validation::validate_value,
};

#[cfg(test)]
use crate::types::Timestamp;

pub mod attack_pattern;
pub mod campaign;
pub mod course_of_action;
pub mod grouping;
pub mod identity;
pub mod incident;
pub mod indicator;
pub mod infrastructure;
pub mod intrusion_set;
pub mod location;
pub mod malware;
pub mod malware_analysis;
pub mod note;
pub mod observed_data;
pub mod opinion;
pub mod report;
pub mod threat_actor;
pub mod tool;
pub mod vulnerability;
pub mod builder;

#[cfg(test)]
use crate::relationship_objects::RelationshipObject;

pub use attack_pattern::AttackPattern;
pub use campaign::Campaign;
pub use course_of_action::CourseOfAction;
pub use grouping::Grouping;
pub use identity::Identity;
pub use incident::Incident;
pub use indicator::Indicator;
pub use infrastructure::Infrastructure;
pub use intrusion_set::IntrusionSet;
pub use location::Location;
pub use malware::Malware;
pub use malware_analysis::MalwareAnalysis;
pub use note::Note;
pub use observed_data::ObservedData;
pub use opinion::Opinion;
pub use report::Report;
pub use threat_actor::ThreatActor;
pub use tool::Tool;
pub use vulnerability::Vulnerability;
use stix_derive::StixProperties;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, Display as StrumDisplay, EnumString};

/// A STIX Domain Object (SDO) of some type.
///
/// Each of SDO type corresponds to a unique concept commonly represented in CTI.
/// These types can be categorized as tactics, techniques, and procedures (TTPs) or as adversary information.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_nrhq5e9nylke>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainObject {
    /// Identifies the type of SDO.
    #[serde(flatten)]
    pub object_type: DomainObjectType,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
}

impl DomainObject {
    /// Deserializes an SDO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard.
    /// If the `allow_custom` flag is false, checks that there are no fields in the JSON String
    /// that are not in the SDO type definition.
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let value: Value =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        validate_value(value, allow_custom, true)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    pub fn add_sighting(self) -> Result<RelationshipObjectBuilder, Error> {
        let sighting_of_ref = self.get_id().to_owned();

        RelationshipObjectBuilder::new_sighting(sighting_of_ref)
    }
}

// Returns a reference to the identifier of the `DomainObject`.
// This implementation accesses the `id` field from the `common_properties`
// of the `DomainObject`, providing a way to retrieve the unique identifier
// associated with this object.
impl Identified for DomainObject {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for DomainObject {
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

crate::impl_custom_properties_holder!(DomainObject);

impl Stix for DomainObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SDO
        add_error(&mut errors, check_sdo_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check that the id prefix matches the object type
        let expected_type = self.object_type.as_ref();
        let actual_type = self.common_properties.id.get_type();
        if expected_type != actual_type {
            errors.push(Error::ValidationError(format!(
                "The `id` prefix '{}' does not match the object type '{}'",
                actual_type, expected_type
            )));
        }

        // Check specific SDO type constraints
        add_error(
            &mut errors,
            self.object_type.stix_check().map_err(|e| {
                Error::ValidationError(format!(
                    "Domain Object {} is not a valid {}: {}",
                    self.get_id(),
                    self.object_type.as_ref(),
                    e
                ))
            }),
        );

        return_multiple_errors(errors)
    }
}

// Checks that the required properties for an SDO are present and that the prohibited fields for an SDO are not present
pub fn check_sdo_properties(properties: &CommonProperties) -> Result<(), Error> {
    let mut errors = Vec::new();

    // Check that the `spec_version` field exists for SDOs
    if properties.spec_version.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `spec_version` property.".to_string(),
        ));
    }
    // Check that the `created` field exists for SDOs
    if properties.created.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `created` property.".to_string(),
        ));
    }
    // Check that the `modified` field exists for SDOs
    if properties.modified.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `modified` property.".to_string(),
        ));
    }
    // Check that the `defanged` property is `None` for SDOs
    if properties.defanged.is_some() {
        errors.push(Error::ValidationError(
            "SDOs cannot have a `defanged` property.".to_string(),
        ));
    }

    return_multiple_errors(errors)
}

/// The various SDO types represented in STIX.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    AsRefStr,
    EnumString,
    StrumDisplay,
    StixProperties,
)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum DomainObjectType {
    AttackPattern(AttackPattern),
    Campaign(Campaign),
    CourseOfAction(CourseOfAction),
    Grouping(Grouping),
    Identity(Identity),
    Incident(Incident),
    Indicator(Indicator),
    Infrastructure(Infrastructure),
    IntrusionSet(IntrusionSet),
    Location(Location),
    Malware(Malware),
    MalwareAnalysis(MalwareAnalysis),
    Note(Note),
    ObservedData(ObservedData),
    Opinion(Opinion),
    Report(Report),
    ThreatActor(ThreatActor),
    Tool(Tool),
    Vulnerability(Vulnerability),
}

impl Stix for DomainObjectType {
    /// Calls `stix_check()` on the internal SDO type struct
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            DomainObjectType::AttackPattern(attack_pattern) => attack_pattern.stix_check(),
            DomainObjectType::Campaign(campaign) => campaign.stix_check(),
            DomainObjectType::CourseOfAction(course_of_action) => course_of_action.stix_check(),
            DomainObjectType::Grouping(grouping) => grouping.stix_check(),
            DomainObjectType::Identity(identity) => identity.stix_check(),
            DomainObjectType::Incident(incident) => incident.stix_check(),
            DomainObjectType::Indicator(indicator) => indicator.stix_check(),
            DomainObjectType::Infrastructure(infrastructure) => infrastructure.stix_check(),
            DomainObjectType::IntrusionSet(intrustion_set) => intrustion_set.stix_check(),
            DomainObjectType::Location(location) => location.stix_check(),
            DomainObjectType::Note(note) => note.stix_check(),
            DomainObjectType::ObservedData(observed_data) => observed_data.stix_check(),
            DomainObjectType::Opinion(opinion) => opinion.stix_check(),
            DomainObjectType::Malware(malware) => malware.stix_check(),
            DomainObjectType::MalwareAnalysis(malware_anlaysis) => malware_anlaysis.stix_check(),
            DomainObjectType::Report(report) => report.stix_check(),
            DomainObjectType::ThreatActor(threat_actor) => threat_actor.stix_check(),
            DomainObjectType::Tool(tool) => tool.stix_check(),
            DomainObjectType::Vulnerability(vulnerability) => vulnerability.stix_check(),
        }
    }
}


pub use builder::DomainObjectBuilder;

#[cfg(test)]
impl DomainObject {
    pub(crate) fn test_id(mut self) -> Self {
        let object_type = self.object_type.as_ref();
        self.common_properties.id = Identifier::new_test(object_type);
        self
    }

    pub(crate) fn created(mut self, datetime: &str) -> Self {
        self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
        self
    }

    pub(crate) fn modified(mut self, datetime: &str) -> Self {
        self.common_properties.modified = Some(Timestamp(datetime.parse().unwrap()));
        self
    }
}

#[cfg(test)]
impl RelationshipObject {
    pub(crate) fn test_id(mut self) -> Self {
        let object_type = self.object_type.as_ref();
        self.common_properties.id = Identifier::new_test(object_type);
        self
    }

    pub(crate) fn created(mut self, datetime: &str) -> Self {
        self.common_properties.created = Some(Timestamp(datetime.parse().unwrap()));
        self
    }

    pub(crate) fn modified(mut self, datetime: &str) -> Self {
        self.common_properties.modified = Some(Timestamp(datetime.parse().unwrap()));
        self
    }
}
