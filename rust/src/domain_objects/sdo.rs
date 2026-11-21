//! Contains the implementation logic for Stix Domain Objects (SDOs).

#![allow(dead_code)]

use crate::error::CheckContext;
use jiff::Timestamp as JiffTimestamp;

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
pub mod builder;
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
use stixflayer_derive::StixProperties;
pub use threat_actor::ThreatActor;
pub use tool::Tool;
pub use vulnerability::Vulnerability;

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

    /// Returns whether this SDO has been marked as revoked.
    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }

    /// Creates a Sighting SRO builder with this SDO as the `sighting_of_ref`.
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

/// Required-property checks shared by builder assembly and semantic validation.
///
/// These used to live in the builder, which meant `from_json` accepted empty
/// required strings that constructors rejected. Running them from `check`
/// gives both paths identical behavior.
fn check_required_fields(object_type: &DomainObjectType) -> Result<(), Error> {
    match object_type {
        DomainObjectType::AttackPattern(ref attack_pattern) => {
            if attack_pattern.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Campaign(ref campaign) => {
            if campaign.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::CourseOfAction(ref course_of_action) => {
            if course_of_action.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Grouping(ref grouping) => {
            if grouping.object_refs.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "object_refs".to_string(),
                });
            }
        }
        DomainObjectType::Identity(ref identity) => {
            if identity.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Incident(ref incident) => {
            if incident.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Indicator(ref indicator) => {
            if indicator.pattern.is_empty()
                || indicator.pattern_type.is_empty()
                || indicator.valid_from.0 == JiffTimestamp::UNIX_EPOCH
            {
                return Err(Error::ValidationErrors(vec![
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "pattern".to_string(),
                    },
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "pattern_type".to_string(),
                    },
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "valid_from".to_string(),
                    },
                ]));
            }
        }
        DomainObjectType::Infrastructure(ref infrastructure) => {
            if infrastructure.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::IntrusionSet(ref intrusion_set) => {
            if intrusion_set.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Location(ref location) => {
            let _ = location.stix_check();
        }
        DomainObjectType::Malware(ref malware) => {
            if malware.name.is_none() || malware.name.as_ref().unwrap().is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
            let _ = malware.stix_check();
        }
        DomainObjectType::MalwareAnalysis(ref malware_analysis) => {
            if malware_analysis.product.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "product".to_string(),
                });
            }
            if malware_analysis.result.is_none() && malware_analysis.analysis_sco_refs.is_none() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "result or analysis_sco_refs".to_string(),
                });
            }
        }
        DomainObjectType::Note(ref note) => {
            if note.content.is_empty() || note.object_refs.is_empty() {
                return Err(Error::ValidationErrors(vec![
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "content".to_string(),
                    },
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "object_refs".to_string(),
                    },
                ]));
            }
        }
        DomainObjectType::ObservedData(ref observed_data) => {
            if observed_data.first_observed.0 == JiffTimestamp::UNIX_EPOCH
                || observed_data.last_observed.0 == JiffTimestamp::UNIX_EPOCH
                || observed_data.number_observed == 0
                || observed_data.object_refs.is_empty()
            {
                return Err(Error::ValidationErrors(vec![
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "first_observed".to_string(),
                    },
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "last_observed".to_string(),
                    },
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "number_observed".to_string(),
                    },
                    Error::MissingProperty {
                        object_type: object_type.to_string(),
                        property: "object_refs".to_string(),
                    },
                ]));
            }
        }
        DomainObjectType::Opinion(ref opinion) => {
            if opinion.object_refs.is_empty() || opinion.opinion.as_ref().is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "object_refs or opinion".to_string(),
                });
            }
        }
        DomainObjectType::Report(ref report) => {
            if report.name.is_empty()
                || report.object_refs.is_empty()
                || report.published.0 == JiffTimestamp::UNIX_EPOCH
            {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name, published, or object_refs".to_string(),
                });
            }
        }
        DomainObjectType::ThreatActor(ref threat_actor) => {
            if threat_actor.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Tool(ref tool) => {
            if tool.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
        DomainObjectType::Vulnerability(ref vulnerability) => {
            if vulnerability.name.is_empty() {
                return Err(Error::MissingProperty {
                    object_type: object_type.to_string(),
                    property: "name".to_string(),
                });
            }
        }
    }
    Ok(())
}

impl Stix for DomainObject {
    fn check(&self, ctx: &mut CheckContext) -> Result<(), Error> {
        ctx.set_object_id(Some(self.get_id().to_string()));
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SDO
        add_error(&mut errors, check_sdo_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.check(ctx));

        // Required fields that must also be non-empty.
        add_error(&mut errors, check_required_fields(&self.object_type));

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
            self.object_type
                .check(ctx)
                .map_err(|e| Error::InvalidNestedObject {
                    context: format!(
                        "Domain Object {} is not a valid {}",
                        self.get_id(),
                        self.object_type.as_ref()
                    ),
                    source: Box::new(e),
                }),
        );

        return_multiple_errors(errors)
    }
}

/// Checks that the required properties for an SDO are present and that the prohibited fields for an SDO are not present
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
    /// An attack-pattern SDO, describing a way that adversaries attempt to compromise targets.
    AttackPattern(AttackPattern),
    /// A campaign SDO, a grouping of adversarial behaviors over a period of time.
    Campaign(Campaign),
    /// A course-of-action SDO, an action taken to prevent or respond to an attack.
    CourseOfAction(CourseOfAction),
    /// A grouping SDO, asserting that referenced STIX Objects share a common context.
    Grouping(Grouping),
    /// An identity SDO, representing an individual, organization, or group (or a class thereof).
    Identity(Identity),
    /// An incident SDO, which is a stub in STIX 2.1.
    Incident(Incident),
    /// An indicator SDO, containing a pattern used to detect suspicious or malicious activity.
    Indicator(Indicator),
    /// An infrastructure SDO, describing systems and resources supporting some purpose.
    Infrastructure(Infrastructure),
    /// An intrusion-set SDO, a grouped set of adversarial behaviors with common properties.
    IntrusionSet(IntrusionSet),
    /// A location SDO, representing a geographic location.
    Location(Location),
    /// A malware SDO, representing a malware instance or family.
    Malware(Malware),
    /// A malware-analysis SDO, capturing the metadata and results of a malware analysis.
    MalwareAnalysis(MalwareAnalysis),
    /// A note SDO, conveying informative text for further context or analysis.
    Note(Note),
    /// An observed-data SDO, conveying information about observed cyber-security related entities.
    ObservedData(ObservedData),
    /// An opinion SDO, assessing the correctness of the information in another STIX Object.
    Opinion(Opinion),
    /// A report SDO, a collection of threat intelligence focused on one or more topics.
    Report(Report),
    /// A threat-actor SDO, representing an individual, group, or organization with malicious intent.
    ThreatActor(ThreatActor),
    /// A tool SDO, representing legitimate software that can be used to perform attacks.
    Tool(Tool),
    /// A vulnerability SDO, representing a weakness in software or hardware logic.
    Vulnerability(Vulnerability),
}

impl Stix for DomainObjectType {
    /// Calls `stix_check()` on the internal SDO type struct
    fn check(&self, ctx: &mut CheckContext) -> Result<(), Error> {
        match self {
            DomainObjectType::AttackPattern(attack_pattern) => attack_pattern.check(ctx),
            DomainObjectType::Campaign(campaign) => campaign.check(ctx),
            DomainObjectType::CourseOfAction(course_of_action) => course_of_action.check(ctx),
            DomainObjectType::Grouping(grouping) => grouping.check(ctx),
            DomainObjectType::Identity(identity) => identity.check(ctx),
            DomainObjectType::Incident(incident) => incident.check(ctx),
            DomainObjectType::Indicator(indicator) => indicator.check(ctx),
            DomainObjectType::Infrastructure(infrastructure) => infrastructure.check(ctx),
            DomainObjectType::IntrusionSet(intrustion_set) => intrustion_set.check(ctx),
            DomainObjectType::Location(location) => location.check(ctx),
            DomainObjectType::Note(note) => note.check(ctx),
            DomainObjectType::ObservedData(observed_data) => observed_data.check(ctx),
            DomainObjectType::Opinion(opinion) => opinion.check(ctx),
            DomainObjectType::Malware(malware) => malware.check(ctx),
            DomainObjectType::MalwareAnalysis(malware_anlaysis) => malware_anlaysis.check(ctx),
            DomainObjectType::Report(report) => report.check(ctx),
            DomainObjectType::ThreatActor(threat_actor) => threat_actor.check(ctx),
            DomainObjectType::Tool(tool) => tool.check(ctx),
            DomainObjectType::Vulnerability(vulnerability) => vulnerability.check(ctx),
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
