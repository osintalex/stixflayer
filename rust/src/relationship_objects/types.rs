use crate::{error::StixError as Error, types::Identifier};

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use strum::{AsRefStr, Display as StrumDisplay, EnumString};

/// The relationship types allowed between STIX Objects.
///
/// Contains the common relationship types defined by the STIX 2.1 standard
/// (see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_f3dx2rhc3vl>),
/// the types specific to individual SDOs, and [`RelationshipType::Custom`] for
/// user-defined names.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, StrumDisplay, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum RelationshipType {
    // Common relationships
    /// Indicates that the source and target objects are semantically duplicates of each other.
    DuplicateOf,
    /// Indicates that the target object is based on information from the source object.
    DerivedFrom,
    /// Asserts a non-specific relationship between two objects.
    RelatedTo,
    // SDO specific relationships
    /// Indicates that the source malware-analysis is results for the target malware.
    AnalysisOf,
    /// Indicates that the source campaign, intrusion-set, or threat-actor is attributed to the target.
    AttributedTo,
    /// Indicates that the source malware was authored by the target intrusion-set or threat-actor.
    AuthoredBy,
    /// Indicates that the source indicator is based on information from the target observed-data.
    BasedOn,
    /// Indicates that the source malware beacons to the target infrastructure.
    BeaconsTo,
    /// Indicates that the source malware-analysis describes the target malware.
    Characterizes,
    /// Indicates that the source infrastructure or malware communicates with the target.
    CommunicatesWith,
    /// Indicates that the source campaign, intrusion-set, or threat-actor compromises the target.
    Compromises,
    /// Indicates that the source infrastructure consists of the target objects or observables.
    ConsistsOf,
    /// Indicates that the source infrastructure or malware controls the target.
    Controls,
    /// Indicates that the source attack-pattern, infrastructure, or tool delivers the malware.
    Delivers,
    /// Indicates that the source malware downloads the target file, malware, or tool.
    Downloads,
    /// Indicates that the source malware drops the target file, malware, or tool.
    Drops,
    /// Indicates that the source malware-analysis is dynamic analysis of the target malware.
    DynamicAnalysisOf,
    /// Indicates that the source malware exfiltrates data to the target infrastructure.
    ExfiltratesTo,
    /// Indicates that the source malware exploits the target vulnerability.
    Exploits,
    /// Indicates that the source infrastructure or tool has the target vulnerability.
    Has,
    /// Indicates that the source hosts the target malware, tool, or infrastructure.
    Hosts,
    /// Indicates that the source threat-actor impersonates the target identity.
    Impersonates,
    /// Indicates that the source indicator detects evidence of the target.
    Indicates,
    /// Indicates that the source course-of-action investigates the target indicator.
    Investigates,
    /// Indicates that the source identity, infrastructure, or threat-actor is located at the target.
    LocatedAt,
    /// Indicates that the source course-of-action mitigates the target threat.
    Mitigates,
    /// Indicates that the source campaign, intrusion-set, or malware originates from the target.
    OriginatesFrom,
    /// Indicates that the source intrusion-set or threat-actor owns the target infrastructure.
    Owns,
    /// Indicates that the source course-of-action remediates the target malware or vulnerability.
    Remediates,
    /// Indicates that the source malware-analysis is static analysis of the target malware.
    StaticAnalysisOf,
    /// Indicates that the source targets the given identity, location, or vulnerability.
    Targets,
    /// Indicates that the source uses the target attack-pattern, infrastructure, malware, or tool.
    Uses,
    /// Indicates that the source malware is a variant of the target malware.
    VariantOf,
    // Custom relationship, storing the relationship name
    /// A user-defined relationship type not defined by the STIX 2.1 standard; holds its name.
    Custom(String),
}

impl RelationshipType {
    /// Checks that the relationship type is allowed between the provided source and target SDOs or SCOs
    /// Errors if not allowed
    pub fn validate(&self, source: &Identifier, target: &Identifier) -> Result<(), Error> {
        let source_type = source.get_type();
        let target_type = target.get_type();

        let valid = match self {
            RelationshipType::DerivedFrom => source_type == target_type,
            RelationshipType::DuplicateOf => source_type == target_type,
            RelationshipType::RelatedTo => true,
            RelationshipType::AnalysisOf => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::AttributedTo => {
                (source_type == "campaign"
                    && ["intrusion-set", "threat-actor"].contains(&target_type))
                    || (source_type == "intrusion-set" && target_type == "threat-actor")
                    || (source_type == "threat-actor" && target_type == "identity")
            }
            RelationshipType::AuthoredBy => {
                source_type == "malware" && ["intrusion-set", "threat-actor"].contains(&target_type)
            }
            RelationshipType::BasedOn => {
                source_type == "indicator" && target_type == "observed-data"
            }
            RelationshipType::BeaconsTo => {
                source_type == "malware" && target_type == "infrastructure"
            }
            RelationshipType::Characterizes => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::CommunicatesWith => {
                (source_type == "infrastructure"
                    && [
                        "domain-name",
                        "infrastructure",
                        "ipv4-addr",
                        "ipv6-addr",
                        "url",
                    ]
                    .contains(&target_type))
                    || (source_type == "malware"
                        && ["domain-name", "ipv4-addr", "ipv6-addr", "url"].contains(&target_type))
            }
            RelationshipType::Compromises => {
                ["campaign", "intrusion-set", "threat-actor"].contains(&source_type)
                    && target_type == "infrastructure"
            }
            RelationshipType::ConsistsOf => {
                source_type == "infrastructure"
                    && [
                        "infrastructure",
                        "observed-data",
                        "artifact",
                        "autonomous-system",
                        "directory",
                        "domain-name",
                        "email-addr",
                        "email-message",
                        "email-mime-part-type",
                        "file",
                        "ipv4-addr",
                        "ipv6-addr",
                        "mac-addr",
                        "mutex",
                        "network-traffic",
                        "process",
                        "software",
                        "url",
                        "user-account",
                        "windows-registry-key",
                        "x509-certificate",
                    ]
                    .contains(&target_type)
            }
            RelationshipType::Controls => {
                (source_type == "infrastructure"
                    && ["infrastructure", "malware"].contains(&target_type))
                    || (source_type == "malware" && target_type == "malware")
            }
            RelationshipType::Delivers => {
                ["attack-pattern", "infrastructure", "tool"].contains(&source_type)
                    && target_type == "malware"
            }
            RelationshipType::Downloads => {
                source_type == "malware" && ["malware", "file", "tool"].contains(&target_type)
            }
            RelationshipType::Drops => {
                source_type == "malware" && ["malware", "file", "tool"].contains(&target_type)
            }
            RelationshipType::DynamicAnalysisOf => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::ExfiltratesTo => {
                source_type == "malware" && target_type == "infrastructure"
            }
            RelationshipType::Exploits => {
                source_type == "malware" && target_type == "vulnerability"
            }
            RelationshipType::Has => {
                ["infrastructure", "tool"].contains(&source_type) && target_type == "vulnerability"
            }
            RelationshipType::Hosts => {
                (source_type == "infrastructure" && ["malware", "tool"].contains(&target_type))
                    || (source_type == "intrusion-set" && target_type == "infrastructure")
                    || (source_type == "threat-actor" && target_type == "infrastructure")
            }
            RelationshipType::Impersonates => {
                source_type == "indicator" && target_type == "identity"
            }
            RelationshipType::Indicates => {
                source_type == "indicator"
                    && [
                        "attack-pattern",
                        "campaign",
                        "infrastructure",
                        "intrusion-set",
                        "malware",
                        "threat-actor",
                        "tool",
                    ]
                    .contains(&target_type)
            }
            RelationshipType::Investigates => {
                source_type == "course-of-action" && target_type == "indicator"
            }
            RelationshipType::LocatedAt => {
                ["identity", "infrastructure", "threat-actor"].contains(&source_type)
                    && target_type == "location"
            }
            RelationshipType::Mitigates => {
                source_type == "course-of-action"
                    && [
                        "attack-pattern",
                        "infrastructure",
                        "malware",
                        "tool",
                        "vulnerability",
                    ]
                    .contains(&target_type)
            }
            RelationshipType::OriginatesFrom => {
                ["campaign", "intrusion-set", "malware"].contains(&source_type)
                    && target_type == "location"
            }
            RelationshipType::Owns => {
                ["intrusion-set", "threat-actor"].contains(&source_type)
                    && target_type == "infrastructure"
            }
            RelationshipType::Remediates => {
                source_type == "course-of-action"
                    && ["malware", "vulnerability"].contains(&target_type)
            }
            RelationshipType::StaticAnalysisOf => {
                source_type == "malware-analysis" && target_type == "malware"
            }
            RelationshipType::Targets => {
                ([
                    "attack-pattern",
                    "campaign",
                    "intrusion-set",
                    "threat-actor",
                ]
                .contains(&source_type)
                    && ["identity", "location", "vulnerability"].contains(&target_type))
                    || (["malware", "tool"].contains(&source_type)
                        && ["identity", "infrastructure", "location", "vulnerability"]
                            .contains(&target_type))
            }
            RelationshipType::Uses => {
                (source_type == "attack-pattern" && ["malware", "tool"].contains(&target_type))
                    || (["campaign", "intrusion-set", "malware", "threat-actor"]
                        .contains(&source_type)
                        && ["attack-pattern", "infrastructure", "malware", "tool"]
                            .contains(&target_type))
                    || (source_type == "infrastructure" && target_type == "infrastructure")
            }
            RelationshipType::VariantOf => source_type == "malware" && target_type == "malware",
            // Custom relationship types always pass this validation step
            RelationshipType::Custom(_) => true,
        };

        if valid {
            Ok(())
        } else {
            Err(Error::InvalidRelationship {
                relationship: self.to_string(),
                source_type: source_type.to_string(),
                target_type: target_type.to_string(),
            })
        }
    }
}

impl Serialize for RelationshipType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            RelationshipType::Custom(s) => s.as_str(),
            _ => self.as_ref(),
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for RelationshipType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(RelationshipType::from_str(&s).unwrap_or(RelationshipType::Custom(s)))
    }
}
