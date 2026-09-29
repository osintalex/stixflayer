//! STIX object type taxonomies and classification helpers.
use crate::common::string::stix_case;
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, EnumIter, EnumString, IntoEnumIterator};

/// The Extensions Type enumeration used in the Extension SMO and the `extensions` common property.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, AsRefStr, EnumIter, EnumString)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum ExtensionType {
    /// Specifies that the Extension includes a new SDO.
    NewSdo,
    /// Specifies that the Extension includes a new SCO.
    NewSco,
    /// Specifies that the Extension includes a new SRO.
    NewSro,
    /// Specifies that the Extension includes additional properties for a given STIX Object.
    PropertyExtension,
    /// Specifies that the Extension includes additional properties for a given STIX Object at the *top-level*.
    ///
    /// Organizations are encouraged to use the `property-extension` instead of this extension type.
    ToplevelPropertyExtension,
}

/// A list of all STIX Domain Objects (SDO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum SdoTypes {
    AttackPattern,
    Campaign,
    CourseOfAction,
    Grouping,
    Identity,
    Incident,
    Indicator,
    Infrastructure,
    IntrusionSet,
    Location,
    Malware,
    MalwareAnalysis,
    Note,
    ObservedData,
    Opinion,
    Report,
    ThreatActor,
    Tool,
    Vulnerability,
}

/// A list of all STIX Cyber Observable Object (SCO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ScoTypes {
    Artifact,
    AutonomousSystem,
    Directory,
    DomainName,
    #[strum(serialize = "email-addr")]
    EmailAddress,
    EmailMessage,
    File,
    Ipv4Addr,
    Ipv6Addr,
    MacAddr,
    Mutex,
    NetworkTraffic,
    Process,
    Software,
    Url,
    UserAccount,
    WindowsRegistryKey,
    X509Certificate,
}

/// Check whether a given type name is a known SCO type.
///
/// Also accepts the legacy `email-address` spelling as an alias for the
/// spec-correct `email-addr` type.
pub fn is_sco_type_name(name: &str) -> bool {
    let cased = stix_case(name);
    ScoTypes::iter().any(|x| x.as_ref() == cased) || cased == "email-address"
}

/// A list of all STIX Relationship Object (SRO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum SroTypes {
    Relationship,
    Sighting,
}

/// A list of all STIX Meta Object (SMO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum StixMetaTypes {
    LanguageContent,
    MarkingDefinition,
    ExtensionDefinition,
    Bundle,
}

/// Function to return the STIX Object type associated with the "type" value, or return "custom" if the type is not recognized
pub fn get_object_type(sub_type: &str) -> String {
    // Note: sub_type is expected to already be in kebab-case (from JSON type field)
    // Do NOT use to_case(Case::Kebab) here as it incorrectly splits numbers
    // e.g., "ipv4-addr" -> "ipv-4-addr", "x509-certificate" -> "x-509-certificate"
    // Also accept the legacy "email-address" spelling since
    // ScoTypes::EmailAddress serializes as "email-addr"
    if SdoTypes::iter().any(|s| s.as_ref() == sub_type) {
        "sdo".to_string()
    } else if ScoTypes::iter().any(|s| s.as_ref() == sub_type) || sub_type == "email-address" {
        "sco".to_string()
    } else if SroTypes::iter().any(|s| s.as_ref() == sub_type) {
        "sro".to_string()
    } else if StixMetaTypes::iter().any(|s| s.as_ref() == sub_type) {
        sub_type.to_string()
    } else {
        "custom".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_sdo_from_type() {
        let sub_type = "attack-pattern";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "sdo");
    }

    #[test]
    fn get_sco_from_type() {
        let sub_type = "ipv4-addr";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "sco");
    }

    #[test]
    fn get_sro_from_type() {
        let sub_type = "relationship";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "sro");
    }

    #[test]
    fn get_smo_from_type() {
        let sub_type = "extension-definition";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "extension-definition");
    }

    #[test]
    fn get_smo_marking_from_type() {
        let sub_type = "marking-definition";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "marking-definition");
    }

    #[test]
    fn get_custom_from_type() {
        let sub_type = "foo";
        let result = get_object_type(sub_type);
        assert_eq!(&result, "custom");
    }
}
