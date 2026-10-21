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
    /// The attack-pattern SDO type: tactics and techniques used by adversaries.
    AttackPattern,
    /// The campaign SDO type: a grouping of related adversary behavior over time.
    Campaign,
    /// The course-of-action SDO type: an action to take in response to an attack.
    CourseOfAction,
    /// The grouping SDO type: a set of STIX Objects the producer believes are related.
    Grouping,
    /// The identity SDO type: the identity of a specific person or organization.
    Identity,
    /// The incident SDO type: a stub object representing a security incident.
    Incident,
    /// The indicator SDO type: a pattern that detects suspicious or malicious activity.
    Indicator,
    /// The infrastructure SDO type: systems and resources intended to support a purpose.
    Infrastructure,
    /// The intrusion-set SDO type: a coordinated set of adversarial behaviors.
    IntrusionSet,
    /// The location SDO type: a geographic location.
    Location,
    /// The malware SDO type: malicious code.
    Malware,
    /// The malware-analysis SDO type: the results of analyzing malware.
    MalwareAnalysis,
    /// The note SDO type: a prose note attached to one or more objects.
    Note,
    /// The observed-data SDO type: observations of cyber-related entities over time.
    ObservedData,
    /// The opinion SDO type: an analyst's assessment of another object.
    Opinion,
    /// The report SDO type: a collection of threat intelligence about one or more topics.
    Report,
    /// The threat-actor SDO type: an individual or group operating with malicious intent.
    ThreatActor,
    /// The tool SDO type: legitimate software used by threat actors to perform attacks.
    Tool,
    /// The vulnerability SDO type: a software flaw that can be used to gain access.
    Vulnerability,
}

/// A list of all STIX Cyber Observable Object (SCO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum ScoTypes {
    /// The artifact SCO type: the raw bytes of a file or memory region.
    Artifact,
    /// The autonomous-system SCO type: an autonomous system on the Internet.
    AutonomousSystem,
    /// The directory SCO type: a directory on a filesystem.
    Directory,
    /// The domain-name SCO type: a domain name.
    DomainName,
    /// The email-addr SCO type: a single email address.
    #[strum(serialize = "email-addr")]
    EmailAddress,
    /// The email-message SCO type: an instance of an email.
    EmailMessage,
    /// The file SCO type: the properties of a file.
    File,
    /// The ipv4-addr SCO type: an IPv4 address.
    Ipv4Addr,
    /// The ipv6-addr SCO type: an IPv6 address.
    Ipv6Addr,
    /// The mac-addr SCO type: a Media Access Control (MAC) address.
    MacAddr,
    /// The mutex SCO type: a mutex on a system.
    Mutex,
    /// The network-traffic SCO type: network traffic between two or more endpoints.
    NetworkTraffic,
    /// The process SCO type: an instance of a program running on a system.
    Process,
    /// The software SCO type: a high-level software application.
    Software,
    /// The url SCO type: a uniform resource locator.
    Url,
    /// The user-account SCO type: a user account on a system or service.
    UserAccount,
    /// The windows-registry-key SCO type: a Windows registry key.
    WindowsRegistryKey,
    /// The x509-certificate SCO type: an X.509 certificate.
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
    /// The relationship SRO type: a typed connection between two STIX Objects.
    Relationship,
    /// The sighting SRO type: an assertion that an object was seen in a context.
    Sighting,
}

/// A list of all STIX Meta Object (SMO) types found in the STIX 2.1 standard.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter)]
#[strum(serialize_all = "kebab-case")]
pub enum StixMetaTypes {
    /// The language-content SMO type: language-specific content for another object.
    LanguageContent,
    /// The marking-definition SMO type: data markings for handling requirements.
    MarkingDefinition,
    /// The extension-definition SMO type: the definition of a STIX extension.
    ExtensionDefinition,
    /// The bundle type: a collection of STIX Objects transmitted together.
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
