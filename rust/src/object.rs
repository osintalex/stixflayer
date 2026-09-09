//! Top level STIX object structures and implementation
use crate::{
    base::Stix,
    custom_objects::CustomObject,
    cyber_observable_objects::sco::{CyberObject, CyberObjectType},
    cyber_observable_objects::sco_types::{
        Artifact, AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage,
        File as ScoFile, Ipv4Addr, Ipv6Addr, MacAddr as ScoMacAddr, Mutex as ScoMutex,
        NetworkTraffic, Process as ScoProcess, Software, Url as ScoUrl, UserAccount,
        WindowsRegistryKey, WindowsRegistryKeyType, X509Certificate,
    },
    domain_objects::sdo::{DomainObject, DomainObjectType},
    domain_objects::sdo_types::{
        AttackPattern, Campaign, CourseOfAction, Grouping, Identity, Incident, Indicator,
        Infrastructure, IntrusionSet, Location, Malware, MalwareAnalysis, Note, ObservedData,
        Opinion, Report, ThreatActor, Tool, Vulnerability,
    },
    error::StixError as Error,
    meta_objects::{
        extension_definition::ExtensionDefinition, language_content::LanguageContent,
        marking_definition::MarkingDefinition,
    },
    relationship_objects::{Relationship, RelationshipObject, RelationshipObjectType, Sighting},
    types::{get_object_type, ExtensionType, Identified},
    validation::validate_value,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::AsRefStr;

/// Possible STIX Objects
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, AsRefStr)]
#[serde(untagged)]
pub enum StixObject {
    #[strum(serialize = "sdo")]
    Sdo(DomainObject),
    #[strum(serialize = "sro")]
    Sro(RelationshipObject),
    #[strum(serialize = "sco")]
    Sco(CyberObject),
    #[strum(serialize = "language-content")]
    LanguageContent(LanguageContent),
    // #[strum(serialize = "object-marking")]
    // ObjectMarking(ObjectMarking),
    #[strum(serialize = "extension-definition")]
    ExtensionDefinition(ExtensionDefinition),
    #[strum(serialize = "marking-definition")]
    MarkingDefinition(MarkingDefinition),
    #[strum(serialize = "custom")]
    Custom(CustomObject),
}

impl StixObject {
    /// Get the object type of a STIX Object
    pub fn get_object_type(&self) -> Result<&str, Error> {
        match self {
            // If the object is a custom object, check its extensions property for its type
            StixObject::Custom(custom_object) => match custom_object.get_object_type()? {
                ExtensionType::NewSdo => Ok("sdo"),
                ExtensionType::NewSro => Ok("sro"),
                ExtensionType::NewSco => Ok("sco"),
                _ => unreachable!(),
            },
            _ => Ok(self.as_ref()),
        }
    }

    /// Get the specific type of the STIX Object
    pub fn get_type(&self) -> &str {
        match self {
            StixObject::Sdo(sdo) => sdo.object_type.as_ref(),
            StixObject::Sro(sro) => sro.object_type.as_ref(),
            StixObject::Sco(sco) => sco.object_type.as_ref(),
            StixObject::LanguageContent(_) => "language-content",
            // StixObject::ObjectMarking(_) = > "object-marking",
            StixObject::ExtensionDefinition(_) => "extension-definition",
            StixObject::MarkingDefinition(_) => "marking-definition",
            Self::Custom(custom) => custom.object_type.as_ref(),
        }
    }

    /// Get the id of the STIX Object
    pub fn get_id(&self) -> String {
        match self {
            StixObject::Sdo(sdo) => sdo.get_id().to_string(),
            StixObject::Sro(sro) => sro.get_id().to_string(),
            StixObject::Sco(sco) => sco.get_id().to_string(),
            StixObject::LanguageContent(language_content) => language_content.get_id().to_string(),
            // StixObject::ObjectMarking(object_marking) = > "object_marking.get_id().to_string()",
            StixObject::ExtensionDefinition(extension_definition) => {
                extension_definition.get_id().to_string()
            }
            StixObject::MarkingDefinition(marking_definition) => {
                marking_definition.get_id().to_string()
            }
            Self::Custom(custom) => custom.get_id().to_string(),
        }
    }

    /// If the type of STIX Object can be versioned, return its modified datetime as a String.
    /// If it cannot be versioned, return `None`.
    pub fn get_modified(&self) -> Option<String> {
        match self {
            StixObject::Sdo(sdo) => Some(sdo.common_properties.modified.as_ref()?.to_string()),
            StixObject::Sro(sro) => Some(sro.common_properties.modified.as_ref()?.to_string()),
            StixObject::Sco(_) => None,
            StixObject::LanguageContent(language_content) => Some(
                language_content
                    .common_properties
                    .modified
                    .as_ref()?
                    .to_string(),
            ),
            // StixObject::ObjectMarking(_) => None,
            StixObject::ExtensionDefinition(extension_definition) => Some(
                extension_definition
                    .common_properties
                    .modified
                    .as_ref()?
                    .to_string(),
            ),
            StixObject::MarkingDefinition(marking_definition) => Some(
                marking_definition
                    .common_properties
                    .modified
                    .as_ref()?
                    .to_string(),
            ),

            Self::Custom(custom) => custom.get_modified(),
        }
    }

    /// Deserialize any STIX Object from a JSON string.
    pub fn from_json(json_str: &str, allow_custom: bool) -> Result<Self, Error> {
        let value: Value = serde_json::from_str(json_str)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        Self::from_value(value, allow_custom, true)
    }

    /// Deserialize any STIX Object from an already-parsed JSON value.
    pub fn from_value(value: Value, allow_custom: bool, strict: bool) -> Result<Self, Error> {
        let type_name = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        match get_object_type(type_name).as_ref() {
            "sdo" => Ok(StixObject::Sdo(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
            "sro" => Ok(StixObject::Sro(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
            "sco" => Ok(StixObject::Sco(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
            "language-content" => Ok(StixObject::LanguageContent(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
            "extension-definition" => Ok(StixObject::ExtensionDefinition(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
            "marking-definition" => Ok(StixObject::MarkingDefinition(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
            // "object-marking" => Ok(StixObject::ObjectMarking(validate_value(value, allow_custom, strict)?)),
            "custom" | _ => Ok(StixObject::Custom(validate_value(
                value,
                allow_custom,
                strict,
            )?)),
        }
    }

    /// Deserialize a STIX Object from a JSON envelope.
    ///
    /// Envelope format:
    /// ```json
    /// {
    ///   "object": { ...stix object... },
    ///   "options": {
    ///     "strict": true,
    ///     "version": "2.1",
    ///     "allow_custom": false
    ///   }
    /// }
    /// ```
    ///
    /// `strict: true` (default) runs full validation (`stix_check`).
    /// `strict: false` skips validation but still respects `allow_custom`.
    /// `allow_custom: false` (default) rejects unknown fields.
    pub fn from_envelope(envelope_json: &str) -> Result<Self, Error> {
        let mut envelope: Value = serde_json::from_str(envelope_json)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        let object = envelope
            .get_mut("object")
            .map(|v| v.take())
            .ok_or_else(|| Error::ValidationError("Envelope missing 'object' field".to_string()))?;
        let options = envelope.get("options").unwrap_or(&Value::Null);
        let strict = options
            .get("strict")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let version = options
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("2.1");
        let allow_custom = options
            .get("allow_custom")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if version != "2.1" {
            return Err(Error::ValidationError(format!(
                "Unsupported STIX version '{}'. Only 2.1 is supported.",
                version
            )));
        }

        Self::from_value(object, allow_custom, strict)
    }
}

impl Stix for StixObject {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            StixObject::Sdo(sdo) => sdo.stix_check(),
            StixObject::Sro(sro) => sro.stix_check(),
            StixObject::Sco(sco) => sco.stix_check(),
            StixObject::LanguageContent(language_content) => language_content.stix_check(),
            // StixObject::ObjectMarking(object_marking) => object_marking.stix_check(),
            StixObject::ExtensionDefinition(extension_definition) => {
                extension_definition.stix_check()
            }
            StixObject::MarkingDefinition(marking_definition) => marking_definition.stix_check(),
            StixObject::Custom(custom) => custom.stix_check(),
        }
    }
}

// -- Public parse helpers (used by bindings, avoids exposing StixObject) -----

/// Parse an SDO from a JSON envelope.
///
/// `strict` controls full validation, `version` must be "2.1", and
/// `allow_custom` permits unknown fields.
pub fn parse_sdo(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<DomainObject, Error> {
    let envelope = serde_json::json!({
        "object": serde_json::from_str::<serde_json::Value>(json_str)
            .map_err(|e| Error::DeserializationError(e.to_string()))?,
        "options": {
            "strict": strict,
            "version": version,
            "allow_custom": allow_custom
        }
    });
    let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
    match stix_obj {
        StixObject::Sdo(sdo) => Ok(sdo),
        _ => Err(Error::ValidationError(format!(
            "Expected SDO, got {}",
            stix_obj.get_type()
        ))),
    }
}

/// Parse an SCO from a JSON envelope.
///
/// See [`parse_sdo`] for parameter semantics.
pub fn parse_sco(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<CyberObject, Error> {
    let envelope = serde_json::json!({
        "object": serde_json::from_str::<serde_json::Value>(json_str)
            .map_err(|e| Error::DeserializationError(e.to_string()))?,
        "options": {
            "strict": strict,
            "version": version,
            "allow_custom": allow_custom
        }
    });
    let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
    match stix_obj {
        StixObject::Sco(sco) => Ok(sco),
        _ => Err(Error::ValidationError(format!(
            "Expected SCO, got {}",
            stix_obj.get_type()
        ))),
    }
}

/// Parse an SRO from a JSON envelope.
///
/// See [`parse_sdo`] for parameter semantics.
pub fn parse_sro(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<RelationshipObject, Error> {
    let envelope = serde_json::json!({
        "object": serde_json::from_str::<serde_json::Value>(json_str)
            .map_err(|e| Error::DeserializationError(e.to_string()))?,
        "options": {
            "strict": strict,
            "version": version,
            "allow_custom": allow_custom
        }
    });
    let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
    match stix_obj {
        StixObject::Sro(sro) => Ok(sro),
        _ => Err(Error::ValidationError(format!(
            "Expected SRO, got {}",
            stix_obj.get_type()
        ))),
    }
}

/// Trait for parsing a concrete STIX type from a JSON string.
///
/// This provides a uniform, type-safe entry point for deserializing any
/// STIX object without exposing the internal [`StixObject`] dispatch enum.
///
/// Use [`FromJson::from_json(json, strict, version, allow_custom)`] where
/// `strict` controls full validation, `version` is checked against "2.1",
/// and `allow_custom` permits unknown fields.
pub trait FromJson: Sized {
    /// Deserialize a STIX object from a JSON string.
    ///
    /// - `strict: true` validates against the STIX 2.1 spec (default).
    /// - `strict: false` skips validation but still parses.
    /// - `allow_custom: true` permits unknown fields; `false` rejects them.
    /// - `version` must currently be `"2.1"`.
    fn from_json(
        json_str: &str,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, Error>;
}

macro_rules! impl_from_json_sdo {
    ($type:ty, $variant:path, $expected:literal) => {
        impl FromJson for $type {
            fn from_json(json_str: &str, strict: bool, version: &str, allow_custom: bool) -> Result<Self, Error> {
                let envelope = serde_json::json!({
                    "object": serde_json::from_str::<serde_json::Value>(json_str)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                    "options": {
                        "strict": strict,
                        "version": version,
                        "allow_custom": allow_custom
                    }
                });
                let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
                match stix_obj {
                    StixObject::Sdo(sdo) => match sdo.object_type {
                        $variant(value) => Ok(value),
                        _ => Err(Error::ValidationError(format!(
                            "Expected {}, got {}",
                            $expected,
                            sdo.object_type.as_ref()
                        ))),
                    },
                    _ => Err(Error::ValidationError(format!(
                        "Expected {}, got {}",
                        $expected,
                        stix_obj.get_type()
                    ))),
                }
            }
        }
    };
}

macro_rules! impl_from_json_sco {
    ($type:ty, $variant:path, $expected:literal) => {
        impl FromJson for $type {
            fn from_json(json_str: &str, strict: bool, version: &str, allow_custom: bool) -> Result<Self, Error> {
                let envelope = serde_json::json!({
                    "object": serde_json::from_str::<serde_json::Value>(json_str)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                    "options": {
                        "strict": strict,
                        "version": version,
                        "allow_custom": allow_custom
                    }
                });
                let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
                match stix_obj {
                    StixObject::Sco(sco) => match sco.object_type {
                        $variant(value) => Ok(value),
                        _ => Err(Error::ValidationError(format!(
                            "Expected {}, got {}",
                            $expected,
                            sco.object_type.as_ref()
                        ))),
                    },
                    _ => Err(Error::ValidationError(format!(
                        "Expected {}, got {}",
                        $expected,
                        stix_obj.get_type()
                    ))),
                }
            }
        }
    };
}

macro_rules! impl_from_json_sro {
    ($type:ty, $variant:path, $expected:literal) => {
        impl FromJson for $type {
            fn from_json(json_str: &str, strict: bool, version: &str, allow_custom: bool) -> Result<Self, Error> {
                let envelope = serde_json::json!({
                    "object": serde_json::from_str::<serde_json::Value>(json_str)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                    "options": {
                        "strict": strict,
                        "version": version,
                        "allow_custom": allow_custom
                    }
                });
                let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
                match stix_obj {
                    StixObject::Sro(sro) => match sro.object_type {
                        $variant(value) => Ok(value),
                        _ => Err(Error::ValidationError(format!(
                            "Expected {}, got {}",
                            $expected,
                            sro.object_type.as_ref()
                        ))),
                    },
                    _ => Err(Error::ValidationError(format!(
                        "Expected {}, got {}",
                        $expected,
                        stix_obj.get_type()
                    ))),
                }
            }
        }
    };
}

macro_rules! impl_from_json_meta {
    ($type:ty, $variant:path, $expected:literal) => {
        impl FromJson for $type {
            fn from_json(json_str: &str, strict: bool, version: &str, allow_custom: bool) -> Result<Self, Error> {
                let envelope = serde_json::json!({
                    "object": serde_json::from_str::<serde_json::Value>(json_str)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                    "options": {
                        "strict": strict,
                        "version": version,
                        "allow_custom": allow_custom
                    }
                });
                let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
                match stix_obj {
                    $variant(value) => Ok(value),
                    _ => Err(Error::ValidationError(format!(
                        "Expected {}, got {}",
                        $expected,
                        stix_obj.get_type()
                    ))),
                }
            }
        }
    };
}

macro_rules! impl_from_json_custom {
    ($type:ty) => {
        impl FromJson for $type {
            fn from_json(json_str: &str, strict: bool, version: &str, allow_custom: bool) -> Result<Self, Error> {
                let envelope = serde_json::json!({
                    "object": serde_json::from_str::<serde_json::Value>(json_str)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                    "options": {
                        "strict": strict,
                        "version": version,
                        "allow_custom": allow_custom
                    }
                });
                let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
                match stix_obj {
                    StixObject::Custom(value) => Ok(value),
                    _ => Err(Error::ValidationError(format!(
                        "Expected custom object, got {}",
                        stix_obj.get_type()
                    ))),
                }
            }
        }
    };
}

// ── SDO implementations ──────────────────────────────────────────────

impl_from_json_sdo!(
    AttackPattern,
    DomainObjectType::AttackPattern,
    "attack-pattern"
);
impl_from_json_sdo!(Campaign, DomainObjectType::Campaign, "campaign");
impl_from_json_sdo!(
    CourseOfAction,
    DomainObjectType::CourseOfAction,
    "course-of-action"
);
impl_from_json_sdo!(Grouping, DomainObjectType::Grouping, "grouping");
impl_from_json_sdo!(Identity, DomainObjectType::Identity, "identity");
impl_from_json_sdo!(Incident, DomainObjectType::Incident, "incident");
impl_from_json_sdo!(Indicator, DomainObjectType::Indicator, "indicator");
impl_from_json_sdo!(
    Infrastructure,
    DomainObjectType::Infrastructure,
    "infrastructure"
);
impl_from_json_sdo!(
    IntrusionSet,
    DomainObjectType::IntrusionSet,
    "intrusion-set"
);
impl_from_json_sdo!(Location, DomainObjectType::Location, "location");
impl_from_json_sdo!(Malware, DomainObjectType::Malware, "malware");
impl_from_json_sdo!(
    MalwareAnalysis,
    DomainObjectType::MalwareAnalysis,
    "malware-analysis"
);
impl_from_json_sdo!(Note, DomainObjectType::Note, "note");
impl_from_json_sdo!(
    ObservedData,
    DomainObjectType::ObservedData,
    "observed-data"
);
impl_from_json_sdo!(Opinion, DomainObjectType::Opinion, "opinion");
impl_from_json_sdo!(Report, DomainObjectType::Report, "report");
impl_from_json_sdo!(ThreatActor, DomainObjectType::ThreatActor, "threat-actor");
impl_from_json_sdo!(Tool, DomainObjectType::Tool, "tool");
impl_from_json_sdo!(
    Vulnerability,
    DomainObjectType::Vulnerability,
    "vulnerability"
);

// ── SCO implementations ──────────────────────────────────────────────

impl_from_json_sco!(Artifact, CyberObjectType::Artifact, "artifact");
impl_from_json_sco!(
    AutonomousSystem,
    CyberObjectType::AutonomousSystem,
    "autonomous-system"
);
impl_from_json_sco!(Directory, CyberObjectType::Directory, "directory");
impl_from_json_sco!(DomainName, CyberObjectType::DomainName, "domain-name");
impl_from_json_sco!(EmailAddress, CyberObjectType::EmailAddress, "email-addr");
impl_from_json_sco!(EmailMessage, CyberObjectType::EmailMessage, "email-message");
impl_from_json_sco!(ScoFile, CyberObjectType::File, "file");
impl_from_json_sco!(Ipv4Addr, CyberObjectType::Ipv4Addr, "ipv4-addr");
impl_from_json_sco!(Ipv6Addr, CyberObjectType::Ipv6Addr, "ipv6-addr");
impl_from_json_sco!(ScoMacAddr, CyberObjectType::MacAddr, "mac-addr");
impl_from_json_sco!(ScoMutex, CyberObjectType::Mutex, "mutex");
impl_from_json_sco!(
    NetworkTraffic,
    CyberObjectType::NetworkTraffic,
    "network-traffic"
);
impl_from_json_sco!(ScoProcess, CyberObjectType::Process, "process");
impl_from_json_sco!(Software, CyberObjectType::Software, "software");
impl_from_json_sco!(ScoUrl, CyberObjectType::Url, "url");
impl_from_json_sco!(UserAccount, CyberObjectType::UserAccount, "user-account");
impl_from_json_sco!(
    WindowsRegistryKey,
    CyberObjectType::WindowsRegistryKey,
    "windows-registry-key"
);
impl_from_json_sco!(
    WindowsRegistryKeyType,
    CyberObjectType::WindowsRegistryKeyType,
    "windows-registry-key-type"
);
impl FromJson for X509Certificate {
    fn from_json(
        json_str: &str,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, Error> {
        let envelope = serde_json::json!({
            "object": serde_json::from_str::<serde_json::Value>(json_str)
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
            "options": {
                "strict": strict,
                "version": version,
                "allow_custom": allow_custom
            }
        });
        let stix_obj = StixObject::from_envelope(&envelope.to_string())?;
        match stix_obj {
            StixObject::Sco(sco) => match sco.object_type {
                CyberObjectType::X509Certificate(value) => Ok(*value),
                _ => Err(Error::ValidationError(format!(
                    "Expected x509-certificate, got {}",
                    sco.object_type.as_ref()
                ))),
            },
            _ => Err(Error::ValidationError(format!(
                "Expected x509-certificate, got {}",
                stix_obj.get_type()
            ))),
        }
    }
}

// ── SRO implementations ──────────────────────────────────────────────

impl_from_json_sro!(
    Relationship,
    RelationshipObjectType::Relationship,
    "relationship"
);
impl_from_json_sro!(Sighting, RelationshipObjectType::Sighting, "sighting");

// ── Meta implementations ────────────────────────────────────────────────

impl_from_json_meta!(
    LanguageContent,
    StixObject::LanguageContent,
    "language-content"
);
impl_from_json_meta!(
    ExtensionDefinition,
    StixObject::ExtensionDefinition,
    "extension-definition"
);
impl_from_json_meta!(
    MarkingDefinition,
    StixObject::MarkingDefinition,
    "marking-definition"
);

// ── Custom implementation ─────────────────────────────────────────────

impl_from_json_custom!(CustomObject);

#[cfg(test)]
mod tests {
    use crate::object::*;

    #[test]
    fn reserialize_stix_object() {
        let mut json_str = r#"{
                "type": "identity",
                "name": "Identity",
                "description": "Responsible for managing personal digital identity",
                "roles": ["User", "Administrator"],
                "identity_class": "individual",
                "sectors": ["Technology","Aerospace"],
                "contact_information": "alex.johnson@example.com",
                "spec_version": "2.1",
                "id": "identity--12345678-1234-5678-1234-567812345678",
                "created": "2016-05-12T08:17:27Z",
                "modified": "2016-05-12T08:17:27Z",
                "external_references": [
                    {
                        "source_name": "capec",
                        "external_id": "CAPEC-163"
                    }
                ]
            }"#
        .to_string();
        json_str.retain(|c| !c.is_whitespace());

        let object = StixObject::from_json(&json_str, false).unwrap();

        let mut new_json = serde_json::to_string_pretty(&object).unwrap();
        new_json.retain(|c| !c.is_whitespace());

        assert_eq!(json_str, new_json)
    }
}
