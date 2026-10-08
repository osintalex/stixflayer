//! Contains the implementation logic for STIX Cyber-observable Objects (SCOs).

pub mod artifact;
pub mod autonomous_system;
pub mod builder;
pub mod directory;
pub mod domain_name;
pub mod email_addr;
pub mod email_message;
pub mod file;
pub mod ipv4_addr;
pub mod ipv6_addr;
pub mod mac_addr;
pub mod mutex;
pub mod network_traffic;
pub mod process;
pub mod software;
pub mod url;
pub mod user_account;
pub mod windows_registry_key;
pub mod x509_certificate;

pub use artifact::Artifact;
pub use autonomous_system::AutonomousSystem;
pub use directory::Directory;
pub use domain_name::DomainName;
pub use email_addr::EmailAddress;
pub use email_message::{EmailMessage, EmailMimeCompomentType};
pub use file::File;
pub use file::File as ScoFile;
pub use ipv4_addr::Ipv4Addr;
pub use ipv6_addr::Ipv6Addr;
pub use mac_addr::MacAddr;
pub use mac_addr::MacAddr as ScoMacAddr;
pub use mutex::Mutex;
pub use mutex::Mutex as ScoMutex;
pub use network_traffic::NetworkTraffic;
pub use process::Process;
pub use process::Process as ScoProcess;
pub use software::Software;
pub use url::Url;
pub use url::Url as ScoUrl;
pub use user_account::UserAccount;
pub use windows_registry_key::{WindowsRegistryKey, WindowsRegistryKeyType};
pub use x509_certificate::{X509Certificate, X509V3Extensions};

use crate::{
    base::{CommonProperties, Stix},
    error::{add_error, return_multiple_errors, StixError as Error},
    relationship_objects::{Related, RelationshipObjectBuilder},
    types::{Identified, Identifier},
    validation::validate_value,
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::{collections::HashMap, sync::LazyLock};
use stix_derive::StixProperties;
use strum::{AsRefStr, Display as StrumDisplay, EnumString};
// Static dictionaries of ID contributing properties for each SCO type

// ID Contributing properties that will always be present for a given SCO type
pub(super) static REQUIRED_ID_PROPERTIES: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("artifact", Vec::new());
        m.insert("autonomous-system", vec!["number"]);
        m.insert("directory", vec!["path"]);
        m.insert("domain-name", vec!["value"]);
        m.insert("email-addr", vec!["value"]);
        m.insert("email-message", Vec::new());
        m.insert("file", Vec::new());
        m.insert("ipv4-addr", vec!["value"]);
        m.insert("ipv6-addr", vec!["value"]);
        m.insert("mac-addr", vec!["value"]);
        m.insert("mutex", vec!["name"]);
        m.insert("network-traffic", vec!["protocols"]);
        m.insert("process", Vec::new());
        m.insert("software", vec!["name"]);
        m.insert("url", vec!["value"]);
        m.insert("user-account", Vec::new());
        m.insert("windows-registry-key", Vec::new());
        m.insert("x509-certificate", Vec::new());
        m
    });

// ID Contributing properties that are not guaranteed to be present for a given SCO type, but should be used if they are
pub(super) static OPTIONAL_ID_PROPERTIES: LazyLock<HashMap<&'static str, Vec<&'static str>>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        m.insert("artifact", vec!["hashes", "payload_bin"]);
        m.insert("autonomous-system", Vec::new());
        m.insert("directory", Vec::new());
        m.insert("domain-name", Vec::new());
        m.insert("email-addr", Vec::new());
        m.insert("email-message", vec!["from_ref", "subject", "body"]);
        m.insert(
            "file",
            vec!["hashes", "name", "extensions", "parent_directory_ref"],
        );
        m.insert("ipv4-addr", Vec::new());
        m.insert("ipv6-addr", Vec::new());
        m.insert("mac-addr", Vec::new());
        m.insert(
            "network-traffic",
            vec![
                "start",
                "end",
                "src_ref",
                "dst_ref",
                "src_port",
                "dst_port",
                "extensions",
            ],
        );
        m.insert("process", Vec::new());
        m.insert("url", Vec::new());
        m.insert(
            "user-account",
            vec!["account_type", "user_id", "account_login"],
        );
        m.insert("windows-registry-key", vec!["key", "values"]);
        m.insert("x509-certificate", vec!["hashes", "serial_number"]);
        m
    });

// Static dictionary of network-traffic extension protocols
static PROTOCOLS_MAP: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let mut protocols_map = HashMap::new();
    protocols_map.insert("http-request-ext".to_string(), "http".to_string());
    protocols_map.insert("tcp-ext".to_string(), "tcp".to_string());
    protocols_map.insert("imcp-ext".to_string(), "imcp".to_string());
    protocols_map.insert("socket-ext".to_string(), "tcp".to_string());
    protocols_map
});

/// A STIX Cyber-observable Object (SCO) of some type.
///
/// STIX defines a set of STIX Cyber-observable Objects (SCOs) for characterizing host-based and network-based information.
///
/// SCOs are used by various STIX Domain Objects (SDOs) to provide supporting context. The Observed Data SDO, for example, indicates that the raw data was observed at a particular time.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rosvg2qjx4h4>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CyberObject {
    /// Identifies the SCO type of SCO.
    #[serde(flatten)]
    pub object_type: CyberObjectType,
    /// Common object properties
    #[serde(flatten)]
    pub common_properties: CommonProperties,
}
impl CyberObject {
    /// Deserializes an SCO from a JSON String.
    /// Checks that all fields conform to the STIX 2.1 standard.
    /// If the `allow_custom` flag is false, checks that there are no fields in the JSON String
    /// that are not in the SCO type definition.
    pub fn from_json(json: &str, allow_custom: bool) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::DeserializationError(e.to_string()))?;
        validate_value(value, allow_custom, true)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.common_properties.revoked, Some(true))
    }
}

// Returns a reference to the identifier of the `CyberObject`.
// This implementation accesses the `id` field from the `common_properties`
// of the `CyberObject`, providing a way to retrieve the unique identifier
// associated with this object.
impl Identified for CyberObject {
    fn get_id(&self) -> &Identifier {
        &self.common_properties.id
    }
}

impl Related for CyberObject {
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

crate::impl_custom_properties_holder!(CyberObject);

impl Stix for CyberObject {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that we have the correct common properties for an SCO
        add_error(&mut errors, check_sco_properties(&self.common_properties));

        // Check common properties
        add_error(&mut errors, self.common_properties.stix_check());

        // Check the identifier (enforces UUIDv5 for SCOs)
        add_error(&mut errors, self.common_properties.id.stix_check());

        // Special check for NetworkTraffic that looks at both a NetworkTraffic property and a CommonProperty
        // If a protocol extension is present for a NetworkTraffic SCO, the corresponding protocol value for that extension **SHOULD** be listed in the protocols property.
        if let (CyberObjectType::NetworkTraffic(network_traffic), Some(extensions)) =
            (&self.object_type, &self.common_properties.extensions)
        {
            for key in extensions.keys() {
                // Check if the extension key is in the list of predefined protocol extensions
                if let Some(protocol) = PROTOCOLS_MAP.get(key) {
                    // If it is, check that the corresponding protocol is in the protocols property list, otherwise warn the user
                    if !network_traffic.protocols.contains(protocol) {
                        warn!("A {} extension is present for the Network Traffic Cyber Object {}, but it is missing the protocol {} in its protocols property.", key, self.get_id(), protocol);
                    }
                }
            }
        }

        // Check SCO type specific errors
        add_error(
            &mut errors,
            self.object_type.stix_check().map_err(|e| {
                Error::ValidationError(format!(
                    "Cyber Object {} is not a valid {}: {}",
                    self.get_id(),
                    self.object_type.as_ref(),
                    e
                ))
            }),
        );

        return_multiple_errors(errors)
    }
}

/// Checks that the required properties for an SCO are present and that the prohibited fields for an SCO are not present
pub fn check_sco_properties(properties: &CommonProperties) -> Result<(), Error> {
    let mut errors = Vec::new();

    if properties.created_by_ref.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `created_by_ref` property.".to_string(),
        ));
    }
    if properties.revoked.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `revoked` property.".to_string(),
        ));
    }
    if properties.labels.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `labels` property.".to_string(),
        ));
    }
    if properties.confidence.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `confidence` property.".to_string(),
        ));
    }
    if properties.lang.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `lang` property.".to_string(),
        ));
    }
    if properties.external_references.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `external_references` property.".to_string(),
        ));
    }
    if properties.created.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `created` property.".to_string(),
        ));
    }
    if properties.modified.is_some() {
        errors.push(Error::ValidationError(
            "SCOs cannot have a `modified` property.".to_string(),
        ));
    }

    return_multiple_errors(errors)
}

impl Stix for CyberObjectType {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            CyberObjectType::Artifact(artifact) => artifact.stix_check(),
            CyberObjectType::AutonomousSystem(automomous_system) => automomous_system.stix_check(),
            CyberObjectType::Directory(directory) => directory.stix_check(),
            CyberObjectType::DomainName(domain_name) => domain_name.stix_check(),
            CyberObjectType::EmailAddress(email_address) => email_address.stix_check(),
            CyberObjectType::EmailMessage(email_message) => email_message.stix_check(),
            CyberObjectType::File(file) => file.stix_check(),
            CyberObjectType::Ipv4Addr(ipv4_addr) => ipv4_addr.stix_check(),
            CyberObjectType::Ipv6Addr(ipv6_addr) => ipv6_addr.stix_check(),
            CyberObjectType::MacAddr(mac_address) => mac_address.stix_check(),
            CyberObjectType::Mutex(mutex) => mutex.stix_check(),
            CyberObjectType::NetworkTraffic(network_traffic) => network_traffic.stix_check(),
            CyberObjectType::Process(process) => process.stix_check(),
            CyberObjectType::Software(software) => software.stix_check(),
            CyberObjectType::Url(url) => url.stix_check(),
            CyberObjectType::UserAccount(user_account) => user_account.stix_check(),
            CyberObjectType::WindowsRegistryKey(windows_registry_key) => {
                windows_registry_key.stix_check()
            }
            CyberObjectType::WindowsRegistryKeyType(windows_registry_key_type) => {
                windows_registry_key_type.stix_check()
            }
            CyberObjectType::X509Certificate(x509_certificate) => x509_certificate.stix_check(),
        }
    }
}

pub use builder::CyberObjectBuilder;

/// The various SCO types represented in STIX.
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
pub enum CyberObjectType {
    Artifact(Artifact),
    AutonomousSystem(AutonomousSystem),
    Directory(Directory),
    DomainName(DomainName),
    #[serde(rename = "email-addr", alias = "email-address")]
    #[strum(serialize = "email-addr")]
    EmailAddress(EmailAddress),
    EmailMessage(EmailMessage),
    File(File),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    MacAddr(MacAddr),
    Mutex(Mutex),
    NetworkTraffic(NetworkTraffic),
    Process(Process),
    Software(Software),
    Url(Url),
    UserAccount(UserAccount),
    WindowsRegistryKey(WindowsRegistryKey),
    WindowsRegistryKeyType(WindowsRegistryKeyType),
    X509Certificate(Box<X509Certificate>),
}
