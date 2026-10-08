use crate::{
    base::Stix,
    common::validation::{is_exact_vocab_value, validate_refs_are_type},
    cyber_observable_objects::vocab::{
        WindowsIntegrityEnum, WindowsServiceStartTypeEnum, WindowsServiceStatusEnum,
        WindowsServiceTypeEnum,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{Identifier, StixDictionary},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::{AsRefStr, EnumIter};

/// Possible extensions for Process SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum ProcessExtensions {
    WindowsProcessExt(WindowsProcessExtension),
    WindowsServiceExt(WindowsServiceExtension),
}

/// The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oyegq07gjf5t>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessExtension {
    /// Specifies whether Address Space Layout Randomization (ASLR) is enabled for the process.
    pub aslr_enabled: Option<bool>,
    /// Specifies whether Data Execution Prevention (DEP) is enabled for the process.
    pub dep_enabled: Option<bool>,
    /// Specifies the current priority class of the process in Windows.
    pub priority: Option<String>,
    /// Specifies the Security ID (SID) value of the owner of the process.
    pub owner_sid: Option<String>,
    /// Specifies the title of the main window of the process.
    pub window_title: Option<String>,
    /// Specifies the STARTUP_INFO struct used by the process, as a dictionary.
    pub startup_info: Option<StixDictionary<Vec<String>>>,
    /// Specifies the Windows integrity level, or trustworthiness, of the process.
    pub integrity_level: Option<String>,
}
impl Stix for WindowsProcessExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(priority) = &self.priority {
            if !priority.ends_with("_CLASS") {
                errors.push(Error::ValidationError(format!(
                    "priority MUST end with '_CLASS'. Got '{}'.",
                    priority,
                )));
            }
        }
        if let Some(integrity_level) = &self.integrity_level {
            if !is_exact_vocab_value::<WindowsIntegrityEnum, _>(integrity_level) {
                errors.push(Error::ValidationError(format!(
                        "The values of integrity_level MUST come from the windows-integrity-level-enum enumeration. {}.",
                        integrity_level,
                    )));
            }
        }

        if let Some(startup_info) = &self.startup_info {
            add_error(&mut errors, startup_info.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Windows Service Extension
///
/// The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lbcvc2ahx1s0>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsServiceExtension {
    /// Specifies the name of the service.
    pub service_name: Option<String>,
    /// Specifies the descriptions defined for the service.
    pub descriptions: Option<Vec<String>>,
    /// Specifies the display name of the service in Windows GUI controls.
    pub display_name: Option<String>,
    /// Specifies the name of the load ordering group of which the service is a member.
    pub group_name: Option<String>,
    /// Specifies the start options defined for the service.
    pub start_type: Option<String>,
    /// Specifies the DLLs loaded by the service, as a reference to one or more File objects.
    pub service_dll_refs: Option<Vec<Identifier>>,
    /// Specifies the type of the service.
    pub service_type: Option<String>,
    /// Specifies the current status of the service.
    pub service_status: Option<String>,
}
impl Stix for WindowsServiceExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(service_dll_refs) = &self.service_dll_refs {
            add_error(
                &mut errors,
                validate_refs_are_type(service_dll_refs, &["file"], "service_dll_refs"),
            );
        }
        if let Some(start_type) = &self.start_type {
            if !is_exact_vocab_value::<WindowsServiceStartTypeEnum, _>(start_type) {
                errors.push(Error::ValidationError(format!(
                        "The values of start_type MUST come from the windows-service-start-type-enum enumeration.. {}.",
                        start_type,
                    )));
            }
        }
        if let Some(service_status) = &self.service_status {
            if !is_exact_vocab_value::<WindowsServiceStatusEnum, _>(service_status) {
                errors.push(Error::ValidationError(format!(
                        "The values of service_status MUST come from the windows-service-status-enum enumeration.. {}.",
                        service_status,
                    )));
            }
        }
        if let Some(service_type) = &self.service_type {
            if !is_exact_vocab_value::<WindowsServiceTypeEnum, _>(service_type) {
                errors.push(Error::ValidationError(format!(
                        "The values of service_type MUST come from the windows-service-type-enum enumeration.. {}.",
                        service_type,
                    )));
            }
        }

        return_multiple_errors(errors)
    }
}
