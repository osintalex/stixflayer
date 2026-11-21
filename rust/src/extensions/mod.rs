//! Contains the data structures and implementation for predefined Stix Cyber-observable object extensions.
//!
//! These provide additional functionality and customization options for various SCOs

use crate::{
    base::Stix,
    error::{CheckContext, StixError as Error},
    types::{stix_case, DictionaryValue, StixDictionary},
};
use serde::{de::DeserializeOwned, Serialize};

/// Known predefined extensions specific to particular SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SpecialExtensions {
    /// A predefined extension for File SCOs.
    FileExtensions(FileExtensions),
    /// A predefined extension for NetworkTraffic SCOs.
    NetworkTrafficExtensions(NetworkTrafficExtensions),
    /// A predefined extension for Process SCOs.
    ProcessExtensions(ProcessExtensions),
    /// A predefined extension for UserAccount SCOs.
    UserAccountExtensions(UserAccountExtensions),
}

impl SpecialExtensions {
    /// Convert a known predefined extension to a raw extension dictionary
    pub fn extension_to_dict(&self) -> Result<StixDictionary<DictionaryValue>, Error> {
        serde_json::from_value(
            serde_json::to_value(self).map_err(|e| Error::SerializationError(e.to_string()))?,
        )
        .map_err(|e| Error::DeserializationError(e.to_string()))
    }
}

/// Validate a known predefined extension expressed as a raw extension dictionary
pub fn check_extension(
    key: &str,
    value: &StixDictionary<DictionaryValue>,
    ctx: &mut CheckContext,
) -> Result<(), Error> {
    match stix_case(key).as_ref() {
        "archive-ext" => dict_to_extension::<ArchiveExtension>(value)?.check(ctx),
        "ntfs-ext" => dict_to_extension::<NtfsExtension>(value)?.check(ctx),
        "pdf-ext" => dict_to_extension::<PdfExtension>(value)?.check(ctx),
        "raster-ext" => dict_to_extension::<RasterExtension>(value)?.check(ctx),
        "windows-pebinary-ext" => dict_to_extension::<WindowsPebinaryExtension>(value)?.check(ctx),
        "icmp-ext" => dict_to_extension::<IcmpExtension>(value)?.check(ctx),
        "http-request-ext" => dict_to_extension::<HttpRequestExtension>(value)?.check(ctx),
        "socket-ext" => dict_to_extension::<SocketExtenion>(value)?.check(ctx),
        "tcp-ext" => dict_to_extension::<TcpExtension>(value)?.check(ctx),
        "windows-process-ext" => dict_to_extension::<WindowsProcessExtension>(value)?.check(ctx),
        "windows-service-ext" => dict_to_extension::<WindowsServiceExtension>(value)?.check(ctx),
        "unix-account-ext" => dict_to_extension::<UnixAccountExtension>(value)?.check(ctx),
        _ => Err(Error::UnknownExtension),
    }
}

/// Convert a raw extension dictionary to a known predefined extension
fn dict_to_extension<T: DeserializeOwned>(
    dictionary: &StixDictionary<DictionaryValue>,
) -> Result<T, Error> {
    let extension: Result<T, Error> = serde_json::from_value(
        serde_json::to_value(dictionary).map_err(|e| Error::SerializationError(e.to_string()))?,
    )
    .map_err(|e| Error::DeserializationError(e.to_string()));
    extension
}

/// Predefined extensions for File SCOs.
pub mod file;
/// Predefined extensions for NetworkTraffic SCOs.
pub mod network_traffic;
/// Predefined extensions for Process SCOs.
pub mod process;
/// Predefined extensions for UserAccount SCOs.
pub mod user_account;

pub use self::file::*;
pub use self::network_traffic::*;
pub use self::process::*;
pub use self::user_account::*;
