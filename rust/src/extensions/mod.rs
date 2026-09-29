//! Contains the data structures and implementation for predefined Stix Cyber-observable object extensions.
//!
//! These provide additional functionality and customization options for various SCOs

use crate::{
    base::Stix,
    error::StixError as Error,
    types::{stix_case, DictionaryValue, StixDictionary},
};
use serde::{de::DeserializeOwned, Serialize};

/// Known predefined extensions specific to particular SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SpecialExtensions {
    FileExtensions(FileExtensions),
    NetworkTrafficExtensions(NetworkTrafficExtensions),
    ProcessExtensions(ProcessExtensions),
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
pub fn check_extension(key: &str, value: &StixDictionary<DictionaryValue>) -> Result<(), Error> {
    match stix_case(key).as_ref() {
        "archive-ext" => dict_to_extension::<ArchiveExtension>(value)?.stix_check(),
        "ntfs-ext" => dict_to_extension::<NtfsExtension>(value)?.stix_check(),
        "pdf-ext" => dict_to_extension::<PdfExtension>(value)?.stix_check(),
        "raster-ext" => dict_to_extension::<RasterExtension>(value)?.stix_check(),
        "windows-pebinary-ext" => {
            dict_to_extension::<WindowsPebinaryExtension>(value)?.stix_check()
        }
        "icmp-ext" => dict_to_extension::<IcmpExtension>(value)?.stix_check(),
        "http-request-ext" => dict_to_extension::<HttpRequestExtension>(value)?.stix_check(),
        "socket-ext" => dict_to_extension::<SocketExtenion>(value)?.stix_check(),
        "tcp-ext" => dict_to_extension::<TcpExtension>(value)?.stix_check(),
        "windows-process-ext" => dict_to_extension::<WindowsProcessExtension>(value)?.stix_check(),
        "windows-service-ext" => dict_to_extension::<WindowsServiceExtension>(value)?.stix_check(),
        "unix-account-ext" => dict_to_extension::<UnixAccountExtension>(value)?.stix_check(),
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

pub mod file;
pub mod network_traffic;
pub mod process;
pub mod user_account;

pub use self::file::*;
pub use self::network_traffic::*;
pub use self::process::*;
pub use self::user_account::*;
