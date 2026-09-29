use crate::{
    base::Stix,
    common::validation::is_valid_hex,
    cyber_observable_objects::vocab::{
        NetworkSocketAddressFamilyEnum, NetworkSocketTypeEnum,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{DictionaryValue, Identifier, StixDictionary},
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_u64;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, EnumIter, IntoEnumIterator};

/// Possible extensions for NetworkTraffic SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum NetworkTrafficExtensions {
    IcmpExt(IcmpExtension),
    HttpRequestExt(HttpRequestExtension),
    SocketExt(SocketExtenion),
    TcpExt(TcpExtension),
}

/// The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ozypx0lmkebv>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IcmpExtension {
    /// Specifies the ICMP type byte.
    pub icmp_type_hex: String,
    /// Specifies the ICMP code byte.
    pub icmp_code_hex: String,
}

impl Stix for IcmpExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();
        let icmp_type_hex = &self.icmp_type_hex;
        if !is_valid_hex(icmp_type_hex) {
            errors.push(Error::ParseHexError(
                "icmp_type_hex -- ".to_string() + icmp_type_hex,
            ))
        }
        let icmp_code_hex = &self.icmp_code_hex;
        if !is_valid_hex(icmp_code_hex) {
            errors.push(Error::ParseHexError(
                "icmp_code_hex -- ".to_string() + icmp_code_hex,
            ))
        }

        return_multiple_errors(errors)
    }
}

/// Valid HTTP request header names as defined by stix2validator v3.3.1.
const HTTP_REQUEST_HEADERS: &[&str] = &[
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Datetime",
    "Authorization",
    "Cache-Control",
    "Connection",
    "Cookie",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Expect",
    "Forwarded",
    "From",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Pragma",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent",
    "Upgrade",
    "Via",
    "Warning",
    "X-Requested-With",
    "DNT",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Front-End-Https",
    "X-Http-Method-Override",
    "X-ATT-DeviceId",
    "X-Wap-Profile",
    "Proxy-Connection",
    "X-UIDH",
    "X-Csrf-Token",
    "X-Request-ID",
    "X-Correlation-ID",
];

/// The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_b0e376hgtml8>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestExtension {
    /// Specifies the HTTP method portion of the HTTP request line, as a lowercase string.
    pub request_method: String,
    /// Specifies the value (typically a resource path) portion of the HTTP request line.
    pub request_value: String,
    /// Specifies the HTTP version portion of the HTTP request line, as a lowercase string.
    pub request_version: Option<String>,
    /// Specifies all of the HTTP header fields that may be found in the HTTP client request, as a dictionary.
    pub request_header: Option<StixDictionary<String>>,
    /// Specifies the length of the HTTP message body, if included, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub message_body_length: Option<u64>,
    /// Specifies the data contained in the HTTP message body, if included.
    pub message_body_data_ref: Option<Identifier>,
}

impl Stix for HttpRequestExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(message_body_length) = &self.message_body_length {
            add_error(&mut errors, message_body_length.stix_check());
        }
        if let Some(message_body_data_ref) = &self.message_body_data_ref {
            message_body_data_ref.stix_check()?;
            if message_body_data_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "message_body_data_ref {} must be of type 'artifact'.",
                    message_body_data_ref.get_type()
                )));
            }
        }
        if let Some(request_header) = &self.request_header {
            add_error(&mut errors, request_header.stix_check());
            for (key, _) in request_header.iter() {
                if !HTTP_REQUEST_HEADERS.contains(&key.as_str()) {
                    errors.push(Error::ValidationError(format!(
                        "The 'request_header' property contains an invalid HTTP request header ('{}').",
                        key
                    )));
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8jamupj9ubdv>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketExtenion {
    /// Specifies the address family (AF_*) that the socket is configured for.
    pub address_family: Option<String>,
    /// Specifies whether the socket is in blocking mode.
    pub is_blocking: Option<bool>,
    /// Specifies whether the socket is in listening mode.
    pub is_listening: Option<bool>,
    /// Specifies any options (e.g., SO_*) that may be used by the socket, as a dictionary.
    pub options: Option<StixDictionary<DictionaryValue>>,
    /// Specifies the type of the socket.
    pub socket_type: Option<String>,
    /// Specifies the socket file descriptor value associated with the socket, as a non-negative integer.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub socket_descriptor: Option<u64>,
    /// Specifies the handle or inode value associated with the socket.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub socket_handle: Option<u64>,
}

impl Stix for SocketExtenion {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(socket_descriptor) = &self.socket_descriptor {
            add_error(&mut errors, socket_descriptor.stix_check());
        }
        if let Some(address_family) = &self.address_family {
            if NetworkSocketAddressFamilyEnum::iter().all(|x| x.as_ref() != address_family) {
                errors.push(Error::ValidationError(format!(
                        "The values of this property MUST come from the network-socket-address-family-enum enumeration. {}.",
                        address_family,
                    )));
            }
        }
        if let Some(socket_type) = &self.socket_type {
            if NetworkSocketTypeEnum::iter().all(|x| x.as_ref() != socket_type) {
                errors.push(Error::ValidationError(format!(
                        "The values of this property MUST come from the network-socket-type-enum enumeration. {}.",
                        socket_type,
                    )));
            }
        }
        if let Some(options) = &self.options {
            add_error(&mut errors, options.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// The TCP extension specifies a default extension for capturing network traffic properties specific to TCP.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k2njqio7f142>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpExtension {
    /// Specifies the source TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).
    pub src_flags_hex: Option<String>,
    /// Specifies the destination TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).
    pub dst_flags_hex: Option<String>,
}

impl Stix for TcpExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(src_flags_hex) = &self.src_flags_hex {
            warn!("If the start and end times of the traffic are not specified, src_flags_hex {} SHOULD be interpreted as the union of all TCP flags observed over the entirety of the network traffic being reported upon.",src_flags_hex);
        }
        if let Some(dst_flags_hex) = &self.dst_flags_hex {
            warn!("If the start and end times of the traffic are not specified, dst_flags_hex {} SHOULD be interpreted as the union of all TCP flags observed over the entirety of the network traffic being reported upon.",dst_flags_hex);
        }
        let mut errors = Vec::new();
        if let Some(src_flags_hex) = &self.src_flags_hex {
            if !is_valid_hex(src_flags_hex) {
                errors.push(Error::ParseHexError(
                    "src_flags_hex -- ".to_string() + src_flags_hex,
                ))
            }
        }
        if let Some(dst_flags_hex) = &self.dst_flags_hex {
            if !is_valid_hex(dst_flags_hex) {
                errors.push(Error::ParseHexError(
                    "dst_flags_hex -- ".to_string() + dst_flags_hex,
                ))
            }
        }

        return_multiple_errors(errors)
    }
}
