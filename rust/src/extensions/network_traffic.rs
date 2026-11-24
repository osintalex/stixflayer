use crate::error::CheckContext;
use crate::{
    base::Stix,
    common::validation::{is_exact_vocab_value, is_valid_hex},
    cyber_observable_objects::vocab::{NetworkSocketAddressFamilyEnum, NetworkSocketTypeEnum},
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{DictionaryValue, Identifier, StixDictionary},
};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_u64;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, EnumIter};

/// Possible extensions for NetworkTraffic SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum NetworkTrafficExtensions {
    /// The ICMP extension (`icmp-ext`).
    IcmpExt(IcmpExtension),
    /// The HTTP request extension (`http-request-ext`).
    HttpRequestExt(HttpRequestExtension),
    /// The Network Socket extension (`socket-ext`).
    SocketExt(SocketExtenion),
    /// The TCP extension (`tcp-ext`).
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
    fn check(&self, _ctx: &mut CheckContext) -> Result<(), Error> {
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
    ///
    /// Each value is a list of strings, so a repeated header can be represented.
    ///
    /// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_b0e376hgtml8>
    pub request_header: Option<StixDictionary<Vec<String>>>,
    /// Specifies the length of the HTTP message body, if included, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub message_body_length: Option<u64>,
    /// Specifies the data contained in the HTTP message body, if included.
    pub message_body_data_ref: Option<Identifier>,
}

impl Stix for HttpRequestExtension {
    fn check(&self, ctx: &mut CheckContext) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(message_body_length) = &self.message_body_length {
            add_error(&mut errors, message_body_length.check(ctx));
        }
        if let Some(message_body_data_ref) = &self.message_body_data_ref {
            message_body_data_ref.check(ctx)?;
            if message_body_data_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "message_body_data_ref {} must be of type 'artifact'.",
                    message_body_data_ref.get_type()
                )));
            }
        }
        if let Some(request_header) = &self.request_header {
            // Any valid header field name is accepted; STIX 2.1 does not
            // restrict this dictionary to a fixed list, and headers SHOULD
            // preserve case, so no lowercase warning is applied.
            add_error(&mut errors, request_header.check(ctx));
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
    fn check(&self, ctx: &mut CheckContext) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(socket_descriptor) = &self.socket_descriptor {
            add_error(&mut errors, socket_descriptor.check(ctx));
        }
        if let Some(address_family) = &self.address_family {
            if !is_exact_vocab_value::<NetworkSocketAddressFamilyEnum, _>(address_family) {
                errors.push(Error::ValidationError(format!(
                        "The values of this property MUST come from the network-socket-address-family-enum enumeration. {}.",
                        address_family,
                    )));
            }
        }
        if let Some(socket_type) = &self.socket_type {
            if !is_exact_vocab_value::<NetworkSocketTypeEnum, _>(socket_type) {
                errors.push(Error::ValidationError(format!(
                        "The values of this property MUST come from the network-socket-type-enum enumeration. {}.",
                        socket_type,
                    )));
            }
        }
        if let Some(options) = &self.options {
            add_error(&mut errors, options.check(ctx));
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
    fn check(&self, _ctx: &mut CheckContext) -> Result<(), Error> {
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
