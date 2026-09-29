use crate::base::Stix;
use crate::types::{DictionaryValue, Identifier, StixDictionary, Timestamp};
use crate::common::validation::{validate_refs_are_type};
use crate::error::{add_error, return_multiple_errors, StixError as Error};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;
use serde_this_or_that::{as_opt_u64};
use regex::Regex;
use log::warn;

/// Network Traffic
///
/// The Network Traffic object represents arbitrary network traffic that originates \
/// from a source and is addressed to a destination. The network traffic MAY or MAY NOT
/// constitute a valid unicast, multicast, or broadcast network connection. This MAY also
/// include traffic that is not established, such as a SYN flood.
///
/// To allow for use cases where a source or destination address may be sensitive and not
/// suitable for sharing, such as addresses that are internal to an organization’s network,
/// the source and destination properties (src_ref and dst_ref, respectively) are defined
/// as optional in the properties table below. However, a Network Traffic object **MUST**
/// contain the protocols property and at least one of the src_ref or dst_ref properties
/// and SHOULD contain the src_port and dst_port properties.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rgnc3w40xy>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct NetworkTraffic {
    pub start: Option<Timestamp>,
    pub end: Option<Timestamp>,
    pub is_active: Option<bool>,
    pub src_ref: Option<Identifier>,
    pub dst_ref: Option<Identifier>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub src_port: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub dst_port: Option<u64>,
    pub protocols: Vec<String>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub src_byte_count: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub dst_byte_count: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub src_packets: Option<u64>,
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub dst_packets: Option<u64>,
    pub ipfix: Option<StixDictionary<DictionaryValue>>,
    pub src_payload_ref: Option<Identifier>,
    pub dst_payload_ref: Option<Identifier>,
    pub encapsulates_refs: Option<Vec<Identifier>>,
    pub encapsulated_by_ref: Option<Identifier>,
}
impl Stix for NetworkTraffic {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(src_port) = &self.src_port {
            add_error(&mut errors, src_port.stix_check());
        }
        if let Some(dst_port) = &self.dst_port {
            add_error(&mut errors, dst_port.stix_check());
        }
        if let Some(src_byte_count) = &self.src_byte_count {
            add_error(&mut errors, src_byte_count.stix_check());
        }
        if let Some(dst_byte_count) = &self.dst_byte_count {
            add_error(&mut errors, dst_byte_count.stix_check());
        }
        if let Some(src_packets) = &self.src_packets {
            add_error(&mut errors, src_packets.stix_check());
        }
        if let Some(dst_packets) = &self.dst_packets {
            add_error(&mut errors, dst_packets.stix_check());
        }

        if self.src_port.is_none() || self.dst_port.is_none() {
            warn!("Network traffic should contain both the src_port and dst_port properties.");
        }
        if let Some(dst_payload_ref) = &self.dst_payload_ref {
            dst_payload_ref.stix_check()?;
            if dst_payload_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "dst_payload_ref {} MUST be of type artifact.",
                    dst_payload_ref.get_type()
                )));
            }
        }
        if let Some(encapsulated_by_ref) = &self.encapsulated_by_ref {
            encapsulated_by_ref.stix_check()?;
            if encapsulated_by_ref.get_type() != "network-traffic" {
                errors.push(Error::ValidationError(format!(
                    "encapsulated_by_ref {} MUST be of type network-traffic.",
                    encapsulated_by_ref.get_type()
                )));
            }
        }
        if let Some(dst_port) = self.dst_port {
            if !(0..=65535).contains(&dst_port) {
                errors.push(Error::ValidationError(
                format!("dst_port {} Specifies the source port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.",dst_port),
            ));
            }
        }
        if let Some(src_port) = self.src_port {
            if !(0..=65535).contains(&src_port) {
                errors.push(Error::ValidationError(
                format!("src_port {} Specifies the source port used in the network traffic, as an integer. The port value MUST be in the range of 0 - 65535.",src_port),
            ));
            }
        }
        if let Some(dst_ref) = &self.dst_ref {
            add_error(&mut errors, dst_ref.stix_check());
            if dst_ref.get_type() != "ipv4-addr"
                && dst_ref.get_type() != "ipv6-addr"
                && dst_ref.get_type() != "mac-addr"
                && dst_ref.get_type() != "domain-name"
            {
                errors.push(Error::ValidationError(
                    format!("dst_ref {} MUST be of type ipv4-addr, ipv6-addr, mac-addr, or domain-name (for cases where the IP address for a domain name is unknown).",dst_ref.get_type(),
                )));
            }
        }
        if let Some(encapsulates_refs) = &self.encapsulates_refs {
            encapsulates_refs.stix_check()?;
            add_error(
                &mut errors,
                validate_refs_are_type(encapsulates_refs, &["network-traffic"], "encapsulates_refs"),
            );
        }
        if let (Some(end), Some(is_active)) = (&self.end, &self.is_active) {
            if *is_active {
                errors.push(Error::ValidationError(
                    format!("If the is_active property is true, then the end {} property MUST NOT be included. If the end property is provided, is_active MUST be false.",end)
                ));
            }
        }

        if let (Some(start), Some(stop)) = (&self.start, &self.end) {
            if stop < start {
                errors.push(Error::ValidationError(format!("Network traffic has an end timestamp of {} and a start timestamp of {}. The former cannot be earlier than the latter.",
                    stop,
                    start
                )));
            }
        }

        if let Some(src_payload_ref) = &self.src_payload_ref {
            src_payload_ref.stix_check()?;
            if src_payload_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "src_payload_ref {} MUST be of type artifact.",
                    src_payload_ref.get_type()
                )));
            }
        }
        if let Some(src_ref) = &self.src_ref {
            add_error(&mut errors, src_ref.stix_check());
            if src_ref.get_type() != "ipv4-addr"
                && src_ref.get_type() != "ipv6-addr"
                && src_ref.get_type() != "mac-addr"
                && src_ref.get_type() != "domain-name"
            {
                errors.push(Error::ValidationError(
                        format!("src_ref {} MUST be of type ipv4-addr, ipv6-addr, mac-addr, or domain-name (for cases where the IP address for a domain name is unknown).",src_ref.get_type()),
                    ));
            }
        }

        add_error(&mut errors, self.protocols.stix_check());

        let protocols_joined = &self.protocols.join(",");
        if protocols_joined.contains("ip") && !protocols_joined.starts_with("ip") {
            errors.push(Error::ValidationError(
                    format!("protocols {} Protocols MUST be listed in low to high order, from outer to inner in terms of packet encapsulation. That is, the protocols in the outer level of the packet, such as IP, MUST be listed first.",protocols_joined),
                ));
        }
        let protocol_re = Regex::new(r"^[a-zA-Z0-9-]{1,15}$").unwrap();
        for p in &self.protocols {
            if !protocol_re.is_match(p) {
                errors.push(Error::ValidationError(format!(
                "The protocol name '{}' is not a valid IANA service name or protocol identifier.", p
            )));
            }
        }
        if let Some(ipfix) = &self.ipfix {
            add_error(&mut errors, ipfix.stix_check());
            let ipfix_key_re = Regex::new(r"^[a-z][a-zA-Z0-9]+$").unwrap();
            for (key, val) in ipfix.iter() {
                if !ipfix_key_re.is_match(key) {
                    errors.push(Error::ValidationError(format!(
                        "IPFIX key '{}' is not valid. Must start with a lowercase letter and contain only alphanumeric characters.", key
                    )));
                }
                match val {
                    DictionaryValue::String(string) => add_error(&mut errors,string.stix_check()),
                    DictionaryValue::Int(int) => add_error(&mut errors,int.stix_check()),
                    _ =>  errors.push(Error::ValidationError(
                        format!("Ipfix dictionary value {} SHOULD be a case-preserved version of the IPFIX element name, e.g., octetDeltaCount. Each dictionary value MUST be either an integer or a string, as well as a valid IPFIX property.",val)
                    )),
                };
            }
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_imports)]
    use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder};
    use crate::extensions::{
        ArchiveExtension, FileExtensions, HttpRequestExtension, IcmpExtension,
        NetworkTrafficExtensions, ProcessExtensions, SocketExtenion, SpecialExtensions,
        UnixAccountExtension, UserAccountExtensions, WindowsProcessExtension,
    };
    use crate::types::{DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp};
    use log::warn;
    use serde_json::Value;
    use std::{collections::HashMap, str::FromStr};
    use test_log::test;

    #[test]
    fn deserialize_network_traffic_se() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "src_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "src_port": 223,
            "protocols": [
                "ip",
                "tcp"
            ],
            "extensions": {
                "socket-ext": {
                "address_family": "AF_INET",
                "is_listening": true,
                "socket_type": "SOCK_STREAM"
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let se = SpecialExtensions::NetworkTrafficExtensions(NetworkTrafficExtensions::SocketExt(
            SocketExtenion {
                address_family: Some("AF_INET".to_string()),
                is_blocking: None,
                is_listening: Some(true),
                options: None,
                socket_type: Some("SOCK_STREAM".to_string()),
                socket_descriptor: None,
                socket_handle: None,
            },
        ));

        let expected = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .src_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .src_port(223)
            .unwrap()
            .protocols(vec!["ip".to_string(), "tcp".to_string()])
            .unwrap()
            .add_extension("socket-ext", se.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn serialize_network_traffic_se() {
        let mut se = r#"{
            "type": "network-traffic",
            "src_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "src_port": 223,
            "is_active":false,
            "end":"2016-05-12T08:17:27Z",
            "protocols": [
                "ip",
                "tcp"
            ],
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "extensions": {
                "socket-ext": {
                "address_family": "AF_INET",
                "is_listening": true,
                "socket_type": "SOCK_STREAM"
                }
            }
        }"#
        .to_string();
        se.retain(|c| !c.is_whitespace());

        let expected: Value = serde_json::from_str(&se).unwrap();

        let se = SpecialExtensions::NetworkTrafficExtensions(NetworkTrafficExtensions::SocketExt(
            SocketExtenion {
                address_family: Some("AF_INET".to_string()),
                is_listening: Some(true),
                socket_type: Some("SOCK_STREAM".to_string()),
                is_blocking: None,
                options: None,

                socket_descriptor: None,
                socket_handle: None,
            },
        ));

        let nt = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .src_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .src_port(223)
            .unwrap()
            .is_active(false)
            .unwrap()
            .end(Timestamp("2016-05-12T08:17:27.000Z".parse().unwrap()))
            .unwrap()
            .protocols(vec!["ip".to_string(), "tcp".to_string()])
            .unwrap()
            .add_extension("socket-ext", se.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();
        let result = serde_json::to_value(&nt).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_http_err() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4x-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "protocols": [
                "tcp",
                "http"
            ],
            "extensions": {
                "http-request-ext": {
                "request_method": "get",
                "request_value": "/download.html",
                "request_version": "http/1.1"
                }
            }             
        }"#;

        let result = CyberObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_network_traffic_http_dict() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "protocols": [
                "tcp",
                "http"
            ],
            "extensions": {
                    "http-request-ext": {
                    "request_method": "get",
                    "request_value": "/download.html",
                    "request_version": "http/1.1",
                    "request_header": {
                        "Accept-Encoding": "gzip,deflate",
                        "User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113",
                        "Host": "www.example.com"
                    }
                }
            }             
        }"#;

        let result = CyberObject::from_json(json, false).unwrap();

        let mut rh = StixDictionary::new();
        rh.insert("Accept-Encoding", "gzip,deflate".to_string())
            .unwrap();
        rh.insert(
            "User-Agent",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113".to_string(),
        )
        .unwrap();
        rh.insert("Host", "www.example.com".to_string()).unwrap();

        let hre = SpecialExtensions::NetworkTrafficExtensions(
            NetworkTrafficExtensions::HttpRequestExt(HttpRequestExtension {
                request_method: "get".to_string(),
                request_value: "/download.html".to_string(),
                request_version: Some("http/1.1".to_string()),
                request_header: Some(rh),
                message_body_length: None,
                message_body_data_ref: None,
            }),
        );

        let expected = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .dst_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .protocols(vec!["tcp".to_string(), "http".to_string()])
            .unwrap()
            .add_extension("http-request-ext", hre.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_icmp() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "src_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "ipfix": {
                "minimumIpTotalLength": 32,
                "maximumIpTotalLength": 2556
            },
            "protocols": [
                "icmp"
            ],
            "extensions": {
                "icmp-ext": {
                "icmp_type_hex": "08",
                "icmp_code_hex": "00"
                }
            }
        }"#;

        let mut ipfix = StixDictionary::new();
        ipfix
            .insert("minimumIpTotalLength", DictionaryValue::Int(32))
            .unwrap();
        ipfix
            .insert("maximumIpTotalLength", DictionaryValue::Int(2556))
            .unwrap();

        let result = CyberObject::from_json(json, false).unwrap();

        let icmp = SpecialExtensions::NetworkTrafficExtensions(NetworkTrafficExtensions::IcmpExt(
            IcmpExtension {
                icmp_type_hex: "08".to_string(),
                icmp_code_hex: "00".to_string(),
            },
        ));

        let expected = CyberObjectBuilder::new("network-traffic")
            .unwrap()
            .src_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .dst_ref(Identifier::new_test("ipv4-addr"))
            .unwrap()
            .ipfix(ipfix)
            .unwrap()
            .protocols(vec!["icmp".to_string()])
            .unwrap()
            .add_extension("icmp-ext", icmp.extension_to_dict().unwrap())
            .unwrap()
            .build()
            .unwrap()
            // Change id, created, and modified fields for test matching
            .test_id();

        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_network_traffic_icmp_invalid() {
        //using invalid icmp_type_hex
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "src_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "ipfix": {
                "minimumIpTotalLength": 32,
                "maximumIpTotalLength": 2556
            },
            "protocols": [
                "icmp"
            ],
            "extensions": {
                "icmp-ext": {
                "icmp_type_hex": "081",
                "icmp_code_hex": "00"
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false);

        assert!(result.is_err());
    }

    #[test]
    fn deserialize_network_traffic_http_request_invalid_header() {
        let json = r#"{
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "dst_ref": "ipv4-addr--cc7fa653-c35f-53db-afdd-dce4c3a241d5",
            "protocols": [
                "tcp",
                "http"
            ],
            "extensions": {
                "http-request-ext": {
                    "request_method": "get",
                    "request_value": "/download.html",
                    "request_version": "http/1.1",
                    "request_header": {
                        "Accept-Encoding": ["gzip,deflate"],
                        "Host": ["www.example.com"],
                        "x-foobar": ["something"]
                    }
                }
            }
        }"#;

        let result = CyberObject::from_json(json, false);
        assert!(result.is_err());
    }
}
