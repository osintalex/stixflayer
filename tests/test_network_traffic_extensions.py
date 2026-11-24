"""HTTP request extension header value shape (STIX 2.1 §6.12.2).

Each ``request_header`` value MUST be a list of strings so a repeated header
can be represented. A bare string value is rejected at deserialization time.
"""

from __future__ import annotations

import json

import pytest

import stixflayer

VALID_HEADERS_JSON = """
{
    "type": "network-traffic",
    "spec_version": "2.1",
    "id": "network-traffic--550e8400-e29b-51d4-a716-446655440026",
    "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
    "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012",
    "src_port": 80,
    "dst_port": 443,
    "protocols": ["http"],
    "extensions": {
        "http-request-ext": {
            "request_method": "get",
            "request_value": "/api/data",
            "request_header": {
                "Host": ["www.example.com"],
                "X-Forwarded-For": ["192.0.2.1", "192.0.2.2"]
            }
        }
    }
}
"""

STRING_HEADER_JSON = """
{
    "type": "network-traffic",
    "spec_version": "2.1",
    "id": "network-traffic--550e8400-e29b-51d4-a716-446655440027",
    "src_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440011",
    "dst_ref": "ipv4-addr--550e8400-e29b-51d4-a716-446655440012",
    "src_port": 80,
    "dst_port": 443,
    "protocols": ["http"],
    "extensions": {
        "http-request-ext": {
            "request_method": "get",
            "request_value": "/api/data",
            "request_header": {
                "Host": "www.example.com"
            }
        }
    }
}
"""


def test_request_header_lists_roundtrip() -> None:
    network_traffic = stixflayer.NetworkTraffic.from_json(VALID_HEADERS_JSON)

    assert network_traffic.extensions is not None
    headers = network_traffic.extensions["http-request-ext"]["request_header"]
    assert headers["Host"] == ["www.example.com"]
    assert headers["X-Forwarded-For"] == ["192.0.2.1", "192.0.2.2"]

    roundtrip = json.loads(network_traffic.to_json())
    roundtrip_headers = roundtrip["extensions"]["http-request-ext"]["request_header"]
    assert roundtrip_headers["Host"] == ["www.example.com"]
    assert roundtrip_headers["X-Forwarded-For"] == ["192.0.2.1", "192.0.2.2"]


def test_request_header_string_value_is_rejected() -> None:
    with pytest.raises(stixflayer.DeserializationError):
        stixflayer.NetworkTraffic.from_json(STRING_HEADER_JSON)
