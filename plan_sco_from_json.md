# SCO from_json Implementation

## Problem
SCO classes (IPv4Address, File, DomainName, etc.) don't have `from_json` method - only SDOs have it.

## Solution
Add `CyberObjectBuilder::from()` method in Rust to create builder from parsed CyberObject.

## Changes Needed

### 1. Rust (rust/src/cyber_observable_objects/sco.rs)
```rust
impl CyberObjectBuilder {
    /// Create a new CyberObjectBuilder from an existing CyberObject
    pub fn from(cyber_object: &CyberObject) -> Result<Self, Error> {
        // Clone the object_type and common_properties
        // Would create versionable builder
    }
}
```

### 2. Python (python/src/lib.rs)
- Add `from_json` staticmethod to each SCO class
- Uses: `CyberObjectBuilder::from()` then wrap in Python class

## Classes Needing from_json (18)
IPv4Address, IPv6Address, DomainName, URL, EmailAddress, EmailMessage, MacAddr, AutonomousSystem, File, Software, Directory, Mutex, Process, NetworkTraffic, UserAccount, WindowsRegistryKey, X509Certificate, Artifact

## Test
```python
ipv4 = IPv4Address.from_json('{"type": "ipv4-addr", "value": "192.168.1.1", ...}')
assert ipv4.value == "192.168.1.1"
```

## Effort
~1 hour once Rust method exists.