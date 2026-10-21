# Cyber-observables

All classes below share the [common interface](overview.md#shared-behavior).
SCOs are identified by deterministic UUIDv5 identifiers derived from their
content — you never supply an `id` when constructing one.

```python
from stixflayer import IPv4Address

ip = IPv4Address(value="203.0.113.7")
print(ip.type, ip.id)
#> ipv4-addr ipv4-addr--9ddd739e-87b1-587d-83f2-62ef1130af2f
```

## Classes

| Class | Key properties |
|---|---|
| `IPv4Address` | `value` |
| `IPv6Address` | `value` |
| `DomainName` | `value` |
| `URL` | `value` |
| `EmailAddress` | `value`, `display_name` |
| `EmailMessage` | `subject`, `body`, `from_ref`, `to_refs` |
| `MacAddr` | `value` |
| `AutonomousSystem` | `number`, `name` |
| `File` | `name`, `hashes`, `size` |
| `Software` | `name`, `version` |
| `Directory` | `path` |
| `Mutex` | `name` |
| `Process` | `pid`, `command_line` |
| `NetworkTraffic` | `src_ref`, `dst_ref`, `src_port`, `dst_port`, `protocols` |
| `UserAccount` | `user_id`, `account_login` |
| `WindowsRegistryKey` | `key`, `values` |
| `X509Certificate` | `serial_number`, `hashes` |
| `Artifact` | `payload_bin`, `url`, `hashes` |

## Deterministic identifiers

The same observable always produces the same identifier — useful for
deduplication across feeds.

```python
from stixflayer import DomainName

a = DomainName(value="example.com")
b = DomainName(value="example.com")
print(a.id == b.id)
#> True
```
