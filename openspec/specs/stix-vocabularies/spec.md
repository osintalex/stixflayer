# stix-vocabularies Specification

## Purpose

Guarantees that values the library emits for STIX-defined enumerations are identical to the ST 2.1 specification (and the IANA/Windows registries it incorporates), so documents produced by stixflayer are conformant byte-for-byte.

## Requirements

### Requirement: Vocabulary values match the ST 2.1 specification

Every serialized value of a STIX-defined vocabulary SHALL be identical to the corresponding value in the ST 2.1 specification, including casing and spelling.

#### Scenario: Windows registry DWORD datatype

- **WHEN** a windows registry datatype value for the DWORD type is serialized
- **THEN** it is emitted as `REG_DWORD`

#### Scenario: Windows registry resource requirements datatype

- **WHEN** a windows registry datatype value for the resource requirements list type is serialized
- **THEN** it is emitted as `REG_RESOURCE_REQUIREMENTS_LIST`

#### Scenario: ICMP protocol value

- **WHEN** the network-traffic extension-to-protocol mapping resolves the ICMP extension
- **THEN** the protocol value is `icmp`

#### Scenario: Emergency services identity sector

- **WHEN** identity sector values are serialized
- **THEN** the emergency services sector is emitted as `emergency-services`
- **AND** no value `emergency-services-sanitation` exists in the vocabulary
