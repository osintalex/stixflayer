# Spec Delta

## MODIFIED Requirements

### Requirement: HTTP request header names are not restricted to a fixed list

The `request_header` dictionary SHALL accept any valid HTTP header field name and MUST NOT reject a name solely because it is absent from a fixed list. Each header value SHALL be a list of strings, and a non-list value MUST be rejected.

#### Scenario: Custom header is accepted

- **WHEN** a network-traffic HTTP request extension contains a header named `X-Custom-Header` with a list value
- **THEN** validation succeeds

#### Scenario: Single and repeated header values are accepted

- **WHEN** `request_header` maps one header to `["value"]` and another to `["first", "second"]`
- **THEN** validation succeeds and both values survive serialization as lists

#### Scenario: String header value is rejected

- **WHEN** `request_header` maps a header to a bare string instead of a list
- **THEN** validation fails with a deserialization error
