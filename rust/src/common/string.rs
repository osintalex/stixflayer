//! Kebab-case normalization for STIX identifiers and type names.
use convert_case::{Boundary, Case, Casing};

/// Converts a raw string to kebab-case.
pub fn stix_case(raw_str: &str) -> String {
    raw_str
        .without_boundaries(&[Boundary::UPPER_DIGIT, Boundary::LOWER_DIGIT])
        .to_case(Case::Kebab)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_case() {
        let raw_str = "Ipv4Addr";
        let result = stix_case(raw_str);
        assert_eq!(&result, "ipv4-addr");
    }
}
