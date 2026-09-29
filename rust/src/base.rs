//! Re-export facade for STIX-wide properties, traits, and helpers.
pub use crate::builder::{BuilderType, CommonPropertiesBuilder, StixObjectCategory};
pub use crate::common::time::check_timestamp_ordering;
pub use crate::custom_property::{
    validate_custom_property_name, validate_custom_property_suffix_value,
};
pub use crate::stix::{CommonProperties, CustomPropertiesHolder, Stix};
