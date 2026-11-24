//! Rust crate documentation is the crate README so docs.rs and crates.io
//! render the same page, and the README's Rust example is compiled and run as
//! a doctest by `cargo test`.
#![doc = include_str!("../README.md")]
// Every public item in the public API surface must be documented; the
// Python-binding module is #[doc(hidden)], which also exempts it from this lint.
#![deny(missing_docs)]

pub mod base;
pub mod builder;
pub mod bundles;
/// Shared helper modules: validation utilities, string normalization, and timestamp ordering checks.
pub mod common;
pub mod custom_objects;
pub mod custom_property;
pub mod cyber_observable_objects;
pub mod dictionary;
pub mod domain_objects;
pub mod error;
pub mod extensions;
pub mod external_reference;
pub mod granular_marking;
pub mod hashes;
pub mod identifier;
pub mod json;
pub mod kill_chain;
pub mod meta_objects;
pub mod object;
pub mod pattern;
pub mod properties;
pub mod relationship_objects;
pub mod stix;
pub mod taxonomy;
pub mod timestamp;
pub mod types;
pub mod validation;

#[cfg(feature = "pyo3")]
#[doc(hidden)]
pub mod python_bindings;

// Re-export commonly used types and builders
pub use bundles::Bundle;
pub use cyber_observable_objects::sco::CyberObjectBuilder;
pub use domain_objects::sdo::{DomainObjectBuilder, DomainObjectType};
pub use error::StixError;
pub use meta_objects::extension_definition::ExtensionDefinitionBuilder;
pub use meta_objects::language_content::LanguageContentBuilder;
pub use meta_objects::marking_definition::MarkingDefinitionBuilder;
pub use object::FromJson;
pub use relationship_objects::RelationshipObjectBuilder;
pub use types::{ExtensionType, Hashes, Identified, Identifier, KillChainPhase, Timestamp};
pub use validation::ValidationOptions;
