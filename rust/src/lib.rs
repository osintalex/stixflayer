//! #stixflayer
//!
//! An implementation of STIX 2.1 in Rust.
//!
//! This is a work in progress implementation of the object and features of STIX 2.1 as a Rust library.
//! Eventually, this will become a full Rust-based STIX API.
//!
//! The objects and features in this library are intended to conform to the STIX 2.1 standards detailed in [this document](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).

pub mod base;
pub mod bundles;
pub mod custom_objects;
pub mod cyber_observable_objects;
pub mod datastore;
pub mod domain_objects;
pub mod error;
pub mod extensions;
pub mod json;
pub mod meta_objects;
pub mod object;
pub mod pattern;
pub mod relationship_objects;
pub mod types;

// Re-export commonly used types and builders
pub use bundles::Bundle;
pub use cyber_observable_objects::sco::CyberObjectBuilder;
pub use domain_objects::sdo::{DomainObjectBuilder, DomainObjectType};
pub use error::StixError;
pub use meta_objects::extension_definition::ExtensionDefinitionBuilder;
pub use meta_objects::language_content::LanguageContentBuilder;
pub use meta_objects::marking_definition::MarkingDefinitionBuilder;
pub use object::StixObject;
pub use relationship_objects::RelationshipObjectBuilder;
pub use types::{ExtensionType, Hashes, Identified, Identifier, KillChainPhase, Timestamp};
