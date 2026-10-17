//! # stixflayer
//!
//! Fast, strict [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
//! parsing, validation, and serialization in Rust.
//!
//! stixflayer is a single spec-compliant engine shared by every language
//! binding, so a document is validated the same way in Rust, Python, and
//! beyond — instead of each language carrying its own subtly different
//! reimplementation.
//!
//! # Quick start
//!
//! Parsing validates: [`Bundle::from_json`](bundles::Bundle::from_json) returns
//! a parsed bundle or a structured [`StixError`].
//!
//! ```
//! use stixflayer::Bundle;
//!
//! let json = r#"{
//!     "type": "bundle",
//!     "id": "bundle--0c7b5d88-7c1c-4a8b-8f0c-6e9d4f2b1a55",
//!     "objects": [{
//!         "type": "attack-pattern",
//!         "spec_version": "2.1",
//!         "id": "attack-pattern--d3046a90-580c-4004-8208-66915bc29830",
//!         "created": "2019-04-24T15:12:36.609Z",
//!         "modified": "2023-03-24T15:14:15.637Z",
//!         "name": "Clear Command History"
//!     }]
//! }"#;
//!
//! let bundle = Bundle::from_json(json)?;
//! assert_eq!(bundle.get_objects().len(), 1);
//!
//! # Ok::<(), stixflayer::StixError>(())
//! ```
//!
//! Documents that break STIX 2.1 rules are rejected with machine-readable
//! detail — see [`error::StixError`] for the error kinds and the fields each
//! carries.
//!
//! # Python and other languages
//!
//! The [`python_bindings`] module exposes this engine to Python via
//! [PyO3](https://pyo3.rs/) and is not part of the Rust API — it is hidden
//! from documentation. The Python user-facing documentation lives at
//! <https://osintalex.github.io/stixflayer/> and the Rust API reference on
//! [docs.rs](https://docs.rs/stixflayer).

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
pub mod datastore;
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
