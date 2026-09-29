//! Re-export facade for legacy `domain_objects::sdo_types` imports.
//!
//! SDO type definitions now live in per-object modules under `domain_objects::sdo`.
//! This file preserves backward compatibility for any code importing from
//! `domain_objects::sdo_types`.

pub use crate::domain_objects::sdo::*;
