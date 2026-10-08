use crate::{
    base::{check_timestamp_ordering, Stix},
    error::StixError as Error,
    relationship_objects::types::RelationshipType,
    types::{Identifier, ScoTypes, SdoTypes, Timestamp},
};
use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::sync::OnceLock;
use stix_derive::StixProperties;
use strum::IntoEnumIterator;

fn relationship_type_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-z0-9\-]+$").expect("relationship type regex is valid"))
}

/// Nested struct for properties only found in generic SROs
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Relationship {
    /// The type of relationship
    ///
    /// This **SHOULD** be a value specified for the source and target objects, but **MAY** be any String
    pub relationship_type: RelationshipType,
    /// The id of the source (from) object. **MUST** be the id of an SRO or SCO
    pub source_ref: Identifier,
    /// The id of the target (to) object. **MUST** be the id of an SRO or SCO
    pub target_ref: Identifier,
    /// An optional timestamp representing the earliest time at which the Relationship exists.
    ///
    /// May be a future time if used as an estimate
    pub start_time: Option<Timestamp>,
    /// An optional timestamp representing the latest time at which the Relationship exists.
    ///
    /// **MUST** be later than `start_time`
    /// May be a future time if used as an estimate
    pub stop_time: Option<Timestamp>,
}
impl Stix for Relationship {
    fn stix_check(&self) -> Result<(), Error> {
        let is_invalid_ref = |t: &str| -> bool {
            !SdoTypes::iter().any(|x| x.as_ref() == t) && !ScoTypes::iter().any(|x| x.as_ref() == t)
        };
        let source_type = self.source_ref.get_type();
        let target_type = self.target_ref.get_type();
        if is_invalid_ref(source_type) || is_invalid_ref(target_type) {
            return Err(Error::ValidationError(format!(
                "The source and target of a Relationship Object must be SDOs or SCOs. This SRO points from a {} to a {}.",
                source_type, target_type
            )));
        }

        if let RelationshipType::Custom(custom_type) = &self.relationship_type {
            // Custom relationship types must match the STIX schema pattern
            if !relationship_type_re().is_match(custom_type) {
                return Err(Error::ValidationError(format!(
                    "Relationship type '{}' contains invalid characters. Relationship types must match the pattern '^[a-z0-9\\-]+$'.",
                    custom_type
                )));
            }
            warn!("A relationship type should come from the STIX relationship types vocabulary. Relationship type {} is not in the vocabulary.",
                custom_type
            );
        } else {
            self.relationship_type
                .validate(&self.source_ref, &self.target_ref)?;
        }

        self.source_ref.stix_check()?;
        self.target_ref.stix_check()?;

        if let (Some(start), Some(stop)) = (&self.start_time, &self.stop_time) {
            check_timestamp_ordering(start, stop, "start_time", "stop_time", "Relationship")?;
        }

        Ok(())
    }
}
