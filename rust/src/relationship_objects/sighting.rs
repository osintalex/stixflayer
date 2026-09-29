use crate::{
    base::{check_timestamp_ordering, Stix},
    common::validation::validate_refs_are_type,
    error::StixError as Error,
    types::{
        stix_case, Identifier,
        ScoTypes, SdoTypes, SroTypes, StixMetaTypes, Timestamp,
    },
};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_opt_u64;
use serde_with::skip_serializing_none;
use strum::IntoEnumIterator;
use stix_derive::StixProperties;


/// Nested struct for properties only found in Sightings
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Sighting {
    /// The beginning of the time window during which the SDO referenced by the `sighting_of_ref` property was sighted.
    pub first_seen: Option<Timestamp>,
    /// The end of the time window during which the SDO referenced by the `sighting_of_ref` property was sighted.
    ///
    /// If this property and the `first_seen`` property are both defined, then this property **MUST** be greater than or equal
    /// to the timestamp in the `first_seen` property.
    pub last_seen: Option<Timestamp>,
    /// If present, this **MUST** be an integer between 0 and 999,999,999 inclusive and represents the number of times the
    /// SDO referenced by the sighting_of_ref property was sighted.
    ///
    /// A sighting with a count of 0 can be used to express that an indicator was not seen at all.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub count: Option<u64>,
    /// An ID reference to the SDO that was sighted (e.g., Indicator or Malware).
    ///
    /// This property **MUST** reference only an SDO.
    pub sighting_of_ref: Identifier,
    /// A list of ID references to the Observed Data objects that contain the raw cyber data for this Sighting.
    ///
    /// This property **MUST** reference only Observed Data SDOs.
    pub observed_data_refs: Option<Vec<Identifier>>,
    /// A list of ID references to the Identity or Location objects describing the entities or types of entities that saw the sighting.
    ///
    /// This property **MUST** reference only Identity or Location SDOs.
    pub where_sighted_refs: Option<Vec<Identifier>>,
    /// The summary property indicates whether the Sighting should be considered summary data. Summary data is an aggregation of
    /// previous Sightings reports and should not be considered primary source data.
    pub summary: Option<bool>,
}

impl Stix for Sighting {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(count) = &self.count {
            count.stix_check()?;
        }
        if let (Some(start), Some(stop)) = (&self.first_seen, &self.last_seen) {
            check_timestamp_ordering(start, stop, "first_seen", "last_seen", "Sighting")?;
        }

        if let Some(count) = self.count {
            if count > 999999999 {
                return Err(Error::ValidationError(format!("This sighting SRO has a count of {}. This field cannot have a value larger than 999,999,999.",
                count
            )));
            }
        }

        if SdoTypes::iter().all(|x| x.as_ref() != stix_case(&self.sighting_of_ref.get_type())) {
            return Err(Error::ValidationError(format!(
                "Sighting of ref must be an SDO. Sighting of ref is type {}.",
                self.sighting_of_ref.get_type()
            )));
        }
        if !ScoTypes::iter().all(|x| x.as_ref() != stix_case(&self.sighting_of_ref.get_type()))
            || !StixMetaTypes::iter()
                .all(|x| x.as_ref() != stix_case(&self.sighting_of_ref.get_type()))
            || !SroTypes::iter().all(|x| x.as_ref() != stix_case(&self.sighting_of_ref.get_type()))
        {
            return Err(Error::ValidationError(format!(
                "Sighting of ref must be an SDO. Sighting of ref is type {}.",
                self.sighting_of_ref.get_type()
            )));
        }

        self.sighting_of_ref.stix_check()?;

        if let Some(observed_data_refs) = &self.observed_data_refs {
            validate_refs_are_type(observed_data_refs, &["observed-data"], "observed_data_refs")?;
        }

        if let Some(where_sighted_refs) = &self.where_sighted_refs {
            validate_refs_are_type(
                where_sighted_refs,
                &["identity", "location"],
                "where_sighted_refs",
            )?;
        }

        Ok(())
    }
}
