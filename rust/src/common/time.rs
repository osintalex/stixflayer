//! Timestamp-ordering validation helper.
use crate::{error::StixError as Error, timestamp::Timestamp};

/// Helper: check that `stop` timestamp is not before `start` timestamp.
///
/// Used for first_seen/last_seen, start_time/stop_time, valid_from/valid_until, etc.
pub fn check_timestamp_ordering(
    start: &Timestamp,
    stop: &Timestamp,
    start_name: &str,
    stop_name: &str,
    object_kind: &str,
) -> Result<(), Error> {
    if *stop < *start {
        Err(Error::ValidationError(format!(
            "The {} has a {} timestamp of {} and a {} timestamp of {}. The former cannot be earlier than the latter.",
            object_kind, stop_name, stop, start_name, start
        )))
    } else {
        Ok(())
    }
}
