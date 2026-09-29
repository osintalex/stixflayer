//! Error-collection helpers for STIX validation.
use super::StixError;

/// Checks a Result to see if it is an Error. If it is, add that Error to a Vec of StixErrors
pub fn add_error<T>(errors: &mut Vec<StixError>, possible_error: Result<T, StixError>) {
    if let Err(error) = possible_error {
        errors.push(error)
    };
}

/// Return a Vec of StixErrors as a single Error, unless the Vec is empty
///
/// This is useful when checking multiple possible sources of error, such as during STIX validation
pub fn return_multiple_errors(errors: Vec<StixError>) -> Result<(), StixError> {
    if errors.is_empty() {
        return Ok(());
    }
    // If there is only one Error in the Vec, return it as itself
    if errors.len() == 1 {
        return Err(errors[0].clone());
    }
    Err(StixError::ValidationErrors(errors))
}
