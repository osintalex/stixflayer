use crate::{
    base::CommonProperties,
    error::{return_multiple_errors, StixError as Error},
};

// Checks that the required properties for an SRO are present and that the prohibited fields for an SRO are not present
pub fn check_sro_properties(properties: &CommonProperties) -> Result<(), Error> {
    let mut errors = Vec::new();

    // Check that the `spec_version` field exists for SROs
    if properties.spec_version.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `spec_version` property.".to_string(),
        ));
    }
    // Check that the `created` field exists for SROs
    if properties.created.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `created` property.".to_string(),
        ));
    }
    // Check that the `modified` field exists for SROs
    if properties.modified.is_none() {
        errors.push(Error::ValidationError(
            "SDOs must have a `modified` property.".to_string(),
        ));
    }
    // Check that the `defanged` property is `None` for SROs
    if properties.defanged.is_some() {
        errors.push(Error::ValidationError(
            "SDOs cannot have a `defanged` property.".to_string(),
        ));
    }

    return_multiple_errors(errors)
}
