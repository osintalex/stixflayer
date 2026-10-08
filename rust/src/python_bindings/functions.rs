use crate::pattern::validate_pattern as rust_validate_pattern;
use crate::python_bindings::error::{stix_to_pyerr, StixError};
use crate::types::{ExtensionType, Timestamp};
use pyo3::prelude::*;

#[pyfunction]
pub fn version() -> String {
    "0.1.0".to_string()
}

#[pyfunction]
pub fn test_stix() -> String {
    "STIX 2.1".to_string()
}

#[pyfunction]
pub fn create_timestamp(value: &str) -> String {
    match Timestamp::new(value) {
        Ok(t) => t.to_string(),
        Err(_) => value.to_string(),
    }
}

/// Validate a STIX Pattern string against the STIX 2.1 pattern grammar
#[pyfunction]
pub fn validate_pattern(pattern: &str) -> Result<(), PyErr> {
    rust_validate_pattern(pattern).map_err(stix_to_pyerr)
}

// PyO3 limitation: #[pyclass] and #[pymethods] cannot be generated via macros.
// Each SCO struct must be written explicitly with these proc-macro attributes.

pub fn parse_extension_type(val: &str) -> Result<ExtensionType, PyErr> {
    match val {
        "new-sdo" => Ok(ExtensionType::NewSdo),
        "new-sco" => Ok(ExtensionType::NewSco),
        "new-sro" => Ok(ExtensionType::NewSro),
        "property-extension" => Ok(ExtensionType::PropertyExtension),
        "toplevel-property-extension" => Ok(ExtensionType::ToplevelPropertyExtension),
        _ => Err(PyErr::new::<StixError, _>(format!(
            "Invalid extension_type: '{}'. Valid values: new-sdo, new-sco, new-sro, property-extension, toplevel-property-extension",
            val
        ))),
    }
}
