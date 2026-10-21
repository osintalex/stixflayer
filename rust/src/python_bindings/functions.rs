// pyo3 0.22's generated trampolines convert the error side of `Result<T, PyErr>`
// returns through a no-op `PyErr -> PyErr` conversion (pyo3-macros-backend
// `ok_wrap`), and clippy attributes the warning span to our return types.
// Remove this allow when pyo3 is upgraded past 0.22.
#![allow(clippy::useless_conversion)]
use crate::pattern::validate_pattern as rust_validate_pattern;
use crate::python_bindings::error::{stix_to_pyerr, StixError};
use crate::types::ExtensionType;
use pyo3::prelude::*;

/// Return the stixflayer version.
#[pyfunction]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Validate a STIX Pattern string against the STIX 2.1 pattern grammar
#[pyfunction]
pub fn validate_pattern(pattern: &str) -> Result<(), PyErr> {
    rust_validate_pattern(pattern).map_err(stix_to_pyerr)
}

// PyO3 limitation: #[pyclass] and #[pymethods] cannot be generated via macros.
// Each SCO struct must be written explicitly with these proc-macro attributes.

/// Parse an extension type name (`new-sdo`, `new-sco`, `new-sro`, ...)
/// into its typed representation.
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
