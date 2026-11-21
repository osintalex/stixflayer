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

/// Non-raising validation outcome returned by `stixflayer.check()`.
#[pyclass(name = "Outcome")]
pub struct PyOutcome {
    valid: bool,
    errors: Vec<crate::error::Entry>,
    warnings: Vec<crate::error::Entry>,
    value: Option<crate::object::StixObject>,
}

#[pymethods]
impl PyOutcome {
    /// Whether validation succeeded (no errors).
    #[getter]
    fn valid(&self) -> bool {
        self.valid
    }

    /// MUST-level findings.
    #[getter]
    fn errors(&self, py: Python<'_>) -> PyObject {
        crate::python_bindings::error::entries_to_py(py, &self.errors)
    }

    /// SHOULD-level findings.
    #[getter]
    fn warnings(&self, py: Python<'_>) -> PyObject {
        crate::python_bindings::error::entries_to_py(py, &self.warnings)
    }

    /// The validated object, or `None` when validation failed.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<PyObject> {
        match &self.value {
            Some(object) => {
                let object_id = object.get_id();
                let object_warnings: Vec<crate::error::Entry> = self
                    .warnings
                    .iter()
                    .filter(|warning| warning.object_id.as_deref() == Some(object_id.as_str()))
                    .cloned()
                    .collect();
                crate::python_bindings::wrap_stix_object(py, object.clone(), object_warnings)
            }
            None => Ok(py.None()),
        }
    }

    /// Serialize the outcome to its language-agnostic JSON object.
    fn to_json(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("valid".to_string(), serde_json::Value::Bool(self.valid));
        map.insert(
            "errors".to_string(),
            serde_json::to_value(&self.errors).expect("entries serialize"),
        );
        map.insert(
            "warnings".to_string(),
            serde_json::to_value(&self.warnings).expect("entries serialize"),
        );
        if let Some(value) = &self.value {
            map.insert(
                "value".to_string(),
                serde_json::to_value(value).expect("object serializes"),
            );
        }
        serde_json::Value::Object(map).to_string()
    }
}

/// Validate a STIX object without raising, returning the raw outcome.
#[pyfunction]
#[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
pub fn check(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> PyResult<PyOutcome> {
    let value = crate::python_bindings::builder::parse_value(json_str, version)?;
    let (result, warnings) =
        crate::object::StixObject::from_value_parts(value, allow_custom, strict);
    match result {
        Ok(object) => Ok(PyOutcome {
            valid: true,
            errors: Vec::new(),
            warnings,
            value: Some(object),
        }),
        Err(error) => Ok(PyOutcome {
            valid: false,
            errors: error.errors(),
            warnings,
            value: None,
        }),
    }
}
