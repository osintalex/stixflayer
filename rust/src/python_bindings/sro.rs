// pyo3 0.22's generated trampolines convert the error side of `Result<T, PyErr>`
// returns through a no-op `PyErr -> PyErr` conversion (pyo3-macros-backend
// `ok_wrap`), and clippy attributes the warning span to our return types.
// Remove this allow when pyo3 is upgraded past 0.22.
#![allow(clippy::useless_conversion)]
use crate::error::Entry;
use crate::python_bindings::builder::{build_sro_envelope, parse_sro_builder};
use crate::python_bindings::convert::{custom_properties_dict, dynamic_getattr};
use crate::python_bindings::error::{entries_to_py, stix_to_pyerr, StixError};
use crate::relationship_objects::RelationshipObjectBuilder;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Python binding for the Relationship relationship object.
#[pyclass]
pub struct Relationship(pub RelationshipObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Relationship {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sro_envelope("relationship", kwargs, strict, allow_custom)?;
        Ok(Relationship(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sro_builder(&json_str, strict, version, allow_custom)?;
        Ok(Relationship(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "relationship".to_string()
    }

    #[getter]
    fn warnings(&self, py: Python<'_>) -> PyObject {
        entries_to_py(py, &self.1)
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        if name == "custom_properties" {
            return custom_properties_dict(py, &obj).map(|d| d.into_py(py));
        }
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

/// Python binding for the Sighting relationship object.
#[pyclass]
pub struct Sighting(pub RelationshipObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Sighting {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sro_envelope("sighting", kwargs, strict, allow_custom)?;
        Ok(Sighting(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sro_builder(&json_str, strict, version, allow_custom)?;
        Ok(Sighting(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "sighting".to_string()
    }

    #[getter]
    fn warnings(&self, py: Python<'_>) -> PyObject {
        entries_to_py(py, &self.1)
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        if name == "custom_properties" {
            return custom_properties_dict(py, &obj).map(|d| d.into_py(py));
        }
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}
