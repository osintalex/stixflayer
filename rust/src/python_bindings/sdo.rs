// pyo3 0.22's generated trampolines convert the error side of `Result<T, PyErr>`
// returns through a no-op `PyErr -> PyErr` conversion (pyo3-macros-backend
// `ok_wrap`), and clippy attributes the warning span to our return types.
// Remove this allow when pyo3 is upgraded past 0.22.
#![allow(clippy::useless_conversion)]
use crate::domain_objects::sdo::DomainObjectBuilder;
use crate::error::Entry;
use crate::python_bindings::builder::{build_sdo_envelope, parse_sdo_builder};
use crate::python_bindings::convert::{custom_properties_dict, dynamic_getattr};
use crate::python_bindings::error::{entries_to_py, stix_to_pyerr, StixError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Python binding for the Campaign domain object.
#[pyclass]
pub struct Campaign(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Campaign {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("campaign", kwargs, strict, allow_custom)?;
        Ok(Campaign(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Campaign(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "campaign".to_string()
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

/// Python binding for the CourseOfAction domain object.
#[pyclass]
pub struct CourseOfAction(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl CourseOfAction {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("course-of-action", kwargs, strict, allow_custom)?;
        Ok(CourseOfAction(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(CourseOfAction(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "course-of-action".to_string()
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

/// Python binding for the Grouping domain object.
#[pyclass]
pub struct Grouping(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Grouping {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("grouping", kwargs, strict, allow_custom)?;
        Ok(Grouping(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Grouping(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "grouping".to_string()
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

/// Python binding for the Identity domain object.
#[pyclass]
pub struct Identity(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Identity {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("identity", kwargs, strict, allow_custom)?;
        Ok(Identity(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Identity(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "identity".to_string()
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

/// Python binding for the Incident domain object.
#[pyclass]
pub struct Incident(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Incident {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("incident", kwargs, strict, allow_custom)?;
        Ok(Incident(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Incident(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "incident".to_string()
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

/// Python binding for the Infrastructure domain object.
#[pyclass]
pub struct Infrastructure(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Infrastructure {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("infrastructure", kwargs, strict, allow_custom)?;
        Ok(Infrastructure(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Infrastructure(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "infrastructure".to_string()
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

/// Python binding for the IntrusionSet domain object.
#[pyclass]
pub struct IntrusionSet(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl IntrusionSet {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("intrusion-set", kwargs, strict, allow_custom)?;
        Ok(IntrusionSet(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(IntrusionSet(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "intrusion-set".to_string()
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

/// Python binding for the Location domain object.
#[pyclass]
pub struct Location(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Location {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("location", kwargs, strict, allow_custom)?;
        Ok(Location(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Location(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "location".to_string()
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

/// Python binding for the MalwareAnalysis domain object.
#[pyclass]
pub struct MalwareAnalysis(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl MalwareAnalysis {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("malware-analysis", kwargs, strict, allow_custom)?;
        Ok(MalwareAnalysis(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(MalwareAnalysis(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "malware-analysis".to_string()
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

/// Python binding for the Note domain object.
#[pyclass]
pub struct Note(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Note {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("note", kwargs, strict, allow_custom)?;
        Ok(Note(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Note(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "note".to_string()
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

/// Python binding for the ObservedData domain object.
#[pyclass]
pub struct ObservedData(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl ObservedData {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("observed-data", kwargs, strict, allow_custom)?;
        Ok(ObservedData(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(ObservedData(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "observed-data".to_string()
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

/// Python binding for the Opinion domain object.
#[pyclass]
pub struct Opinion(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Opinion {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("opinion", kwargs, strict, allow_custom)?;
        Ok(Opinion(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Opinion(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "opinion".to_string()
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

/// Python binding for the Report domain object.
#[pyclass]
pub struct Report(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Report {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("report", kwargs, strict, allow_custom)?;
        Ok(Report(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Report(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "report".to_string()
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

/// Python binding for the ThreatActor domain object.
#[pyclass]
pub struct ThreatActor(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl ThreatActor {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("threat-actor", kwargs, strict, allow_custom)?;
        Ok(ThreatActor(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(ThreatActor(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "threat-actor".to_string()
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

/// Python binding for the Tool domain object.
#[pyclass]
pub struct Tool(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Tool {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("tool", kwargs, strict, allow_custom)?;
        Ok(Tool(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Tool(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "tool".to_string()
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

/// Python binding for the Vulnerability domain object.
#[pyclass]
pub struct Vulnerability(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Vulnerability {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("vulnerability", kwargs, strict, allow_custom)?;
        Ok(Vulnerability(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Vulnerability(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "vulnerability".to_string()
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

// ============================================================================
// EXPLICIT MALWARE CLASS — kwargs-based prototype
// ============================================================================

/// Python binding for the Malware domain object.
#[pyclass]
pub struct Malware(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Malware {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("malware", kwargs, strict, allow_custom)?;
        Ok(Malware(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Malware(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "malware".to_string()
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

// ============================================================================
// EXPLICIT ATTACK PATTERN CLASS — kwargs-based
// ============================================================================

/// Python binding for the AttackPattern domain object.
#[pyclass]
pub struct AttackPattern(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl AttackPattern {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sdo_envelope("attack-pattern", kwargs, strict, allow_custom)?;
        Ok(AttackPattern(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(AttackPattern(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "attack-pattern".to_string()
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

// ============================================================================
// EXPLICIT INDICATOR CLASS — kwargs-based
// ============================================================================

/// Python binding for the Indicator domain object.
#[pyclass]
pub struct Indicator(pub DomainObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Indicator {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sdo_envelope("indicator", kwargs, strict, allow_custom)?;
        Ok(Indicator(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sdo_builder(&json_str, strict, version, allow_custom)?;
        Ok(Indicator(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "indicator".to_string()
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
