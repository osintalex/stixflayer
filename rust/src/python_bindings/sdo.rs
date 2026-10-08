use crate::domain_objects::sdo::DomainObjectBuilder;
use crate::python_bindings::builder::build_sdo_envelope;
use crate::python_bindings::convert::{custom_properties_dict, dynamic_getattr};
use crate::python_bindings::error::{stix_to_pyerr, StixError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyclass]
pub struct Campaign(pub DomainObjectBuilder);

#[pymethods]
impl Campaign {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("campaign", kwargs, strict, allow_custom)?;
        Ok(Campaign(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Campaign(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "campaign".to_string()
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

#[pyclass]
pub struct CourseOfAction(pub DomainObjectBuilder);

#[pymethods]
impl CourseOfAction {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("course-of-action", kwargs, strict, allow_custom)?;
        Ok(CourseOfAction(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(CourseOfAction(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "course-of-action".to_string()
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

#[pyclass]
pub struct Grouping(pub DomainObjectBuilder);

#[pymethods]
impl Grouping {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("grouping", kwargs, strict, allow_custom)?;
        Ok(Grouping(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Grouping(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "grouping".to_string()
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

#[pyclass]
pub struct Identity(pub DomainObjectBuilder);

#[pymethods]
impl Identity {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("identity", kwargs, strict, allow_custom)?;
        Ok(Identity(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Identity(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "identity".to_string()
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

#[pyclass]
pub struct Incident(pub DomainObjectBuilder);

#[pymethods]
impl Incident {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("incident", kwargs, strict, allow_custom)?;
        Ok(Incident(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Incident(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "incident".to_string()
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

#[pyclass]
pub struct Infrastructure(pub DomainObjectBuilder);

#[pymethods]
impl Infrastructure {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("infrastructure", kwargs, strict, allow_custom)?;
        Ok(Infrastructure(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Infrastructure(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "infrastructure".to_string()
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

#[pyclass]
pub struct IntrusionSet(pub DomainObjectBuilder);

#[pymethods]
impl IntrusionSet {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("intrusion-set", kwargs, strict, allow_custom)?;
        Ok(IntrusionSet(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(IntrusionSet(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "intrusion-set".to_string()
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

#[pyclass]
pub struct Location(pub DomainObjectBuilder);

#[pymethods]
impl Location {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("location", kwargs, strict, allow_custom)?;
        Ok(Location(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Location(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "location".to_string()
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

#[pyclass]
pub struct MalwareAnalysis(pub DomainObjectBuilder);

#[pymethods]
impl MalwareAnalysis {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("malware-analysis", kwargs, strict, allow_custom)?;
        Ok(MalwareAnalysis(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(MalwareAnalysis(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "malware-analysis".to_string()
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

#[pyclass]
pub struct Note(pub DomainObjectBuilder);

#[pymethods]
impl Note {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("note", kwargs, strict, allow_custom)?;
        Ok(Note(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Note(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "note".to_string()
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

#[pyclass]
pub struct ObservedData(pub DomainObjectBuilder);

#[pymethods]
impl ObservedData {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("observed-data", kwargs, strict, allow_custom)?;
        Ok(ObservedData(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(ObservedData(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "observed-data".to_string()
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

#[pyclass]
pub struct Opinion(pub DomainObjectBuilder);

#[pymethods]
impl Opinion {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("opinion", kwargs, strict, allow_custom)?;
        Ok(Opinion(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Opinion(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "opinion".to_string()
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

#[pyclass]
pub struct Report(pub DomainObjectBuilder);

#[pymethods]
impl Report {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("report", kwargs, strict, allow_custom)?;
        Ok(Report(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Report(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "report".to_string()
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

#[pyclass]
pub struct ThreatActor(pub DomainObjectBuilder);

#[pymethods]
impl ThreatActor {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("threat-actor", kwargs, strict, allow_custom)?;
        Ok(ThreatActor(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(ThreatActor(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "threat-actor".to_string()
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

#[pyclass]
pub struct Tool(pub DomainObjectBuilder);

#[pymethods]
impl Tool {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("tool", kwargs, strict, allow_custom)?;
        Ok(Tool(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Tool(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "tool".to_string()
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

#[pyclass]
pub struct Vulnerability(pub DomainObjectBuilder);

#[pymethods]
impl Vulnerability {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("vulnerability", kwargs, strict, allow_custom)?;
        Ok(Vulnerability(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Vulnerability(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "vulnerability".to_string()
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

#[pyclass]
pub struct Malware(pub DomainObjectBuilder);

#[pymethods]
impl Malware {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("malware", kwargs, strict, allow_custom)?;
        Ok(Malware(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Malware(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "malware".to_string()
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

#[pyclass]
pub struct AttackPattern(pub DomainObjectBuilder);

#[pymethods]
impl AttackPattern {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("attack-pattern", kwargs, strict, allow_custom)?;
        Ok(AttackPattern(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(AttackPattern(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "attack-pattern".to_string()
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

#[pyclass]
pub struct Indicator(pub DomainObjectBuilder);

#[pymethods]
impl Indicator {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("indicator", kwargs, strict, allow_custom)?;
        Ok(Indicator(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = DomainObjectBuilder::from_parsed(&sdo).map_err(stix_to_pyerr)?;
        Ok(Indicator(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "indicator".to_string()
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
