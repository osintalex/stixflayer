// pyo3 0.22's generated trampolines convert the error side of `Result<T, PyErr>`
// returns through a no-op `PyErr -> PyErr` conversion (pyo3-macros-backend
// `ok_wrap`), and clippy attributes the warning span to our return types.
// Remove this allow when pyo3 is upgraded past 0.22.
#![allow(clippy::useless_conversion)]
use crate::cyber_observable_objects::sco::CyberObjectBuilder;
use crate::error::Entry;
use crate::python_bindings::builder::{build_sco_envelope, parse_sco_builder};
use crate::python_bindings::convert::{custom_properties_dict, dynamic_getattr};
use crate::python_bindings::error::{entries_to_py, stix_to_pyerr, StixError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Python binding for the IPv4Address cyber-observable.
#[pyclass]
pub struct IPv4Address(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl IPv4Address {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("ipv4-addr", kwargs, strict, allow_custom)?;
        Ok(IPv4Address(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(IPv4Address(builder, warnings))
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv4-addr".to_string()
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

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Ipv4Addr(ip) =
                &sco.object_type
            {
                return ip.value.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the IPv6Address cyber-observable.
#[pyclass]
pub struct IPv6Address(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl IPv6Address {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("ipv6-addr", kwargs, strict, allow_custom)?;
        Ok(IPv6Address(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(IPv6Address(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv6-addr".to_string()
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

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Ipv6Addr(ip) =
                &sco.object_type
            {
                return ip.value.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the DomainName cyber-observable.
#[pyclass]
pub struct DomainName(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl DomainName {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("domain-name", kwargs, strict, allow_custom)?;
        Ok(DomainName(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(DomainName(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "domain-name".to_string()
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

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::DomainName(d) =
                &sco.object_type
            {
                return d.value.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the URL cyber-observable.
#[pyclass]
pub struct URL(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl URL {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("url", kwargs, strict, allow_custom)?;
        Ok(URL(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(URL(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "url".to_string()
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

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Url(u) = &sco.object_type
            {
                return u.value.to_string();
            }
        }
        "".to_string()
    }
}

/// Python binding for the EmailAddress cyber-observable.
#[pyclass]
pub struct EmailAddress(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl EmailAddress {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("email-addr", kwargs, strict, allow_custom)?;
        Ok(EmailAddress(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(EmailAddress(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "email-addr".to_string()
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

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::EmailAddress(e) =
                &sco.object_type
            {
                return e.value.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the EmailMessage cyber-observable.
#[pyclass]
pub struct EmailMessage(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl EmailMessage {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sco_envelope("email-message", kwargs, strict, allow_custom)?;
        Ok(EmailMessage(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(EmailMessage(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "email-message".to_string()
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

    // The getter name must match the STIX property `from_ref` on EmailMessage,
    // so clippy's from_* naming convention cannot be satisfied.
    #[allow(clippy::wrong_self_convention)]
    #[getter]
    fn from_ref(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::EmailMessage(em) =
                &sco.object_type
            {
                return em
                    .from_ref
                    .clone()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
            }
        }
        "".to_string()
    }
}

/// Python binding for the MacAddr cyber-observable.
#[pyclass]
pub struct MacAddr(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl MacAddr {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("mac-addr", kwargs, strict, allow_custom)?;
        Ok(MacAddr(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(MacAddr(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "mac-addr".to_string()
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

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::MacAddr(m) =
                &sco.object_type
            {
                return m.value.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the AutonomousSystem cyber-observable.
#[pyclass]
pub struct AutonomousSystem(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl AutonomousSystem {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sco_envelope("autonomous-system", kwargs, strict, allow_custom)?;
        Ok(AutonomousSystem(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(AutonomousSystem(builder, warnings))
    }

    #[getter]
    fn r#type(&self) -> String {
        "autonomous-system".to_string()
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

    #[getter]
    fn number(&self) -> u64 {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::AutonomousSystem(obj) =
                &sco.object_type
            {
                return obj.number;
            }
        }
        0
    }
}

/// Python binding for the File cyber-observable.
#[pyclass]
pub struct File(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl File {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("file", kwargs, strict, allow_custom)?;
        Ok(File(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(File(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "file".to_string()
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

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::File(f) = &sco.object_type
            {
                return f.name.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

/// Python binding for the Software cyber-observable.
#[pyclass]
pub struct Software(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Software {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("software", kwargs, strict, allow_custom)?;
        Ok(Software(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(Software(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "software".to_string()
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

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Software(s) =
                &sco.object_type
            {
                return s.name.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the Directory cyber-observable.
#[pyclass]
pub struct Directory(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Directory {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("directory", kwargs, strict, allow_custom)?;
        Ok(Directory(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(Directory(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "directory".to_string()
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

    #[getter]
    fn path(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Directory(d) =
                &sco.object_type
            {
                return d.path.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the Mutex cyber-observable.
#[pyclass]
pub struct Mutex(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Mutex {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("mutex", kwargs, strict, allow_custom)?;
        Ok(Mutex(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(Mutex(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "mutex".to_string()
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

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Mutex(m) =
                &sco.object_type
            {
                return m.name.clone();
            }
        }
        "".to_string()
    }
}

/// Python binding for the Process cyber-observable.
#[pyclass]
pub struct Process(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Process {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("process", kwargs, strict, allow_custom)?;
        Ok(Process(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(Process(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "process".to_string()
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

/// Python binding for the NetworkTraffic cyber-observable.
#[pyclass]
pub struct NetworkTraffic(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl NetworkTraffic {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sco_envelope("network-traffic", kwargs, strict, allow_custom)?;
        Ok(NetworkTraffic(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(NetworkTraffic(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "network-traffic".to_string()
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

/// Python binding for the UserAccount cyber-observable.
#[pyclass]
pub struct UserAccount(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl UserAccount {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("user-account", kwargs, strict, allow_custom)?;
        Ok(UserAccount(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(UserAccount(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "user-account".to_string()
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

    #[getter]
    fn account_login(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::UserAccount(u) =
                &sco.object_type
            {
                return u.account_login.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

/// Python binding for the WindowsRegistryKey cyber-observable.
#[pyclass]
pub struct WindowsRegistryKey(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl WindowsRegistryKey {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sco_envelope("windows-registry-key", kwargs, strict, allow_custom)?;
        Ok(WindowsRegistryKey(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(WindowsRegistryKey(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "windows-registry-key".to_string()
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

    #[getter]
    fn key(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::WindowsRegistryKey(w) =
                &sco.object_type
            {
                return w.key.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

/// Python binding for the X509Certificate cyber-observable.
#[pyclass]
pub struct X509Certificate(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl X509Certificate {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) =
            build_sco_envelope("x509-certificate", kwargs, strict, allow_custom)?;
        Ok(X509Certificate(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(X509Certificate(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "x509-certificate".to_string()
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

    #[getter]
    fn serial_number(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::X509Certificate(x) =
                &sco.object_type
            {
                return x.serial_number.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

/// Python binding for the Artifact cyber-observable.
#[pyclass]
pub struct Artifact(pub CyberObjectBuilder, pub Vec<Entry>);

#[pymethods]
impl Artifact {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = build_sco_envelope("artifact", kwargs, strict, allow_custom)?;
        Ok(Artifact(builder, warnings))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let (builder, warnings) = parse_sco_builder(&json_str, strict, version, allow_custom)?;
        Ok(Artifact(builder, warnings))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self
            .0
            .clone()
            .build_no_validate()
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        serde_json::to_string(&sco).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "artifact".to_string()
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

    #[getter]
    fn mime_type(&self) -> String {
        if let Ok(sco) = self.0.clone().build_no_validate() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Artifact(a) =
                &sco.object_type
            {
                return a.mime_type.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}
