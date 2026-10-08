use crate::cyber_observable_objects::sco::CyberObjectBuilder;
use crate::python_bindings::builder::build_sco_envelope;
use crate::python_bindings::convert::{custom_properties_dict, dynamic_getattr};
use crate::python_bindings::error::{stix_to_pyerr, StixError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyclass]
pub struct IPv4Address(pub CyberObjectBuilder);

#[pymethods]
impl IPv4Address {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("ipv4-addr", kwargs, strict, allow_custom)?;
        Ok(IPv4Address(builder))
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
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(IPv4Address(builder))
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv4-addr".to_string()
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

#[pyclass]
pub struct IPv6Address(pub CyberObjectBuilder);

#[pymethods]
impl IPv6Address {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("ipv6-addr", kwargs, strict, allow_custom)?;
        Ok(IPv6Address(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(IPv6Address(builder))
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

#[pyclass]
pub struct DomainName(pub CyberObjectBuilder);

#[pymethods]
impl DomainName {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("domain-name", kwargs, strict, allow_custom)?;
        Ok(DomainName(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(DomainName(builder))
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

#[pyclass]
pub struct URL(pub CyberObjectBuilder);

#[pymethods]
impl URL {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("url", kwargs, strict, allow_custom)?;
        Ok(URL(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(URL(builder))
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

#[pyclass]
pub struct EmailAddress(pub CyberObjectBuilder);

#[pymethods]
impl EmailAddress {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("email-addr", kwargs, strict, allow_custom)?;
        Ok(EmailAddress(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(EmailAddress(builder))
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

#[pyclass]
pub struct EmailMessage(pub CyberObjectBuilder);

#[pymethods]
impl EmailMessage {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("email-message", kwargs, strict, allow_custom)?;
        Ok(EmailMessage(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(EmailMessage(builder))
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

#[pyclass]
pub struct MacAddr(pub CyberObjectBuilder);

#[pymethods]
impl MacAddr {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("mac-addr", kwargs, strict, allow_custom)?;
        Ok(MacAddr(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(MacAddr(builder))
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

#[pyclass]
pub struct AutonomousSystem(pub CyberObjectBuilder);

#[pymethods]
impl AutonomousSystem {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("autonomous-system", kwargs, strict, allow_custom)?;
        Ok(AutonomousSystem(builder))
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
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(AutonomousSystem(builder))
    }

    #[getter]
    fn r#type(&self) -> String {
        "autonomous-system".to_string()
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

#[pyclass]
pub struct File(pub CyberObjectBuilder);

#[pymethods]
impl File {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("file", kwargs, strict, allow_custom)?;
        Ok(File(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(File(builder))
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

#[pyclass]
pub struct Software(pub CyberObjectBuilder);

#[pymethods]
impl Software {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("software", kwargs, strict, allow_custom)?;
        Ok(Software(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(Software(builder))
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

#[pyclass]
pub struct Directory(pub CyberObjectBuilder);

#[pymethods]
impl Directory {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("directory", kwargs, strict, allow_custom)?;
        Ok(Directory(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(Directory(builder))
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

#[pyclass]
pub struct Mutex(pub CyberObjectBuilder);

#[pymethods]
impl Mutex {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("mutex", kwargs, strict, allow_custom)?;
        Ok(Mutex(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(Mutex(builder))
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

#[pyclass]
pub struct Process(pub CyberObjectBuilder);

#[pymethods]
impl Process {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("process", kwargs, strict, allow_custom)?;
        Ok(Process(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(Process(builder))
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
pub struct NetworkTraffic(pub CyberObjectBuilder);

#[pymethods]
impl NetworkTraffic {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("network-traffic", kwargs, strict, allow_custom)?;
        Ok(NetworkTraffic(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(NetworkTraffic(builder))
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
pub struct UserAccount(pub CyberObjectBuilder);

#[pymethods]
impl UserAccount {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("user-account", kwargs, strict, allow_custom)?;
        Ok(UserAccount(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(UserAccount(builder))
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

#[pyclass]
pub struct WindowsRegistryKey(pub CyberObjectBuilder);

#[pymethods]
impl WindowsRegistryKey {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("windows-registry-key", kwargs, strict, allow_custom)?;
        Ok(WindowsRegistryKey(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(WindowsRegistryKey(builder))
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

#[pyclass]
pub struct X509Certificate(pub CyberObjectBuilder);

#[pymethods]
impl X509Certificate {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("x509-certificate", kwargs, strict, allow_custom)?;
        Ok(X509Certificate(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(X509Certificate(builder))
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

#[pyclass]
pub struct Artifact(pub CyberObjectBuilder);

#[pymethods]
impl Artifact {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("artifact", kwargs, strict, allow_custom)?;
        Ok(Artifact(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = CyberObjectBuilder::from_parsed(&sco).map_err(stix_to_pyerr)?;
        Ok(Artifact(builder))
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
