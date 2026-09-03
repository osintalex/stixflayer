use pyo3::exceptions::PyAttributeError as PyO3AttributeError;
use pyo3::prelude::*;
use pyo3::{create_exception, PyErr};
use std::collections::BTreeMap;
use std::str::FromStr;

use crate::bundles::Bundle as StixBundle;
use crate::custom_objects::CustomObjectBuilder;
use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder, CyberObjectType};
use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder, DomainObjectType};
use crate::error::StixError as RustStixError;
use crate::meta_objects::extension_definition::{
    ExtensionDefinition as StixExtensionDefinition, ExtensionDefinitionBuilder,
};
use crate::meta_objects::language_content::LanguageContent as StixLanguageContent;
use crate::meta_objects::language_content::LanguageContentBuilder;
use crate::meta_objects::marking_definition::MarkingDefinitionBuilder;
use crate::pattern::validate_pattern as rust_validate_pattern;
use crate::relationship_objects::{
    RelationshipObject, RelationshipObjectBuilder, RelationshipObjectType,
};
use crate::types::DictionaryValue;
use crate::types::ExtensionType;
use crate::types::Identifier;
use crate::types::Timestamp;
use crate::validation::validate_value;
use jiff::Timestamp as JiffTimestamp;
use pyo3::types::PyDict;
use pyo3::types::PyList;
use strum::IntoEnumIterator;

// Python-facing exception hierarchy.
//
// These are raised by the central `stix_to_pyerr` mapper from the typed Rust
// error envelope. They subclass Exception directly (not ValueError) so callers
// can opt-in to handling structured validation failures.
create_exception!(stixflayer, StixError, pyo3::exceptions::PyException);
create_exception!(stixflayer, ValidationError, StixError);
create_exception!(stixflayer, DeserializationError, StixError);

/// Recursively convert a [`serde_json::Value`] into a Python object.
///
/// This is used so that structured Rust error details can be surfaced to Python
/// consumers without pulling in an extra serialization dependency.
fn json_value_to_py(py: Python<'_>, value: &serde_json::Value) -> PyObject {
    match value {
        serde_json::Value::Null => py.None(),
        serde_json::Value::Bool(b) => b.into_py(py),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py(py)
            } else if let Some(u) = n.as_u64() {
                u.into_py(py)
            } else {
                n.as_f64().into_py(py)
            }
        }
        serde_json::Value::String(s) => s.clone().into_py(py),
        serde_json::Value::Array(arr) => {
            let py_list = PyList::empty_bound(py);
            for item in arr {
                py_list.append(json_value_to_py(py, item)).unwrap();
            }
            py_list.into_py(py)
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_value_to_py(py, v)).unwrap();
            }
            dict.into_py(py)
        }
    }
}

/// Builds the Python `list[dict]` for the structured validation entries
/// associated with `error`.
fn errors_to_py(py: Python<'_>, error: &RustStixError) -> PyObject {
    let entries = error.errors();
    let value = serde_json::to_value(entries).expect("ErrorEntry serializes to JSON");
    json_value_to_py(py, &value)
}

/// Converts a Rust STIX error into the appropriate Python exception.
///
/// The exception instance carries a human-readable message in `args[0]` and a
/// sparse `.errors` list for callers that want structured field-level details.
/// The full JSON envelope remains an internal Rust concern.
fn stix_to_pyerr(error: RustStixError) -> PyErr {
    Python::with_gil(|py| {
        let message = error.display_message();
        let py_errors = errors_to_py(py, &error);

        let err = match error.envelope_category() {
            "validation" => PyErr::new::<ValidationError, _>((message,)),
            "deserialization" => PyErr::new::<DeserializationError, _>((message,)),
            _ => PyErr::new::<StixError, _>((message,)),
        };

        // Attach structured entries as a normal attribute, silencing the rare
        // case where an exception subclass forbids attribute assignment.
        err.value_bound(py).setattr("errors", py_errors).ok();

        err
    })
}

/// Reclassifies a top-level serde type error from a kwargs constructor into a
/// structured `InvalidPropertyType` validation error.
///
/// Because the SDO/SCO/SRO structs flatten their fields at the root, serde
/// reports the path as `.`, losing the offending property name. We recover it
/// by scanning the synthesized kwargs JSON for a value matching the `got` JSON
/// kind in the error message.
fn classify_top_level_type_error(
    error: RustStixError,
    object_type: &str,
    json_obj: &serde_json::Value,
) -> RustStixError {
    let RustStixError::DeserializationError(message) = &error else {
        return error;
    };

    // Strip serde's " at line N column M" suffix.
    let position = message.find(" at line ").unwrap_or(message.len());
    let message = &message[..position];

    let Some(rest) = message.strip_prefix("invalid type: ") else {
        return error;
    };
    let Some((got, expected)) = rest.split_once(", expected ") else {
        return error;
    };

    let value_matches = |value: &serde_json::Value| -> bool {
        if got.starts_with("integer") || got.starts_with("floating point") {
            value.is_number()
        } else if got.starts_with("string") {
            value.is_string()
        } else if got.starts_with("boolean") {
            value.is_boolean()
        } else if got.starts_with("map") || got.starts_with("struct") {
            value.is_object()
        } else if got.starts_with("sequence") || got.starts_with("array") {
            value.is_array()
        } else {
            false
        }
    };

    let Some(obj) = json_obj.as_object() else {
        return error;
    };

    for (property, value) in obj {
        if value_matches(value) {
            return RustStixError::InvalidPropertyType {
                object_type: object_type.to_string(),
                property: property.clone(),
                expected: expected.to_string(),
                got: got.to_string(),
            };
        }
    }

    error
}

/// Helper function to validate that required fields are present in a DomainObjectBuilder.
/// When `strict` is false the validation step is skipped.
fn validate_sdo_builder(
    builder: DomainObjectBuilder,
    strict: bool,
) -> Result<DomainObjectBuilder, PyErr> {
    if strict {
        builder.clone().build().map_err(stix_to_pyerr)?;
    }
    Ok(builder)
}

/// Helper function to validate that required fields are present in a CyberObjectBuilder.
/// When `strict` is false the validation step is skipped.
fn validate_sco_builder(
    builder: CyberObjectBuilder,
    strict: bool,
) -> Result<CyberObjectBuilder, PyErr> {
    if strict {
        builder.clone().build().map_err(stix_to_pyerr)?;
    }
    Ok(builder)
}

/// Helper function to validate that required fields are present in a RelationshipObjectBuilder.
/// When `strict` is false the validation step is skipped.
fn validate_sro_builder(
    builder: RelationshipObjectBuilder,
    strict: bool,
) -> Result<RelationshipObjectBuilder, PyErr> {
    if strict {
        builder.clone().build().map_err(stix_to_pyerr)?;
    }
    Ok(builder)
}

/// Helper function to validate that required fields are present in a MarkingDefinitionBuilder.
/// When `strict` is false the validation step is skipped.
fn validate_marking_builder(
    builder: MarkingDefinitionBuilder,
    strict: bool,
) -> Result<MarkingDefinitionBuilder, PyErr> {
    if strict {
        builder.clone().build().map_err(stix_to_pyerr)?;
    }
    Ok(builder)
}

/// Build a JSON envelope for an SDO.
fn build_sdo_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
) -> Result<DomainObjectBuilder, PyErr> {
    let id = Identifier::new(type_name).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let mut json_obj = serde_json::json!({
        "type": type_name,
        "spec_version": "2.1",
        "id": id.to_string()
    });
    if let Some(kwargs) = kwargs {
        for (k, v) in kwargs.iter() {
            let key: String = k.extract().map_err(|e| {
                PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
            })?;
            json_obj[key] = py_to_json(&v)?;
        }
    }
    // Timestamps default to now, but caller-supplied values are preserved.
    // When neither is supplied, both share the same stamp so created == modified.
    if json_obj.get("created").is_none() || json_obj.get("modified").is_none() {
        let now = Timestamp::now().to_string();
        if json_obj.get("created").is_none() {
            json_obj["created"] = serde_json::Value::String(now.clone());
        }
        if json_obj.get("modified").is_none() {
            json_obj["modified"] = serde_json::Value::String(now);
        }
    }
    let value: serde_json::Value = serde_json::from_str(&json_obj.to_string())
        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let domain_obj: DomainObject = validate_value(value, false, strict)
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(stix_to_pyerr)?;
    let builder = DomainObjectBuilder::from_parsed(&domain_obj).map_err(stix_to_pyerr)?;
    validate_sdo_builder(builder, strict)
}

/// Build a JSON envelope for an SCO.
fn build_sco_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
) -> Result<CyberObjectBuilder, PyErr> {
    let mut json_obj = serde_json::json!({"type": type_name});
    if let Some(kwargs) = kwargs {
        for (k, v) in kwargs.iter() {
            let key: String = k.extract().map_err(|e| {
                PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
            })?;
            json_obj[key] = py_to_json(&v)?;
        }
    }
    if json_obj.get("id").is_none() {
        let id =
            Identifier::new(type_name).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        json_obj["id"] = serde_json::Value::String(id.to_string());
    }
    let value: serde_json::Value = serde_json::from_str(&json_obj.to_string())
        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let cyber_obj: CyberObject = validate_value(value, false, strict)
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(stix_to_pyerr)?;
    let builder = CyberObjectBuilder::from(&cyber_obj).map_err(stix_to_pyerr)?;
    validate_sco_builder(builder, strict)
}

/// Build a JSON envelope for an SRO.
fn build_sro_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
) -> Result<RelationshipObjectBuilder, PyErr> {
    let id = Identifier::new(type_name).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let now = Timestamp::now();
    let mut json_obj = serde_json::json!({
        "type": type_name,
        "spec_version": "2.1",
        "id": id.to_string(),
        "created": now.to_string(),
        "modified": now.to_string()
    });
    if let Some(kwargs) = kwargs {
        for (k, v) in kwargs.iter() {
            let key: String = k.extract().map_err(|e| {
                PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
            })?;
            json_obj[key] = py_to_json(&v)?;
        }
    }
    let value: serde_json::Value = serde_json::from_str(&json_obj.to_string())
        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let sro_obj: RelationshipObject = validate_value(value, false, strict)
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(stix_to_pyerr)?;
    let builder = RelationshipObjectBuilder::from_parsed(&sro_obj).map_err(stix_to_pyerr)?;
    validate_sro_builder(builder, strict)
}

/// Macro to generate a Python class for STIX vocabulary enums
macro_rules! make_vocab_enum {
    ($name:ident, $enum_type:ty) => {
        #[pyclass]
        pub struct $name(String);

        #[pymethods]
        impl $name {
            #[new]
            fn new(value: &str) -> Result<Self, PyErr> {
                // Check if the string matches any variant of the enum
                let valid = <$enum_type>::iter().any(|v| v.as_ref() == value);
                if valid {
                    Ok($name(value.to_string()))
                } else {
                    // Get all valid variants for error message
                    let valid_values: Vec<String> = <$enum_type>::iter()
                        .map(|v| v.as_ref().to_string())
                        .collect();
                    Err(PyErr::new::<StixError, _>(format!(
                        "Invalid {} value: '{}'. Valid values: {:?}",
                        stringify!($enum_type),
                        value,
                        valid_values
                    )))
                }
            }

            /// Get the string value of the vocabulary enum
            fn value(&self) -> String {
                self.0.clone()
            }

            /// Get all valid values for this vocabulary enum
            #[staticmethod]
            fn values() -> Vec<String> {
                <$enum_type>::iter()
                    .map(|v| v.as_ref().to_string())
                    .collect()
            }

            /// Check if a value is valid for this vocabulary enum
            #[staticmethod]
            fn is_valid(value: &str) -> bool {
                <$enum_type>::iter().any(|v| v.as_ref() == value)
            }
        }
    };
}

// Generate vocab enum classes
make_vocab_enum!(
    AttackMotivation,
    crate::domain_objects::vocab::AttackMotivation
);
make_vocab_enum!(
    IdentitySectors,
    crate::domain_objects::vocab::IdentitySectors
);
make_vocab_enum!(
    ThreatActorType,
    crate::domain_objects::vocab::ThreatActorType
);
make_vocab_enum!(MalwareType, crate::domain_objects::vocab::MalwareType);
make_vocab_enum!(IndicatorType, crate::domain_objects::vocab::IndicatorType);
make_vocab_enum!(ReportType, crate::domain_objects::vocab::ReportType);
make_vocab_enum!(
    AttackResourceLevel,
    crate::domain_objects::vocab::AttackResourceLevel
);
make_vocab_enum!(
    ThreatActorSophistication,
    crate::domain_objects::vocab::ThreatActorSophistication
);

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

fn parse_extension_type(val: &str) -> Result<ExtensionType, PyErr> {
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

/// Convert any Python object to a serde_json::Value for use with from_json.
fn py_to_json(obj: &Bound<'_, PyAny>) -> Result<serde_json::Value, PyErr> {
    if obj.is_none() {
        return Ok(serde_json::Value::Null);
    }
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(serde_json::Value::Bool(b));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(serde_json::Value::Number(i.into()));
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(serde_json::json!(f));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(serde_json::Value::String(s));
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        let mut items = Vec::new();
        for item in list.iter() {
            items.push(py_to_json(&item)?);
        }
        return Ok(serde_json::Value::Array(items));
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key: String = k.extract().map_err(|e| {
                PyErr::new::<StixError, _>(format!("Dict key must be a string: {}", e))
            })?;
            map.insert(key, py_to_json(&v)?);
        }
        return Ok(serde_json::Value::Object(map));
    }
    Err(PyErr::new::<StixError, _>(format!(
        "Unsupported Python type for STIX field: {}",
        obj.get_type().name()?.to_string()
    )))
}

fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    Ok(match value {
        serde_json::Value::Null => py.None(),
        serde_json::Value::Bool(b) => b.to_object(py),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_object(py)
            } else if let Some(u) = n.as_u64() {
                u.to_object(py)
            } else {
                n.as_f64()
                    .expect("JSON number is neither integer nor float")
                    .to_object(py)
            }
        }
        serde_json::Value::String(s) => s.to_object(py),
        serde_json::Value::Array(items) => {
            let list = PyList::empty_bound(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (key, item) in map {
                dict.set_item(key, json_to_py(py, item)?)?;
            }
            dict.into_any().unbind()
        }
    })
}

/// Resolve a dynamically-requested property from an object's serialized form.
/// Missing properties raise AttributeError (typos are never silently None).
fn dynamic_getattr(
    py: Python<'_>,
    type_path: &str,
    value: &serde_json::Value,
    name: &str,
) -> PyResult<Py<PyAny>> {
    let class_name = type_path.rsplit("::").next().unwrap_or(type_path);
    match value.get(name) {
        Some(v) => json_to_py(py, v),
        None => Err(PyErr::new::<PyO3AttributeError, _>(format!(
            "'{}' object has no attribute '{}'",
            class_name, name
        ))),
    }
}

#[pyclass]
pub struct Campaign(DomainObjectBuilder);

#[pymethods]
impl Campaign {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("campaign", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct CourseOfAction(DomainObjectBuilder);

#[pymethods]
impl CourseOfAction {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("course-of-action", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Grouping(DomainObjectBuilder);

#[pymethods]
impl Grouping {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("grouping", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Identity(DomainObjectBuilder);

#[pymethods]
impl Identity {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("identity", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Incident(DomainObjectBuilder);

#[pymethods]
impl Incident {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("incident", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Infrastructure(DomainObjectBuilder);

#[pymethods]
impl Infrastructure {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("infrastructure", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct IntrusionSet(DomainObjectBuilder);

#[pymethods]
impl IntrusionSet {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("intrusion-set", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Location(DomainObjectBuilder);

#[pymethods]
impl Location {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("location", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct MalwareAnalysis(DomainObjectBuilder);

#[pymethods]
impl MalwareAnalysis {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("malware-analysis", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Note(DomainObjectBuilder);

#[pymethods]
impl Note {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("note", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct ObservedData(DomainObjectBuilder);

#[pymethods]
impl ObservedData {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("observed-data", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Opinion(DomainObjectBuilder);

#[pymethods]
impl Opinion {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("opinion", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Report(DomainObjectBuilder);

#[pymethods]
impl Report {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("report", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct ThreatActor(DomainObjectBuilder);

#[pymethods]
impl ThreatActor {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("threat-actor", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Tool(DomainObjectBuilder);

#[pymethods]
impl Tool {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("tool", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Vulnerability(DomainObjectBuilder);

#[pymethods]
impl Vulnerability {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("vulnerability", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

// ============================================================================
// EXPLICIT MALWARE CLASS — kwargs-based prototype
// ============================================================================

#[pyclass]
pub struct Malware(DomainObjectBuilder);

#[pymethods]
impl Malware {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("malware", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

// ============================================================================
// EXPLICIT ATTACK PATTERN CLASS — kwargs-based
// ============================================================================

#[pyclass]
pub struct AttackPattern(DomainObjectBuilder);

#[pymethods]
impl AttackPattern {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("attack-pattern", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

// ============================================================================
// EXPLICIT INDICATOR CLASS — kwargs-based
// ============================================================================

#[pyclass]
pub struct Indicator(DomainObjectBuilder);

#[pymethods]
impl Indicator {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("indicator", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct IPv4Address(CyberObjectBuilder);

#[pymethods]
impl IPv4Address {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("ipv4-addr", kwargs, strict)?;
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
pub struct IPv6Address(CyberObjectBuilder);

#[pymethods]
impl IPv6Address {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("ipv6-addr", kwargs, strict)?;
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
pub struct DomainName(CyberObjectBuilder);

#[pymethods]
impl DomainName {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("domain-name", kwargs, strict)?;
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
pub struct URL(CyberObjectBuilder);

#[pymethods]
impl URL {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("url", kwargs, strict)?;
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
pub struct EmailAddress(CyberObjectBuilder);

#[pymethods]
impl EmailAddress {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("email-addr", kwargs, strict)?;
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
pub struct EmailMessage(CyberObjectBuilder);

#[pymethods]
impl EmailMessage {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("email-message", kwargs, strict)?;
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
pub struct MacAddr(CyberObjectBuilder);

#[pymethods]
impl MacAddr {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("mac-addr", kwargs, strict)?;
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
pub struct AutonomousSystem(CyberObjectBuilder);

#[pymethods]
impl AutonomousSystem {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("autonomous-system", kwargs, strict)?;
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
pub struct File(CyberObjectBuilder);

#[pymethods]
impl File {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("file", kwargs, strict)?;
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
pub struct Software(CyberObjectBuilder);

#[pymethods]
impl Software {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("software", kwargs, strict)?;
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
pub struct Directory(CyberObjectBuilder);

#[pymethods]
impl Directory {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("directory", kwargs, strict)?;
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
pub struct Mutex(CyberObjectBuilder);

#[pymethods]
impl Mutex {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("mutex", kwargs, strict)?;
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
pub struct Process(CyberObjectBuilder);

#[pymethods]
impl Process {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("process", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct NetworkTraffic(CyberObjectBuilder);

#[pymethods]
impl NetworkTraffic {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("network-traffic", kwargs, strict)?;
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
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct UserAccount(CyberObjectBuilder);

#[pymethods]
impl UserAccount {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("user-account", kwargs, strict)?;
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
pub struct WindowsRegistryKey(CyberObjectBuilder);

#[pymethods]
impl WindowsRegistryKey {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("windows-registry-key", kwargs, strict)?;
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
pub struct X509Certificate(CyberObjectBuilder);

#[pymethods]
impl X509Certificate {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("x509-certificate", kwargs, strict)?;
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
pub struct Artifact(CyberObjectBuilder);

#[pymethods]
impl Artifact {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("artifact", kwargs, strict)?;
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

#[pyclass]
pub struct Relationship(RelationshipObjectBuilder);

#[pymethods]
impl Relationship {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sro_envelope("relationship", kwargs, strict)?;
        Ok(Relationship(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sro = crate::object::parse_sro(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = RelationshipObjectBuilder::from_parsed(&sro).map_err(stix_to_pyerr)?;
        Ok(Relationship(builder))
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

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct Sighting(RelationshipObjectBuilder);

#[pymethods]
impl Sighting {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sro_envelope("sighting", kwargs, strict)?;
        Ok(Sighting(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let sro = crate::object::parse_sro(&json_str, strict, version, allow_custom)
            .map_err(stix_to_pyerr)?;
        let builder = RelationshipObjectBuilder::from_parsed(&sro).map_err(stix_to_pyerr)?;
        Ok(Sighting(builder))
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

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct MarkingDefinition(MarkingDefinitionBuilder);

#[pymethods]
impl MarkingDefinition {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut builder = MarkingDefinitionBuilder::new().map_err(stix_to_pyerr)?;

        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract().map_err(|e| {
                    PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
                })?;
                match key.as_str() {
                    "definition_type" => {
                        let val: String = v.extract()?;
                        builder = builder.definition_type(val);
                    }
                    "name" => {
                        let val: String = v.extract()?;
                        builder = builder.name(val);
                    }
                    "definition" => {
                        let val = py_to_json(&v)?;
                        let marking_type: crate::meta_objects::marking_definition::MarkingTypes =
                            serde_json::from_value(val)
                                .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
                        builder = builder.definition(marking_type);
                    }
                    "created" => {
                        let val: String = v.extract()?;
                        let ts = JiffTimestamp::from_str(&val).map_err(|e| {
                            PyErr::new::<StixError, _>(format!(
                                "Invalid created timestamp '{}': {}",
                                val, e
                            ))
                        })?;
                        builder = builder.created(Timestamp(ts));
                    }
                    "modified" => {
                        return Err(stix_to_pyerr(RustStixError::ValidationError(
                            "MarkingDefinition cannot have a modified property".to_string(),
                        )));
                    }
                    _ => {
                        return Err(PyErr::new::<StixError, _>(format!(
                            "Unknown argument for MarkingDefinition: '{}'",
                            key
                        )));
                    }
                }
            }
        }

        Ok(MarkingDefinition(validate_marking_builder(
            builder, strict,
        )?))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, _version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        _version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let md = crate::meta_objects::marking_definition::MarkingDefinition::from_json(
            &json_str,
            strict,
            allow_custom,
        )
        .map_err(stix_to_pyerr)?;
        let builder = MarkingDefinitionBuilder::from_parsed(&md).map_err(stix_to_pyerr)?;
        Ok(MarkingDefinition(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build_no_validate()
            .map_err(stix_to_pyerr)
            .and_then(|obj| {
                serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "marking-definition".to_string()
    }

    #[getter]
    fn id(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|obj| obj.common_properties.id.to_string())
            .unwrap_or_default()
    }

    #[getter]
    fn created(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.created.map(|t| t.to_string()))
    }

    #[getter]
    fn name(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.name)
    }

    #[getter]
    fn definition_type(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.definition_type)
    }

    #[getter]
    fn definition<'py>(&self, py: Python<'py>) -> Result<Option<Bound<'py, PyDict>>, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        match obj.definition {
            Some(def) => {
                let value = serde_json::to_value(&def)
                    .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
                if let serde_json::Value::Object(map) = value {
                    let dict = PyDict::new_bound(py);
                    for (k, v) in map {
                        dict.set_item(k, json_to_py(py, &v)?)?;
                    }
                    Ok(Some(dict))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct CustomObject(CustomObjectBuilder);

#[pymethods]
impl CustomObject {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut type_ = None;
        let mut extension_type = None;
        let mut extension_definition_id: Option<String> = None;
        let mut custom_properties: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let mut created: Option<String> = None;
        let mut modified: Option<String> = None;

        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract().map_err(|e| {
                    PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
                })?;
                match key.as_str() {
                    "type" | "type_" => {
                        let val: String = v.extract()?;
                        type_ = Some(val);
                    }
                    "extension_type" => {
                        let val: String = v.extract()?;
                        extension_type = Some(val);
                    }
                    "custom_properties" => {
                        let val = py_to_json(&v)?;
                        if let serde_json::Value::Object(m) = val {
                            custom_properties = m.into_iter().collect();
                        } else {
                            return Err(PyErr::new::<StixError, _>(
                                "custom_properties must be a dictionary".to_string(),
                            ));
                        }
                    }
                    "created" => {
                        created = Some(v.extract()?);
                    }
                    "modified" => {
                        modified = Some(v.extract()?);
                    }
                    "extension_definition_id" => {
                        let val: String = v.extract()?;
                        extension_definition_id = Some(val);
                    }
                    "custom_properties_json" => {
                        return Err(PyErr::new::<StixError, _>(
                            "custom_properties_json is no longer supported; pass custom_properties as a dict".to_string(),
                        ));
                    }
                    _ => {
                        // Any other keyword becomes a custom property, matching the SDO/SCO/SRO
                        // envelope behaviour for arbitrary fields.
                        let val = py_to_json(&v)?;
                        custom_properties.insert(key, val);
                    }
                }
            }
        }

        let type_ = type_.ok_or_else(|| {
            PyErr::new::<StixError, _>("CustomObject requires a 'type_' argument".to_string())
        })?;
        let extension_type = extension_type.ok_or_else(|| {
            PyErr::new::<StixError, _>(
                "CustomObject requires an 'extension_type' argument".to_string(),
            )
        })?;

        let ext_def_id = extension_definition_id
            .as_deref()
            .unwrap_or("extension-definition--00000000-0000-0000-0000-000000000000");

        let mut builder = match extension_type.as_str() {
            "new-sdo" => CustomObjectBuilder::new_sdo(&type_, custom_properties, ext_def_id),
            "new-sro" => CustomObjectBuilder::new_sro(&type_, custom_properties, ext_def_id),
            "new-sco" => CustomObjectBuilder::new_sco(&type_, custom_properties, ext_def_id),
            _ => {
                return Err(PyErr::new::<StixError, _>(format!(
                    "Invalid extension_type: '{}'. Valid values: new-sdo, new-sco, new-sro",
                    extension_type
                )));
            }
        }
        .map_err(stix_to_pyerr)?;

        if let Some(created) = created {
            let ts = JiffTimestamp::from_str(&created).map_err(|e| {
                PyErr::new::<StixError, _>(format!(
                    "Invalid created timestamp '{}': {}",
                    created, e
                ))
            })?;
            builder = builder.created(Timestamp(ts));
        }
        if let Some(modified) = modified {
            let ts = JiffTimestamp::from_str(&modified).map_err(|e| {
                PyErr::new::<StixError, _>(format!(
                    "Invalid modified timestamp '{}': {}",
                    modified, e
                ))
            })?;
            builder = builder.modified(Timestamp(ts));
        }

        // Validate at construction time unless asked otherwise.
        if strict {
            builder.clone().build().map_err(stix_to_pyerr)?;
        }

        Ok(CustomObject(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let obj = <crate::custom_objects::CustomObject as crate::object::FromJson>::from_json(
            &json_str,
            strict,
            version,
            allow_custom,
        )
        .map_err(stix_to_pyerr)?;
        let builder = CustomObjectBuilder::from_parsed(&obj).map_err(stix_to_pyerr)?;
        Ok(CustomObject(builder))
    }

    #[getter]
    fn r#type(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|obj| obj.object_type)
            .unwrap_or_default()
    }

    #[getter]
    fn id(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|obj| obj.common_properties.id.to_string())
            .unwrap_or_default()
    }

    #[getter]
    fn created(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.created.map(|t| t.to_string()))
    }

    #[getter]
    fn modified(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.modified.map(|t| t.to_string()))
    }

    #[getter]
    fn spec_version(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.spec_version)
    }

    #[getter]
    fn extension_type(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let ext_type = obj.get_object_type().map_err(stix_to_pyerr)?;
        Ok(match ext_type {
            ExtensionType::NewSdo => "new-sdo".to_string(),
            ExtensionType::NewSro => "new-sro".to_string(),
            ExtensionType::NewSco => "new-sco".to_string(),
            _ => "unknown".to_string(),
        })
    }

    #[getter]
    fn extension_definition_id(&self) -> Option<String> {
        let obj = self.0.clone().build_no_validate().ok()?;
        obj.common_properties.extensions.as_ref().and_then(|exts| {
            for (key, ext) in exts.iter() {
                if Identifier::from_str(key)
                    .map(|id| id.get_type() == "extension-definition")
                    .unwrap_or(false)
                {
                    if let Some(DictionaryValue::String(val)) = ext.get("extension_type") {
                        if val != "property-extension" && val != "toplevel-property-extension" {
                            return Some(key.clone());
                        }
                    }
                }
            }
            None
        })
    }

    #[getter]
    fn custom_properties<'py>(&self, py: Python<'py>) -> Result<Bound<'py, PyDict>, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let dict = PyDict::new_bound(py);
        for (k, v) in obj.custom_properties.iter() {
            dict.set_item(k, json_to_py(py, v)?)?;
        }
        Ok(dict)
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct ExtensionDefinition(ExtensionDefinitionBuilder);

#[pymethods]
impl ExtensionDefinition {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut builder = if let Some(kwargs) = kwargs.as_ref() {
            if let Some(name_val) = kwargs.get_item("name")? {
                let name: String = name_val.extract()?;
                ExtensionDefinitionBuilder::new(&name)
            } else {
                ExtensionDefinitionBuilder::new("")
            }
        } else {
            ExtensionDefinitionBuilder::new("")
        }
        .map_err(stix_to_pyerr)?;

        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract().map_err(|e| {
                    PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
                })?;
                match key.as_str() {
                    "schema" => {
                        let val: String = v.extract()?;
                        builder = builder.schema(val);
                    }
                    "version" => {
                        let val: String = v.extract()?;
                        builder = builder.set_version(val);
                    }
                    "extension_type" => {
                        let val: String = v.extract()?;
                        let ext_type = parse_extension_type(&val)?;
                        builder = builder.extension_types(vec![ext_type]);
                    }
                    "extension_types" => {
                        let vals: Vec<String> = v.extract()?;
                        let ext_types: Result<Vec<ExtensionType>, PyErr> =
                            vals.iter().map(|s| parse_extension_type(s)).collect();
                        builder = builder.extension_types(ext_types?);
                    }
                    "created_by_ref" => {
                        let val: String = v.extract()?;
                        let id = Identifier::from_str(&val).map_err(|e| {
                            PyErr::new::<StixError, _>(format!(
                                "Invalid created_by_ref identifier '{}': {}",
                                val, e
                            ))
                        })?;
                        builder = builder
                            .created_by_ref(id)
                            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
                    }
                    "description" => {
                        let val: String = v.extract()?;
                        builder = builder.description(val);
                    }
                    "created" => {
                        let val: String = v.extract()?;
                        let ts = JiffTimestamp::from_str(&val).map_err(|e| {
                            PyErr::new::<StixError, _>(format!(
                                "Invalid created timestamp '{}': {}",
                                val, e
                            ))
                        })?;
                        builder = builder.created(Timestamp(ts));
                    }
                    "modified" => {
                        let val: String = v.extract()?;
                        let ts = JiffTimestamp::from_str(&val).map_err(|e| {
                            PyErr::new::<StixError, _>(format!(
                                "Invalid modified timestamp '{}': {}",
                                val, e
                            ))
                        })?;
                        builder = builder.modified(Timestamp(ts));
                    }
                    "extension_properties" => {
                        let val: Vec<String> = v.extract()?;
                        builder = builder.extension_properties(val);
                    }
                    "name" => {
                        // Already handled above
                    }
                    _ => {
                        return Err(PyErr::new::<StixError, _>(format!(
                            "Unknown argument for ExtensionDefinition: '{}'",
                            key
                        )));
                    }
                }
            }
        }
        // Validate at construction time unless asked otherwise.
        if strict {
            builder.clone().build().map_err(stix_to_pyerr)?;
        }
        Ok(ExtensionDefinition(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let ext_def = <StixExtensionDefinition as crate::object::FromJson>::from_json(
            &json_str,
            strict,
            version,
            allow_custom,
        )
        .map_err(stix_to_pyerr)?;
        let builder = ExtensionDefinitionBuilder::from_parsed(&ext_def).map_err(stix_to_pyerr)?;
        Ok(ExtensionDefinition(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build_no_validate()
            .map_err(stix_to_pyerr)
            .and_then(|obj| {
                serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "extension-definition".to_string()
    }

    #[getter]
    fn id(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|obj| obj.common_properties.id.to_string())
            .unwrap_or_default()
    }

    #[getter]
    fn created(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.created.map(|t| t.to_string()))
    }

    #[getter]
    fn modified(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.modified.map(|t| t.to_string()))
    }

    #[getter]
    fn name(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|obj| obj.name)
            .unwrap_or_default()
    }

    #[getter]
    fn description(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.description)
    }

    #[getter]
    fn schema(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .map(|obj| obj.schema)
    }

    #[getter]
    fn version(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .map(|obj| obj.version)
    }

    #[getter]
    fn extension_types(&self) -> Result<Option<Vec<String>>, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        Ok(Some(
            obj.extension_types
                .iter()
                .map(|et| match et {
                    ExtensionType::NewSdo => "new-sdo".to_string(),
                    ExtensionType::NewSro => "new-sro".to_string(),
                    ExtensionType::NewSco => "new-sco".to_string(),
                    ExtensionType::PropertyExtension => "property-extension".to_string(),
                    ExtensionType::ToplevelPropertyExtension => {
                        "toplevel-property-extension".to_string()
                    }
                })
                .collect(),
        ))
    }

    #[getter]
    fn extension_properties(&self) -> Option<Vec<String>> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.extension_properties)
    }

    #[getter]
    fn created_by_ref(&self) -> Option<String> {
        self.0.clone().build_no_validate().ok().and_then(|obj| {
            obj.common_properties
                .created_by_ref
                .map(|id| id.to_string())
        })
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct LanguageContent(LanguageContentBuilder);

#[pymethods]
impl LanguageContent {
    #[new]
    #[pyo3(signature = (strict = true, **kwargs))]
    fn new(strict: bool, kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut json_obj = serde_json::json!({"type": "language-content"});
        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract().map_err(|e| {
                    PyErr::new::<StixError, _>(format!("STIX field name must be a string: {}", e))
                })?;
                json_obj[key] = py_to_json(&v)?;
            }
        }
        // Ensure required fields
        if json_obj.get("id").is_none() {
            let id = Identifier::new("language-content")
                .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
            json_obj["id"] = serde_json::Value::String(id.to_string());
        }
        if json_obj.get("created").is_none() {
            let now = Timestamp::now();
            json_obj["created"] = serde_json::Value::String(now.to_string());
        }
        if json_obj.get("modified").is_none() {
            let now = Timestamp::now();
            json_obj["modified"] = serde_json::Value::String(now.to_string());
        }
        if json_obj.get("spec_version").is_none() {
            json_obj["spec_version"] = serde_json::Value::String("2.1".to_string());
        }
        if json_obj.get("contents").is_none() {
            json_obj["contents"] = serde_json::json!({});
        }
        // Deserialize immediately. from_parsed preserves the caller-supplied
        // timestamps/contents, and build() runs stix_check when strict is true.
        let lc: StixLanguageContent = serde_json::from_str(&json_obj.to_string())
            .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        let builder = LanguageContentBuilder::from_parsed(&lc).map_err(stix_to_pyerr)?;
        if strict {
            builder.clone().build().map_err(stix_to_pyerr)?;
        }
        Ok(LanguageContent(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(
        json_str: String,
        strict: bool,
        version: &str,
        allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let lc = <StixLanguageContent as crate::object::FromJson>::from_json(
            &json_str,
            strict,
            version,
            allow_custom,
        )
        .map_err(stix_to_pyerr)?;
        let builder = LanguageContentBuilder::from_parsed(&lc).map_err(stix_to_pyerr)?;
        Ok(LanguageContent(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build_no_validate()
            .map_err(stix_to_pyerr)
            .and_then(|obj| {
                serde_json::to_string(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "language-content".to_string()
    }

    #[getter]
    fn id(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|obj| obj.common_properties.id.to_string())
            .unwrap_or_default()
    }

    #[getter]
    fn created(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.created.map(|t| t.to_string()))
    }

    #[getter]
    fn modified(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.common_properties.modified.map(|t| t.to_string()))
    }

    #[getter]
    fn object_modified(&self) -> Option<String> {
        self.0
            .clone()
            .build_no_validate()
            .ok()
            .and_then(|obj| obj.object_modified.map(|t| t.to_string()))
    }

    #[getter]
    fn contents<'py>(&self, py: Python<'py>) -> Result<Bound<'py, PyDict>, PyErr> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        let contents = value
            .get("contents")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        json_to_py(py, &contents)?.extract(py)
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build_no_validate().map_err(stix_to_pyerr)?;
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }

    fn insert_content_strings(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let hashmap: std::collections::HashMap<String, String> = content
            .extract()
            .map_err(|e| PyErr::new::<StixError, _>(format!("Failed to extract content: {}", e)))?;
        self.0 = self
            .0
            .clone()
            .insert_content_strings(&lang, hashmap)
            .map_err(stix_to_pyerr)?;
        Ok(())
    }

    fn insert_content_lists(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let hashmap: std::collections::HashMap<String, Vec<String>> = content
            .extract()
            .map_err(|e| PyErr::new::<StixError, _>(format!("Failed to extract content: {}", e)))?;
        self.0 = self
            .0
            .clone()
            .insert_content_lists(&lang, hashmap)
            .map_err(stix_to_pyerr)?;
        Ok(())
    }

    fn insert_content_objects(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let _py = content.py();
        let mut hashmap: std::collections::HashMap<
            String,
            std::collections::HashMap<String, serde_json::Value>,
        > = std::collections::HashMap::new();

        for (key, value) in content.iter() {
            let k: String = key
                .extract()
                .map_err(|e| PyErr::new::<StixError, _>(format!("Failed to extract key: {}", e)))?;

            if value.is_none() {
                continue;
            }

            let v: pyo3::Bound<'_, pyo3::types::PyDict> = value.extract().map_err(|e| {
                PyErr::new::<StixError, _>(format!("Failed to extract nested dict: {}", e))
            })?;

            let mut inner_hashmap = std::collections::HashMap::new();
            for (inner_key, inner_value) in v.iter() {
                let ik: String = inner_key.extract().map_err(|e| {
                    PyErr::new::<StixError, _>(format!("Failed to extract inner key: {}", e))
                })?;

                if inner_value.is_none() {
                    inner_hashmap.insert(ik, serde_json::Value::String(String::new()));
                    continue;
                }

                if let Ok(s) = inner_value.extract::<String>() {
                    inner_hashmap.insert(ik, serde_json::Value::String(s));
                } else if let Ok(arr) = inner_value.extract::<Vec<String>>() {
                    inner_hashmap.insert(
                        ik,
                        serde_json::Value::Array(
                            arr.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                } else {
                    inner_hashmap.insert(ik, serde_json::Value::String(String::new()));
                }
            }
            hashmap.insert(k, inner_hashmap);
        }

        self.0 = self
            .0
            .clone()
            .insert_content_objects(&lang, hashmap)
            .map_err(stix_to_pyerr)?;
        Ok(())
    }

    #[getter]
    fn object_ref(&self) -> String {
        self.0
            .clone()
            .build_no_validate()
            .map(|lc| lc.object_ref.to_string())
            .unwrap_or_default()
    }
}

#[pyclass]
pub struct Bundle(StixBundle);

#[pymethods]
impl Bundle {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut bundle = StixBundle {
            object_type: "bundle".to_string(),
            id: crate::types::Identifier::new("bundle")
                .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?,
            objects: Vec::new(),
        };
        if let Some(kwargs) = kwargs {
            if let Some(objects_val) = kwargs.get_item("objects")? {
                let py_list = objects_val.downcast::<PyList>().map_err(|_| {
                    PyErr::new::<StixError, _>("Bundle.objects must be a list".to_string())
                })?;
                for item in py_list.iter() {
                    let json_str = if let Ok(s) = item.extract::<String>() {
                        s
                    } else {
                        let json_obj = item.call_method0("to_json")?;
                        json_obj.extract::<String>()?
                    };
                    bundle
                        .push_json(&json_str)
                        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
                }
            }
        }
        if bundle.objects.is_empty() {
            return Err(PyErr::new::<ValidationError, _>(
                "Bundle must contain at least one object",
            ));
        }
        Ok(Bundle(bundle))
    }

    fn add(&mut self, stix_json: String) -> Result<(), PyErr> {
        self.0.push_json(&stix_json).map_err(stix_to_pyerr)?;
        Ok(())
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, _strict = true, _version = "2.1", _allow_custom = false))]
    fn from_json(
        json_str: String,
        _strict: bool,
        _version: &str,
        _allow_custom: bool,
    ) -> Result<Self, PyErr> {
        let bundle = StixBundle::from_json(&json_str).map_err(stix_to_pyerr)?;
        Ok(Bundle(bundle))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        // Serialization does not re-validate the bundle. Validation is the
        // caller's responsibility before reaching this stage.
        serde_json::to_string(&self.0).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))
    }

    #[getter]
    fn id(&self) -> String {
        self.0.id.to_string()
    }

    #[getter]
    fn object_count(&self) -> usize {
        self.0.get_objects().len()
    }

    #[getter]
    fn r#type(&self) -> String {
        "bundle".to_string()
    }

    #[getter]
    fn objects<'py>(&self, py: Python<'py>) -> Result<Bound<'py, PyList>, PyErr> {
        let list = PyList::empty_bound(py);
        for obj in self.0.get_objects() {
            let py_obj = wrap_stix_object(py, obj)?;
            list.append(py_obj)?;
        }
        Ok(list)
    }
}

/// Convert a typed [`StixObject`] into its corresponding Python wrapper class.
fn wrap_stix_object(py: Python<'_>, obj: crate::object::StixObject) -> Result<PyObject, PyErr> {
    match obj {
        crate::object::StixObject::Sdo(domain_obj) => {
            let builder = DomainObjectBuilder::from_parsed(&domain_obj).map_err(stix_to_pyerr)?;
            Ok(match domain_obj.object_type {
                DomainObjectType::AttackPattern(_) => {
                    Py::new(py, AttackPattern(builder))?.into_py(py)
                }
                DomainObjectType::Campaign(_) => Py::new(py, Campaign(builder))?.into_py(py),
                DomainObjectType::CourseOfAction(_) => {
                    Py::new(py, CourseOfAction(builder))?.into_py(py)
                }
                DomainObjectType::Grouping(_) => Py::new(py, Grouping(builder))?.into_py(py),
                DomainObjectType::Identity(_) => Py::new(py, Identity(builder))?.into_py(py),
                DomainObjectType::Incident(_) => Py::new(py, Incident(builder))?.into_py(py),
                DomainObjectType::Indicator(_) => Py::new(py, Indicator(builder))?.into_py(py),
                DomainObjectType::Infrastructure(_) => {
                    Py::new(py, Infrastructure(builder))?.into_py(py)
                }
                DomainObjectType::IntrusionSet(_) => {
                    Py::new(py, IntrusionSet(builder))?.into_py(py)
                }
                DomainObjectType::Location(_) => Py::new(py, Location(builder))?.into_py(py),
                DomainObjectType::Malware(_) => Py::new(py, Malware(builder))?.into_py(py),
                DomainObjectType::MalwareAnalysis(_) => {
                    Py::new(py, MalwareAnalysis(builder))?.into_py(py)
                }
                DomainObjectType::Note(_) => Py::new(py, Note(builder))?.into_py(py),
                DomainObjectType::ObservedData(_) => {
                    Py::new(py, ObservedData(builder))?.into_py(py)
                }
                DomainObjectType::Opinion(_) => Py::new(py, Opinion(builder))?.into_py(py),
                DomainObjectType::Report(_) => Py::new(py, Report(builder))?.into_py(py),
                DomainObjectType::ThreatActor(_) => Py::new(py, ThreatActor(builder))?.into_py(py),
                DomainObjectType::Tool(_) => Py::new(py, Tool(builder))?.into_py(py),
                DomainObjectType::Vulnerability(_) => {
                    Py::new(py, Vulnerability(builder))?.into_py(py)
                }
            })
        }
        crate::object::StixObject::Sro(rel_obj) => {
            let builder =
                RelationshipObjectBuilder::from_parsed(&rel_obj).map_err(stix_to_pyerr)?;
            Ok(match rel_obj.object_type {
                RelationshipObjectType::Relationship(_) => {
                    Py::new(py, Relationship(builder))?.into_py(py)
                }
                RelationshipObjectType::Sighting(_) => Py::new(py, Sighting(builder))?.into_py(py),
            })
        }
        crate::object::StixObject::Sco(cyber_obj) => {
            let builder = CyberObjectBuilder::from_parsed(&cyber_obj).map_err(stix_to_pyerr)?;
            Ok(match cyber_obj.object_type {
                CyberObjectType::Artifact(_) => Py::new(py, Artifact(builder))?.into_py(py),
                CyberObjectType::AutonomousSystem(_) => {
                    Py::new(py, AutonomousSystem(builder))?.into_py(py)
                }
                CyberObjectType::Directory(_) => Py::new(py, Directory(builder))?.into_py(py),
                CyberObjectType::DomainName(_) => Py::new(py, DomainName(builder))?.into_py(py),
                CyberObjectType::EmailAddress(_) => Py::new(py, EmailAddress(builder))?.into_py(py),
                CyberObjectType::EmailMessage(_) => Py::new(py, EmailMessage(builder))?.into_py(py),
                CyberObjectType::File(_) => Py::new(py, File(builder))?.into_py(py),
                CyberObjectType::Ipv4Addr(_) => Py::new(py, IPv4Address(builder))?.into_py(py),
                CyberObjectType::Ipv6Addr(_) => Py::new(py, IPv6Address(builder))?.into_py(py),
                CyberObjectType::MacAddr(_) => Py::new(py, MacAddr(builder))?.into_py(py),
                CyberObjectType::Mutex(_) => Py::new(py, Mutex(builder))?.into_py(py),
                CyberObjectType::NetworkTraffic(_) => {
                    Py::new(py, NetworkTraffic(builder))?.into_py(py)
                }
                CyberObjectType::Process(_) => Py::new(py, Process(builder))?.into_py(py),
                CyberObjectType::Software(_) => Py::new(py, Software(builder))?.into_py(py),
                CyberObjectType::Url(_) => Py::new(py, URL(builder))?.into_py(py),
                CyberObjectType::UserAccount(_) => Py::new(py, UserAccount(builder))?.into_py(py),
                CyberObjectType::WindowsRegistryKey(_) => {
                    Py::new(py, WindowsRegistryKey(builder))?.into_py(py)
                }
                CyberObjectType::WindowsRegistryKeyType(_) => {
                    // Not a top-level SCO; fall back to a JSON dict.
                    let value = serde_json::to_value(&cyber_obj)
                        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
                    json_to_py(py, &value)?
                }
                CyberObjectType::X509Certificate(_) => {
                    Py::new(py, X509Certificate(builder))?.into_py(py)
                }
            })
        }
        crate::object::StixObject::LanguageContent(lc) => {
            let builder = LanguageContentBuilder::from_parsed(&lc).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, LanguageContent(builder))?.into_py(py))
        }
        crate::object::StixObject::ExtensionDefinition(ed) => {
            let builder = ExtensionDefinitionBuilder::from_parsed(&ed).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, ExtensionDefinition(builder))?.into_py(py))
        }
        crate::object::StixObject::MarkingDefinition(md) => {
            let builder = MarkingDefinitionBuilder::from_parsed(&md).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, MarkingDefinition(builder))?.into_py(py))
        }
        crate::object::StixObject::Custom(custom) => {
            let builder = CustomObjectBuilder::from_parsed(&custom).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, CustomObject(builder))?.into_py(py))
        }
    }
}

#[pymodule(name = "stixflayer")]
pub fn stixflayer_bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(test_stix, m)?)?;
    m.add_function(wrap_pyfunction!(create_timestamp, m)?)?;
    m.add_function(wrap_pyfunction!(validate_pattern, m)?)?;

    m.add_class::<AttackPattern>()?;
    m.add_class::<Campaign>()?;
    m.add_class::<CourseOfAction>()?;
    m.add_class::<Grouping>()?;
    m.add_class::<Identity>()?;
    m.add_class::<Incident>()?;
    m.add_class::<Indicator>()?;
    m.add_class::<Infrastructure>()?;
    m.add_class::<IntrusionSet>()?;
    m.add_class::<Location>()?;
    m.add_class::<Malware>()?;
    m.add_class::<MalwareAnalysis>()?;
    m.add_class::<Note>()?;
    m.add_class::<ObservedData>()?;
    m.add_class::<Opinion>()?;
    m.add_class::<Report>()?;
    m.add_class::<ThreatActor>()?;
    m.add_class::<Tool>()?;
    m.add_class::<Vulnerability>()?;

    m.add_class::<IPv4Address>()?;
    m.add_class::<IPv6Address>()?;
    m.add_class::<DomainName>()?;
    m.add_class::<URL>()?;
    m.add_class::<EmailAddress>()?;
    m.add_class::<EmailMessage>()?;
    m.add_class::<MacAddr>()?;
    m.add_class::<AutonomousSystem>()?;
    m.add_class::<File>()?;
    m.add_class::<Software>()?;
    m.add_class::<Directory>()?;
    m.add_class::<Mutex>()?;
    m.add_class::<Process>()?;
    m.add_class::<NetworkTraffic>()?;
    m.add_class::<UserAccount>()?;
    m.add_class::<WindowsRegistryKey>()?;
    m.add_class::<X509Certificate>()?;
    m.add_class::<Artifact>()?;

    m.add_class::<Relationship>()?;
    m.add_class::<Sighting>()?;
    m.add_class::<MarkingDefinition>()?;
    m.add_class::<CustomObject>()?;
    m.add_class::<ExtensionDefinition>()?;
    m.add_class::<LanguageContent>()?;
    m.add_class::<Bundle>()?;

    // Errors
    m.add("StixError", py.get_type_bound::<StixError>())?;
    m.add("ValidationError", py.get_type_bound::<ValidationError>())?;
    m.add(
        "DeserializationError",
        py.get_type_bound::<DeserializationError>(),
    )?;

    // Vocab enums
    m.add_class::<AttackMotivation>()?;
    m.add_class::<IdentitySectors>()?;
    m.add_class::<ThreatActorType>()?;
    m.add_class::<MalwareType>()?;
    m.add_class::<IndicatorType>()?;
    m.add_class::<ReportType>()?;
    m.add_class::<AttackResourceLevel>()?;
    m.add_class::<ThreatActorSophistication>()?;

    Ok(())
}
