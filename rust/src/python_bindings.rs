use pyo3::exceptions::PyValueError as PyO3ValueError;
use pyo3::exceptions::PyAttributeError as PyO3AttributeError;
use pyo3::prelude::*;
use std::collections::BTreeMap;
use std::str::FromStr;
use ordered_float::OrderedFloat;
use crate::cyber_observable_objects::sco::CyberObjectBuilder;
use crate::custom_objects::CustomObjectBuilder;
use crate::domain_objects::sdo::DomainObjectBuilder;
use crate::error::StixError;
use crate::meta_objects::extension_definition::{ExtensionDefinition as StixExtensionDefinition, ExtensionDefinitionBuilder};
use crate::meta_objects::language_content::LanguageContentBuilder;
use crate::meta_objects::language_content::LanguageContent as StixLanguageContent;
use crate::meta_objects::marking_definition::MarkingDefinitionBuilder;
use crate::relationship_objects::RelationshipObjectBuilder;
use crate::relationship_objects::RelationshipObject as StixRelationshipObject;
use crate::base::Stix;
use crate::bundles::Bundle as StixBundle;
use crate::pattern::validate_pattern as rust_validate_pattern;
use strum::IntoEnumIterator;
use crate::types::ExtensionType;
use crate::types::Identifier;
use crate::types::Timestamp;
use crate::types::{DictionaryValue, StixDictionary};
use pyo3::types::PyDict;
use pyo3::types::PyList;

/// Helper function to validate that required fields are present in a DomainObjectBuilder
fn validate_sdo_builder(builder: DomainObjectBuilder) -> Result<DomainObjectBuilder, PyErr> {
    builder.clone().build()
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    Ok(builder)
}

/// Helper function to validate that required fields are present in a CyberObjectBuilder
fn validate_sco_builder(builder: CyberObjectBuilder) -> Result<CyberObjectBuilder, PyErr> {
    builder.clone().build()
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    Ok(builder)
}

/// Helper function to validate that required fields are present in a RelationshipObjectBuilder
fn validate_sro_builder(builder: RelationshipObjectBuilder) -> Result<RelationshipObjectBuilder, PyErr> {
    builder.clone().build()
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    Ok(builder)
}

/// Helper function to validate that required fields are present in a MarkingDefinitionBuilder
fn validate_marking_builder(builder: MarkingDefinitionBuilder) -> Result<MarkingDefinitionBuilder, PyErr> {
    builder.clone().build()
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    Ok(builder)
}

/// Build a JSON envelope for an SDO and validate it
fn build_sdo_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
) -> Result<DomainObjectBuilder, PyErr> {
    let id = Identifier::new(type_name)
        .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    let mut json_obj = serde_json::json!({
        "type": type_name,
        "spec_version": "2.1",
        "id": id.to_string()
    });
    if let Some(kwargs) = kwargs {
        for (k, v) in kwargs.iter() {
            let key: String = k.extract()
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
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
    let domain_obj = crate::domain_objects::sdo::DomainObject::from_json(&json_obj.to_string(), false)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    let builder = DomainObjectBuilder::from_parsed(&domain_obj)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    validate_sdo_builder(builder)
}

/// Build a JSON envelope for an SCO and validate it
fn build_sco_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
) -> Result<CyberObjectBuilder, PyErr> {
    let mut json_obj = serde_json::json!({"type": type_name});
    if let Some(kwargs) = kwargs {
        for (k, v) in kwargs.iter() {
            let key: String = k.extract()
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
            json_obj[key] = py_to_json(&v)?;
        }
    }
    if json_obj.get("id").is_none() {
        let id = Identifier::new(type_name)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        json_obj["id"] = serde_json::Value::String(id.to_string());
    }
    let cyber_obj = crate::cyber_observable_objects::sco::CyberObject::from_json(&json_obj.to_string(), false)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    let builder = CyberObjectBuilder::from(&cyber_obj)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    validate_sco_builder(builder)
}

/// Build a JSON envelope for an SRO and validate it
fn build_sro_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
) -> Result<RelationshipObjectBuilder, PyErr> {
    let id = Identifier::new(type_name)
        .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
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
            let key: String = k.extract()
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
            json_obj[key] = py_to_json(&v)?;
        }
    }
    let sro_obj = crate::relationship_objects::RelationshipObject::from_json(&json_obj.to_string(), false)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    let builder = RelationshipObjectBuilder::version(&sro_obj)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    validate_sro_builder(builder)
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
                let valid = <$enum_type>::iter()
                    .any(|v| v.as_ref() == value);
                if valid {
                    Ok($name(value.to_string()))
                } else {
                    // Get all valid variants for error message
                    let valid_values: Vec<String> = <$enum_type>::iter()
                        .map(|v| v.as_ref().to_string())
                        .collect();
                    Err(PyErr::new::<PyO3ValueError, _>(
                        format!("Invalid {} value: '{}'. Valid values: {:?}", 
                            stringify!($enum_type), value, valid_values)
                    ))
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
                <$enum_type>::iter()
                    .any(|v| v.as_ref() == value)
            }
        }
    };
}

// Generate vocab enum classes
make_vocab_enum!(AttackMotivation, crate::domain_objects::vocab::AttackMotivation);
make_vocab_enum!(IdentitySectors, crate::domain_objects::vocab::IdentitySectors);
make_vocab_enum!(ThreatActorType, crate::domain_objects::vocab::ThreatActorType);
make_vocab_enum!(MalwareType, crate::domain_objects::vocab::MalwareType);
make_vocab_enum!(IndicatorType, crate::domain_objects::vocab::IndicatorType);
make_vocab_enum!(ReportType, crate::domain_objects::vocab::ReportType);
make_vocab_enum!(AttackResourceLevel, crate::domain_objects::vocab::AttackResourceLevel);
make_vocab_enum!(ThreatActorSophistication, crate::domain_objects::vocab::ThreatActorSophistication);

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
    rust_validate_pattern(pattern)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))
}

// PyO3 limitation: #[pyclass] and #[pymethods] cannot be generated via macros.
// Each SCO struct must be written explicitly with these proc-macro attributes.

fn pydict_to_stix_dict(dict: &Bound<'_, PyDict>) -> Result<StixDictionary<DictionaryValue>, PyErr> {
    let mut output = StixDictionary::new();
    for (key, value) in dict.iter() {
        let k: String = key.extract()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("Extension key must be a string: {}", e)))?;
        let v = pyobj_to_dict_value(value)?;
        let _ = output.insert(&k, v);
    }
    Ok(output)
}

fn pyobj_to_dict_value(obj: Bound<'_, PyAny>) -> Result<DictionaryValue, PyErr> {
    // Handle None
    if obj.is_none() {
        return Ok(DictionaryValue::String(String::new()));
    }
    // Handle string
    if let Ok(s) = obj.extract::<String>() {
        return Ok(DictionaryValue::String(s));
    }
    // Handle integer (i64 first, then u64)
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(DictionaryValue::SInt(i));
    }
    if let Ok(u) = obj.extract::<u64>() {
        return Ok(DictionaryValue::Int(u));
    }
    // Handle float
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(DictionaryValue::Float(OrderedFloat::from(f)));
    }
    // Handle boolean
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(DictionaryValue::Bool(b));
    }
    // Handle list
    if let Ok(list) = obj.downcast::<PyList>() {
        let mut items = Vec::new();
        for item in list.iter() {
            items.push(pyobj_to_dict_value(item)?);
        }
        return Ok(DictionaryValue::List(items));
    }
    // Handle dict
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let stix_dict = pydict_to_stix_dict(dict)?;
        return Ok(DictionaryValue::Dict(stix_dict));
    }
    // Fallback: convert to string
    Ok(DictionaryValue::String(obj.to_string()))
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
            let key: String = k.extract()
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("Dict key must be a string: {}", e)))?;
            map.insert(key, py_to_json(&v)?);
        }
        return Ok(serde_json::Value::Object(map));
    }
    Err(PyErr::new::<PyO3ValueError, _>(format!(
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


#[pyclass]
pub struct Campaign(DomainObjectBuilder);

#[pymethods]
impl Campaign {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("campaign", kwargs)?;
        Ok(Campaign(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Campaign(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "campaign".to_string()
    }
}

#[pyclass]
pub struct CourseOfAction(DomainObjectBuilder);

#[pymethods]
impl CourseOfAction {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("course-of-action", kwargs)?;
        Ok(CourseOfAction(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(CourseOfAction(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "course-of-action".to_string()
    }
}

#[pyclass]
pub struct Grouping(DomainObjectBuilder);

#[pymethods]
impl Grouping {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("grouping", kwargs)?;
        Ok(Grouping(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Grouping(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "grouping".to_string()
    }
}

#[pyclass]
pub struct Identity(DomainObjectBuilder);

#[pymethods]
impl Identity {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("identity", kwargs)?;
        Ok(Identity(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Identity(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "identity".to_string()
    }
}

#[pyclass]
pub struct Incident(DomainObjectBuilder);

#[pymethods]
impl Incident {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("incident", kwargs)?;
        Ok(Incident(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Incident(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "incident".to_string()
    }
}

#[pyclass]
pub struct Infrastructure(DomainObjectBuilder);

#[pymethods]
impl Infrastructure {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("infrastructure", kwargs)?;
        Ok(Infrastructure(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Infrastructure(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "infrastructure".to_string()
    }
}

#[pyclass]
pub struct IntrusionSet(DomainObjectBuilder);

#[pymethods]
impl IntrusionSet {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("intrusion-set", kwargs)?;
        Ok(IntrusionSet(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(IntrusionSet(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "intrusion-set".to_string()
    }
}

#[pyclass]
pub struct Location(DomainObjectBuilder);

#[pymethods]
impl Location {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("location", kwargs)?;
        Ok(Location(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Location(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "location".to_string()
    }
}

#[pyclass]
pub struct MalwareAnalysis(DomainObjectBuilder);

#[pymethods]
impl MalwareAnalysis {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("malware-analysis", kwargs)?;
        Ok(MalwareAnalysis(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(MalwareAnalysis(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "malware-analysis".to_string()
    }
}

#[pyclass]
pub struct Note(DomainObjectBuilder);

#[pymethods]
impl Note {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("note", kwargs)?;
        Ok(Note(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Note(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "note".to_string()
    }
}

#[pyclass]
pub struct ObservedData(DomainObjectBuilder);

#[pymethods]
impl ObservedData {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("observed-data", kwargs)?;
        Ok(ObservedData(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(ObservedData(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "observed-data".to_string()
    }
}

#[pyclass]
pub struct Opinion(DomainObjectBuilder);

#[pymethods]
impl Opinion {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("opinion", kwargs)?;
        Ok(Opinion(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Opinion(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "opinion".to_string()
    }
}

#[pyclass]
pub struct Report(DomainObjectBuilder);

#[pymethods]
impl Report {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("report", kwargs)?;
        Ok(Report(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Report(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "report".to_string()
    }
}

#[pyclass]
pub struct ThreatActor(DomainObjectBuilder);

#[pymethods]
impl ThreatActor {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("threat-actor", kwargs)?;
        Ok(ThreatActor(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(ThreatActor(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "threat-actor".to_string()
    }
}

#[pyclass]
pub struct Tool(DomainObjectBuilder);

#[pymethods]
impl Tool {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("tool", kwargs)?;
        Ok(Tool(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Tool(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "tool".to_string()
    }
}

#[pyclass]
pub struct Vulnerability(DomainObjectBuilder);

#[pymethods]
impl Vulnerability {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("vulnerability", kwargs)?;
        Ok(Vulnerability(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Vulnerability(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "vulnerability".to_string()
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("malware", kwargs)?;
        Ok(Malware(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Malware(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "malware".to_string()
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("attack-pattern", kwargs)?;
        Ok(AttackPattern(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(AttackPattern(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "attack-pattern".to_string()
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let value = serde_json::to_value(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        match value.get(name) {
            Some(v) => json_to_py(py, v),
            None => Err(PyErr::new::<PyO3AttributeError, _>(format!(
                "'AttackPattern' object has no attribute '{}'",
                name
            ))),
        }
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sdo_envelope("indicator", kwargs)?;
        Ok(Indicator(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sdo = crate::object::parse_sdo(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = DomainObjectBuilder::from_parsed(&sdo)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Indicator(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "indicator".to_string()
    }
}

#[pyclass]
pub struct IPv4Address(CyberObjectBuilder);

#[pymethods]
impl IPv4Address {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("ipv4-addr", kwargs)?;
        Ok(IPv4Address(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(IPv4Address(builder))
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv4-addr".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("ipv6-addr", kwargs)?;
        Ok(IPv6Address(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(IPv6Address(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "ipv6-addr".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("domain-name", kwargs)?;
        Ok(DomainName(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(DomainName(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "domain-name".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("url", kwargs)?;
        Ok(URL(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(URL(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "url".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Url(u) =
                &sco.object_type
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("email-addr", kwargs)?;
        Ok(EmailAddress(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(EmailAddress(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "email-address".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("email-message", kwargs)?;
        Ok(EmailMessage(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(EmailMessage(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "email-message".to_string()
    }

    #[getter]
    fn from_ref(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::EmailMessage(em) =
                &sco.object_type
            {
                return em.from_ref.clone().map(|i| i.to_string()).unwrap_or_default();
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("mac-addr", kwargs)?;
        Ok(MacAddr(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(MacAddr(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "mac-addr".to_string()
    }

    #[getter]
    fn value(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("autonomous-system", kwargs)?;
        Ok(AutonomousSystem(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(AutonomousSystem(builder))
    }

    #[getter]
    fn r#type(&self) -> String {
        "autonomous-system".to_string()
    }

    #[getter]
    fn number(&self) -> u64 {
        if let Ok(sco) = self.0.clone().build() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::AutonomousSystem(
                obj,
            ) = &sco.object_type
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("file", kwargs)?;
        Ok(File(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(File(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "file".to_string()
    }

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::File(f) =
                &sco.object_type
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("software", kwargs)?;
        Ok(Software(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Software(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "software".to_string()
    }

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("directory", kwargs)?;
        Ok(Directory(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Directory(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "directory".to_string()
    }

    #[getter]
    fn path(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("mutex", kwargs)?;
        Ok(Mutex(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Mutex(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "mutex".to_string()
    }

    #[getter]
    fn name(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("process", kwargs)?;
        Ok(Process(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Process(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "process".to_string()
    }
}

#[pyclass]
pub struct NetworkTraffic(CyberObjectBuilder);

#[pymethods]
impl NetworkTraffic {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("network-traffic", kwargs)?;
        Ok(NetworkTraffic(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(NetworkTraffic(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "network-traffic".to_string()
    }
}

#[pyclass]
pub struct UserAccount(CyberObjectBuilder);

#[pymethods]
impl UserAccount {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("user-account", kwargs)?;
        Ok(UserAccount(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(UserAccount(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "user-account".to_string()
    }

    #[getter]
    fn account_login(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("windows-registry-key", kwargs)?;
        Ok(WindowsRegistryKey(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(WindowsRegistryKey(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "windows-registry-key".to_string()
    }

    #[getter]
    fn key(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::WindowsRegistryKey(
                w,
            ) = &sco.object_type
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("x509-certificate", kwargs)?;
        Ok(X509Certificate(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(X509Certificate(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "x509-certificate".to_string()
    }

    #[getter]
    fn serial_number(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
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
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sco_envelope("artifact", kwargs)?;
        Ok(Artifact(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sco = crate::object::parse_sco(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = CyberObjectBuilder::from(&sco)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Artifact(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let sco = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&sco)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "artifact".to_string()
    }

    #[getter]
    fn mime_type(&self) -> String {
        if let Ok(sco) = self.0.clone().build() {
            if let crate::cyber_observable_objects::sco::CyberObjectType::Artifact(a) =
                &sco.object_type
            {
                return a.mime_type.clone().unwrap_or_default();
            }
        }
        "".to_string()
    }
}

/// Helper function to build an SRO from kwargs
fn build_sro_from_kwargs(
    sro_type: &str,
    kwargs: Option<Bound<'_, PyDict>>,
) -> Result<RelationshipObjectBuilder, PyErr> {
    let id = Identifier::new(sro_type)
        .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    let now = Timestamp::now();
    let mut json_obj = serde_json::json!({
        "type": sro_type,
        "spec_version": "2.1",
        "id": id.to_string(),
        "created": now.to_string(),
        "modified": now.to_string()
    });
    if let Some(kwargs) = kwargs {
        for (k, v) in kwargs.iter() {
            let key: String = k.extract()
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
            json_obj[key] = py_to_json(&v)?;
        }
    }
    let sro = StixRelationshipObject::from_json(&json_obj.to_string(), false)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    let builder = RelationshipObjectBuilder::version(&sro)
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
    validate_sro_builder(builder)
}

#[pyclass]
pub struct Relationship(RelationshipObjectBuilder);

#[pymethods]
impl Relationship {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sro_envelope("relationship", kwargs)?;
        Ok(Relationship(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sro = crate::object::parse_sro(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = RelationshipObjectBuilder::version(&sro)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Relationship(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "relationship".to_string()
    }
}

#[pyclass]
pub struct Sighting(RelationshipObjectBuilder);

#[pymethods]
impl Sighting {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let builder = build_sro_envelope("sighting", kwargs)?;
        Ok(Sighting(builder))
    }

    #[staticmethod]
    #[pyo3(signature = (json_str, strict = true, version = "2.1", allow_custom = false))]
    fn from_json(json_str: String, strict: bool, version: &str, allow_custom: bool) -> Result<Self, PyErr> {
        let sro = crate::object::parse_sro(&json_str, strict, version, allow_custom)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = RelationshipObjectBuilder::version(&sro)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Sighting(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let obj = self.0.clone().build()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&obj)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
    }

    #[getter]
    fn r#type(&self) -> String {
        "sighting".to_string()
    }
}

#[pyclass]
pub struct MarkingDefinition(MarkingDefinitionBuilder);

#[pymethods]
impl MarkingDefinition {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut builder = MarkingDefinitionBuilder::new()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        
        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract()
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
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
                                .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
                        builder = builder.definition(marking_type);
                    }
                    _ => {
                        // Unknown field - we could store it or ignore it
                        // For now, just ignore unknown fields to allow flexibility
                    }
                }
            }
        }
        
        Ok(MarkingDefinition(validate_marking_builder(builder)?))
    }

    #[staticmethod]
    fn from_json(json_str: String) -> Result<Self, PyErr> {
        let md = crate::meta_objects::marking_definition::MarkingDefinition::from_json(&json_str, false)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = MarkingDefinitionBuilder::version(&md)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(MarkingDefinition(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            .and_then(|obj| {
                serde_json::to_string(&obj)
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "marking-definition".to_string()
    }
}

#[pyclass]
pub struct CustomObject {
    type_: String,
    custom_properties_json: String,
    extension_type: String,
    extension_definition_id: Option<String>,
}

#[pymethods]
impl CustomObject {
    #[new]
    fn new(
        type_: String,
        extension_type: String,
        custom_properties_json: String,
        extension_definition_id: Option<String>,
    ) -> Result<Self, PyErr> {
        // Validate it's valid JSON
        let _: serde_json::Value = serde_json::from_str(&custom_properties_json)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        
        Ok(CustomObject {
            type_,
            extension_type,
            custom_properties_json,
            extension_definition_id,
        })
    }

    fn to_json(&self) -> Result<String, PyErr> {
        let props: serde_json::Value = serde_json::from_str(&self.custom_properties_json)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        
        let props_map: BTreeMap<String, serde_json::Value> = if let serde_json::Value::Object(m) = props {
            let mut map = BTreeMap::new();
            for (k, v) in m {
                let _ = map.insert(k, v);
            }
            map
        } else {
            return Err(PyErr::new::<PyO3ValueError, _>("custom_properties must be a JSON object".to_string()));
        };
        
        let ext_def_id = self.extension_definition_id
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("extension-definition--00000000-0000-0000-0000-000000000000");
        
        let builder = match self.extension_type.as_str() {
            "new-sdo" => CustomObjectBuilder::new_sdo(&self.type_, props_map, ext_def_id),
            "new-sro" => CustomObjectBuilder::new_sro(&self.type_, props_map, ext_def_id),
            "new-sco" => CustomObjectBuilder::new_sco(&self.type_, props_map, ext_def_id),
            _ => {
                return Err(PyErr::new::<PyO3ValueError, _>(
                    "extension_type must be new-sdo, new-sco, or new-sro".to_string(),
                ))
            }
        }
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;

        builder
            .build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            .and_then(|obj| {
                serde_json::to_string(&obj)
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            })
    }

    /// Deserialize a CustomObject from JSON string
    /// Note: from_json needs pyo3 0.22 fix - using staticmethod pattern
    /// Usage: CustomObject.from_json('{"type": "my-sdo", ...}')
    #[staticmethod]
    fn from_json(json_str: String) -> Result<Self, PyErr> {
        let obj = crate::custom_objects::CustomObject::from_json(&json_str)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;

        let extension_type = obj
            .get_object_type()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;

        let ext_type_str = match extension_type {
            ExtensionType::NewSdo => "new-sdo",
            ExtensionType::NewSro => "new-sro",
            ExtensionType::NewSco => "new-sco",
            _ => "unknown",
        };

        let extension_definition_id = obj.common_properties.extensions.as_ref().and_then(|exts| {
            exts.keys().next().cloned()
        });

        let custom_properties_json = serde_json::to_string(&obj.custom_properties)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;

        Ok(CustomObject {
            type_: obj.object_type,
            custom_properties_json,
            extension_type: ext_type_str.to_string(),
            extension_definition_id,
        })
    }

    #[getter]
    fn r#type(&self) -> String {
        self.type_.clone()
    }

    #[getter]
    fn custom_properties(&self) -> String {
        self.custom_properties_json.clone()
    }
}

#[pyclass]
pub struct ExtensionDefinition(ExtensionDefinitionBuilder);

#[pymethods]
impl ExtensionDefinition {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
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
        .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        
        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract()
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
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
                        let ext_type = match val.as_str() {
                            "new-sdo" => ExtensionType::NewSdo,
                            "new-sco" => ExtensionType::NewSco,
                            "new-sro" => ExtensionType::NewSro,
                            "property-extension" => ExtensionType::PropertyExtension,
                            "toplevel-property-extension" => ExtensionType::ToplevelPropertyExtension,
                            _ => {
                                return Err(PyErr::new::<PyO3ValueError, _>(format!(
                                    "Invalid extension_type: '{}'. Valid values: new-sdo, new-sco, new-sro, property-extension, toplevel-property-extension",
                                    val
                                )));
                            }
                        };
                        builder = builder.extension_types(vec![ext_type]);
                    }
                    "created_by_ref" => {
                        let val: String = v.extract()?;
                        if let Ok(id) = Identifier::from_str(&val) {
                            builder = builder.created_by_ref(id).map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
                        }
                    }
                    "description" => {
                        let val: String = v.extract()?;
                        builder = builder.description(val);
                    }
                    "extension_properties" => {
                        let val: Vec<String> = v.extract()?;
                        builder = builder.extension_properties(val);
                    }
                    "name" => {
                        // Already handled above
                    }
                    _ => {}
                }
            }
        }
        Ok(ExtensionDefinition(builder))
    }

    #[staticmethod]
    fn from_json(json_str: String) -> Result<Self, PyErr> {
        let ext_def = StixExtensionDefinition::from_json(&json_str, false)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = ExtensionDefinitionBuilder::version(&ext_def)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(ExtensionDefinition(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            .and_then(|obj| {
                serde_json::to_string(&obj)
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "extension-definition".to_string()
    }
}

#[pyclass]
pub struct LanguageContent(LanguageContentBuilder);

#[pymethods]
impl LanguageContent {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<Bound<'_, PyDict>>) -> Result<Self, PyErr> {
        let mut json_obj = serde_json::json!({"type": "language-content"});
        if let Some(kwargs) = kwargs {
            for (k, v) in kwargs.iter() {
                let key: String = k.extract()
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(format!("STIX field name must be a string: {}", e)))?;
                json_obj[key] = py_to_json(&v)?;
            }
        }
        // Ensure required fields
        if json_obj.get("id").is_none() {
            let id = Identifier::new("language-content")
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
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
        // Deserialize WITHOUT running stix_check (validation happens at to_json time)
        let lc: StixLanguageContent = serde_json::from_str(&json_obj.to_string())
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = LanguageContentBuilder::version(&lc)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(LanguageContent(builder))
    }

    #[staticmethod]
    fn from_json(json_str: String) -> Result<Self, PyErr> {
        let lc = StixLanguageContent::from_json(&json_str, false)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        let builder = LanguageContentBuilder::version(&lc)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(LanguageContent(builder))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0
            .clone()
            .build()
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            .and_then(|obj| {
                serde_json::to_string(&obj)
                    .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
            })
    }

    #[getter]
    fn r#type(&self) -> String {
        "language-content".to_string()
    }

    fn insert_content_strings(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let hashmap: std::collections::HashMap<String, String> = content.extract().map_err(|e| {
            PyErr::new::<PyO3ValueError, _>(format!("Failed to extract content: {}", e))
        })?;
        self.0 = self.0.clone()
            .insert_content_strings(&lang, hashmap)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(())
    }

    fn insert_content_lists(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let hashmap: std::collections::HashMap<String, Vec<String>> = content.extract().map_err(|e| {
            PyErr::new::<PyO3ValueError, _>(format!("Failed to extract content: {}", e))
        })?;
        self.0 = self.0.clone()
            .insert_content_lists(&lang, hashmap)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(())
    }

    fn insert_content_objects(
        &mut self,
        lang: String,
        content: pyo3::Bound<'_, pyo3::types::PyDict>,
    ) -> Result<(), PyErr> {
        let _py = content.py();
        let mut hashmap: std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>> = std::collections::HashMap::new();
        
        for (key, value) in content.iter() {
            let k: String = key.extract().map_err(|e| {
                PyErr::new::<PyO3ValueError, _>(format!("Failed to extract key: {}", e))
            })?;
            
            if value.is_none() {
                continue;
            }
            
            let v: pyo3::Bound<'_, pyo3::types::PyDict> = value.extract().map_err(|e| {
                PyErr::new::<PyO3ValueError, _>(format!("Failed to extract nested dict: {}", e))
            })?;
            
            let mut inner_hashmap = std::collections::HashMap::new();
            for (inner_key, inner_value) in v.iter() {
                let ik: String = inner_key.extract().map_err(|e| {
                    PyErr::new::<PyO3ValueError, _>(format!("Failed to extract inner key: {}", e))
                })?;
                
                if inner_value.is_none() {
                    inner_hashmap.insert(ik, serde_json::Value::String(String::new()));
                    continue;
                }
                
                if let Ok(s) = inner_value.extract::<String>() {
                    inner_hashmap.insert(ik, serde_json::Value::String(s));
                } else if let Ok(arr) = inner_value.extract::<Vec<String>>() {
                    inner_hashmap.insert(ik, serde_json::Value::Array(arr.into_iter().map(serde_json::Value::String).collect()));
                } else {
                    inner_hashmap.insert(ik, serde_json::Value::String(String::new()));
                }
            }
            hashmap.insert(k, inner_hashmap);
        }
        
        self.0 = self.0.clone()
            .insert_content_objects(&lang, hashmap)
            .map_err(|e: StixError| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(())
    }

    #[getter]
    fn object_ref(&self) -> String {
        self.0.clone().build()
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
                .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?,
            objects: Vec::new(),
        };
        if let Some(kwargs) = kwargs {
            if let Some(objects_val) = kwargs.get_item("objects")? {
                let obj_jsons: Vec<String> = objects_val.extract()?;
                for obj_json in obj_jsons {
                    bundle.push_json(&obj_json)
                        .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
                }
            }
        }
        if bundle.objects.is_empty() {
            return Err(PyErr::new::<PyO3ValueError, _>(
                "Bundle must contain at least one object"
            ));
        }
        Ok(Bundle(bundle))
    }

    fn add(&mut self, stix_json: String) -> Result<(), PyErr> {
        self.0.push_json(&stix_json)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(())
    }

    #[staticmethod]
    fn from_json(json_str: String) -> Result<Self, PyErr> {
        let bundle = StixBundle::from_json(&json_str)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        Ok(Bundle(bundle))
    }

    fn to_json(&self) -> Result<String, PyErr> {
        self.0.stix_check()
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))?;
        serde_json::to_string(&self.0)
            .map_err(|e| PyErr::new::<PyO3ValueError, _>(e.to_string()))
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
}

#[pymodule(name = "stixflayer")]
pub fn stixflayer_bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
