use crate::base::CustomPropertiesHolder;
use crate::error::StixError as RustStixError;
use crate::python_bindings::error::StixError;
use pyo3::exceptions::PyAttributeError as PyO3AttributeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// Recursively convert a [`serde_json::Value`] into a Python object.
///
/// This is used so that structured Rust error details can be surfaced to Python
/// consumers without pulling in an extra serialization dependency.
pub fn json_value_to_py(py: Python<'_>, value: &serde_json::Value) -> PyObject {
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
/// Reclassifies a top-level serde type error from a kwargs constructor into a
/// structured `InvalidPropertyType` validation error.
///
/// Because the SDO/SCO/SRO structs flatten their fields at the root, serde
/// reports the path as `.`, losing the offending property name. We recover it
/// by scanning the synthesized kwargs JSON for a value matching the `got` JSON
/// kind in the error message.
pub fn classify_top_level_type_error(
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
pub fn py_to_json(obj: &Bound<'_, PyAny>) -> Result<serde_json::Value, PyErr> {
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
pub fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
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
pub fn dynamic_getattr(
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
/// Build the Python `dict` for `obj.custom_properties` from a typed STIX object.
pub fn custom_properties_dict<'py, T: CustomPropertiesHolder>(
    py: Python<'py>,
    obj: &T,
) -> Result<Bound<'py, PyDict>, PyErr> {
    let dict = PyDict::new_bound(py);
    if let Some(props) = obj.custom_properties().as_ref() {
        for (k, v) in props.iter() {
            dict.set_item(k, json_value_to_py(py, v))?;
        }
    }
    Ok(dict)
}
