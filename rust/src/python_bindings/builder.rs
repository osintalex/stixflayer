use pyo3::prelude::*;
use pyo3::types::PyDict;
use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder};
use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};
use crate::meta_objects::marking_definition::MarkingDefinitionBuilder;
use crate::relationship_objects::{RelationshipObject, RelationshipObjectBuilder};
use crate::types::Identifier;
use crate::types::Timestamp;
use crate::validation::validate_value;
use crate::python_bindings::convert::{classify_top_level_type_error, py_to_json};
use crate::python_bindings::error::{StixError, stix_to_pyerr};

/// Helper function to validate that required fields are present in a DomainObjectBuilder.
/// When `strict` is false the validation step is skipped.
pub fn validate_sdo_builder(
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
pub fn validate_sco_builder(
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
pub fn validate_sro_builder(
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
pub fn validate_marking_builder(
    builder: MarkingDefinitionBuilder,
    strict: bool,
) -> Result<MarkingDefinitionBuilder, PyErr> {
    if strict {
        builder.clone().build().map_err(stix_to_pyerr)?;
    }
    Ok(builder)
}

/// Build a JSON envelope for an SDO.
pub fn build_sdo_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
    allow_custom: bool,
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
    let domain_obj: DomainObject = validate_value(value, allow_custom, strict)
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(stix_to_pyerr)?;
    let builder = DomainObjectBuilder::from_parsed(&domain_obj).map_err(stix_to_pyerr)?;
    validate_sdo_builder(builder, strict)
}

/// Build a JSON envelope for an SCO.
pub fn build_sco_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
    allow_custom: bool,
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
    let cyber_obj: CyberObject = validate_value(value, allow_custom, strict)
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(stix_to_pyerr)?;
    let builder = CyberObjectBuilder::from(&cyber_obj).map_err(stix_to_pyerr)?;
    validate_sco_builder(builder, strict)
}

/// Build a JSON envelope for an SRO.
pub fn build_sro_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
    allow_custom: bool,
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
    let sro_obj: RelationshipObject = validate_value(value, allow_custom, strict)
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(stix_to_pyerr)?;
    let builder = RelationshipObjectBuilder::from_parsed(&sro_obj).map_err(stix_to_pyerr)?;
    validate_sro_builder(builder, strict)
}
