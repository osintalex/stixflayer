use crate::custom_objects::{CustomObject, CustomObjectBuilder};
use crate::cyber_observable_objects::sco::{CyberObject, CyberObjectBuilder};
use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};
use crate::error::Entry;
use crate::meta_objects::extension_definition::{ExtensionDefinition, ExtensionDefinitionBuilder};
use crate::meta_objects::language_content::{LanguageContent, LanguageContentBuilder};
use crate::meta_objects::marking_definition::{MarkingDefinition, MarkingDefinitionBuilder};
use crate::python_bindings::convert::{classify_top_level_type_error, py_to_json};
use crate::python_bindings::error::{stix_to_pyerr, stix_to_pyerr_with, StixError};
use crate::relationship_objects::{RelationshipObject, RelationshipObjectBuilder};
use crate::types::Identifier;
use crate::types::Timestamp;
use crate::validation::validate_value_from_object_parts;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

pub(crate) fn parse_value(json_str: &str, version: &str) -> Result<Value, PyErr> {
    if version != "2.1" {
        return Err(stix_to_pyerr(crate::error::StixError::ValidationError(
            format!(
                "Unsupported STIX version '{}'. Only 2.1 is supported.",
                version
            ),
        )));
    }
    serde_json::from_str(json_str)
        .map_err(|e| stix_to_pyerr(crate::error::StixError::DeserializationError(e.to_string())))
}

/// Builds a JSON envelope for an SDO and validates it exactly once.
pub fn build_sdo_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
    allow_custom: bool,
) -> Result<(DomainObjectBuilder, Vec<Entry>), PyErr> {
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
    let value: Value = serde_json::from_str(&json_obj.to_string())
        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let (result, warnings) =
        validate_value_from_object_parts::<DomainObject>(value, allow_custom, strict);
    let domain_obj = result
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder = DomainObjectBuilder::from_parsed(&domain_obj)
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses an SDO from JSON and validates it exactly once.
pub fn parse_sdo_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(DomainObjectBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<DomainObject>(value, allow_custom, strict);
    let sdo = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder =
        DomainObjectBuilder::from_parsed(&sdo).map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Builds a JSON envelope for an SCO and validates it exactly once.
pub fn build_sco_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
    allow_custom: bool,
) -> Result<(CyberObjectBuilder, Vec<Entry>), PyErr> {
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
    let value: Value = serde_json::from_str(&json_obj.to_string())
        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let (result, warnings) =
        validate_value_from_object_parts::<CyberObject>(value, allow_custom, strict);
    let cyber_obj = result
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder =
        CyberObjectBuilder::from(&cyber_obj).map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses an SCO from JSON and validates it exactly once.
pub fn parse_sco_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(CyberObjectBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<CyberObject>(value, allow_custom, strict);
    let sco = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder =
        CyberObjectBuilder::from_parsed(&sco).map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Builds a JSON envelope for an SRO and validates it exactly once.
pub fn build_sro_envelope(
    type_name: &str,
    kwargs: Option<Bound<'_, PyDict>>,
    strict: bool,
    allow_custom: bool,
) -> Result<(RelationshipObjectBuilder, Vec<Entry>), PyErr> {
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
    let value: Value = serde_json::from_str(&json_obj.to_string())
        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
    let (result, warnings) =
        validate_value_from_object_parts::<RelationshipObject>(value, allow_custom, strict);
    let sro_obj = result
        .map_err(|e| classify_top_level_type_error(e, type_name, &json_obj))
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder = RelationshipObjectBuilder::from_parsed(&sro_obj)
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses an SRO from JSON and validates it exactly once.
pub fn parse_sro_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(RelationshipObjectBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<RelationshipObject>(value, allow_custom, strict);
    let sro = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder = RelationshipObjectBuilder::from_parsed(&sro)
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses a MarkingDefinition from JSON and validates it exactly once.
pub fn parse_marking_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(MarkingDefinitionBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<MarkingDefinition>(value, allow_custom, strict);
    let object = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder = MarkingDefinitionBuilder::from_parsed(&object)
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses an ExtensionDefinition from JSON and validates it exactly once.
pub fn parse_extension_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(ExtensionDefinitionBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<ExtensionDefinition>(value, allow_custom, strict);
    let object = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder = ExtensionDefinitionBuilder::from_parsed(&object)
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses a LanguageContent from JSON and validates it exactly once.
pub fn parse_language_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(LanguageContentBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<LanguageContent>(value, allow_custom, strict);
    let object = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder = LanguageContentBuilder::from_parsed(&object)
        .map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}

/// Parses a CustomObject from JSON and validates it exactly once.
pub fn parse_custom_builder(
    json_str: &str,
    strict: bool,
    version: &str,
    allow_custom: bool,
) -> Result<(CustomObjectBuilder, Vec<Entry>), PyErr> {
    let value = parse_value(json_str, version)?;
    let (result, warnings) =
        validate_value_from_object_parts::<CustomObject>(value, allow_custom, strict);
    let object = result.map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    let builder =
        CustomObjectBuilder::from_parsed(&object).map_err(|e| stix_to_pyerr_with(e, &warnings))?;
    Ok((builder, warnings))
}
