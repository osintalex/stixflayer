use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::BTreeMap;
use std::str::FromStr;
use jiff::Timestamp as JiffTimestamp;
use crate::bundles::Bundle as StixBundle;
use crate::custom_objects::CustomObjectBuilder;
use crate::error::StixError as RustStixError;
use crate::meta_objects::extension_definition::{
    ExtensionDefinition as StixExtensionDefinition, ExtensionDefinitionBuilder,
};
use crate::meta_objects::language_content::LanguageContent as StixLanguageContent;
use crate::meta_objects::language_content::LanguageContentBuilder;
use crate::meta_objects::marking_definition::MarkingDefinitionBuilder;
use crate::types::{DictionaryValue, ExtensionType, Identifier, Timestamp};
use crate::validation::validate_value;
use crate::python_bindings::builder::validate_marking_builder;
use crate::python_bindings::convert::{
    custom_properties_dict, dynamic_getattr, json_to_py, py_to_json,
};
use crate::python_bindings::error::{StixError, ValidationError, stix_to_pyerr};
use crate::python_bindings::functions::parse_extension_type;
use crate::python_bindings::wrap_stix_object;

#[pyclass]
pub struct MarkingDefinition(pub MarkingDefinitionBuilder);

#[pymethods]
impl MarkingDefinition {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
        let mut builder = MarkingDefinitionBuilder::new().map_err(stix_to_pyerr)?;
        let mut custom_properties: BTreeMap<String, serde_json::Value> = BTreeMap::new();

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
                        if allow_custom {
                            let val = py_to_json(&v)?;
                            custom_properties.insert(key, val);
                        } else {
                            return Err(PyErr::new::<StixError, _>(format!(
                                "Unknown argument for MarkingDefinition: '{}'",
                                key
                            )));
                        }
                    }
                }
            }
        }

        if !custom_properties.is_empty() {
            builder = builder.custom_properties(custom_properties);
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
        if name == "custom_properties" {
            return custom_properties_dict(py, &obj).map(|d| d.into_py(py));
        }
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct CustomObject(pub CustomObjectBuilder);

#[pymethods]
impl CustomObject {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = true, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
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
                        if allow_custom {
                            // Any other keyword becomes a custom property, matching the SDO/SCO/SRO
                            // envelope behaviour for arbitrary fields.
                            let val = py_to_json(&v)?;
                            custom_properties.insert(key, val);
                        } else {
                            return Err(PyErr::new::<StixError, _>(format!(
                                "Unknown argument for CustomObject: '{}'",
                                key
                            )));
                        }
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
        if name == "custom_properties" {
            return custom_properties_dict(py, &obj).map(|d| d.into_py(py));
        }
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct ExtensionDefinition(pub ExtensionDefinitionBuilder);

#[pymethods]
impl ExtensionDefinition {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
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
        let mut custom_properties: BTreeMap<String, serde_json::Value> = BTreeMap::new();

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
                        if allow_custom {
                            let val = py_to_json(&v)?;
                            custom_properties.insert(key, val);
                        } else {
                            return Err(PyErr::new::<StixError, _>(format!(
                                "Unknown argument for ExtensionDefinition: '{}'",
                                key
                            )));
                        }
                    }
                }
            }
        }

        if !custom_properties.is_empty() {
            builder = builder.custom_properties(custom_properties);
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
        if name == "custom_properties" {
            return custom_properties_dict(py, &obj).map(|d| d.into_py(py));
        }
        let value =
            serde_json::to_value(&obj).map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
        dynamic_getattr(py, std::any::type_name::<Self>(), &value, name)
    }
}

#[pyclass]
pub struct LanguageContent(pub LanguageContentBuilder);

#[pymethods]
impl LanguageContent {
    #[new]
    #[pyo3(signature = (strict = true, allow_custom = false, **kwargs))]
    fn new(
        strict: bool,
        allow_custom: bool,
        kwargs: Option<Bound<'_, PyDict>>,
    ) -> Result<Self, PyErr> {
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
        // Use validate_value so unknown keys respect `allow_custom` and are stored
        // in the custom-property bag.
        let lc: StixLanguageContent =
            validate_value(json_obj, allow_custom, strict).map_err(stix_to_pyerr)?;
        let builder = LanguageContentBuilder::from_parsed(&lc).map_err(stix_to_pyerr)?;
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
        if name == "custom_properties" {
            return custom_properties_dict(py, &obj).map(|d| d.into_py(py));
        }
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
pub struct Bundle(pub StixBundle);

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
