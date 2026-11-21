//! PyO3 bindings exposing the engine to Python.
//!
//! This module is `#[doc(hidden)]`: it is implementation plumbing for the
//! Python package, not part of the Rust API. The Python-facing surface is the
//! generated `stixflayer` package plus its type stubs; Rust users should rely
//! on the engine modules instead.

use crate::custom_objects::CustomObjectBuilder;
use crate::cyber_observable_objects::sco::{CyberObjectBuilder, CyberObjectType};
use crate::domain_objects::sdo::{DomainObjectBuilder, DomainObjectType};
use crate::error::Entry;
use crate::meta_objects::extension_definition::ExtensionDefinitionBuilder;
use crate::meta_objects::language_content::LanguageContentBuilder;
use crate::meta_objects::marking_definition::MarkingDefinitionBuilder;
use crate::relationship_objects::{RelationshipObjectBuilder, RelationshipObjectType};
use pyo3::prelude::*;

/// Builder glue shared by the Python wrapper classes.
pub mod builder;
/// Conversions between Python objects and JSON values.
pub mod convert;
/// Python exception types mirroring [`crate::error::StixError`].
pub mod error;
/// Python-facing free functions (`version`, `validate_pattern`).
pub mod functions;
/// Wrappers for meta objects, custom objects, and bundles.
pub mod meta;
/// Wrappers for STIX cyber-observable objects.
pub mod sco;
/// Wrappers for STIX domain objects.
pub mod sdo;
/// Wrappers for STIX relationship objects.
pub mod sro;
/// Wrappers for STIX open-vocabulary enums.
pub mod vocab;

pub use builder::{
    build_sco_envelope, build_sdo_envelope, build_sro_envelope, parse_sco_builder,
    parse_sdo_builder, parse_sro_builder,
};
pub use convert::{
    classify_top_level_type_error, custom_properties_dict, dynamic_getattr, json_to_py,
    json_value_to_py, py_to_json,
};
pub use error::{stix_to_pyerr, DeserializationError, StixError, ValidationError};
pub use functions::{check, parse_extension_type, validate_pattern, version, PyOutcome};
pub use meta::{Bundle, CustomObject, ExtensionDefinition, LanguageContent, MarkingDefinition};
pub use sco::{
    Artifact, AutonomousSystem, Directory, DomainName, EmailAddress, EmailMessage, File,
    IPv4Address, IPv6Address, MacAddr, Mutex, NetworkTraffic, Process, Software, UserAccount,
    WindowsRegistryKey, X509Certificate, URL,
};
pub use sdo::{
    AttackPattern, Campaign, CourseOfAction, Grouping, Identity, Incident, Indicator,
    Infrastructure, IntrusionSet, Location, Malware, MalwareAnalysis, Note, ObservedData, Opinion,
    Report, ThreatActor, Tool, Vulnerability,
};
pub use sro::{Relationship, Sighting};
pub use vocab::{
    AttackMotivation, AttackResourceLevel, IdentitySectors, IndicatorType, MalwareType, ReportType,
    ThreatActorSophistication, ThreatActorType,
};

/// Convert a typed [`StixObject`](crate::object::StixObject) into its corresponding Python wrapper class.
pub fn wrap_stix_object(
    py: Python<'_>,
    obj: crate::object::StixObject,
    warnings: Vec<Entry>,
) -> Result<PyObject, PyErr> {
    match obj {
        crate::object::StixObject::Sdo(domain_obj) => {
            let builder = DomainObjectBuilder::from_parsed(&domain_obj).map_err(stix_to_pyerr)?;
            Ok(match domain_obj.object_type {
                DomainObjectType::AttackPattern(_) => {
                    Py::new(py, AttackPattern(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Campaign(_) => {
                    Py::new(py, Campaign(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::CourseOfAction(_) => {
                    Py::new(py, CourseOfAction(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Grouping(_) => {
                    Py::new(py, Grouping(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Identity(_) => {
                    Py::new(py, Identity(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Incident(_) => {
                    Py::new(py, Incident(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Indicator(_) => {
                    Py::new(py, Indicator(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Infrastructure(_) => {
                    Py::new(py, Infrastructure(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::IntrusionSet(_) => {
                    Py::new(py, IntrusionSet(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Location(_) => {
                    Py::new(py, Location(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Malware(_) => {
                    Py::new(py, Malware(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::MalwareAnalysis(_) => {
                    Py::new(py, MalwareAnalysis(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Note(_) => {
                    Py::new(py, Note(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::ObservedData(_) => {
                    Py::new(py, ObservedData(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Opinion(_) => {
                    Py::new(py, Opinion(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Report(_) => {
                    Py::new(py, Report(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::ThreatActor(_) => {
                    Py::new(py, ThreatActor(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Tool(_) => {
                    Py::new(py, Tool(builder, warnings.clone()))?.into_py(py)
                }
                DomainObjectType::Vulnerability(_) => {
                    Py::new(py, Vulnerability(builder, warnings.clone()))?.into_py(py)
                }
            })
        }
        crate::object::StixObject::Sro(rel_obj) => {
            let builder =
                RelationshipObjectBuilder::from_parsed(&rel_obj).map_err(stix_to_pyerr)?;
            Ok(match rel_obj.object_type {
                RelationshipObjectType::Relationship(_) => {
                    Py::new(py, Relationship(builder, warnings.clone()))?.into_py(py)
                }
                RelationshipObjectType::Sighting(_) => {
                    Py::new(py, Sighting(builder, warnings.clone()))?.into_py(py)
                }
            })
        }
        crate::object::StixObject::Sco(cyber_obj) => {
            let builder = CyberObjectBuilder::from_parsed(&cyber_obj).map_err(stix_to_pyerr)?;
            Ok(match cyber_obj.object_type {
                CyberObjectType::Artifact(_) => {
                    Py::new(py, Artifact(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::AutonomousSystem(_) => {
                    Py::new(py, AutonomousSystem(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Directory(_) => {
                    Py::new(py, Directory(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::DomainName(_) => {
                    Py::new(py, DomainName(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::EmailAddress(_) => {
                    Py::new(py, EmailAddress(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::EmailMessage(_) => {
                    Py::new(py, EmailMessage(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::File(_) => {
                    Py::new(py, File(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Ipv4Addr(_) => {
                    Py::new(py, IPv4Address(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Ipv6Addr(_) => {
                    Py::new(py, IPv6Address(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::MacAddr(_) => {
                    Py::new(py, MacAddr(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Mutex(_) => {
                    Py::new(py, Mutex(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::NetworkTraffic(_) => {
                    Py::new(py, NetworkTraffic(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Process(_) => {
                    Py::new(py, Process(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Software(_) => {
                    Py::new(py, Software(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::Url(_) => Py::new(py, URL(builder, warnings.clone()))?.into_py(py),
                CyberObjectType::UserAccount(_) => {
                    Py::new(py, UserAccount(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::WindowsRegistryKey(_) => {
                    Py::new(py, WindowsRegistryKey(builder, warnings.clone()))?.into_py(py)
                }
                CyberObjectType::WindowsRegistryKeyType(_) => {
                    // Not a top-level SCO; fall back to a JSON dict.
                    let value = serde_json::to_value(&cyber_obj)
                        .map_err(|e| PyErr::new::<StixError, _>(e.to_string()))?;
                    json_to_py(py, &value)?
                }
                CyberObjectType::X509Certificate(_) => {
                    Py::new(py, X509Certificate(builder, warnings.clone()))?.into_py(py)
                }
            })
        }
        crate::object::StixObject::LanguageContent(lc) => {
            let builder = LanguageContentBuilder::from_parsed(&lc).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, LanguageContent(builder, warnings.clone()))?.into_py(py))
        }
        crate::object::StixObject::ExtensionDefinition(ed) => {
            let builder = ExtensionDefinitionBuilder::from_parsed(&ed).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, ExtensionDefinition(builder, warnings.clone()))?.into_py(py))
        }
        crate::object::StixObject::MarkingDefinition(md) => {
            let builder = MarkingDefinitionBuilder::from_parsed(&md).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, MarkingDefinition(builder, warnings.clone()))?.into_py(py))
        }
        crate::object::StixObject::Custom(custom) => {
            let builder = CustomObjectBuilder::from_parsed(&custom).map_err(stix_to_pyerr)?;
            Ok(Py::new(py, CustomObject(builder, warnings.clone()))?.into_py(py))
        }
    }
}

/// Define the `stixflayer` Python module: functions, wrapper classes, and exceptions.
#[pymodule(name = "stixflayer")]
pub fn stixflayer_bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(validate_pattern, m)?)?;
    m.add_function(wrap_pyfunction!(check, m)?)?;

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
    m.add_class::<PyOutcome>()?;

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
