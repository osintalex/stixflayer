//! Builder for common STIX object properties.
use crate::{
    error::StixError as Error,
    stix::CommonProperties,
    types::{
        DictionaryValue, ExternalReference, GranularMarking, Identifier, StixDictionary,
        Timestamp, stix_case,
    },
};
use serde::Serialize;
use std::str::FromStr;
use strum::EnumString;

/// Builder struct for common STIX properties.
///
/// This follows the "Rust builder pattern," where we  use a `new()` function to construct a Builder
/// with a minimum set of required fields, then set additional fields with their own setter functions.
/// Once all fields have been set, the `build()` function will take all of the fields in the Builder
/// struct and use them to create the final `CommonProperties` struct.
///
/// This struct is intended to be nested inside of a STIX Object's `Builder` struct to help with building
/// that object by constructing the common properties.
///
/// Because different STIX Objects have different common properties, they should check that they have all
/// required properties and do not have any omitted properties as part of their own `stix_check()` function
/// during the build stage.
#[derive(Clone, Debug, Serialize)]
pub struct CommonPropertiesBuilder {
    /// The kind of Stix Object for which we are building the common properties
    stix_object: StixObjectCategory,
    /// Whether we are creating a new object or versioning an existing one.
    pub builder_type: BuilderType,
    /// The common properties that will be added to the object being built
    pub properties: CommonProperties,
}

impl CommonPropertiesBuilder {
    /// Construct a `CommonPropertiesBuilder` with default values for the properties
    /// Used when building a new STIX Object.
    pub fn new(object_name: &str, type_name: &str) -> Result<CommonPropertiesBuilder, Error> {
        let stix_object =
            StixObjectCategory::from_str(&stix_case(object_name)).map_err(Error::UnrecognizedObject)?;
        let properties = CommonProperties {
            spec_version: Some("2.1".to_string()),
            id: Identifier::new(&stix_case(type_name))?,
            created_by_ref: Default::default(),
            created: Default::default(),
            modified: Default::default(),
            revoked: Default::default(),
            labels: Default::default(),
            confidence: Default::default(),
            // Under STIX 2.1, a missing `lang` field is treated as "en"
            lang: Default::default(),
            external_references: Default::default(),
            object_marking_refs: Default::default(),
            granular_markings: Default::default(),
            defanged: Default::default(),
            extensions: Default::default(),
            custom_properties: Default::default(),
        };

        Ok(CommonPropertiesBuilder {
            stix_object,
            builder_type: BuilderType::Creation,
            properties,
        })
    }

    /// Construct a `CommonPropertiesBuilder` by cloning an existing set of properites
    /// Used when versioning an existing STIX Object.
    pub fn version(
        object_name: &str,
        old: &CommonProperties,
    ) -> Result<CommonPropertiesBuilder, Error> {
        let stix_object =
            StixObjectCategory::from_str(&stix_case(object_name)).map_err(Error::UnrecognizedObject)?;
        let properties = CommonProperties {
            spec_version: old.spec_version.clone(),
            id: old.id.clone(),
            created_by_ref: old.created_by_ref.clone(),
            created: old.created.clone(),
            modified: old.modified.clone(),
            revoked: Default::default(),
            labels: old.labels.clone(),
            confidence: old.confidence,
            lang: old.lang.clone(),
            external_references: old.external_references.clone(),
            object_marking_refs: old.object_marking_refs.clone(),
            granular_markings: old.granular_markings.clone(),
            defanged: old.defanged,
            extensions: old.extensions.clone(),
            custom_properties: old.custom_properties.clone(),
        };

        Ok(CommonPropertiesBuilder {
            stix_object,
            builder_type: BuilderType::Version,
            properties,
        })
    }

    /// Construct a `CommonPropertiesBuilder` by cloning an existing set of properties verbatim,
    /// including `created` and `modified`. Used when reconstructing an already-parsed STIX
    /// Object (as opposed to `version()`, which treats the object as the basis for a new version).
    pub fn from_existing(
        object_name: &str,
        old: &CommonProperties,
    ) -> Result<CommonPropertiesBuilder, Error> {
        let stix_object =
            StixObjectCategory::from_str(&stix_case(object_name)).map_err(Error::UnrecognizedObject)?;
        Ok(CommonPropertiesBuilder {
            stix_object,
            builder_type: BuilderType::FromExisting,
            properties: old.clone(),
        })
    }

    // Setter functions for common properties

    /// Set the `created_by_ref` field for an object under construction
    /// This is only allowed when creating a new object or reconstructing a parsed one,
    /// not when versioning an existing one,
    /// as only the original creator of an object can version it.
    pub fn created_by_ref(mut self, id: Identifier) -> Result<Self, Error> {
        match self.builder_type {
            BuilderType::Creation | BuilderType::FromExisting => {
                self.properties.created_by_ref = Some(id);
                Ok(self)
            }
            BuilderType::Version => Err(Error::UnableToVersion(
                "You are not allowed to change the creator when versioning an existing object"
                    .to_string(),
            )),
        }
    }

    /// Set the optional `labels` field for an object under construction.
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.properties.labels = Some(labels);
        self
    }

    /// Set the optional `confidence` field for an object under construction.
    pub fn confidence(mut self, confidence: u8) -> Self {
        self.properties.confidence = Some(confidence);
        self
    }

    /// Set the optional `lang` field for an object under construction.
    /// If the language is English ("en"), this does not need to be set (but it can be if specificity is desired).
    pub fn lang(mut self, language: String) -> Self {
        self.properties.lang = Some(language);
        self
    }

    /// Set the optional `external_references` field for an object under construction.
    pub fn external_references(mut self, references: Vec<ExternalReference>) -> Self {
        self.properties.external_references = Some(references);
        self
    }

    /// Set the optional `object_marking_refs` field for an object under construction.
    pub fn object_marking_refs(mut self, references: Vec<Identifier>) -> Self {
        self.properties.object_marking_refs = Some(references);
        self
    }

    /// Set the optional `defanged` field to `Some(true)` for an object under construction.
    pub fn defanged(mut self) -> Self {
        self.properties.defanged = Some(true);
        self
    }

    /// Set the optional `granular_markings` field for an object under construction.
    pub fn granular_markings(mut self, markings: Vec<GranularMarking>) -> Self {
        self.properties.granular_markings = Some(markings);
        self
    }

    /// Set the `created` timestamp for an object under construction.
    ///
    /// When creating a new object this overrides the default "now" timestamp.
    pub fn created(mut self, created: Timestamp) -> Self {
        self.properties.created = Some(created);
        self
    }

    /// Set the `modified` timestamp for an object under construction.
    ///
    /// When creating a new object this overrides the default "now" timestamp.
    pub fn modified(mut self, modified: Timestamp) -> Self {
        self.properties.modified = Some(modified);
        self
    }

    /// Set the custom property bag for an object under construction.
    ///
    /// This is used by the Python constructors for objects whose fields are
    /// mapped manually (e.g. `MarkingDefinition`) rather than synthesized from a
    /// JSON envelope.
    pub fn custom_properties(mut self, custom_properties: std::collections::BTreeMap<String, serde_json::Value>) -> Self {
        self.properties.custom_properties = Some(custom_properties);
        self
    }

    /// Add an optional extension to the `extensions` field for an object under construction, creating the field if it does not already exist.
    pub fn add_extension(
        mut self,
        key: &str,
        extension: StixDictionary<DictionaryValue>,
    ) -> Result<Self, Error> {
        if let Some(ref mut extensions) = self.properties.extensions {
            extensions.insert(key, extension)?
        } else {
            let mut extensions = StixDictionary::new();
            extensions.insert(key, extension)?;
            self.properties.extensions = Some(extensions);
        }

        Ok(self)
    }

    pub fn build(&self) -> CommonProperties {
        let properties = self.properties.clone();

        // If the object is not an SCO, set the `created` datetime, and if it is also not a Data Markings, set the `modified` datetime.
        let (created, modified) = match self.stix_object {
            StixObjectCategory::Sco => (None, None),
            StixObjectCategory::MarkingDefinition => {
                // If we are reconstructing a parsed object, keep its timestamps as-is
                if self.builder_type == BuilderType::FromExisting {
                    (properties.created, None)
                } else {
                    // If we are creating a new object, `created` defaults to the time of creation
                    // but may be overridden by the caller. When versioning, `created` is preserved
                    // and `modified` is left None (marking definitions cannot be versioned).
                    let created = match self.builder_type {
                        BuilderType::Creation => {
                            Some(properties.created.unwrap_or_else(Timestamp::now))
                        }
                        BuilderType::Version => properties.created,
                        BuilderType::FromExisting => unreachable!(),
                    };
                    (created, None)
                }
            }
            _ => {
                // If we are reconstructing a parsed object, keep its timestamps as-is
                if self.builder_type == BuilderType::FromExisting {
                    (properties.created, properties.modified)
                } else {
                    // When creating a new object, the caller may override the default
                    // "now" timestamps. When versioning, `created` is preserved and
                    // `modified` is set to the current time.
                    let now = Timestamp::now();
                    let created = match self.builder_type {
                        BuilderType::Creation => properties.created.unwrap_or_else(|| now.clone()),
                        BuilderType::Version => properties
                            .created
                            .expect("versioned object must retain its original created time"),
                        BuilderType::FromExisting => unreachable!(),
                    };
                    let modified = match self.builder_type {
                        BuilderType::Creation => properties.modified.unwrap_or_else(|| now.clone()),
                        BuilderType::Version => now,
                        BuilderType::FromExisting => unreachable!(),
                    };
                    (Some(created), Some(modified))
                }
            }
        };

        CommonProperties {
            spec_version: properties.spec_version,
            id: properties.id,
            created_by_ref: properties.created_by_ref,
            created,
            granular_markings: properties.granular_markings,
            modified,
            // Since we are making a new object or new version of an object, we cannot create it already revoked.
            // When reconstructing a parsed object, its revoked state is preserved as-is.
            revoked: if self.builder_type == BuilderType::FromExisting {
                properties.revoked
            } else {
                None
            },
            labels: properties.labels,
            confidence: properties.confidence,
            lang: properties.lang,
            external_references: properties.external_references,
            defanged: properties.defanged,
            object_marking_refs: properties.object_marking_refs,
            extensions: properties.extensions,
            custom_properties: properties.custom_properties,
        }
    }
}

/// Category of STIX object that a builder is constructing.
#[derive(Clone, Debug, PartialEq, Eq, EnumString, Serialize)]
#[strum(serialize_all = "kebab-case")]
pub enum StixObjectCategory {
    Sdo,
    Sro,
    Sco,
    ExtensionDefinition,
    LanguageContent,
    MarkingDefinition,
    Custom,
}

/// Whether the object under construction is a new object, a version of an existing one,
/// or a faithful reconstruction of an already-parsed one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum BuilderType {
    Creation,
    Version,
    FromExisting,
}
