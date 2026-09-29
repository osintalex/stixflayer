//! A collection of STIX-wide properties and features that could be used by any STIX object or type.
use crate::{
    common::{time::check_timestamp_ordering, validation::validate_vocab_value},
    custom_property::{validate_custom_property_name, validate_custom_property_suffix_value},
    error::{add_error, return_multiple_errors, StixError as Error},
    extensions::{
        check_extension, FileExtensions, NetworkTrafficExtensions, ProcessExtensions,
        UserAccountExtensions,
    },
    types::{
        check_observable_dictionary_key, stix_case, DictionaryValue, ExtensionType,
        ExternalReference, GranularMarking, Identifier, StixDictionary, Timestamp,
    },
};
use language_tags::LanguageTag;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use std::collections::BTreeMap;
use std::str::FromStr;
use stix_derive::StixProperties;
use strum::IntoEnumIterator;

/// A trait for all STIX 2.1 compliant objects and properties.
pub trait Stix {
    /// Method that ensures that all fields in the object or property conform to the STIX 2.1 standard.
    fn stix_check(&self) -> Result<(), Error>;
}

/// Properties that are common across multiple STIX Objects.
///
/// This struct is intended to be nested and flattened inside of a specific STIX Object,
/// with the validator ensuring that properties that cannot exist for that object are not included.
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Default, Deserialize, StixProperties)]
pub struct CommonProperties {
    /// The version of the STIX specification used to represent this object (**MUST** be 2.1 in STIX 2.1).
    ///
    /// Required property for SDOs, SROs, and Meta Objects.
    pub spec_version: Option<String>,
    /// Uniquely identifies this object.
    ///
    /// For objects that support versioning, all objects with the same `id` are considered different versions of the same object and the version of the object is identified by
    /// its `modified` property.
    pub id: Identifier,
    /// Specifies the identity that describes the entity that created this object.
    ///
    /// Can be omitted for objects with anonymous creators, except for Extenion Objects, for which it is a required property.
    pub created_by_ref: Option<Identifier>,
    /// Represents the time at which the object was originally created.
    /// The object creator can use the time it deems most appropriate as the time the object was created.
    ///
    /// The minimum precision **MUST** be milliseconds but **MAY** be more precise.
    /// This **MUST** remain constant even if a new version of the same object is created.
    ///
    /// Required property for SDOs, SROs, and Meta Objects.
    pub created: Option<Timestamp>,
    /// Represents the time that this particular version of the object was last modified.
    /// The object creator can use the time it deems most appropriate as the time this version of the object was modified.
    ///
    /// The minimum precision **MUST** be milliseconds but **MAY** be more precise.
    /// This **MUST** be later than or equal to `created`. This is set each time a new version of an object is created.
    ///
    /// Required property for SDOs, SROs, Extension Objects, and Language Marking Objects.
    pub modified: Option<Timestamp>,
    /// Indicates whether the object has been revoked.
    ///
    /// Revoked objects are no longer considered valid by the object creator. Revoking an object is permanent; future versions of the object with this `id` **MUST NOT** be created.
    pub revoked: Option<bool>,
    /// Specifies an optional set of terms used to describe this object.
    /// The terms are user-defined or trust-group defined and their meaning is outside the scope of this specification.
    pub labels: Option<Vec<String>>,
    /// Identifies the confidence that the creator has in the correctness of their data.
    ///
    /// **MUST** be a number in the range of 0-100.
    /// Omitted if the confidence is unspecified.
    pub confidence: Option<u8>,
    /// Identifies the language of the text content in this object.
    ///
    /// **MUST** be a language code conformant to [RFC5646](https://www.rfc-editor.org/info/rfc5646).
    /// If omitted, then the language of the content is `en` (English).
    pub lang: Option<String>,
    /// Specifies a list of external references which refers to non-STIX information.
    /// Provides descriptions, URLs, or IDs to other system's records.
    pub external_references: Option<Vec<ExternalReference>>,
    /// Specifies a list of identities of marking-definition objects that apply to this object.
    pub object_marking_refs: Option<Vec<Identifier>>,
    pub granular_markings: Option<Vec<GranularMarking>>,
    /// This property defines whether or not the data contained within the object has been defanged.
    ///
    /// `None` is the same as `Some(false)`
    /// This property **MUST NOT** be used for any STIX Objects other than SCOs.
    pub defanged: Option<bool>,
    /// Specifies any extensions of the object, as a dictionary.
    ///
    /// Dictionary keys SHOULD be the id of a STIX Extension object or the name of a predefined object extension found in this specification,
    /// depending on the type of extension being used.
    ///
    /// The corresponding dictionary values **MUST** contain the contents of the extension instance.
    pub extensions: Option<StixDictionary<StixDictionary<DictionaryValue>>>,
    /// Custom properties that are not part of the STIX 2.1 specification.
    ///
    /// This bag is populated after deserialization by stripping unknown top-level keys from the
    /// incoming JSON. It is flattened back out on serialization so custom keys remain as siblings
    /// of the standard properties in the JSON output.
    ///
    /// `skip_deserializing` is required: a flattened map would otherwise absorb every unknown key and
    /// duplicate the fields that serde has already assigned to object_type/common_properties. Unknown
    /// keys are instead captured explicitly in [`crate::validation::validate_value`].
    #[serde(default, skip_deserializing, flatten)]
    pub custom_properties: Option<BTreeMap<String, Value>>,
}

impl Stix for CommonProperties {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(spec_version) = &self.spec_version {
            if spec_version != "2.1" {
                errors.push(Error::ValidationError(format!(
                    "The spec version of Object {} is {}. It must be 2.1.",
                    self.id, spec_version
                )));
            }
        }
        if let Some(creator) = &self.created_by_ref {
            add_error(&mut errors, creator.stix_check());
            if creator.get_type() != "identity" {
                errors.push(Error::ValidationError(format!("Object {} has a 'created by' reference to an object of type '{}'. Only an Identity SDO can be the creator of another STIX object.",
                    self.id,
                    creator.get_type()
                )));
            }
        }
        if let (Some(created), Some(modified)) = (&self.created, &self.modified) {
            add_error(
                &mut errors,
                check_timestamp_ordering(
                    created,
                    modified,
                    "created",
                    "modified",
                    &self.id.to_string(),
                ),
            );
        }
        if let Some(confidence_number) = self.confidence {
            if confidence_number > 100 {
                errors.push(Error::ValidationError(format!("The confidence value of Object {} is {}. An object's confidence value cannot be greater than 100.",
                    self.id,
                    confidence_number
                )));
            }
        }
        if let Some(external_references) = &self.external_references {
            add_error(&mut errors, external_references.stix_check());
        }
        if let Some(language) = &self.lang {
            match LanguageTag::parse(language) {
                Ok(tag) => if let Err(e) = LanguageTag::validate(&tag) {
                    errors.push(Error::ValidationError(format!("Object {}'s `language` is {}. A `language` must conform to RFC5646. Details: {}",
                    self.id,
                    language,
                    e
                )));
                }
                Err(e) => errors.push(Error::ValidationError(format!("Object {}'s `language` is {}. A `language` must conform to RFC5646. Details: {}",
                    self.id,
                    language,
                    e
                ))),
            }
        }
        if let Some(granular_markings) = &self.granular_markings {
            add_error(&mut errors, granular_markings.stix_check());
        }
        if let Some(extensions) = &self.extensions {
            add_error(&mut errors, extensions.stix_check());
            for (key, value) in extensions.iter() {
                // Check constraints for general extensions, idetified by using a STIX identifer as the extension key
                if let Ok(id) = Identifier::from_str(key) {
                    if id.get_type() != "extension-definition" {
                        warn!("If `extensions` keys are STIX Object id's, they should be the id of an Extension Definition SMO. Object {} has an extension id key {}.",
                            self.id,
                            key
                        )
                    }

                    if !value.keys().any(|k| k == "extension_type") {
                        errors.push(Error::ValidationError(format!("If an `extensions` dictionary entry is not predefined object extension, the 'extension_type' property must be present in that dictionary entry. Object {} has an extension with key {} that is missing that property",
                            self.id,
                            key,
                        )));
                    }

                    for (inner_key, inner_value) in value.iter() {
                        if let Err(e) = check_observable_dictionary_key(inner_key) {
                            errors.push(e);
                        }
                        if inner_key == "extension_type" {
                            if let DictionaryValue::String(inner_value_string) = inner_value {
                                add_error(
                                    &mut errors,
                                    validate_vocab_value::<ExtensionType, _>(
                                        inner_value_string,
                                        "extension-type-enum",
                                    ),
                                );
                            } else {
                                errors.push(Error::ValidationError(format!("The value of an 'extension_type' property in an `extensions` dictionary entry must come from the `extension-type-enum` enumeration. Object {} has an extension with key {} whose `extension_type` value is {}.",
                                        self.id,
                                        key,
                                        inner_value
                                    )));
                            }
                        }
                    }
                // Check known SCO-specific predefined extensions
                } else {
                    match self.id.get_type() {
                        "file" => {
                            if key.starts_with("extension-definition--") {
                                // Custom extension - allow
                            } else if FileExtensions::iter().any(|x| x.as_ref() == stix_case(key)) {
                                add_error(&mut errors, check_extension(key, value));
                            } else {
                                errors.push(Error::WrongExtension)
                            }
                        }
                        "network-traffic" => {
                            if key.starts_with("extension-definition--") {
                                // Custom extension - allow
                            } else if NetworkTrafficExtensions::iter()
                                .any(|x| x.as_ref() == stix_case(key))
                            {
                                add_error(&mut errors, check_extension(key, value));
                            } else {
                                errors.push(Error::WrongExtension)
                            }
                        }
                        "process" => {
                            if key.starts_with("extension-definition--") {
                                // Custom extension - allow
                            } else if ProcessExtensions::iter()
                                .any(|x| x.as_ref() == stix_case(key))
                            {
                                add_error(&mut errors, check_extension(key, value));
                            } else {
                                errors.push(Error::WrongExtension)
                            }
                        }
                        "user-account" => {
                            if key.starts_with("extension-definition--") {
                                // Custom extension - allow
                            } else if UserAccountExtensions::iter()
                                .any(|x| x.as_ref() == stix_case(key))
                            {
                                add_error(&mut errors, check_extension(key, value));
                            } else {
                                errors.push(Error::WrongExtension)
                            }
                        }
                        // For other object types, allow any extension key (warn if not extension-definition)
                        _ => {
                            if !key.starts_with("extension-definition--") {
                                warn!("`extensions` keys should be the id of an Extension Definition SMO, unless you are using a predefined object extension. Confirm that object {}'s extension key {} is a predefined object extension.",
                            self.id,
                            key
                        )
                            }
                        }
                    }

                    add_error(&mut errors, value.stix_check());
                }
            }
        }

        if let Some(custom_properties) = &self.custom_properties {
            if custom_properties.is_empty() {
                errors.push(Error::ValidationError(
                    "custom_properties cannot be empty".to_string(),
                ));
            }
            for (key, value) in custom_properties.iter() {
                add_error(&mut errors, validate_custom_property_name(key));
                add_error(
                    &mut errors,
                    validate_custom_property_suffix_value(key, value),
                );
                add_error(&mut errors, value.stix_check());
            }
        }

        return_multiple_errors(errors)
    }
}

/// Trait implemented by top-level STIX object structs so that the central
/// deserialization gate ([`crate::validation::validate_value`]) can store the
/// custom-property bag separately from the serde deserialization of standard fields.
pub trait CustomPropertiesHolder {
    /// Access the object's custom property bag.
    fn custom_properties(&self) -> &Option<BTreeMap<String, Value>>;
    /// Replace the object's custom property bag.
    fn set_custom_properties(&mut self, custom_properties: Option<BTreeMap<String, Value>>);
}

/// Implement [`CustomPropertiesHolder`] for a standard STIX object struct that
/// carries common properties in a field named `common_properties`.
#[macro_export]
macro_rules! impl_custom_properties_holder {
    ($type:ty) => {
        impl $crate::base::CustomPropertiesHolder for $type {
            fn custom_properties(
                &self,
            ) -> &Option<std::collections::BTreeMap<std::string::String, serde_json::Value>> {
                &self.common_properties.custom_properties
            }
            fn set_custom_properties(
                &mut self,
                custom_properties: Option<
                    std::collections::BTreeMap<std::string::String, serde_json::Value>,
                >,
            ) {
                self.common_properties.custom_properties = custom_properties;
            }
        }
    };
}
