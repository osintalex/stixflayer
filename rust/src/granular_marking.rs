//! Granular markings for STIX objects.
use crate::{error::StixError as Error, identifier::Identifier};
use language_tags::LanguageTag;
use serde::{Deserialize, Serialize};

///The `granular-marking` type defines how the `marking-definition` object referenced by the `marking_ref` property or a language specified by the `lang` property applies to a set of
/// content identified by the list of selectors in the selectors property.
///
/// One *and only one* of the `marking_ref` and `lang` properties **MUST** be present.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_robezi5egfdr>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranularMarking {
    /// The lang property identifies the language of the text identified by this marking.
    ///
    /// The value of the lang property, if present, **MUST be an RFC5646 language code.
    pub lang: Option<String>,
    /// The marking_ref property specifies the ID of the marking-definition object that describes the marking.
    pub marking_ref: Option<Identifier>,
    /// The selectors property specifies a list of selectors for content contained within the STIX Object in which this property appears
    pub selectors: Vec<String>,
}

impl crate::base::Stix for GranularMarking {
    fn stix_check(&self) -> Result<(), Error> {
        if self.marking_ref.is_some() && self.lang.is_some() {
            return Err(Error::ValidationError("marking_ref and lang".to_string()));
        }

        if let Some(marking_ref) = &self.marking_ref {
            if marking_ref.get_type() != "marking-definition" {
                return Err(Error::ValidationError(
                    "referenced id must be a marking definition".to_string(),
                ));
            }
        } else if let Some(ref language) = self.lang {
            match LanguageTag::parse(language) {
                Ok(tag) => if let Err(e) = LanguageTag::validate(&tag) {
                    return Err(Error::ValidationError(format!("A language granular marking has a `lang` of {}. A `lang` must conform to RFC5646. Details: {}",
                    language,
                    e
                )));
                }
                Err(e) => return Err(Error::ValidationError(format!("A language granular marking has a `lang` of {}. A `lang` must conform to RFC5646. Details: {}",
                    language,
                    e
                ))),
            }
        } else {
            return Err(Error::ValidationError(
                "A granular marking must have one and only one of a `marking _ref` or a `lang`"
                    .to_string(),
            ));
        }

        //TODO: Add validation for selectors

        Ok(())
    }
}
