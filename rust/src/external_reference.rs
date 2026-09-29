//! External references and reference URLs for STIX objects.
use crate::{error::StixError as Error, hashes::Hashes};
use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// An external reference that describes pointers to information outside STIX.
///
/// A reference can be described by one or more of a human readable description, a URL, or an external id.
/// At least one of these three must be present in an external reference.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_72bcfr3t79jx>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    /// The name of the source that this external-reference is defined within (system, registry, organization, etc.).
    source_name: String,
    /// A human readable description.
    description: Option<String>,
    /// A URL reference to an external resource with its hashes, if any.
    #[serde(flatten)]
    url: Option<ReferenceUrl>,
    /// An identifier for the external reference content.
    external_id: Option<String>,
}

impl ExternalReference {
    /// Creates a new external reference with at least one describing field
    pub fn new(
        source_name: &str,
        description: Option<String>,
        url: Option<ReferenceUrl>,
        external_id: Option<String>,
    ) -> Result<Self, Error> {
        if description.is_none() && url.is_none() && external_id.is_none() {
            Err(Error::ValidationError(format!("External reference {} needs at least one of a description, a URL, or an external ID.", source_name)))
        } else {
            Ok(Self {
                source_name: source_name.to_string(),
                description,
                url,
                external_id,
            })
        }
    }
}

impl crate::base::Stix for ExternalReference {
    fn stix_check(&self) -> Result<(), Error> {
        if self.description.is_none() && self.url.is_none() && self.external_id.is_none() {
            return Err(Error::ValidationError(format!(
                "External reference '{}' must have at least one of a description, a URL, or an external ID",
                self.source_name
            )));
        }

        if let Some(url) = &self.url {
            url.stix_check()?;
        }

        let cve_re = Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap();
        let capec_re = Regex::new(r"^CAPEC-\d+$").unwrap();
        let source_lower = self.source_name.to_lowercase();

        if (source_lower == "cve" || source_lower == "capec") && self.source_name != source_lower {
            return Err(Error::ValidationError(format!(
                "source_name '{}' must be lowercase when referencing '{}'",
                self.source_name, source_lower
            )));
        }

        if self.source_name == "cve" {
            if let Some(ext_id) = &self.external_id {
                if !cve_re.is_match(ext_id) {
                    return Err(Error::ValidationError(format!(
                        "CVE external ID '{}' does not match the required format CVE-YYYY-NNNN+",
                        ext_id
                    )));
                }
            }
        } else if self.source_name == "capec" {
            if let Some(ext_id) = &self.external_id {
                if !capec_re.is_match(ext_id) {
                    return Err(Error::ValidationError(format!(
                        "CAPEC external ID '{}' does not match the required format CAPEC-NNNN+",
                        ext_id
                    )));
                }
            }
        }

        Ok(())
    }
}

/// A URL with one or more hashes for the contents of the URL.
///
/// It is possible to create a URL without any hashes, but STIX 2.1 recommends against it
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceUrl {
    /// The URL itself
    url: Url,
    /// Specifies a dictionary of hashes for the contents of the url. This should be provided when the url property is present.
    ///
    /// The keys must come from one of the entries listed in the hash-algorithm-ov open vocabulary.
    /// A SHA-256 hash SHOULD be included whenever possible.
    hashes: Option<Hashes>,
}

impl ReferenceUrl {
    /// Creates an external reference URL from a provided URL string and an optional but recommended list of hashes
    pub fn new(raw_url: &str, hashes: Option<Hashes>) -> Result<Self, Error> {
        let url =
            Url::parse(raw_url).map_err(|e| Error::ValidationError(format!("invalid URL: {e}")))?;

        if hashes.is_none() {
            warn!("An external reference URL should always come with a dictionary of hashes")
        };
        Ok(Self { url, hashes })
    }

    pub fn get_url(&self) -> &Url {
        &self.url
    }
}

impl crate::base::Stix for ReferenceUrl {
    /// Verifies the hash type is correct for Reference Url
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        } else {
            return Err(Error::ValidationError(
                "An external reference URL should always come with a dictionary of hashes"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
