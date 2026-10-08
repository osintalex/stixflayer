//! STIX 2.1 compliant hash lists.
use crate::error::StixError as Error;
use identyhash::identify_hash;
use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::OnceLock};
use strum::{AsRefStr, EnumIter, IntoEnumIterator};

fn ssdeep_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\d+:[A-Za-z0-9/+]{1,}:[A-Za-z0-9/+]{1,}$").expect("ssdeep regex is valid")
    })
}

/// A STIX 2.1 compliant hash list, with a key/value pair identifying the hashing algorithm used and the hashed value.
///
/// Because hash lists have different constraints than other dictionaries, it is treated as a separate type.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_odoabbtwuxyd>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes(HashMap<String, String>);

impl Hashes {
    /// Creates a new Stix 2.1 compliant hash list with a single key/value pair
    ///
    /// STIX 2.1 requires that hash lists cannot be empty, so to be extra careful we **must** have an initial key-value pair to create a new dictionary
    pub fn new(key: &str, value: &str) -> Result<Self, Error> {
        // Make sure the key is a valid STIX hash
        if check_hash_key(key) {
            let mut hashes = HashMap::new();
            hashes.insert(key.to_string(), value.to_string());

            Ok(Self(hashes))
        } else {
            Err(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
        }
    }

    /// Adds a valid key/value pair to a hash list
    pub fn insert(&mut self, key: &str, value: &str) -> Result<(), Error> {
        // Make sure the key is a valid STIX Dictionary key
        if check_hash_key(key) {
            // We do not allow duplicate keys
            match self.0.insert(key.to_string(), value.to_string()) {
                Some(_duplicate_key) => Err(Error::ValidationError(format!(
                    "Duplicate value specified for {}",
                    key
                ))),
                None => Ok(()),
            }
        } else {
            Err(Error::ValidationError(format!("Key {} is not a valid key under STIX policies. Keys may only contain letters, numbers, '-, or '_'.", key)))
        }
    }

    /// Retrieves the value for a given key in a hash list
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.get(key)
    }

    /// Creates an iterator for the key/value pairs of a hash list
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
    pub fn length(&self) -> usize {
        self.0.len()
    }
}

// Checks that the provided hash key is STIX 2.1 compliant and provides warnings if it compliant but against recommendations
fn check_hash_key(key: &str) -> bool {
    let valid = key.len() >= 3
        && key.len() <= 250
        && (key
            .chars()
            .all(|c| c.is_ascii() && (c.is_alphanumeric() || c == '-' || c == '_')));

    if key != "SHA-256" {
        warn!("STIX 2.1 recommends that the SHA-256 hash should be used whenever possible");
    }

    valid
}

impl crate::base::Stix for Hashes {
    fn stix_check(&self) -> Result<(), Error> {
        for (key, value) in self.iter() {
            let origin_hash_str = value.as_str();
            let hash_type_identity = identify_hash(origin_hash_str).to_lowercase();
            let origin_hash_type = key.as_str().to_lowercase();

            if key.len() < 3 {
                return Err(Error::ValidationError(format!(
                    "Hash type '{}' is shorter than 3 characters.",
                    key,
                )));
            }

            if key.len() > 30 {
                return Err(Error::ValidationError(format!(
                    "Hash type '{}' is longer than 30 characters.",
                    key,
                )));
            }

            if !origin_hash_type.starts_with("x_")
                && LegalHashTypes::iter().all(|x| x.as_ref() != origin_hash_type)
            {
                return Err(Error::ValidationError(format!(
                    "The hash type '{}' is not from the hash-algorithm-ov open vocabulary and does not start with 'x_'.",
                    key,
                )));
            }
            // sha-256 and sha3-256 have same format and identyhash crate treats them the same
            if (origin_hash_type == *LegalHashTypes::SHA256.as_ref()
                || origin_hash_type == *LegalHashTypes::SHA3256.as_ref())
                && hash_type_identity != *LegalHashTypes::SHA256.as_ref()
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
            // sha-512 and sha3-512 have same format and identyhash crate treats them the same
            if (origin_hash_type == *LegalHashTypes::SHA512.as_ref()
                || origin_hash_type == *LegalHashTypes::SHA3512.as_ref())
                && hash_type_identity != *LegalHashTypes::SHA512.as_ref()
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
            if origin_hash_type == *LegalHashTypes::SSDEEP.as_ref()
                && !ssdeep_re().is_match(origin_hash_str)
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
            if origin_hash_type == *LegalHashTypes::TLSH.as_ref() {
                //mimic identyhash crate
                if origin_hash_str.len() != 70
                    && !origin_hash_str.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(Error::InvalidHash {
                        hash_type: origin_hash_type,
                        hash_identity: hash_type_identity,
                        hash_string: origin_hash_str.to_string(),
                    });
                }
            }
            if (origin_hash_type == *LegalHashTypes::SHA1.as_ref()
                || origin_hash_type == *LegalHashTypes::MD5.as_ref())
                && hash_type_identity != origin_hash_type
            {
                return Err(Error::InvalidHash {
                    hash_type: origin_hash_type,
                    hash_identity: hash_type_identity,
                    hash_string: origin_hash_str.to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Refers to the valid hash algorithms like MD5, SHA-1, and SHA-256 used for file identification.
#[derive(Debug, PartialEq, Eq, Clone, AsRefStr, EnumIter, Serialize, Deserialize)]
pub enum LegalHashTypes {
    #[strum(serialize = "md5")]
    MD5,
    #[strum(serialize = "sha-1")]
    SHA1,
    #[strum(serialize = "sha-256")]
    SHA256,
    #[strum(serialize = "sha-512")]
    SHA512,
    #[strum(serialize = "sha3-256")]
    SHA3256,
    #[strum(serialize = "sha3-512")]
    SHA3512,
    #[strum(serialize = "ssdeep")]
    SSDEEP,
    #[strum(serialize = "tlsh")]
    TLSH,
}
