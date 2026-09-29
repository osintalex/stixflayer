//! STIX 2.1 compliant identifiers.
use crate::{
    common::string::stix_case,
    error::StixError as Error,
    taxonomy::is_sco_type_name,
};
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{collections::HashMap, fmt, str::FromStr};
use uuid::{Uuid, Version};

#[cfg(test)]
use uuid::uuid;

/// A STIX 2.1 compliant identifier that uniquely identifies a STIX Object.
///
/// It consists of two parts, the object-type and a UUID.
/// The object type must exactly match the type property of the object being identified or referenced.
/// The UUID is either an RFC 9562 compliant UUIDv4 or UUIDv5.
/// The latter is used only for Cyber-observable objects. All other objects use UUIDv4
///
/// `Identifier` `impl`'s `Display` and `FromStr`, and its String representation is {object-type}--{UUID}
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c>
#[derive(Clone, Debug, PartialEq, Eq, SerializeDisplay, Default, DeserializeFromStr)]
pub struct Identifier {
    /// The object type
    object_type: String,
    /// The UUID
    uuid: Uuid,
}

impl Identifier {
    /// Create a UUIDv4 identifier, used for any Stix Object that is not a Cyber-observable object.
    /// For SCOs, generates a UUIDv5 with empty properties as a fallback (legacy behavior for test IDs and refs).
    /// The builder path uses UUIDv4 when no contributing properties exist, per STIX 2.1 spec section 2.9.
    pub fn new(object_type: &str) -> Result<Self, Error> {
        check_object_type(object_type)?;
        let object_type_cased = stix_case(object_type);

        if is_sco_type_name(&object_type_cased) {
            let id_v5 = Identifier::new_v5(object_type, &HashMap::<String, String>::new())?;
            Ok(id_v5)
        } else {
            Ok(Self {
                object_type: object_type_cased,
                uuid: Uuid::new_v4(),
            })
        }
    }

    /// Create a UUIDv4 identifier. For SCOs, this is the spec-compliant fallback
    /// when no ID contributing properties are present (STIX 2.1 spec section 2.9).
    pub fn new_v4(object_type: &str) -> Result<Self, Error> {
        check_object_type(object_type)?;
        let object_type_cased = stix_case(object_type);
        Ok(Self {
            object_type: object_type_cased,
            uuid: Uuid::new_v4(),
        })
    }

    /// Create a UUIDv5 identifier using the STIX 2.1 preferred namespace, used ONLY for Cyber-observable Objects
    /// The value of the name portion should be the list of "ID Contributing Properties" (property-name and property value pairs), as defined on each object.
    pub fn new_v5<T: Serialize>(
        object_type: &str,
        contributing_properties: &HashMap<String, T>,
    ) -> Result<Self, Error> {
        check_object_type(object_type)?;

        // PANIC: This function is safe to unwrap, as the provided namespace String is a valid hexidecimal string represenation of a UUID
        let namespace = Uuid::parse_str("00abedb4-aa42-466c-9c01-fed23315a9b7").unwrap();
        let names = json_canon::to_vec(contributing_properties)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        Ok(Self {
            object_type: stix_case(object_type),
            uuid: Uuid::new_v5(&namespace, &names),
        })
    }

    /// Returns the object-type of the identifier
    pub fn get_type(&self) -> &str {
        &self.object_type
    }

    /// Return the UUID version of the idetifier's UUID
    /// Only UUIDv4 and UUIDv5 are supported by STIX 2.1, so any other version is labeled as unsupported
    #[cfg(test)]
    pub fn get_uuid_version(&self) -> &str {
        match &self.uuid.get_version() {
            Some(Version::Random) => "UUIDv4",
            Some(Version::Sha1) => "UUIDv5",
            Some(_) => "Unsupported UUID version",
            None => "Could not determine UUID version",
        }
    }

    /// Creates a dummy identifier without a randomly generated UUID
    #[cfg(test)]
    pub fn new_test(object_type: &str) -> Self {
        let object_type_cased = stix_case(object_type);
        let uuid = if is_sco_type_name(&object_type_cased) {
            uuid!("cc7fa653-c35f-53db-afdd-dce4c3a241d5")
        } else {
            uuid!("cc7fa653-c35f-43db-afdd-dce4c3a241d5")
        };
        Self {
            object_type: object_type_cased,
            uuid,
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}--{}", self.object_type, self.uuid)
    }
}

impl FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (object_type, raw_uuid) = s
            .split_once("--")
            .ok_or(Error::ParseIdentifierError(s.to_string()))?;

        let object_type_fromstr = stix_case(object_type);
        let uuid_fromstr =
            Uuid::from_str(raw_uuid).map_err(|_| Error::ParseIdentifierError(s.to_string()))?;

        Ok(Identifier {
            object_type: object_type_fromstr,
            uuid: uuid_fromstr,
        })
    }
}

impl crate::base::Stix for Identifier {
    fn stix_check(&self) -> Result<(), Error> {
        check_object_type(self.get_type())?;

        // Check UUID version.
        // STIX 2.1 spec section 2.9:
        // - Non-SCO objects MUST use UUIDv4.
        // - SCOs MUST use UUIDv5 when ID contributing properties exist.
        // - SCOs MUST use UUIDv4 when no contributing properties exist.
        // At the Identifier level we enforce version bounds only; correctness
        // of a UUIDv5 hash against canonical properties is validated at the
        // object level during deserialization/building.
        match &self.uuid.get_version() {
            Some(Version::Random) => {
                // UUIDv4 is valid for all STIX objects, including SCOs.
                // SCOs without contributing properties MUST use UUIDv4 per spec.
                // SCOs with contributing properties SHOULD use UUIDv5, but that
                // check is performed by comparing the expected UUIDv5 at the
                // object validation level, not here.
            }
            Some(Version::Sha1) => {
                if !is_sco_type_name(self.get_type()) {
                    return Err(Error::InvalidUuid {
                        message:
                            "STIX Objects other than SCOs **MUST** only use UUIDv4's in their id's"
                                .to_string(),
                    });
                }
            }
            Some(_) => {
                return Err(Error::InvalidUuid { message: "STIX does not support UUID versions other than UUIDv4 and UUIDv5 (for SCOs) in object id's".to_string() });
            }
            None => {
                return Err(Error::InvalidUuid {
                    message: "This object's id is not a valid UUID of known type".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Check that a given object type is a valid STIX object type
fn check_object_type(object_type: &str) -> Result<(), Error> {
    if object_type
        .chars()
        .all(|c| char::is_lowercase(c) || char::is_numeric(c) || c == '-')
    {
        Ok(())
    } else {
        Err(Error::ParseIdentifierError(object_type.to_string()))
    }
}

/// A trait for objects that have an identifier, providing a method to access it.
pub trait Identified {
    fn get_id(&self) -> &Identifier;
}
