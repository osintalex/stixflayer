//! Location SDO
//!
//! A Location represents a geographic location. The location may be described as any, some or all of the following: region, civic address, latitude and longitude.
//!
//! For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_th8nitr8jb4k>

use crate::{
    base::Stix,
    common::validation::validate_vocab_value,
    domain_objects::vocab::Region,
    error::{add_error, return_multiple_errors, StixError as Error},
};
use ordered_float::OrderedFloat as ordered_float;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use stix_derive::StixProperties;

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, StixProperties)]
pub struct Location {
    /// A name used to identify the Location.
    pub name: Option<String>,
    /// A textual description of the Location.
    pub description: Option<String>,
    /// The latitude of the Location in decimal degrees.
    pub latitude: Option<ordered_float<f64>>,
    /// The longitude of the Location in decimal degrees.
    pub longitude: Option<ordered_float<f64>>,
    /// Defines the precision of the coordinates specified by the `latitude` and `longitude` properties.
    pub precision: Option<ordered_float<f64>>,
    /// The region that this Location describes.
    pub region: Option<String>,
    /// The country that this Location describes.
    pub country: Option<String>,
    /// The state, province, or other sub-national administrative area that this Location describes.
    pub administrative_area: Option<String>,
    /// The city that this Location describes.
    pub city: Option<String>,
    /// The street address that this Location describes.
    pub street_address: Option<String>,
    /// The postal code for this Location.
    pub postal_code: Option<String>,
}

impl Stix for Location {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        let min_lat = ordered_float(-90.0_f64);
        let max_lat = ordered_float(90.0_f64);
        let min_lon = ordered_float(-180.0_f64);
        let max_lon = ordered_float(180.0_f64);

        if self.precision.is_some() && (self.latitude.is_none() || self.longitude.is_none()) {
            errors.push(Error::ValidationError(
                "Latitude and longitude must be present if precision is set".to_string(),
            ));
        }

        if let Some(lat) = self.latitude {
            if lat < min_lat || lat > max_lat {
                errors.push(Error::ValidationError(
                    "Latitude should be between -90.0 and 90.0".to_string(),
                ));
            }
            if self.longitude.is_none() {
                errors.push(Error::ValidationError(
                    "Longitude must be present if latitude is set".to_string(),
                ));
            }
        }

        if let Some(lon) = self.longitude {
            if lon < min_lon || lon > max_lon {
                errors.push(Error::ValidationError(
                    "Longitude should be between -180.0 and 180.0".to_string(),
                ));
            }
            if self.latitude.is_none() {
                errors.push(Error::ValidationError(
                    "Latitude must be present if longitude is set".to_string(),
                ));
            }
        }
        if let Some(region_str) = &self.region {
            add_error(
                &mut errors,
                validate_vocab_value::<Region, _>(region_str, "region-ov"),
            );
        }
        if let Some(country) = &self.country {
            if rust_iso3166::from_alpha2(country).is_none() {
                errors.push(Error::ValidationError(format!(
                    "Location country '{}' is not a valid ISO 3166-1 ALPHA-2 code",
                    country
                )));
            }
        }
        if let Some(administrative_area) = &self.administrative_area {
            if rust_iso3166::iso3166_2::from_code(administrative_area).is_none() {
                errors.push(Error::ValidationError(format!(
                    "Location administrative_area '{}' is not a valid ISO 3166-2 code",
                    administrative_area
                )));
            }
        }

        return_multiple_errors(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_objects::sdo::{DomainObject, DomainObjectBuilder};
    use serde_json::Value;

    fn expected_location() -> DomainObject {
        DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .latitude(37.7749)
            .unwrap()
            .longitude(-122.4194)
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("US".to_string())
            .unwrap()
            .administrative_area("SE-O".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build()
            .unwrap()
            .test_id()
            .created("2016-05-12T08:17:27.000Z")
            .modified("2016-05-12T08:17:27.000Z")
    }

    #[test]
    fn serialize_location() {
        let location = expected_location();
        let result = serde_json::to_value(&location).unwrap();

        let expected = r#"{
            "type": "location",
            "name": "Test Location",
            "description": "A test location",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "precision": 10.0,
            "region": "northern-america",
            "country": "US",
            "administrative_area": "SE-O",
            "city": "San Francisco",
            "street_address": "1 Market St",
            "postal_code": "94105",
            "spec_version": "2.1",
            "id": "location--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
        }"#;

        let expected_value: Value = serde_json::from_str(expected).unwrap();
        assert_eq!(result, expected_value);
    }

    #[test]
    fn serialize_location_invalid_latitude() {
        let location = DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .latitude(97.7749)
            .unwrap()
            .longitude(-122.4194)
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("US".to_string())
            .unwrap()
            .administrative_area("SE-O".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build();

        assert!(location.is_err());
    }

    #[test]
    fn serialize_location_invalid_precision() {
        let location = DomainObjectBuilder::new("location")
            .unwrap()
            .name("Test Location".to_string())
            .unwrap()
            .description("A test location".to_string())
            .unwrap()
            .precision(10.0)
            .unwrap()
            .region("northern-america".to_string())
            .unwrap()
            .country("us".to_string())
            .unwrap()
            .administrative_area("se-o".to_string())
            .unwrap()
            .city("San Francisco".to_string())
            .unwrap()
            .street_address("1 Market St".to_string())
            .unwrap()
            .postal_code("94105".to_string())
            .unwrap()
            .build();

        assert!(location.is_err());
    }

    #[test]
    fn deserialize_location() {
        let json = r#"{
            "type": "location",
            "name": "Test Location",
            "description": "A test location",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "precision": 10.0,
            "region": "northern-america",
            "country": "US",
            "administrative_area": "SE-O",
            "city": "San Francisco",
            "street_address": "1 Market St",
            "postal_code": "94105",
            "spec_version": "2.1",
            "id": "location--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
        }"#;

        let result = DomainObject::from_json(json, false).unwrap();
        assert_eq!(result, expected_location());
    }

    #[test]
    fn deserialize_location_invalid() {
        let json = r#"{
            "type": "location",
            "name": "Test Location",
            "description": "A test location",
            "precision": 10.0,
            "region": "northern-america",
            "country": "US",
            "administrative_area": "SE-O",
            "city": "San Francisco",
            "street_address": "1 Market St",
            "postal_code": "94105",
            "spec_version": "2.1",
            "id": "location--cc7fa653-c35f-43db-afdd-dce4c3a241d5",
            "created": "2016-05-12T08:17:27Z",
            "modified": "2016-05-12T08:17:27Z"
        }"#;

        let result = DomainObject::from_json(json, false);
        assert!(result.is_err());
    }

    #[test]
    fn location_valid_country_code() {
        let location = Location {
            country: Some("US".to_string()),
            ..Default::default()
        };
        assert!(location.stix_check().is_ok());
    }

    #[test]
    fn location_valid_country_codes() {
        let valid_codes = vec!["US", "GB", "DE", "FR", "JP", "CN", "RU", "CA", "AU"];
        for code in valid_codes {
            let location = Location {
                country: Some(code.to_string()),
                ..Default::default()
            };
            assert!(
                location.stix_check().is_ok(),
                "Country code '{}' should be valid",
                code
            );
        }
    }

    #[test]
    fn location_invalid_country_code() {
        let location = Location {
            country: Some("XX".to_string()),
            ..Default::default()
        };
        assert!(location.stix_check().is_err());
    }

    #[test]
    fn location_invalid_country_codes() {
        let invalid_codes = vec!["XX", "123", "USA", ""];
        for code in invalid_codes {
            let location = Location {
                country: Some(code.to_string()),
                ..Default::default()
            };
            assert!(
                location.stix_check().is_err(),
                "Country code '{}' should be invalid",
                code
            );
        }
    }

    #[test]
    fn location_lowercase_country_code() {
        let location = Location {
            country: Some("us".to_string()),
            ..Default::default()
        };
        assert!(
            location.stix_check().is_err(),
            "Lowercase country code should be invalid"
        );
    }

    #[test]
    fn location_valid_administrative_area() {
        let location = Location {
            administrative_area: Some("US-CA".to_string()),
            ..Default::default()
        };
        assert!(location.stix_check().is_ok());
    }

    #[test]
    fn location_invalid_administrative_area() {
        let location = Location {
            administrative_area: Some("INVALID".to_string()),
            ..Default::default()
        };
        assert!(location.stix_check().is_err());
    }

    #[test]
    fn location_no_country_or_admin_area() {
        let location = Location {
            ..Default::default()
        };
        assert!(location.stix_check().is_ok());
    }

    #[test]
    fn location_error_message_contains_country_code() {
        let location = Location {
            country: Some("XX".to_string()),
            ..Default::default()
        };
        let result = location.stix_check();
        assert!(result.is_err());
        if let Err(crate::error::StixError::ValidationError(msg)) = result {
            assert!(
                msg.contains("XX"),
                "Error message should contain the invalid country code"
            );
            assert!(
                msg.contains("ISO 3166-1"),
                "Error message should mention ISO 3166-1"
            );
        } else {
            panic!("Expected ValidationError");
        }
    }
}
