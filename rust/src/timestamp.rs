//! A STIX 2.1 compliant timestamp type.
use crate::error::StixError as Error;
use jiff::Timestamp as JiffTimestamp;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, sync::OnceLock};

/// A custom Timestamp struct that holds a `jiff::Timestamp`.
///
/// We use this custom type because while `Timestamp` is RFC 3339 compliant, its deserializtion is *more* generous
/// than the STIX 2.1 timestamp formatting rules.
/// A timestamp will not deserialize unless it is in the format `YYYY-MM-DDTHH:mm:ss[.s+]Z` and is not in a timezone other than UTC.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ksbm2nost85y>
fn stix_timestamp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
            .expect("STIX timestamp regex is valid")
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub JiffTimestamp);

impl Timestamp {
    pub fn now() -> Self {
        Self(JiffTimestamp::now())
    }

    pub fn new(timestamp_str: &str) -> Result<Self, Error> {
        // STIX 2.1 has a stricter standard for valid timestamps than the `jiff`` crate we use.
        // Before parsing a given timestamp string, check that it matches the STIX pattern.
        if !stix_timestamp_re().is_match(timestamp_str) {
            return Err(Error::ParseTimestampError(timestamp_str.to_string()));
        }

        let timestamp = JiffTimestamp::from_str(timestamp_str).map_err(Error::DateTimeError)?;
        Ok(Self(timestamp))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Most of the custom `impl` of `serde:Seriazlie and serde:Deserialize` are taken from `jiff::Timestamp`'s `imp` of `Deserialize`
impl Serialize for Timestamp {
    #[inline]
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    #[inline]
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        use serde::de;

        struct TimestampVisitor;

        impl de::Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a timestamp string in STIX 2.1 format")
            }

            #[inline]
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Timestamp, E> {
                // STIX 2.1 has a stricter standard for valid timestamps than the `jiff`` crate we use.
                // Before parsing a given timestamp string, check that it matches the STIX pattern.
                if !stix_timestamp_re().is_match(value) {
                    return Err(de::Error::custom(format!(
                        "Could not parse timestamp {} as a valid STIX 2.1 Timestamp",
                        value
                    )));
                }
                // If the pattern matches, parse the string as a `jiff::Timestamp` and insert it into our custom Timestamp struct
                let ts: JiffTimestamp = value.parse().map_err(de::Error::custom)?;
                Ok(Timestamp(ts))
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}

impl crate::base::Stix for Timestamp {
    fn stix_check(&self) -> Result<(), Error> {
        // If a Timestamp has already been parsed from a string, then we have already checked that is a valid STIX Timestamp
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, serde::Deserialize)]
    struct ExampleObject {
        created: Timestamp,
    }

    #[test]
    fn deserialize_valid_timestamp() {
        let json = r#"{
            "created": "2016-01-20T12:31:12.123Z"
        }"#;
        let result: ExampleObject = serde_json::from_str(json).unwrap();
        let ts: JiffTimestamp = "2016-01-20T12:31:12.123Z".parse().unwrap();
        let expected = ExampleObject {
            created: Timestamp(ts),
        };
        assert_eq!(result, expected);
    }

    #[test]
    fn deserialize_timestamp_with_space() {
        // The timestamp string should correctly parse as a jiff::Timestamp, without our extra deserializer
        let valid_ts: Result<JiffTimestamp, jiff::Error> = "2016-01-20 12:31:12.123Z".parse();
        assert!(valid_ts.is_ok());

        let json = r#"{
            "created": "2016-01-20 12:31:12.123Z"
        }"#;
        let result: Result<ExampleObject, serde_json::Error> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_timestamp_with_offset() {
        // The timestamp string should correctly parse as a jiff::Timestamp, without our extra deserializer
        let valid_ts: Result<JiffTimestamp, jiff::Error> = "2016-01-20T12:31:12.123+05".parse();
        assert!(valid_ts.is_ok());

        let json = r#"{
            "created": "2016-01-20T12:31:12.123+05"
        }"#;
        let result: Result<ExampleObject, serde_json::Error> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
