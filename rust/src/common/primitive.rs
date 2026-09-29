//! `Stix` trait implementations for Rust primitives and containers.
use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
};
use ordered_float::OrderedFloat;
use std::collections::{BTreeMap, HashMap};

impl Stix for bool {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Stix for u8 {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Stix for u64 {
    fn stix_check(&self) -> Result<(), Error> {
        if *self > (1 << 53) - 1 {
            return Err(Error::ValidationError(
                "u64 values must be limited to within [0, (2^53) - 1] or <= 9007199254740991"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl Stix for i64 {
    fn stix_check(&self) -> Result<(), Error> {
        let min = -(2i64.pow(53)) + 1;
        let max = (2i64.pow(53)) - 1;
        if *self < min || *self > max {
            return Err(Error::ValidationError(
                "i64 values must be limited to within [-(2^53)+1, (2^53)-1] or within the number range [-9007199254740991, 9007199254740991]".to_string(),
            ));
        }
        Ok(())
    }
}

impl<T> Stix for OrderedFloat<T> {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Stix for String {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl<T: Stix> Stix for Vec<T> {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();
        for item in self.iter() {
            add_error(&mut errors, item.stix_check());
        }
        return_multiple_errors(errors)
    }
}

impl<T: Stix, U: Stix> Stix for HashMap<T, U> {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that the key and value of each Map entry are valid Stix objects or properties
        for (key, value) in self.iter() {
            add_error(&mut errors, key.stix_check());
            add_error(&mut errors, value.stix_check());
        }
        return_multiple_errors(errors)
    }
}

impl<T: Stix, U: Stix> Stix for BTreeMap<T, U> {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        // Check that the key and value of each Map entry are valid Stix objects or properties
        for (key, value) in self.iter() {
            add_error(&mut errors, key.stix_check());
            add_error(&mut errors, value.stix_check());
        }
        return_multiple_errors(errors)
    }
}

impl Stix for serde_json::Value {
    fn stix_check(&self) -> Result<(), Error> {
        match self {
            Self::Bool(bool) => bool.stix_check(),
            Self::Number(number) => {
                if let Some(unsigned) = number.as_u64() {
                    unsigned.stix_check()
                } else if let Some(signed) = number.as_i64() {
                    if signed < -9007199254740992 {
                        Err(Error::ValidationError(
                            "i64 values must be limited to within 2^53 bits".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                } else {
                    OrderedFloat(number.as_f64()).stix_check()
                }
            }
            Self::String(string) => string.stix_check(),
            Self::Array(array) => array.stix_check(),
            Self::Object(map) => {
                let mut errors = Vec::new();

                // Check that the key and value of each Map entry are valid Stix objects or properties
                for (key, value) in map.iter() {
                    add_error(&mut errors, key.stix_check());
                    add_error(&mut errors, value.stix_check());
                }
                return_multiple_errors(errors)
            }
            Self::Null => Err(Error::JsonNull),
        }
    }
}
