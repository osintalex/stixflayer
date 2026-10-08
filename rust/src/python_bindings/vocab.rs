use crate::python_bindings::error::StixError;
use pyo3::prelude::*;
use strum::IntoEnumIterator;

/// Macro to generate a Python class for STIX vocabulary enums
macro_rules! make_vocab_enum {
    ($name:ident, $enum_type:ty) => {
        #[pyclass]
        pub struct $name(String);

        #[pymethods]
        impl $name {
            #[new]
            fn new(value: &str) -> Result<Self, PyErr> {
                // Check if the string matches any variant of the enum
                let valid = <$enum_type>::iter().any(|v| v.as_ref() == value);
                if valid {
                    Ok($name(value.to_string()))
                } else {
                    // Get all valid variants for error message
                    let valid_values: Vec<String> = <$enum_type>::iter()
                        .map(|v| v.as_ref().to_string())
                        .collect();
                    Err(PyErr::new::<StixError, _>(format!(
                        "Invalid {} value: '{}'. Valid values: {:?}",
                        stringify!($enum_type),
                        value,
                        valid_values
                    )))
                }
            }

            /// Get the string value of the vocabulary enum
            fn value(&self) -> String {
                self.0.clone()
            }

            /// Get all valid values for this vocabulary enum
            #[staticmethod]
            fn values() -> Vec<String> {
                <$enum_type>::iter()
                    .map(|v| v.as_ref().to_string())
                    .collect()
            }

            /// Check if a value is valid for this vocabulary enum
            #[staticmethod]
            fn is_valid(value: &str) -> bool {
                <$enum_type>::iter().any(|v| v.as_ref() == value)
            }
        }
    };
}

// Generate vocab enum classes
make_vocab_enum!(
    AttackMotivation,
    crate::domain_objects::vocab::AttackMotivation
);
make_vocab_enum!(
    IdentitySectors,
    crate::domain_objects::vocab::IdentitySectors
);
make_vocab_enum!(
    ThreatActorType,
    crate::domain_objects::vocab::ThreatActorType
);
make_vocab_enum!(MalwareType, crate::domain_objects::vocab::MalwareType);
make_vocab_enum!(IndicatorType, crate::domain_objects::vocab::IndicatorType);
make_vocab_enum!(ReportType, crate::domain_objects::vocab::ReportType);
make_vocab_enum!(
    AttackResourceLevel,
    crate::domain_objects::vocab::AttackResourceLevel
);
make_vocab_enum!(
    ThreatActorSophistication,
    crate::domain_objects::vocab::ThreatActorSophistication
);
