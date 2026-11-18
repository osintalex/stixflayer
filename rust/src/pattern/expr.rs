//! Data structures used by the STIX Patterning parser

use std::collections::HashSet;

use crate::{
    base::Stix,
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{ScoTypes, Timestamp},
};
use ordered_float::OrderedFloat;
use strum::IntoEnumIterator;

/// A STIX Pattern Constant
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constant {
    /// A boolean literal.
    Boolean(bool),
    /// A binary literal, such as `b'0123'`.
    Binary(String),
    /// A hexadecimal literal, such as `h'ff'`.
    Hex(String),
    /// An integer literal.
    Integer(i64),
    /// A floating-point literal.
    Float(OrderedFloat<f64>),
    /// A string literal.
    String(String),
    /// A timestamp literal.
    Timestamp(Timestamp),
    /// A set of constants, as used with the `IN` operator.
    Set(Vec<Constant>),
}

/// A STIX Pattern Observation Expression
///
/// For more information, see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e8slinrhxcc9> for details of the STIX Patterning grammar
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationExpression {
    /// One or more comparison expressions, optionally joined by boolean operators.
    Comparison(ComparisonComponent),
    /// Two observation expressions joined by an observation operator.
    ObservationOp(
        Box<ObservationExpression>,
        ObservationOperator,
        Box<ObservationExpression>,
    ),
    /// An observation expression qualified by a `REPEATS`, `WITHIN`, or `START`/`STOP` qualifier.
    Qualification(Box<ObservationExpression>, Qualifier),
}
impl ObservationExpression {
    fn validate(
        &self,
        errors: &mut Vec<Error>,
        qualifiers: &mut HashSet<String>,
    ) -> Result<(), Error> {
        match self {
            // Validate an observation expression that is only one or more connected comparision expressions
            Self::Comparison(comparison) => add_error(errors, comparison.validate()),
            // Validate two observation expressions joined by an observation operator
            Self::ObservationOp(lhs, _, rhs) => {
                add_error(errors, lhs.validate(&mut errors.clone(), qualifiers));
                add_error(errors, rhs.validate(&mut errors.clone(), qualifiers));
            }
            // Validate an observation expression followed by a qualifier
            Self::Qualification(observation, qualifier) => {
                add_error(
                    errors,
                    observation.validate(&mut errors.clone(), qualifiers),
                );
                add_error(errors, qualifier.check_qualifier(qualifiers));
            }
        };

        return_multiple_errors(errors.clone())
    }
}

impl Stix for ObservationExpression {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();
        let mut qualifiers = HashSet::new();

        self.validate(&mut errors, &mut qualifiers)
    }
}
/// Left-associative Boolean comparison of one or more Comparison Expressions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonComponent {
    /// A single comparison expression.
    ComparisonExpression(ComparisonExpression),
    /// Two comparison components joined by a boolean operator.
    BooleanOp(
        Box<ComparisonComponent>,
        BooleanOperator,
        Box<ComparisonComponent>,
    ),
}

impl ComparisonComponent {
    /// Get the object type from one or more comparison expressions, **if** those object types are all identical
    fn get_matching_object(&self) -> Option<&str> {
        match self {
            Self::ComparisonExpression(expression) => Some(expression.get_object()),
            Self::BooleanOp(lhs, _, rhs) => {
                let lhs_object = lhs.get_matching_object();
                let rhs_object = rhs.get_matching_object();
                match (lhs_object, rhs_object) {
                    (Some(lhs_object), Some(rhs_object)) if lhs_object == rhs_object => {
                        Some(lhs_object)
                    }
                    _ => None,
                }
            }
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        match self {
            Self::ComparisonExpression(comparison) => add_error(&mut errors, comparison.validate()),
            Self::BooleanOp(lhs, operator, rhs) => {
                add_error(&mut errors, lhs.validate());
                add_error(&mut errors, rhs.validate());
                // Check that if comparison expressions are connect by an AND, both of them refer to the same object type
                if let BooleanOperator::And = operator {
                    if self.get_matching_object().is_none() {
                        errors.push(Error::ValidationError("A pair of Comparison Expressions in the pattern has an AND Boolean Operator between different objects".to_string()));
                    }
                }
            }
        }

        return_multiple_errors(errors)
    }
}

/// A STIX Pattern Comparison Expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonExpression {
    /// The path to the observable property being compared.
    pub object_path: ObjectPath,
    /// The operator applied between the object path and the constant.
    pub operator: ComparisonOperator,
    /// The constant compared against the object path; `None` for `EXISTS` comparisons.
    pub constant: Option<Constant>,
    /// Whether the comparison is negated with `NOT`.
    ///
    /// Negation is preserved rather than rewritten to the opposite operator, so
    /// `NOT IN`, `NOT LIKE`, and `NOT EXISTS` keep the operator the user wrote.
    pub negated: bool,
}

impl ComparisonExpression {
    fn get_object(&self) -> &str {
        &self.object_path.sco
    }

    fn validate(&self) -> Result<(), Error> {
        self.object_path.validate()?;

        if let ComparisonOperator::Exists = self.operator {
            if self.constant.is_some() {
                return Err(Error::ValidationError("A comparison expression in the pattern has an 'EXISTS' Comparison Operator but contains a constant".to_string()));
            }
        } else {
            let Some(ref constant) = self.constant else {
                return Err(Error::ValidationError("A comparison expression in the pattern has a Comparison Operator other than `EXISTS` but is missing a constant".to_string()));
            };

            match self.operator {
                ComparisonOperator::In => {
                    let Constant::Set(_) = constant else {
                        return Err(Error::ValidationError("A comparison expression in the pattern has an 'IN' Comparison Operator that is not applied to a set of constants".to_string()));
                    };
                }
                ComparisonOperator::Like
                | ComparisonOperator::IsSubset
                | ComparisonOperator::IsSuperset => {
                    let Constant::String(_) = constant else {
                        return Err(Error::ValidationError("A comparison expression in the pattern has a Comparison Operator that expects a string but is not applied to a string".to_string()));
                    };
                }
                ComparisonOperator::Matches => {
                    let Constant::String(_) = constant else {
                        return Err(Error::ValidationError("A comparison expression in the pattern has a `MATCHES` Comparison Operator that expects a regular expression string but is not applied to a string".to_string()));
                    };
                }
                _ => (),
            }
        }

        Ok(())
    }
}

/// A STIX Pattern Object Path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPath {
    /// The observable type name at the start of the path, e.g. `ipv4-addr`.
    pub sco: String,
    /// The property path after the `:`, which may index into lists and nested objects.
    pub property: String,
}

impl ObjectPath {
    fn validate(&self) -> Result<(), Error> {
        // 1. Validate SCO type
        let is_known_sco = ScoTypes::iter().any(|x| x.as_ref() == self.sco);
        let is_valid_custom = self.sco.len() >= 3
            && self.sco.len() <= 250
            && self
                .sco
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');

        if !is_known_sco && !is_valid_custom {
            return Err(Error::ValidationError(format!(
                "'{}' is not a valid observable type name",
                self.sco
            )));
        }

        // 2. Reject double quotes anywhere in the property path
        if self.property.contains('"') {
            return Err(Error::ValidationError(format!(
                "Property path '{}' contains invalid double quotes",
                self.property
            )));
        }

        // 3. Validate first property component length
        let first_prop = self
            .property
            .split(['.', '['])
            .next()
            .unwrap_or("")
            .trim_matches('\'');

        if !first_prop.is_empty() && first_prop != "id" && first_prop.len() < 3 {
            return Err(Error::ValidationError(format!(
                "'{}' is not a valid observable property name",
                first_prop
            )));
        }

        Ok(())
    }
}

/// A STIX Pattern Comparison Operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOperator {
    /// An equality comparison (`=`).
    Eq,
    /// An inequality comparison (`!=`).
    Neq,
    /// A greater-than comparison (`>`).
    Gt,
    /// A less-than comparison (`<`).
    Lt,
    /// A greater-than-or-equal comparison (`>=`).
    Gte,
    /// A less-than-or-equal comparison (`<=`).
    Lte,
    /// A test that the path's value is in a set of constants (`IN`).
    In,
    /// A wild-card string comparison (`LIKE`).
    Like,
    /// A regular-expression string comparison (`MATCHES`).
    Matches,
    /// A test that the path's value is a subset of the string constant (`ISSUBSET`).
    IsSubset,
    /// A test that the path's value is a superset of the string constant (`ISSUPERSET`).
    IsSuperset,
    /// A test of whether the property exists (`EXISTS`); takes no constant.
    Exists,
}

/// A STIX Pattern Boolean Operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BooleanOperator {
    /// A boolean OR (`OR`) between comparison expressions.
    Or,
    /// A boolean AND (`AND`) between comparison expressions.
    And,
}

/// A STIX Pattern Observation Operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationOperator {
    /// An observation OR (`OR`) between observation expressions.
    Or,
    /// An observation AND (`AND`) between observation expressions.
    And,
    /// A temporal ordering operator (`FOLLOWEDBY`) between observation expressions.
    FollowedBy,
}

/// A STIX Pattern Observation Expression Qualifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qualifier {
    /// A `REPEATS` qualifier matching an observation repeated a given number of times.
    Repeats(i64),
    /// A `WITHIN` qualifier bounding an observation to a time window, in seconds.
    Within(OrderedFloat<f64>),
    /// A `START`/`STOP` qualifier bounding an observation to a timestamp range.
    StartStop(Timestamp, Timestamp),
}

impl Qualifier {
    fn check_qualifier(&self, qualifiers: &mut HashSet<String>) -> Result<(), Error> {
        match self {
            Qualifier::Repeats(count) => {
                if *count <= 0 {
                    return Err(Error::ValidationError(
                        "An Observation Expression in the pattern has a REPEATS Qualifier that is not a positive integer."
                            .to_string(),
                    ));
                }
                check_insert_qualifier("Repeats", qualifiers)
            }
            Qualifier::Within(seconds) => {
                if *seconds <= OrderedFloat(0.0) {
                    return Err(Error::ValidationError(
                        "An Observation Expression in the pattern has a WITHIN Qualifier that is not a positive number of seconds."
                            .to_string(),
                    ));
                }
                check_insert_qualifier("Within", qualifiers)
            }
            // The specification defines the START/STOP range as x <= observation < y
            // but does not prohibit x >= y, so a reversed or empty range is valid.
            Qualifier::StartStop(..) => check_insert_qualifier("Start Stop", qualifiers),
        }
    }
}

/// Add a qualifier of a given type to a set of qualifiers, erroring if that type is already in the set
fn check_insert_qualifier(qualifier: &str, qualifiers: &mut HashSet<String>) -> Result<(), Error> {
    if qualifiers.contains(qualifier) {
        Err(Error::ValidationError("An Observation Expression in the pattern has more than one Qualifier of the same type.".to_string()))
    } else {
        qualifiers.insert(qualifier.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comparison(sco: &str, property: &str, operator: ComparisonOperator) -> ComparisonExpression {
        ComparisonExpression {
            object_path: ObjectPath {
                sco: sco.to_string(),
                property: property.to_string(),
            },
            operator,
            constant: Some(Constant::String("x".to_string())),
            negated: false,
        }
    }

    fn observation(component: ComparisonComponent) -> ObservationExpression {
        ObservationExpression::Comparison(component)
    }

    #[test]
    fn negation_is_preserved_with_the_underlying_operator() {
        let expression = ComparisonExpression {
            object_path: ObjectPath {
                sco: "file".to_string(),
                property: "name".to_string(),
            },
            operator: ComparisonOperator::Neq,
            constant: Some(Constant::String("x".to_string())),
            negated: true,
        };

        assert!(expression.negated);
        assert_eq!(expression.operator, ComparisonOperator::Neq);
    }

    #[test]
    fn groups_are_preserved_on_both_sides() {
        let a = comparison("file", "name", ComparisonOperator::Eq);
        let b = comparison("file", "name", ComparisonOperator::Neq);
        let c = comparison("file", "size", ComparisonOperator::Gt);

        let left_group = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(a)),
            BooleanOperator::Or,
            Box::new(ComparisonComponent::ComparisonExpression(b)),
        );
        let right_group = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(comparison(
                "file",
                "size",
                ComparisonOperator::Eq,
            ))),
            BooleanOperator::Or,
            Box::new(ComparisonComponent::ComparisonExpression(c)),
        );

        let component = ComparisonComponent::BooleanOp(
            Box::new(left_group),
            BooleanOperator::And,
            Box::new(right_group),
        );

        assert_eq!(component.get_matching_object(), Some("file"));
        assert!(observation(component).stix_check().is_ok());
    }

    #[test]
    fn boolean_op_validates_both_sides() {
        let invalid = ComparisonExpression {
            object_path: ObjectPath {
                sco: "file".to_string(),
                property: "name".to_string(),
            },
            operator: ComparisonOperator::In,
            constant: Some(Constant::String("not a set".to_string())),
            negated: false,
        };
        let valid = comparison("file", "size", ComparisonOperator::Gt);

        let component = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(invalid)),
            BooleanOperator::Or,
            Box::new(ComparisonComponent::ComparisonExpression(valid)),
        );

        assert!(observation(component).stix_check().is_err());
    }

    #[test]
    fn and_across_different_objects_is_rejected() {
        let component = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(comparison(
                "ipv4-addr",
                "value",
                ComparisonOperator::Eq,
            ))),
            BooleanOperator::And,
            Box::new(ComparisonComponent::ComparisonExpression(comparison(
                "ipv6-addr",
                "value",
                ComparisonOperator::Eq,
            ))),
        );

        let error = observation(component).stix_check().unwrap_err();
        assert!(error.to_string().contains("different objects"));
    }

    #[test]
    fn or_across_different_objects_is_accepted() {
        let component = ComparisonComponent::BooleanOp(
            Box::new(ComparisonComponent::ComparisonExpression(comparison(
                "ipv4-addr",
                "value",
                ComparisonOperator::Eq,
            ))),
            BooleanOperator::Or,
            Box::new(ComparisonComponent::ComparisonExpression(comparison(
                "ipv6-addr",
                "value",
                ComparisonOperator::Eq,
            ))),
        );

        assert!(observation(component).stix_check().is_ok());
    }

    #[test]
    fn repeats_must_be_positive() {
        for count in [0, -1] {
            let observation = ObservationExpression::Qualification(
                Box::new(observation(ComparisonComponent::ComparisonExpression(
                    comparison("file", "name", ComparisonOperator::Eq),
                ))),
                Qualifier::Repeats(count),
            );
            let error = observation.stix_check().unwrap_err();
            assert!(error.to_string().contains("positive integer"));
        }
    }

    #[test]
    fn within_must_be_positive() {
        for seconds in [0.0, -1.0] {
            let observation = ObservationExpression::Qualification(
                Box::new(observation(ComparisonComponent::ComparisonExpression(
                    comparison("file", "name", ComparisonOperator::Eq),
                ))),
                Qualifier::Within(OrderedFloat(seconds)),
            );
            let error = observation.stix_check().unwrap_err();
            assert!(error.to_string().contains("positive number"));
        }
    }

    #[test]
    fn empty_start_stop_ranges_are_accepted() {
        let start = Timestamp::new("2025-01-01T00:00:00Z").unwrap();
        let stop = Timestamp::new("2025-02-01T00:00:00Z").unwrap();

        for (start, stop) in [
            (stop.clone(), start.clone()),
            (start.clone(), start.clone()),
            (start, stop),
        ] {
            let observation = ObservationExpression::Qualification(
                Box::new(observation(ComparisonComponent::ComparisonExpression(
                    comparison("file", "name", ComparisonOperator::Eq),
                ))),
                Qualifier::StartStop(start, stop),
            );
            assert!(observation.stix_check().is_ok());
        }
    }

    #[test]
    fn duplicate_qualifiers_are_rejected() {
        let observation = ObservationExpression::Qualification(
            Box::new(ObservationExpression::Qualification(
                Box::new(observation(ComparisonComponent::ComparisonExpression(
                    comparison("file", "name", ComparisonOperator::Eq),
                ))),
                Qualifier::Within(OrderedFloat(600.0)),
            )),
            Qualifier::Within(OrderedFloat(300.0)),
        );

        let error = observation.stix_check().unwrap_err();
        assert!(error.to_string().contains("more than one Qualifier"));
    }

    #[test]
    fn operator_and_literal_kinds_must_agree() {
        for (operator, constant) in [
            (
                ComparisonOperator::In,
                Constant::String("not a set".to_string()),
            ),
            (ComparisonOperator::Like, Constant::Integer(5)),
            (ComparisonOperator::Matches, Constant::Integer(5)),
            (ComparisonOperator::IsSubset, Constant::Integer(5)),
            (ComparisonOperator::IsSuperset, Constant::Integer(5)),
        ] {
            let expression = ComparisonExpression {
                object_path: ObjectPath {
                    sco: "file".to_string(),
                    property: "name".to_string(),
                },
                operator,
                constant: Some(constant),
                negated: false,
            };
            assert!(
                observation(ComparisonComponent::ComparisonExpression(expression))
                    .stix_check()
                    .is_err()
            );
        }
    }

    #[test]
    fn exists_must_not_carry_a_constant() {
        let expression = ComparisonExpression {
            object_path: ObjectPath {
                sco: "file".to_string(),
                property: "name".to_string(),
            },
            operator: ComparisonOperator::Exists,
            constant: Some(Constant::String("x".to_string())),
            negated: true,
        };
        assert!(
            observation(ComparisonComponent::ComparisonExpression(expression))
                .stix_check()
                .is_err()
        );
    }
}
