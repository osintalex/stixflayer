//! The Filter struct enables operations on properties with various value types for flexible filtering.
use crate::types::Timestamp;
use std::collections::HashMap;

/// The Filter struct to apply conditional logic to data retrieval
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    property: String,
    op: FilterOp,
    value: String,
}

/// The FilterOp enum represents different operators
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOp {
    /// Matches when the property value is equal to the filter value.
    Eq,
    /// Matches when the property value is not equal to the filter value.
    Ne,
    /// Matches when the property value is one of the filter values.
    In,
    /// Matches when the property value is greater than the filter value.
    Gt,
    /// Matches when the property value is less than the filter value.
    Lt,
    /// Matches when the property value is greater than or equal to the filter value.
    Gre,
    /// Matches when the property value is less than or equal to the filter value.
    Lte,
    /// Matches when the property value contains the filter value.
    Contains,
}

/// The FilterValue enum encapsulates various data types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterValue {
    /// A boolean value to filter on.
    Bool(bool),
    /// A dictionary of string keys and values to filter on.
    Dict(HashMap<String, String>),
    /// An unsigned integer value to filter on.
    Int(u64),
    /// A list of string values to filter on.
    List(Vec<String>),
    /// A tuple value to filter on.
    Tuple,
    /// A string value to filter on.
    Str(String),
    /// A timestamp value to filter on.
    DateTime(Timestamp),
}
