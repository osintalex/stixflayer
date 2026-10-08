//! Contains the implementation logic for unrecognized custom STIX Objects.
pub mod builder;
pub mod object;
#[cfg(test)]
mod tests;
pub mod validation;

pub use builder::CustomObjectBuilder;
pub use object::CustomObject;
pub use validation::check_custom_object_type;
