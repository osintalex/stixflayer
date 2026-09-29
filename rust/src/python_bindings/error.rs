use pyo3::prelude::*;
use pyo3::{create_exception, PyErr};
use crate::error::StixError as RustStixError;
use crate::python_bindings::convert::json_value_to_py;

// Python-facing exception hierarchy.
//
// These are raised by the central `stix_to_pyerr` mapper from the typed Rust
// error envelope. They subclass Exception directly (not ValueError) so callers
// can opt-in to handling structured validation failures.
create_exception!(stixflayer, StixError, pyo3::exceptions::PyException);
create_exception!(stixflayer, ValidationError, StixError);
create_exception!(stixflayer, DeserializationError, StixError);

/// Builds the Python `list[dict]` for the structured validation entries
/// associated with `error`.
pub fn errors_to_py(py: Python<'_>, error: &RustStixError) -> PyObject {
    let entries = error.errors();
    let value = serde_json::to_value(entries).expect("ErrorEntry serializes to JSON");
    json_value_to_py(py, &value)
}

/// Converts a Rust STIX error into the appropriate Python exception.
///
/// The exception instance carries a human-readable message in `args[0]` and a
/// sparse `.errors` list for callers that want structured field-level details.
/// The full JSON envelope remains an internal Rust concern.
pub fn stix_to_pyerr(error: RustStixError) -> PyErr {
    Python::with_gil(|py| {
        let message = error.display_message();
        let py_errors = errors_to_py(py, &error);

        let err = match error.envelope_category() {
            "validation" => PyErr::new::<ValidationError, _>((message,)),
            "deserialization" => PyErr::new::<DeserializationError, _>((message,)),
            _ => PyErr::new::<StixError, _>((message,)),
        };

        // Attach structured entries as a normal attribute, silencing the rare
        // case where an exception subclass forbids attribute assignment.
        err.value_bound(py).setattr("errors", py_errors).ok();

        err
    })
}
