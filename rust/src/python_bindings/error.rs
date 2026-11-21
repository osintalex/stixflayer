use crate::error::{Entry, StixError as RustStixError};
use crate::python_bindings::convert::json_value_to_py;
use pyo3::prelude::*;
use pyo3::{create_exception, PyErr};

// Python-facing exception hierarchy.
//
// These are raised by the central `stix_to_pyerr` mapper from the typed Rust
// error envelope. They subclass Exception directly (not ValueError) so callers
// can opt-in to handling structured validation failures.
create_exception!(
    stixflayer,
    StixError,
    pyo3::exceptions::PyException,
    "Base class for all stixflayer errors."
);
create_exception!(
    stixflayer,
    ValidationError,
    StixError,
    "Raised when input parses as JSON but violates STIX 2.1 rules."
);
create_exception!(
    stixflayer,
    DeserializationError,
    StixError,
    "Raised when input cannot be parsed as STIX JSON at all."
);

/// Builds the Python `list[dict]` for the structured validation entries
/// associated with `error`.
pub fn errors_to_py(py: Python<'_>, error: &RustStixError) -> PyObject {
    let entries = error.errors();
    let value = serde_json::to_value(entries).expect("Entry serializes to JSON");
    json_value_to_py(py, &value)
}

/// Converts a Rust STIX error into the appropriate Python exception.
///
/// The exception instance carries a human-readable message in `args[0]` and a
/// sparse `.errors` list for callers that want structured field-level details.
/// The full JSON envelope remains an internal Rust concern.
pub fn stix_to_pyerr(error: RustStixError) -> PyErr {
    stix_to_pyerr_with(error, &[])
}

/// Converts a Rust STIX error plus the warnings collected during the same pass
/// into a Python exception carrying both `.errors` and `.warnings`.
pub fn stix_to_pyerr_with(error: RustStixError, warnings: &[Entry]) -> PyErr {
    Python::with_gil(|py| {
        let message = error.display_message();
        let py_errors = errors_to_py(py, &error);
        let py_warnings = entries_to_py(py, warnings);

        let err = match error.envelope_category() {
            "validation" => PyErr::new::<ValidationError, _>((message,)),
            "deserialization" => PyErr::new::<DeserializationError, _>((message,)),
            _ => PyErr::new::<StixError, _>((message,)),
        };

        // Attach structured entries as normal attributes, silencing the rare
        // case where an exception subclass forbids attribute assignment.
        err.value_bound(py).setattr("errors", py_errors).ok();
        err.value_bound(py).setattr("warnings", py_warnings).ok();

        err
    })
}

/// Converts entries into the Python `list[dict]` wire shape.
pub fn entries_to_py(py: Python<'_>, entries: &[Entry]) -> PyObject {
    let value = serde_json::to_value(entries).expect("Entry serializes to JSON");
    json_value_to_py(py, &value)
}

/// Builds a `ValidationError` directly from outcome entries.
///
/// Used by builder paths that compute an `Outcome` rather than a `StixError`.
pub fn entries_to_validation_pyerr(errors: &[Entry], warnings: &[Entry]) -> PyErr {
    Python::with_gil(|py| {
        let message = if errors.is_empty() {
            "Validation error".to_string()
        } else {
            errors
                .iter()
                .map(|entry| entry.message.clone())
                .collect::<Vec<_>>()
                .join("; ")
        };
        let err = PyErr::new::<ValidationError, _>((message,));
        err.value_bound(py)
            .setattr("errors", entries_to_py(py, errors))
            .ok();
        err.value_bound(py)
            .setattr("warnings", entries_to_py(py, warnings))
            .ok();
        err
    })
}
