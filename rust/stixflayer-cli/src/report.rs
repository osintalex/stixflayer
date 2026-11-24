//! The stable JSON report and its human-readable rendering.

use std::fmt::Write;

use serde::Serialize;
use stixflayer::error::Entry;

/// The report envelope's schema version. Evolution is additive only.
pub const SCHEMA_VERSION: u32 = 1;

/// A validated document as it appears in `results`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileResult {
    /// The path shown to the user, or `-` for standard input.
    pub path: String,
    /// Whether the document produced no errors.
    pub valid: bool,
    /// MUST-level findings.
    pub errors: Vec<Entry>,
    /// SHOULD-level findings.
    pub warnings: Vec<Entry>,
}

/// A document that was not STIX 2.1 and therefore not validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// The path shown to the user, or `-` for standard input.
    pub path: String,
    /// A free-form skip reason such as `not_stix`.
    pub reason: String,
}

/// Aggregate counts for the run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Files discovered and processed (validated plus skipped).
    pub files: usize,
    /// Validated documents with no errors.
    pub valid: usize,
    /// Validated documents with at least one error.
    pub invalid: usize,
    /// Documents skipped before validation.
    pub skipped: usize,
    /// STIX objects validated across all documents.
    pub objects: usize,
    /// Total MUST-level findings.
    pub errors: usize,
    /// Total SHOULD-level findings.
    pub warnings: usize,
}

/// The complete `--json` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Aggregate counts.
    pub summary: Summary,
    /// Validated documents, in path order.
    pub results: Vec<FileResult>,
    /// Skipped documents, in path order.
    pub skipped: Vec<Skipped>,
}

/// A validated document plus its object count, before report assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentResult {
    /// The path shown to the user.
    pub path: String,
    /// Whether the document produced no errors.
    pub valid: bool,
    /// MUST-level findings.
    pub errors: Vec<Entry>,
    /// SHOULD-level findings.
    pub warnings: Vec<Entry>,
    /// The number of objects validated in this document.
    pub objects: usize,
}

/// A skipped document, before report assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedDocument {
    /// The path shown to the user.
    pub path: String,
    /// A free-form skip reason.
    pub reason: String,
}

impl Report {
    /// Builds a report and derives every summary count from the two arrays.
    pub fn from_documents(results: Vec<DocumentResult>, skipped: Vec<SkippedDocument>) -> Self {
        let summary = Summary {
            files: results.len() + skipped.len(),
            valid: results.iter().filter(|result| result.valid).count(),
            invalid: results.iter().filter(|result| !result.valid).count(),
            skipped: skipped.len(),
            objects: results.iter().map(|result| result.objects).sum(),
            errors: results.iter().map(|result| result.errors.len()).sum(),
            warnings: results.iter().map(|result| result.warnings.len()).sum(),
        };

        Self {
            schema_version: SCHEMA_VERSION,
            summary,
            results: results
                .into_iter()
                .map(|result| FileResult {
                    path: result.path,
                    valid: result.valid,
                    errors: result.errors,
                    warnings: result.warnings,
                })
                .collect(),
            skipped: skipped
                .into_iter()
                .map(|skipped| Skipped {
                    path: skipped.path,
                    reason: skipped.reason,
                })
                .collect(),
        }
    }
}

/// Renders one line per finding followed by a summary line.
pub fn render_human(report: &Report) -> String {
    let mut output = String::new();

    for result in &report.results {
        for error in &result.errors {
            render_entry(&mut output, &result.path, "error", error);
        }
        for warning in &result.warnings {
            render_entry(&mut output, &result.path, "warning", warning);
        }
    }

    for skipped in &report.skipped {
        let _ = writeln!(output, "{}: skipped ({})", skipped.path, skipped.reason);
    }

    let summary = &report.summary;
    let _ = writeln!(
        output,
        "{} files: {} valid, {} invalid, {} skipped; {} objects, {} errors, {} warnings",
        summary.files,
        summary.valid,
        summary.invalid,
        summary.skipped,
        summary.objects,
        summary.errors,
        summary.warnings
    );

    output
}

fn render_entry(output: &mut String, path: &str, level: &str, entry: &Entry) {
    let object = entry
        .object_id
        .as_ref()
        .map(|id| format!(" ({id})"))
        .unwrap_or_default();
    let _ = writeln!(
        output,
        "{path}: {level} [{}]{object} {}",
        entry.kind, entry.message
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: &str, object_id: Option<&str>) -> Entry {
        let entry = Entry::new(kind, "message");
        match object_id {
            Some(id) => entry.object_id(id),
            None => entry,
        }
    }

    #[test]
    fn summary_counts_match_the_arrays() {
        let report = Report::from_documents(
            vec![
                DocumentResult {
                    path: "a.json".to_string(),
                    valid: true,
                    errors: Vec::new(),
                    warnings: vec![entry("hash_not_sha256", None)],
                    objects: 1,
                },
                DocumentResult {
                    path: "b.json".to_string(),
                    valid: false,
                    errors: vec![
                        entry("missing_property", Some("identity--1")),
                        entry("invalid_pattern", None),
                    ],
                    warnings: Vec::new(),
                    objects: 3,
                },
            ],
            vec![SkippedDocument {
                path: "c.json".to_string(),
                reason: "not_stix".to_string(),
            }],
        );

        assert_eq!(report.summary.files, 3);
        assert_eq!(report.summary.valid, 1);
        assert_eq!(report.summary.invalid, 1);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.objects, 4);
        assert_eq!(report.summary.errors, 2);
        assert_eq!(report.summary.warnings, 1);
    }

    #[test]
    fn report_has_four_top_level_keys_and_no_document() {
        let report = Report::from_documents(
            vec![DocumentResult {
                path: "a.json".to_string(),
                valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
                objects: 1,
            }],
            Vec::new(),
        );
        let value = serde_json::to_value(&report).unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["results", "schema_version", "skipped", "summary"]);
        assert!(object.get("objects").is_none());
        assert!(object.get("value").is_none());
        assert_eq!(object["schema_version"], 1);
    }

    #[test]
    fn human_output_names_path_and_object_id() {
        let report = Report::from_documents(
            vec![DocumentResult {
                path: "bad.json".to_string(),
                valid: false,
                errors: vec![entry("missing_property", Some("identity--1"))],
                warnings: Vec::new(),
                objects: 1,
            }],
            Vec::new(),
        );
        let output = render_human(&report);
        assert!(output.contains("bad.json: error [missing_property] (identity--1) message"));
        assert!(output
            .contains("1 files: 0 valid, 1 invalid, 0 skipped; 1 objects, 1 errors, 0 warnings"));
    }
}
