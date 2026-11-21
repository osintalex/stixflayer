//! Language-agnostic STIX pattern fixture schema and conformance tests.
//!
//! The fixtures under `testdata/stix/{valid,invalid}/patterns/` are the shared
//! corpus for every language binding. This file owns the schema checks; the
//! conformance checks that validate each pattern live alongside them.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use stixflayer::error::StixError;
use stixflayer::pattern::validate_pattern;

/// A valid-pattern fixture entry.
#[derive(Debug, Deserialize)]
struct ValidFixture {
    id: String,
    description: String,
    pattern: String,
    spec: String,
}

/// An invalid-pattern fixture entry.
#[derive(Debug, Deserialize)]
struct InvalidFixture {
    id: String,
    description: String,
    pattern: String,
    spec: String,
    layer: String,
    expected_error: String,
}

fn fixture_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("stix")
        .join(kind)
        .join("patterns")
}

fn load_files<T: DeserializeOwned>(dir: &Path) -> Vec<(PathBuf, T)> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            let parsed = serde_json::from_str(&text)
                .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
            (path, parsed)
        })
        .collect()
}

fn load_valid() -> Vec<ValidFixture> {
    load_files(&fixture_dir("valid"))
        .into_iter()
        .flat_map(|(_, entries): (PathBuf, Vec<ValidFixture>)| entries)
        .collect()
}

fn load_invalid() -> Vec<InvalidFixture> {
    load_files(&fixture_dir("invalid"))
        .into_iter()
        .flat_map(|(_, entries): (PathBuf, Vec<InvalidFixture>)| entries)
        .collect()
}

/// Validate the corpus schema, returning every problem found.
fn validate_fixtures(
    valid: &[ValidFixture],
    invalid: &[InvalidFixture],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut ids = HashSet::new();

    for entry in valid {
        if entry.id.is_empty() {
            errors.push("valid fixture has an empty id".to_string());
        }
        if !ids.insert(entry.id.clone()) {
            errors.push(format!("duplicate fixture id '{}'", entry.id));
        }
        if entry.description.is_empty() {
            errors.push(format!("{}: empty description", entry.id));
        }
        if entry.pattern.is_empty() {
            errors.push(format!("{}: empty pattern", entry.id));
        }
        if entry.spec.is_empty() {
            errors.push(format!("{}: missing spec anchor", entry.id));
        }
    }

    for entry in invalid {
        if entry.id.is_empty() {
            errors.push("invalid fixture has an empty id".to_string());
        }
        if !ids.insert(entry.id.clone()) {
            errors.push(format!("duplicate fixture id '{}'", entry.id));
        }
        if entry.description.is_empty() {
            errors.push(format!("{}: empty description", entry.id));
        }
        if entry.pattern.is_empty() {
            errors.push(format!("{}: empty pattern", entry.id));
        }
        if entry.spec.is_empty() {
            errors.push(format!("{}: missing spec anchor", entry.id));
        }
        if entry.layer != "grammar" && entry.layer != "semantic" {
            errors.push(format!("{}: unknown layer '{}'", entry.id, entry.layer));
        }
        if entry.expected_error.is_empty() {
            errors.push(format!("{}: missing expected_error", entry.id));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[test]
fn fixture_schema_accepts_corpus() {
    let valid = load_valid();
    let invalid = load_invalid();

    if let Err(errors) = validate_fixtures(&valid, &invalid) {
        panic!("fixture schema errors:\n{}", errors.join("\n"));
    }

    assert!(!valid.is_empty(), "valid fixture corpus is empty");
    assert!(!invalid.is_empty(), "invalid fixture corpus is empty");
}

#[test]
fn valid_fixtures_are_accepted() {
    for entry in load_valid() {
        validate_pattern(&entry.pattern)
            .unwrap_or_else(|error| panic!("{}: valid fixture rejected: {error}", entry.id));
    }
}

#[test]
fn invalid_fixtures_fail_at_the_declared_layer() {
    for entry in load_invalid() {
        let error = validate_pattern(&entry.pattern)
            .expect_err(&format!("{}: invalid fixture accepted", entry.id));

        let grammar_rejected = matches!(error, StixError::ParsePatternError(..));
        match entry.layer.as_str() {
            "grammar" => assert!(
                grammar_rejected,
                "{}: expected a grammar rejection, got {error}",
                entry.id
            ),
            "semantic" => assert!(
                !grammar_rejected,
                "{}: expected a semantic rejection, got {error}",
                entry.id
            ),
            other => panic!("{}: unknown layer '{other}'", entry.id),
        }

        let message = error.to_string();
        assert!(
            message.contains(&entry.expected_error),
            "{}: expected '{}' in message '{message}'",
            entry.id,
            entry.expected_error
        );
    }
}
