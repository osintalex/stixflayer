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

    assert_eq!(valid.len(), 64, "unexpected number of valid fixtures");
    assert_eq!(invalid.len(), 34, "unexpected number of invalid fixtures");
}

#[test]
fn fixture_schema_rejects_duplicate_ids() {
    let valid = vec![ValidFixture {
        id: "V01".to_string(),
        description: "first".to_string(),
        pattern: "[file:name = 'a']".to_string(),
        spec: "9.6.1".to_string(),
    }];
    let invalid = vec![InvalidFixture {
        id: "V01".to_string(),
        description: "duplicate across directories".to_string(),
        pattern: "[file:name = ]".to_string(),
        spec: "9.6.1".to_string(),
        layer: "grammar".to_string(),
        expected_error: "a value".to_string(),
    }];

    let errors = validate_fixtures(&valid, &invalid).expect_err("duplicate id must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("duplicate fixture id")),
        "expected a duplicate-id error, got {errors:?}"
    );
}

#[test]
fn fixture_schema_rejects_unknown_layer() {
    let invalid = vec![InvalidFixture {
        id: "I99".to_string(),
        description: "bad layer".to_string(),
        pattern: "[file:name = ]".to_string(),
        spec: "9.6.1".to_string(),
        layer: "lexer".to_string(),
        expected_error: "a value".to_string(),
    }];

    let errors = validate_fixtures(&[], &invalid).expect_err("unknown layer must be rejected");
    assert!(
        errors.iter().any(|error| error.contains("unknown layer")),
        "expected an unknown-layer error, got {errors:?}"
    );
}

#[test]
fn fixture_schema_requires_layer_and_expected_error() {
    let missing = r#"{"id":"I99","description":"x","pattern":"x","spec":"9.6.1"}"#;
    assert!(
        serde_json::from_str::<InvalidFixture>(missing).is_err(),
        "layer and expected_error must be required"
    );
}

#[test]
fn valid_set_contains_all_spec_examples() {
    let spec_examples_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("poc-parser")
        .join("corpus")
        .join("spec_examples.txt");
    let examples: Vec<String> = fs::read_to_string(&spec_examples_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", spec_examples_path.display()))
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    assert_eq!(examples.len(), 23, "expected 23 specification examples");

    let valid = load_valid();
    let anchored: Vec<&ValidFixture> = valid.iter().filter(|entry| entry.spec == "9.8").collect();
    assert_eq!(
        anchored.len(),
        23,
        "expected 23 valid fixtures anchored at 9.8"
    );

    for example in examples {
        assert!(
            anchored.iter().any(|entry| entry.pattern == example),
            "specification example missing from fixtures: {example}"
        );
    }
}

#[test]
fn compliance_cases_declare_the_expected_layer() {
    let valid = load_valid();
    let invalid = load_invalid();

    for id in ["V43", "V44"] {
        let entry = invalid
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("{id} must be an invalid fixture"));
        assert_eq!(
            entry.layer, "semantic",
            "{id} rejects in the semantic layer"
        );
    }

    for id in ["V45", "V51"] {
        let entry = invalid
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("{id} must be an invalid fixture"));
        assert_eq!(
            entry.layer, "semantic",
            "{id} rejects in the semantic layer"
        );
    }

    for id in ["V52", "V53"] {
        assert!(
            valid.iter().any(|entry| entry.id == id),
            "{id} must be a valid fixture"
        );
    }
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
