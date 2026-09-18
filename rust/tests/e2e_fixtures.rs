//! End-to-end fixture-driven tests driven by `testdata/test_matrix.json`.
//!
//! These tests share the same fixtures and expected outcomes as
//! `tests/test_matrix.py`. Keeping the matrix language-agnostic means other
//! language bindings can reuse the same corpus and expectations.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use stixflayer::bundles::Bundle;
use stixflayer::cyber_observable_objects::sco::CyberObject;
use stixflayer::domain_objects::sdo::DomainObject;
use stixflayer::relationship_objects::RelationshipObject;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cargo manifest should be inside the project root")
        .to_path_buf()
}

fn load_fixture(path: &str) -> String {
    let fixture_path = project_root().join("testdata").join("stix").join(path);
    fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", fixture_path.display(), e))
}

fn load_matrix() -> Value {
    let path = project_root().join("testdata").join("test_matrix.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read test matrix {}: {}", path.display(), e));
    serde_json::from_str(&text).expect("test_matrix.json is valid JSON")
}

#[derive(Debug, Deserialize)]
struct Rule {
    category: String,
    #[serde(rename = "object_type")]
    object_type: String,
    fixture: String,
    #[serde(default)]
    strict: Option<bool>,
    #[serde(default)]
    allow_custom: Option<bool>,
    #[serde(default)]
    expected_behavior: Option<String>,
    #[serde(default)]
    expected_error_substring: Option<String>,
}

fn parse(category: &str, object_type: &str, json: &str, allow_custom: bool) -> Result<(), String> {
    match category {
        "sdo" => DomainObject::from_json(json, allow_custom).map(|_| ()),
        "sco" => CyberObject::from_json(json, allow_custom).map(|_| ()),
        "sro" => RelationshipObject::from_json(json, allow_custom).map(|_| ()),
        "meta" => {
            if object_type == "bundle" {
                Bundle::from_json(json).map(|_| ())
            } else {
                panic!("unsupported meta object_type: {}", object_type);
            }
        }
        other => panic!("unsupported category: {}", other),
    }
    .map_err(|e| e.to_string())
}

fn run_matrix_section(section: &str) {
    let matrix = load_matrix();
    let rules: HashMap<String, Rule> = serde_json::from_value(matrix[section].clone())
        .unwrap_or_else(|e| panic!("{} section malformed: {}", section, e));

    for (key, rule) in rules {
        // The Rust enum-level from_json methods are currently strict-only, so
        // skip non-strict rules here; the Python binding covers them.
        if rule.strict == Some(false) {
            continue;
        }

        let allow_custom = rule.allow_custom.unwrap_or(false);
        let json = load_fixture(&rule.fixture);
        let result = parse(&rule.category, &rule.object_type, &json, allow_custom);
        let expected_behavior = rule.expected_behavior.as_deref().unwrap_or("validation_error");

        match expected_behavior {
            "parses_successfully" => assert!(
                result.is_ok(),
                "rule '{}' expected success but got error: {:?}",
                key,
                result.err()
            ),
            _ => {
                let err = result.expect_err(&format!("rule '{}' expected an error", key));
                if let Some(sub) = rule.expected_error_substring {
                    assert!(
                        err.contains(&sub),
                        "rule '{}' error did not contain substring {:?}: {:?}",
                        key,
                        sub,
                        err
                    );
                }
            }
        }
    }
}

#[test]
fn validation_rules_from_matrix() {
    run_matrix_section("validation_rules");
}

#[test]
fn custom_properties_from_matrix() {
    run_matrix_section("custom_properties");
}
