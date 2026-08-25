//! End-to-end fixture-driven tests for STIX 2.1 validation.
//!
//! These tests load JSON fixtures from `testdata/stix/` and exercise the
//! library the way a consumer would: parse typed objects, run validation,
//! and roundtrip through JSON.

use std::fs;
use std::path::PathBuf;

use stixflayer::bundles::Bundle;
use stixflayer::domain_objects::sdo_types::Indicator;
use stixflayer::FromJson;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_fixture(path: &str) -> String {
    let mut fixture_path = project_root();
    fixture_path.push("..");
    fixture_path.push("testdata");
    fixture_path.push("stix");
    fixture_path.push(path);
    fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", fixture_path.display(), e))
}

// ============================================================================
// Valid fixture acceptance tests
// ============================================================================

#[test]
fn test_valid_indicator_roundtrip() {
    let json = load_fixture("valid/sdos/indicator.json");
    let obj = Indicator::from_json(&json, true, "2.1", false).unwrap();
    assert_eq!(obj.name.as_deref(), Some("Poison Ivy Malware"));
    assert_eq!(obj.pattern_type, "stix");
}

#[test]
fn test_valid_bundle_accepted() {
    let json = load_fixture("valid/bundle.json");
    let bundle = Bundle::from_json(&json).unwrap();
    assert_eq!(bundle.get_objects().len(), 2);
}

// ============================================================================
// Invalid fixture rejection tests
// ============================================================================

#[test]
fn test_invalid_indicator_missing_name_rejected() {
    let json = load_fixture("invalid/sdo/indicator-no-name.json");
    let err = Indicator::from_json(&json, true, "2.1", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("missing required property 'name'"),
        "Expected error about missing name, got: {}",
        msg
    );
}

#[test]
fn test_invalid_indicator_bad_pattern_type_rejected() {
    let json = load_fixture("invalid/sdo/indicator-bad-pattern-type.json");
    let err = Indicator::from_json(&json, true, "2.1", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("pattern type should come from the STIX pattern type open vocabulary"),
        "Expected error about bad pattern_type, got: {}",
        msg
    );
}

#[test]
fn test_invalid_bundle_empty_rejected() {
    let json = load_fixture("invalid/bundle/bundle-empty.json");
    let err = Bundle::from_json(&json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Bundle must contain at least one object"),
        "Expected error about empty bundle, got: {}",
        msg
    );
}
