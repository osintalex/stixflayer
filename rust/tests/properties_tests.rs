//! Registry completeness tests for the property registry.
//!
//! The registry must structurally cover every property that appears in a
//! valid STIX fixture: for every fixture with a recognized `type`, each
//! top-level key must be a known property of that type. This is the guard
//! against the registry drifting from the real serde type definitions.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use stixflayer::properties::{type_properties, type_properties_by_category};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn walk_json_files(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {}", dir.display(), e));
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk_json_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
}

fn fixture_paths(subdir: &str) -> Vec<PathBuf> {
    let mut root = project_root();
    root.push("..");
    root.push("testdata");
    root.push("stix");
    root.push(subdir);
    let mut out = Vec::new();
    walk_json_files(&root, &mut out);
    out.sort();
    out
}

#[test]
fn registry_covers_all_valid_fixture_properties() {
    let mut checked = 0;
    let mut recognized = 0;
    for path in fixture_paths("valid") {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        let value: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
        let Some(object) = value.as_object() else {
            continue;
        };
        let Some(type_name) = object.get("type").and_then(Value::as_str) else {
            continue;
        };
        checked += 1;
        let Some(props) = type_properties(type_name) else {
            // structurally permissive types (custom, bundle) have no registry
            assert!(
                type_properties_by_category(type_name).is_none(),
                "type `{}` in {} is missing from the registry but its category is not permissive",
                type_name,
                path.display()
            );
            continue;
        };
        recognized += 1;
        for key in object.keys() {
            assert!(
                props.known.contains(&key.as_str()),
                "fixture {} uses property `{}` which is not a known property of type `{}`.\nknown: {:?}",
                path.display(),
                key,
                type_name,
                props.known
            );
        }
    }
    assert!(checked > 0, "no fixtures checked");
    assert!(
        recognized > 0,
        "no fixtures with a registry-recognized type were checked"
    );
}

#[test]
fn composed_registry_includes_common_and_type_properties() {
    let props = type_properties("attack-pattern").expect("attack-pattern in registry");
    for key in ["name", "description", "kill_chain_phases"] {
        assert!(props.known.contains(&key), "attack-pattern known: {key}");
    }
    for key in ["type", "id", "spec_version", "created", "modified", "labels", "extensions"] {
        assert!(props.known.contains(&key), "attack-pattern common: {key}");
    }
    // SDOs cannot have `defanged`
    assert!(!props.known.contains(&"defanged"), "defanged on SDO");

    // Required: variant non-Option fields + common non-Option fields (id)
    assert!(props.required.contains(&"name"), "name required");
    assert!(props.required.contains(&"id"), "id required");
    assert!(!props.required.contains(&"description"));
}

#[test]
fn sco_registry_mirrors_sco_common_subset() {
    let props = type_properties("ipv4-addr").expect("ipv4-addr in registry");
    for key in ["type", "id", "defanged", "extensions"] {
        assert!(props.known.contains(&key), "ipv4-addr common: {key}");
    }
    for key in ["value", "resolves_to_refs", "belongs_to_refs"] {
        assert!(props.known.contains(&key), "ipv4-addr variant: {key}");
    }
    for key in ["created", "modified", "revoked", "labels", "created_by_ref"] {
        assert!(!props.known.contains(&key), "SCO common: {key}");
    }
    assert!(props.required.contains(&"id"), "id required");
    assert!(props.required.contains(&"value"), "value required");
}

#[test]
fn legacy_email_address_alias_resolves() {
    let alias = type_properties("email-address").expect("email-address alias in registry");
    let canonical = type_properties("email-addr").expect("email-addr in registry");
    assert_eq!(alias.known, canonical.known);
    assert_eq!(alias.required, canonical.required);
}

#[test]
fn meta_types_are_registered() {
    let marking = type_properties("marking-definition").expect("marking-definition");
    assert!(marking.known.contains(&"definition_type"));
    assert!(marking.known.contains(&"definition"));
    assert!(marking.known.contains(&"type"));
    assert!(!marking.known.contains(&"defanged"));

    let language = type_properties("language-content").expect("language-content");
    assert!(language.known.contains(&"object_ref"));
    assert!(language.known.contains(&"contents"));
    // non-Option variant + common fields are required
    assert!(language.required.contains(&"object_ref"));
    assert!(language.required.contains(&"contents"));
    assert!(language.required.contains(&"id"));

    let extension = type_properties("extension-definition").expect("extension-definition");
    assert!(extension.known.contains(&"name"));
    assert!(extension.known.contains(&"extension_types"));
}

#[test]
fn relationship_registry_includes_sro_fields() {
    let relationship = type_properties("relationship").expect("relationship");
    for key in ["relationship_type", "source_ref", "target_ref", "start_time", "stop_time"] {
        assert!(relationship.known.contains(&key), "relationship: {key}");
    }
    for key in ["relationship_type", "source_ref", "target_ref", "id"] {
        assert!(relationship.required.contains(&key), "relationship required: {key}");
    }

    let sighting = type_properties("sighting").expect("sighting");
    assert!(sighting.known.contains(&"sighting_of_ref"));
    assert!(sighting.known.contains(&"count"));
    assert!(sighting.required.contains(&"sighting_of_ref"));
    assert!(!sighting.required.contains(&"count"));
}

#[test]
fn permissive_and_unknown_types_return_none() {
    assert!(type_properties("bundle").is_none());
    assert!(type_properties("custom-object").is_none());
    assert!(type_properties("not-a-type").is_none());
    assert!(type_properties("").is_none());
}
