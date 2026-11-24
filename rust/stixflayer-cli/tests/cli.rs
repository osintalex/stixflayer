//! End-to-end tests for the `stixflayer` binary.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde::Deserialize;
use serde_json::Value;
use stixflayer::bundles::Bundle;
use stixflayer::object::StixObject;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("project root exists")
}

fn fixture(relative: &str) -> String {
    project_root()
        .join("testdata/stix")
        .join(relative)
        .to_string_lossy()
        .into_owned()
}

fn cli() -> Command {
    let mut command = Command::cargo_bin("stixflayer").expect("binary is built");
    command.current_dir(project_root());
    command
}

fn run(args: &[&str]) -> Output {
    cli().args(args).output().expect("binary runs")
}

fn run_json(args: &[&str]) -> (i32, Value) {
    let mut all = Vec::with_capacity(args.len() + 1);
    if !args.contains(&"--json") {
        all.push("--json");
    }
    all.extend_from_slice(args);
    let output = run(&all);
    let code = output.status.code().expect("process exited normally");
    assert!(
        code == 0 || code == 1,
        "unexpected exit {code}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout is not JSON: {error}"));
    (code, report)
}

fn valid_bundle_text() -> String {
    fs::read_to_string(project_root().join("testdata/stix/valid/bundle.json")).unwrap()
}

fn valid_identity_line() -> &'static str {
    r#"{"type":"identity","spec_version":"2.1","id":"identity--550e8400-e29b-41d4-a716-446655440000","created":"2016-05-12T08:17:27Z","modified":"2016-05-12T08:17:27Z","name":"Acme"}"#
}

#[test]
fn help_lists_every_flag() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--jobs",
        "--json",
        "--print-schema",
        "--fail-on-warnings",
        "--version",
    ] {
        assert!(help.contains(flag), "help is missing {flag}:\n{help}");
    }
    for removed in [
        "--allow-custom",
        "--allow-custom-relationships",
        "--no-strict",
    ] {
        assert!(
            !help.contains(removed),
            "help still exposes non-spec flag {removed}:\n{help}"
        );
    }
}

#[test]
fn version_prints_the_crate_version() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    let version = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        version.trim(),
        format!("stixflayer {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn no_arguments_exits_two_with_usage() {
    let output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Usage:"), "stderr was: {stderr}");
    assert!(stderr.contains("<PATH>"), "stderr was: {stderr}");
}

#[test]
fn print_schema_exits_zero_without_paths() {
    let output = run(&["--print-schema"]);
    assert!(output.status.success());
    let schema: Value = serde_json::from_slice(&output.stdout).expect("schema is JSON");
    assert!(schema.get("$schema").is_some());
    assert!(schema["properties"]["schema_version"].is_object());
    assert!(
        jsonschema::validator_for(&schema).is_ok(),
        "printed schema is not a usable JSON Schema"
    );
}

#[test]
fn jobs_zero_matches_the_default() {
    let fixture = fixture("valid/bundle.json");
    let default = run(&[&fixture]);
    let zero = run(&["-j", "0", &fixture]);
    assert!(default.status.success());
    assert_eq!(default.stdout, zero.stdout);
}

#[test]
fn all_valid_exits_zero() {
    let (code, report) = run_json(&[&fixture("valid/bundle.json")]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["valid"], 1);
    assert_eq!(report["summary"]["objects"], 2);
}

#[test]
fn any_invalid_exits_one() {
    let (code, report) = run_json(&[&fixture("invalid/sdo/identity-no-name.json")]);
    assert_eq!(code, 1);
    assert_eq!(report["summary"]["invalid"], 1);
}

#[test]
fn skips_only_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("not-stix.json"), r#"{"hello":"world"}"#).unwrap();
    fs::write(dir.path().join("not-json.json"), "{oops").unwrap();

    let (code, report) = run_json(&[dir.path().to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["files"], 2);
    assert_eq!(report["summary"]["skipped"], 2);
    assert_eq!(report["summary"]["valid"], 0);
    assert_eq!(report["summary"]["invalid"], 0);
}

#[test]
fn missing_path_exits_two() {
    let output = run(&["does-not-exist.json"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot access path"),
        "stderr was: {stderr}"
    );
}

#[test]
fn unreadable_file_exits_two() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();

    let output = run(&[path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("cannot read file"), "stderr was: {stderr}");
}

#[test]
fn warnings_only_exit_zero_unless_gated() {
    let fixture = fixture("valid/scos/file-md5.json");
    let (code, report) = run_json(&[&fixture]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["warnings"], 1);

    let (gated, _) = run_json(&["--fail-on-warnings", &fixture]);
    assert_eq!(gated, 1);
}

#[test]
fn json_output_is_the_only_stdout() {
    let output = run(&["--json", &fixture("invalid/sdo/identity-no-name.json")]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.trim_start().starts_with('{'));
    assert!(!stdout.contains(": error ["));
    assert!(output.stderr.is_empty());
}

#[test]
fn report_shape_is_stable() {
    let (_, report) = run_json(&[&fixture("valid/bundle.json")]);
    let object = report.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["results", "schema_version", "skipped", "summary"]);
    assert!(object.get("objects").is_none());
    assert!(object.get("value").is_none());
    assert_eq!(report["schema_version"], 1);

    let result = &report["results"][0];
    let mut result_keys: Vec<_> = result
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    result_keys.sort();
    assert_eq!(result_keys, ["errors", "path", "valid", "warnings"]);
}

#[test]
fn summary_counts_match_the_arrays() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("valid.json"),
        fs::read_to_string(project_root().join("testdata/stix/valid/bundle.json")).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.path().join("invalid.json"),
        fs::read_to_string(project_root().join("testdata/stix/invalid/sdo/identity-no-name.json"))
            .unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join("skip.json"), r#"{"hello":"world"}"#).unwrap();
    fs::write(dir.path().join("not-json.json"), "{oops").unwrap();

    let (code, report) = run_json(&[dir.path().to_str().unwrap()]);
    assert_eq!(code, 1);
    let summary = &report["summary"];
    let results = report["results"].as_array().unwrap();
    let skipped = report["skipped"].as_array().unwrap();

    assert_eq!(summary["files"], results.len() + skipped.len());
    assert_eq!(
        summary["valid"],
        results.iter().filter(|r| r["valid"] == true).count()
    );
    assert_eq!(
        summary["invalid"],
        results.iter().filter(|r| r["valid"] == false).count()
    );
    assert_eq!(summary["skipped"], skipped.len());
    assert_eq!(
        summary["errors"],
        results
            .iter()
            .map(|r| r["errors"].as_array().unwrap().len())
            .sum::<usize>()
    );
    assert_eq!(
        summary["warnings"],
        results
            .iter()
            .map(|r| r["warnings"].as_array().unwrap().len())
            .sum::<usize>()
    );
    assert_eq!(summary["objects"], 3);
}

#[test]
fn real_report_validates_against_the_printed_schema() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("valid.json"),
        fs::read_to_string(project_root().join("testdata/stix/valid/bundle.json")).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.path().join("invalid.json"),
        fs::read_to_string(project_root().join("testdata/stix/invalid/sdo/identity-no-name.json"))
            .unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join("skip.json"), r#"{"hello":"world"}"#).unwrap();

    let (_, report) = run_json(&[dir.path().to_str().unwrap()]);
    let schema: Value = serde_json::from_str(stixflayer_cli::REPORT_SCHEMA).unwrap();
    jsonschema::validate(&schema, &report).expect("report matches the printed schema");
}

#[test]
fn jobs_one_and_eight_produce_identical_reports() {
    let directory = project_root().join("testdata/stix/valid");
    let one = run(&["-j", "1", "--json", directory.to_str().unwrap()]);
    let eight = run(&["-j", "8", "--json", directory.to_str().unwrap()]);
    assert_eq!(one.status.code(), eight.status.code());
    assert_eq!(one.stdout, eight.stdout);
}

#[test]
fn standard_input_is_reported_under_dash() {
    let mut command = cli();
    command
        .arg("-")
        .arg("--json")
        .write_stdin(valid_bundle_text());
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["results"][0]["path"], "-");
}

#[test]
fn explicit_txt_path_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("document.txt");
    fs::write(&path, valid_bundle_text()).unwrap();

    let (code, report) = run_json(&[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["valid"], 1);
}

#[test]
fn directory_scan_ignores_non_stix_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("feed.stix2"), valid_bundle_text()).unwrap();
    fs::write(dir.path().join("bundle.json"), valid_bundle_text()).unwrap();
    fs::write(dir.path().join("notes.md"), "{not json").unwrap();
    fs::write(dir.path().join("config.yaml"), "[]").unwrap();

    let (code, report) = run_json(&[dir.path().to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["files"], 2);
    assert_eq!(report["summary"]["skipped"], 0);
    assert_eq!(report["summary"]["valid"], 2);
}

#[test]
fn jsonl_files_are_validated_line_by_line() {
    let dir = tempfile::tempdir().unwrap();

    let good = dir.path().join("objects.jsonl");
    fs::write(
        &good,
        format!("{}\n{}\n", valid_identity_line(), valid_identity_line()),
    )
    .unwrap();
    let (code, report) = run_json(&[good.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["objects"], 2);

    let bad = dir.path().join("bad.jsonl");
    fs::write(&bad, format!("{}\n{{not json\n", valid_identity_line())).unwrap();
    let (code, report) = run_json(&[bad.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(
        report["results"][0]["errors"][0]["kind"],
        "deserialization_error"
    );
    assert!(report["results"][0]["errors"][0]["message"]
        .as_str()
        .unwrap()
        .contains("line 2"));

    let skipped = dir.path().join("skip.jsonl");
    fs::write(&skipped, "{\"hello\":\"world\"}\n").unwrap();
    let (code, report) = run_json(&[skipped.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(report["skipped"][0]["reason"], "not_stix");
}

#[test]
fn unparseable_stix_extension_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("feed.stix2");
    fs::write(&path, "{not json").unwrap();

    let (code, report) = run_json(&[path.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(report["results"][0]["valid"], false);
    assert_eq!(
        report["results"][0]["errors"][0]["kind"],
        "deserialization_error"
    );
}

#[test]
fn custom_properties_are_accepted_by_default() {
    let fixture = fixture("allow_custom/valid/sdos/indicator-custom.json");
    let (code, report) = run_json(&[&fixture]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["valid"], 1);
}

#[test]
fn extensionless_custom_object_is_valid_with_a_warning() {
    let fixture = fixture("custom_objects/extensionless-custom-object.json");
    let (code, report) = run_json(&[&fixture]);
    assert_eq!(code, 0);
    assert_eq!(report["results"][0]["valid"], true);
    assert!(report["results"][0]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning["kind"] == "custom_missing_extension"));
}

#[test]
fn custom_object_relationship_endpoints_stay_strict() {
    let fixture = fixture("custom_objects/custom-object-relationship.json");
    let (code, report) = run_json(&[&fixture]);
    assert_eq!(code, 1);
    assert!(report["results"][0]["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error["kind"] == "invalid_nested_object"));
}

#[test]
fn undefined_relationship_pairs_stay_strict() {
    let fixture = fixture("custom_objects/tool-uses-attack-pattern.json");
    let (code, report) = run_json(&[&fixture]);
    assert_eq!(code, 1);
    assert!(report["results"][0]["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error["kind"] == "invalid_nested_object"));
}

#[test]
fn semantic_errors_are_not_opt_out() {
    let fixture = fixture("invalid/sco/ipv4-bad-format.json");
    let (code, _) = run_json(&[&fixture]);
    assert_eq!(code, 1);
}

#[test]
fn human_output_snapshot() {
    let output = run(&["testdata/stix/invalid/sdo/indicator-no-valid-from.json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout,
        concat!(
            "testdata/stix/invalid/sdo/indicator-no-valid-from.json: error [missing_property] ",
            "(indicator--6f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f) ",
            "`indicator` is missing required property 'valid_from'\n",
            "1 files: 0 valid, 1 invalid, 0 skipped; 1 objects, 1 errors, 0 warnings\n"
        )
    );
}

#[test]
fn a_single_large_bundle_uses_object_level_validation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large.json");
    let objects: Vec<Value> = (0..3000)
        .map(|index| {
            serde_json::json!({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": format!("attack-pattern--00000000-0000-4000-8000-{index:012x}"),
                "created": "2016-05-12T08:17:27.000Z",
                "modified": "2016-05-12T08:17:27.000Z",
                "name": format!("Attack Pattern {index}")
            })
        })
        .collect();
    let bundle = serde_json::json!({
        "type": "bundle",
        "id": "bundle--44580eb5-a924-475f-970c-8b47ee07f641",
        "objects": objects
    });
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();

    let (code, report) = run_json(&[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(report["summary"]["files"], 1);
    assert_eq!(report["summary"]["objects"], 3000);
}

#[derive(Debug, Deserialize)]
struct Rule {
    fixture: String,
    #[serde(default)]
    allow_custom: bool,
    #[serde(default)]
    expected_behavior: Option<String>,
}

#[test]
fn every_matrix_fixture_matches_the_engine_verdict() {
    let matrix_path = project_root().join("testdata/test_matrix.json");
    let matrix: Value = serde_json::from_str(&fs::read_to_string(&matrix_path).unwrap()).unwrap();

    for section in ["validation_rules", "custom_properties"] {
        let rules: HashMap<String, Rule> = serde_json::from_value(matrix[section].clone()).unwrap();
        for (name, rule) in rules {
            let path = fixture(&rule.fixture);
            let text = fs::read_to_string(&path).unwrap();
            let (code, report) = run_json(&[path.as_str()]);

            let results = report["results"].as_array().unwrap();
            let skipped = report["skipped"].as_array().unwrap();
            if results.is_empty() {
                assert_eq!(skipped.len(), 1, "rule {name} was not classified");
                assert_eq!(
                    skipped[0]["reason"], "unsupported_spec_version",
                    "rule {name} skipped for an unexpected reason"
                );
                continue;
            }

            let cli_valid = results[0]["valid"].as_bool().unwrap();
            let value: Value = serde_json::from_str(&text).unwrap();
            // The CLI always accepts custom properties, matching STIX 2.1.
            // Matrix rules that deliberately set allow_custom=false are
            // library-level strictness checks, not CLI expectations.
            if !rule.allow_custom && rule.fixture.starts_with("allow_custom/") {
                assert!(cli_valid, "rule {name} should be valid in the CLI");
                continue;
            }

            let engine_valid = if value.get("type").and_then(Value::as_str) == Some("bundle") {
                Bundle::from_json_outcome(&text).valid
            } else {
                StixObject::from_value_outcome(value, true, true).valid
            };
            assert_eq!(
                cli_valid, engine_valid,
                "rule {name} disagrees with the engine for {}",
                rule.fixture
            );

            match rule.expected_behavior.as_deref() {
                Some("parses_successfully") => {
                    assert!(cli_valid, "rule {name} expected a valid document");
                    assert_eq!(code, 0);
                }
                Some("validation_error" | "stix_error" | "deserialization_error") | None => {
                    assert!(!cli_valid, "rule {name} expected an invalid document");
                    assert_eq!(code, 1);
                }
                Some(other) => panic!("rule {name} has unknown expected_behavior {other}"),
            }
        }
    }
}

#[test]
fn bundle_fixtures_match_bundle_from_json_outcome() {
    let fixtures = [
        "valid/bundle.json",
        "valid/sdos/amnesty-indicators.json",
        "invalid/bundle/bundle-empty.json",
        "invalid/bundle/bundle-duplicate-ids.json",
        "invalid/bundle/bundle-invalid-type.json",
    ];
    for fixture in fixtures {
        let path = fixture_path(fixture);
        let text = fs::read_to_string(&path).unwrap();
        let (_, report) = run_json(&[path.to_str().unwrap()]);
        let cli_valid = report["results"][0]["valid"].as_bool().unwrap();
        assert_eq!(
            cli_valid,
            Bundle::from_json_outcome(&text).valid,
            "bundle verdict differs for {fixture}"
        );
    }
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(&fixture(relative)).to_path_buf()
}
