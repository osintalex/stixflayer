//! Pin the baseline column: the shipped validator's known verdicts.

use harness::load_corpus;

fn is_rejected(rejected: &[String], id: &str) -> bool {
    rejected.iter().any(|candidate| candidate == id)
}

#[test]
fn reproduces_spec_example_failures() {
    let cases = load_corpus(&harness::corpus_dir()).unwrap();
    let rejected: Vec<String> = cases
        .iter()
        .filter(|case| stixflayer::pattern::validate_pattern(&case.input).is_err())
        .map(|case| case.id.clone())
        .collect();

    let spec_failures: Vec<String> = rejected
        .iter()
        .filter(|id| id.starts_with('V') && id[1..].parse::<usize>().is_ok_and(|n| n <= 23))
        .cloned()
        .collect();

    assert_eq!(spec_failures, vec!["V02", "V09", "V17", "V18", "V20"]);
}

#[test]
fn reproduces_shipped_behavior_cases() {
    let cases = load_corpus(&harness::corpus_dir()).unwrap();
    let rejected: Vec<String> = cases
        .iter()
        .filter(|case| stixflayer::pattern::validate_pattern(&case.input).is_err())
        .map(|case| case.id.clone())
        .collect();

    for id in ["V24", "V35", "V36", "V37", "V49"] {
        assert!(is_rejected(&rejected, id), "{id} should be rejected by the baseline");
    }
    for id in ["I17", "I20", "I22"] {
        assert!(!is_rejected(&rejected, id), "{id} should be accepted by the baseline");
    }
}
