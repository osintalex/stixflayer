//! The extended AST must represent every must-pass pattern and check the same
//! semantic rules.

use harness::{load_corpus, Verdict};
use spike_poc::mirror::{build, check, Component, Observation};

fn component(pattern: &str) -> Component {
    let Observation::Comparison(component) = build(pattern).expect("should build") else {
        panic!("expected a single observation");
    };
    component
}

#[test]
fn every_must_pass_pattern_builds() {
    let cases = load_corpus(&harness::corpus_dir()).expect("corpus");
    let accept: Vec<_> = cases
        .iter()
        .filter(|case| case.expected == Verdict::Accept)
        .collect();
    assert_eq!(accept.len(), 51);

    for case in accept {
        build(&case.input).unwrap_or_else(|error| panic!("{}: {error}", case.id));
    }
}

#[test]
fn negation_is_preserved_without_rewriting() {
    let Component::Expression(not_equal) = component("[file:name NOT = 'x']") else {
        panic!("expected a comparison");
    };
    assert!(not_equal.negated);
    assert_eq!(not_equal.operator, stixflayer::pattern::expr::ComparisonOperator::Eq);

    let Component::Expression(not_in) = component("[file:name NOT IN ('a','b')]") else {
        panic!("expected a comparison");
    };
    assert!(not_in.negated);
    assert_eq!(not_in.operator, stixflayer::pattern::expr::ComparisonOperator::In);

    let Component::Expression(not_exists) = component("[NOT EXISTS file:name]") else {
        panic!("expected a comparison");
    };
    assert!(not_exists.negated);
    assert_eq!(not_exists.operator, stixflayer::pattern::expr::ComparisonOperator::Exists);
}

#[test]
fn groups_work_on_both_sides() {
    // Left group: the case the old AST could hold but the old builder rejected.
    assert!(matches!(
        component("[(file:name = 'a' OR file:name = 'b') AND file:size = 1]"),
        Component::BooleanOp(_, _, _)
    ));

    // Right group: the case the old AST could not hold at all.
    assert!(matches!(
        component("[file:name = 'a' AND (file:size = 1 OR file:size = 2)]"),
        Component::BooleanOp(_, _, _)
    ));
}

#[test]
fn qualifier_ranges_are_semantic_errors() {
    assert!(check(&build("[file:name = 'x'] REPEATS 0 TIMES").unwrap()).is_err());
    assert!(check(&build("[file:name = 'x'] WITHIN 0 SECONDS").unwrap()).is_err());
    assert!(check(&build("[file:name = 'x'] REPEATS 5 TIMES").unwrap()).is_ok());
}

#[test]
fn the_four_gap_cases_are_semantically_valid() {
    for pattern in [
        "[(file:name = 'pdf.exe' OR file:size = '371712') AND file:created = t'2014-01-13T07:03:17Z']",
        "[file:name NOT = 'x']",
        "[file:name NOT IN ('a','b')]",
        "[NOT EXISTS file:name]",
    ] {
        let observation = build(pattern).expect("should build");
        assert!(check(&observation).is_ok(), "{pattern}");
    }
}
