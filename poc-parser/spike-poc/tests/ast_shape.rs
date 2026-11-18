//! Structural checks for the pest -> `expr` AST bridge.

use ordered_float::OrderedFloat;
use spike_poc::{build, BuildGap};
use stixflayer::pattern::expr::{
    BooleanOperator, ComparisonComponent, ComparisonExpression, ComparisonOperator, Constant,
    ObservationExpression, ObservationOperator, Qualifier,
};

fn comparison(pattern: &str) -> ComparisonExpression {
    let ast = build(pattern).expect("pattern should build");
    let ObservationExpression::Comparison(ComparisonComponent::ComparisonExpression(expression)) =
        ast
    else {
        panic!("expected a single comparison: {ast:?}");
    };
    expression
}

#[test]
fn and_chains_are_left_associative() {
    let ast = build("[file:name = 'a' AND file:name = 'b' AND file:name = 'c']")
        .expect("pattern should build");
    let ObservationExpression::Comparison(ComparisonComponent::BooleanOp(inner, op, rhs)) = ast
    else {
        panic!("expected a boolean chain");
    };
    assert_eq!(op, BooleanOperator::And);
    assert_eq!(rhs.constant, Some(Constant::String("c".to_string())));

    let ComparisonComponent::BooleanOp(_, op, middle) = *inner else {
        panic!("expected a nested boolean chain");
    };
    assert_eq!(op, BooleanOperator::And);
    assert_eq!(middle.constant, Some(Constant::String("b".to_string())));
}

#[test]
fn qualifiers_nest_one_node_per_qualifier() {
    let ast = build("[file:name = 'x'] WITHIN 600 SECONDS REPEATS 5 TIMES")
        .expect("pattern should build");
    let ObservationExpression::Qualification(inner, outer) = ast else {
        panic!("expected a qualification");
    };
    assert_eq!(outer, Qualifier::Repeats(5));

    let ObservationExpression::Qualification(inner, middle) = *inner else {
        panic!("expected nested qualifications");
    };
    assert_eq!(middle, Qualifier::Within(OrderedFloat(600.0)));
    assert!(matches!(*inner, ObservationExpression::Comparison(_)));
}

#[test]
fn object_paths_are_flattened_the_way_the_validator_expects() {
    let expression = comparison("[file:hashes.'SHA-256' = 'x']");
    assert_eq!(expression.object_path.sco, "file");
    assert_eq!(expression.object_path.property, "hashes.'SHA-256'");

    let expression = comparison("[email-message:body_multipart[*].body_raw_ref.name = 'x']");
    assert_eq!(expression.object_path.sco, "email-message");
    assert_eq!(
        expression.object_path.property,
        "body_multipart[*].body_raw_ref.name"
    );
}

#[test]
fn observation_operators_are_preserved() {
    let ast = build("[file:name = 'a'] FOLLOWEDBY [file:name = 'b']").expect("valid");
    assert!(matches!(
        ast,
        ObservationExpression::ObservationOp(_, ObservationOperator::FollowedBy, _)
    ));
}

#[test]
fn literals_and_operators_are_lossless() {
    assert_eq!(
        comparison("[file:name LIKE '%.dll']").operator,
        ComparisonOperator::Like
    );
    assert_eq!(
        comparison("[file:name != 'x']").operator,
        ComparisonOperator::Neq
    );
    assert_eq!(
        comparison("[file:magic_number_hex = h'ffd8']").constant,
        Some(Constant::Hex("h'ffd8'".to_string()))
    );
    assert_eq!(
        comparison("[file:name = b'YWJjZA==']").constant,
        Some(Constant::Binary("b'YWJjZA=='".to_string()))
    );
}

#[test]
fn ast_shape_gaps_are_reported_not_silently_dropped() {
    assert_eq!(
        build("[(file:name = 'a' OR file:name = 'b') AND file:size = 1]").unwrap_err(),
        BuildGap::ParenthesisedComparison
    );
    assert_eq!(
        build("[file:name NOT = 'x']").unwrap_err(),
        BuildGap::NegatedComparison
    );
    assert_eq!(
        build("[NOT EXISTS file:name]").unwrap_err(),
        BuildGap::NegatedExists
    );
}
