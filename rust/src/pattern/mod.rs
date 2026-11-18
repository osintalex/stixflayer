//! A Rust implementation of the STIX 2.1 Patterning grammar.
//!
//! The grammar is hand-ported to pest in `stix.pest`; this module builds the
//! typed [`expr`] AST from the pest pair tree and maps parser failures to
//! plain-language diagnostics with a line and column.

pub mod expr;

use pest::error::{Error as PestError, ErrorVariant, LineColLocation};
use pest::iterators::Pair;
use pest::Parser;

use crate::base::Stix;
use crate::error::StixError;
use crate::types::Timestamp;
use expr::*;

/// The pest parser generated from `stix.pest`.
///
/// The module is private: the generated `Rule` enum is an implementation
/// detail used by the diagnostics and coverage tests, not public API.
#[allow(missing_docs)]
mod grammar {
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "pattern/stix.pest"]
    pub struct StixParser;
}

use grammar::{Rule, StixParser};

/// A failure while turning a valid parse tree into the typed AST.
///
/// The grammar rejects malformed input before this layer, so a failure here
/// means a value could not be represented (for example an integer overflow).
type BuildResult<T> = Result<T, &'static str>;

/// Validate a STIX Pattern string.
///
/// Parses the pattern against the STIX 2.1 patterning grammar and then applies
/// the patterning semantic rules. A grammar failure is reported as
/// [`StixError::ParsePatternError`] with a `line:column` position and a plain
/// description of what was expected; a semantic failure is reported as a
/// [`StixError::ValidationError`].
pub fn validate_pattern(pattern: &str) -> Result<(), StixError> {
    let observation = parse_pattern(pattern)?;
    observation.stix_check()
}

/// Parse a pattern into the typed AST without applying semantic checks.
fn parse_pattern(pattern: &str) -> Result<ObservationExpression, StixError> {
    let mut pairs = StixParser::parse(Rule::pattern, pattern).map_err(|error| {
        StixError::ParsePatternError(pattern.to_string(), format_parse_error(pattern, &error))
    })?;

    let root = pairs.next().ok_or_else(|| {
        StixError::ParsePatternError(
            pattern.to_string(),
            "the pattern could not be interpreted".to_string(),
        )
    })?;

    build_observation_expression(root).map_err(|_| {
        StixError::ParsePatternError(
            pattern.to_string(),
            "the pattern contains a value that is out of range".to_string(),
        )
    })
}

fn build_observation_expression(pair: Pair<Rule>) -> BuildResult<ObservationExpression> {
    let expressions = pair
        .into_inner()
        .find(|inner| inner.as_rule() == Rule::observation_expressions)
        .ok_or("missing observation expressions")?;
    build_observation_expressions(expressions)
}

fn build_observation_expressions(pair: Pair<Rule>) -> BuildResult<ObservationExpression> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation_or(inner.next().ok_or("empty observation")?)?;

    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_followedby {
            continue;
        }
        let rhs = build_observation_or(inner.next().ok_or("dangling FOLLOWEDBY")?)?;
        acc = ObservationExpression::ObservationOp(
            Box::new(acc),
            ObservationOperator::FollowedBy,
            Box::new(rhs),
        );
    }

    Ok(acc)
}

fn build_observation_or(pair: Pair<Rule>) -> BuildResult<ObservationExpression> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation_and(inner.next().ok_or("empty observation OR")?)?;

    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_or {
            continue;
        }
        let rhs = build_observation_and(inner.next().ok_or("dangling OR")?)?;
        acc = ObservationExpression::ObservationOp(
            Box::new(acc),
            ObservationOperator::Or,
            Box::new(rhs),
        );
    }

    Ok(acc)
}

fn build_observation_and(pair: Pair<Rule>) -> BuildResult<ObservationExpression> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation(inner.next().ok_or("empty observation AND")?)?;

    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_and {
            continue;
        }
        let rhs = build_observation(inner.next().ok_or("dangling AND")?)?;
        acc = ObservationExpression::ObservationOp(
            Box::new(acc),
            ObservationOperator::And,
            Box::new(rhs),
        );
    }

    Ok(acc)
}

fn build_observation(pair: Pair<Rule>) -> BuildResult<ObservationExpression> {
    let mut inner = pair.into_inner();
    let first = inner.next().ok_or("empty observation expression")?;

    let mut acc = match first.as_rule() {
        Rule::comparison_observation => {
            let comparison = first
                .into_inner()
                .find(|inner| inner.as_rule() == Rule::comparison_expression)
                .ok_or("missing comparison expression")?;
            ObservationExpression::Comparison(build_comparison_expression(comparison)?)
        }
        Rule::compound_observation => {
            let nested = first
                .into_inner()
                .find(|inner| inner.as_rule() == Rule::observation_expressions)
                .ok_or("missing nested observation")?;
            build_observation_expressions(nested)?
        }
        _ => return Err("unexpected observation"),
    };

    for qualifier in inner {
        if qualifier.as_rule() == Rule::qualifier {
            acc = ObservationExpression::Qualification(Box::new(acc), build_qualifier(qualifier)?);
        }
    }

    Ok(acc)
}

fn build_comparison_expression(pair: Pair<Rule>) -> BuildResult<ComparisonComponent> {
    let mut inner = pair.into_inner();
    let mut acc = build_comparison_and(inner.next().ok_or("empty comparison")?)?;

    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_or {
            continue;
        }
        let rhs = build_comparison_and(inner.next().ok_or("dangling comparison OR")?)?;
        acc = ComparisonComponent::BooleanOp(Box::new(acc), BooleanOperator::Or, Box::new(rhs));
    }

    Ok(acc)
}

fn build_comparison_and(pair: Pair<Rule>) -> BuildResult<ComparisonComponent> {
    let mut inner = pair.into_inner();
    let mut acc = build_prop_test(inner.next().ok_or("empty comparison AND")?)?;

    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_and {
            continue;
        }
        let rhs = build_prop_test(inner.next().ok_or("dangling comparison AND")?)?;
        acc = ComparisonComponent::BooleanOp(Box::new(acc), BooleanOperator::And, Box::new(rhs));
    }

    Ok(acc)
}

fn build_prop_test(pair: Pair<Rule>) -> BuildResult<ComparisonComponent> {
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let has = |rule: Rule| children.iter().any(|child| child.as_rule() == rule);
    let find = |rule: Rule| children.iter().find(|child| child.as_rule() == rule);

    // A parenthesised comparison group is a component in its own right.
    if has(Rule::l_paren) && has(Rule::comparison_expression) {
        let inner = find(Rule::comparison_expression).ok_or("empty comparison group")?;
        return build_comparison_expression(inner.clone());
    }

    let negated = has(Rule::kw_not);
    let object_path = build_object_path(
        find(Rule::object_path)
            .ok_or("missing object path")?
            .clone(),
    )?;

    if has(Rule::kw_exists) {
        return Ok(ComparisonComponent::ComparisonExpression(
            ComparisonExpression {
                object_path,
                operator: ComparisonOperator::Exists,
                constant: None,
                negated,
            },
        ));
    }

    let (operator, constant) = if find(Rule::eq_op).is_some() {
        (ComparisonOperator::Eq, build_literal(&children)?)
    } else if find(Rule::neq_op).is_some() {
        (ComparisonOperator::Neq, build_literal(&children)?)
    } else if let Some(operator) = find(Rule::order_op) {
        let operator = match operator.as_str().trim() {
            ">=" => ComparisonOperator::Gte,
            "<=" => ComparisonOperator::Lte,
            ">" => ComparisonOperator::Gt,
            "<" => ComparisonOperator::Lt,
            _ => return Err("unknown order operator"),
        };
        (operator, build_literal(&children)?)
    } else if has(Rule::kw_in) {
        let set = find(Rule::set_literal).ok_or("missing set literal")?;
        (ComparisonOperator::In, build_set(set.clone())?)
    } else if has(Rule::kw_like) {
        (ComparisonOperator::Like, build_literal(&children)?)
    } else if has(Rule::kw_matches) {
        (ComparisonOperator::Matches, build_literal(&children)?)
    } else if has(Rule::kw_issubset) {
        (ComparisonOperator::IsSubset, build_literal(&children)?)
    } else if has(Rule::kw_issuperset) {
        (ComparisonOperator::IsSuperset, build_literal(&children)?)
    } else {
        return Err("missing comparison operator");
    };

    Ok(ComparisonComponent::ComparisonExpression(
        ComparisonExpression {
            object_path,
            operator,
            constant: Some(constant),
            negated,
        },
    ))
}

fn build_literal(children: &[Pair<Rule>]) -> BuildResult<Constant> {
    let literal = children
        .iter()
        .find(|child| {
            matches!(
                child.as_rule(),
                Rule::primitive_literal
                    | Rule::orderable_literal
                    | Rule::bool_literal
                    | Rule::string_literal
                    | Rule::timestamp_literal
                    | Rule::hex_literal
                    | Rule::binary_literal
                    | Rule::int_pos
                    | Rule::int_neg
                    | Rule::float_pos
                    | Rule::float_neg
            )
        })
        .ok_or("missing literal")?;
    build_constant(literal.clone())
}

fn build_set(pair: Pair<Rule>) -> BuildResult<Constant> {
    let values = pair
        .into_inner()
        .filter(|child| child.as_rule() == Rule::primitive_literal)
        .map(build_constant)
        .collect::<BuildResult<Vec<_>>>()?;
    Ok(Constant::Set(values))
}

fn build_constant(pair: Pair<Rule>) -> BuildResult<Constant> {
    let text = pair.as_str().trim();

    match pair.as_rule() {
        Rule::primitive_literal | Rule::orderable_literal => {
            let inner = pair.into_inner().next().ok_or("empty literal")?;
            build_constant(inner)
        }
        Rule::bool_literal => Ok(Constant::Boolean(text == "true")),
        Rule::string_literal => Ok(Constant::String(
            text.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
                .ok_or("malformed string literal")?
                .to_string(),
        )),
        Rule::hex_literal => Ok(Constant::Hex(text.to_string())),
        Rule::binary_literal => Ok(Constant::Binary(text.to_string())),
        Rule::timestamp_literal => {
            let inner = text
                .strip_prefix("t'")
                .and_then(|value| value.strip_suffix('\''))
                .ok_or("malformed timestamp literal")?;
            Timestamp::new(inner)
                .map(Constant::Timestamp)
                .map_err(|_| "invalid timestamp")
        }
        Rule::int_pos | Rule::int_neg => text
            .parse::<i64>()
            .map(Constant::Integer)
            .map_err(|_| "integer out of range"),
        Rule::float_pos | Rule::float_neg => text
            .parse::<f64>()
            .map(|value| Constant::Float(ordered_float::OrderedFloat(value)))
            .map_err(|_| "invalid float"),
        _ => Err("unexpected literal"),
    }
}

fn build_object_path(pair: Pair<Rule>) -> BuildResult<ObjectPath> {
    let mut inner = pair.into_inner();
    let sco = inner
        .next()
        .ok_or("missing object type")?
        .as_str()
        .to_string();
    let _colon = inner.next().ok_or("missing path separator")?;
    let first = inner.next().ok_or("missing first path component")?;
    let mut property = first.as_str().to_string();

    for component in inner.filter(|inner| inner.as_rule() == Rule::path_component) {
        for part in component.into_inner() {
            match part.as_rule() {
                Rule::dot | Rule::l_bracket | Rule::r_bracket => property.push_str(part.as_str()),
                Rule::ident_no_hyphen
                | Rule::string_literal
                | Rule::int_pos
                | Rule::int_neg
                | Rule::asterisk => property.push_str(part.as_str()),
                _ => {}
            }
        }
    }

    Ok(ObjectPath { sco, property })
}

fn build_qualifier(pair: Pair<Rule>) -> BuildResult<Qualifier> {
    let inner = pair.into_inner().next().ok_or("empty qualifier")?;

    match inner.as_rule() {
        Rule::repeats => {
            let count = inner
                .into_inner()
                .find(|child| child.as_rule() == Rule::int_pos)
                .ok_or("REPEATS without a count")?;
            count
                .as_str()
                .trim()
                .parse::<i64>()
                .map(Qualifier::Repeats)
                .map_err(|_| "REPEATS count out of range")
        }
        Rule::within => {
            let value = inner
                .into_inner()
                .find(|child| matches!(child.as_rule(), Rule::int_pos | Rule::float_pos))
                .ok_or("WITHIN without a value")?;
            value
                .as_str()
                .trim()
                .parse::<f64>()
                .map(|value| Qualifier::Within(ordered_float::OrderedFloat(value)))
                .map_err(|_| "invalid WITHIN value")
        }
        Rule::start_stop => {
            let mut timestamps = inner
                .into_inner()
                .filter(|child| child.as_rule() == Rule::timestamp_literal)
                .map(build_constant);
            let start = timestamps.next().ok_or("START without a timestamp")??;
            let stop = timestamps.next().ok_or("STOP without a timestamp")??;
            match (start, stop) {
                (Constant::Timestamp(start), Constant::Timestamp(stop)) => {
                    Ok(Qualifier::StartStop(start, stop))
                }
                _ => Err("START/STOP are not timestamps"),
            }
        }
        _ => Err("unexpected qualifier"),
    }
}

/// Format a pest parse failure as `line:column: expected …, found …`.
///
/// Pest's `Display` prints rule names and source snippets; this maps each rule
/// to a plain-language phrase and names the offending token instead.
fn format_parse_error(pattern: &str, error: &PestError<Rule>) -> String {
    let (line, column) = match error.line_col {
        LineColLocation::Pos(position) => position,
        LineColLocation::Span(position, _) => position,
    };

    match &error.variant {
        ErrorVariant::ParsingError {
            positives,
            negatives,
        } => {
            let expected = if positives.is_empty() {
                "a valid pattern element".to_string()
            } else {
                dedup(positives.iter().map(|rule| rule_phrase(*rule)))
            };
            let found = token_at(pattern, line, column).unwrap_or_else(|| {
                if negatives.is_empty() {
                    "the end of the input".to_string()
                } else {
                    dedup(negatives.iter().map(|rule| rule_phrase(*rule)))
                }
            });
            format!("{line}:{column}: expected {expected}, found {found}")
        }
        ErrorVariant::CustomError { message } => format!("{line}:{column}: {message}"),
    }
}

/// The token starting at a 1-based line and column, ignoring leading whitespace.
fn token_at(pattern: &str, line: usize, column: usize) -> Option<String> {
    let line_text = pattern.lines().nth(line.saturating_sub(1))?;
    let rest: String = line_text
        .chars()
        .skip(column.saturating_sub(1))
        .collect::<String>()
        .trim_start()
        .to_string();

    let first = rest.chars().next()?;
    if first.is_alphanumeric() || first == '-' || first == '_' {
        Some(
            rest.chars()
                .take_while(|character| {
                    character.is_alphanumeric() || *character == '-' || *character == '_'
                })
                .collect(),
        )
    } else {
        Some(first.to_string())
    }
}

fn dedup(names: impl Iterator<Item = &'static str>) -> String {
    let mut unique: Vec<&'static str> = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    unique.join(" or ")
}

/// The grammar rule name, used by the fixture coverage check.
#[cfg(test)]
fn rule_name(rule: Rule) -> &'static str {
    match rule {
        Rule::EOI => "EOI",
        Rule::WHITESPACE => "WHITESPACE",
        Rule::COMMENT => "COMMENT",
        Rule::ident_char => "ident_char",
        Rule::keyword => "keyword",
        Rule::ident_no_hyphen => "ident_no_hyphen",
        Rule::ident_with_hyphen => "ident_with_hyphen",
        Rule::pattern => "pattern",
        Rule::observation_expressions => "observation_expressions",
        Rule::observation_expression_or => "observation_expression_or",
        Rule::observation_expression_and => "observation_expression_and",
        Rule::observation_expression => "observation_expression",
        Rule::comparison_observation => "comparison_observation",
        Rule::compound_observation => "compound_observation",
        Rule::comparison_expression => "comparison_expression",
        Rule::comparison_expression_and => "comparison_expression_and",
        Rule::prop_test => "prop_test",
        Rule::object_path => "object_path",
        Rule::object_type => "object_type",
        Rule::first_path_component => "first_path_component",
        Rule::path_component => "path_component",
        Rule::set_literal => "set_literal",
        Rule::primitive_literal => "primitive_literal",
        Rule::orderable_literal => "orderable_literal",
        Rule::qualifier => "qualifier",
        Rule::start_stop => "start_stop",
        Rule::within => "within",
        Rule::repeats => "repeats",
        Rule::string_literal => "string_literal",
        Rule::hex_literal => "hex_literal",
        Rule::base64_char => "base64_char",
        Rule::base64_body => "base64_body",
        Rule::binary_literal => "binary_literal",
        Rule::timestamp_literal => "timestamp_literal",
        Rule::year => "year",
        Rule::month => "month",
        Rule::day => "day",
        Rule::hour => "hour",
        Rule::minute => "minute",
        Rule::second => "second",
        Rule::int_pos => "int_pos",
        Rule::int_neg => "int_neg",
        Rule::float_pos => "float_pos",
        Rule::float_neg => "float_neg",
        Rule::bool_literal => "bool_literal",
        Rule::kw_and => "kw_and",
        Rule::kw_or => "kw_or",
        Rule::kw_not => "kw_not",
        Rule::kw_followedby => "kw_followedby",
        Rule::kw_like => "kw_like",
        Rule::kw_matches => "kw_matches",
        Rule::kw_issuperset => "kw_issuperset",
        Rule::kw_issubset => "kw_issubset",
        Rule::kw_exists => "kw_exists",
        Rule::kw_last => "kw_last",
        Rule::kw_in => "kw_in",
        Rule::kw_start => "kw_start",
        Rule::kw_stop => "kw_stop",
        Rule::kw_seconds => "kw_seconds",
        Rule::kw_true => "kw_true",
        Rule::kw_false => "kw_false",
        Rule::kw_within => "kw_within",
        Rule::kw_repeats => "kw_repeats",
        Rule::kw_times => "kw_times",
        Rule::l_bracket => "l_bracket",
        Rule::r_bracket => "r_bracket",
        Rule::l_paren => "l_paren",
        Rule::r_paren => "r_paren",
        Rule::colon => "colon",
        Rule::comma => "comma",
        Rule::dot => "dot",
        Rule::asterisk => "asterisk",
        Rule::eq_op => "eq_op",
        Rule::neq_op => "neq_op",
        Rule::order_op => "order_op",
    }
}

/// A plain-language phrase for a grammar rule, used in parse diagnostics.
fn rule_phrase(rule: Rule) -> &'static str {
    match rule {
        Rule::kw_and => "'AND'",
        Rule::kw_or => "'OR'",
        Rule::kw_not => "'NOT'",
        Rule::kw_followedby => "'FOLLOWEDBY'",
        Rule::kw_like => "'LIKE'",
        Rule::kw_matches => "'MATCHES'",
        Rule::kw_issuperset => "'ISSUPERSET'",
        Rule::kw_issubset => "'ISSUBSET'",
        Rule::kw_exists => "'EXISTS'",
        Rule::kw_last => "'LAST'",
        Rule::kw_in => "'IN'",
        Rule::kw_start => "'START'",
        Rule::kw_stop => "'STOP'",
        Rule::kw_seconds => "'SECONDS'",
        Rule::kw_true => "'true'",
        Rule::kw_false => "'false'",
        Rule::kw_within => "'WITHIN'",
        Rule::kw_repeats => "'REPEATS'",
        Rule::kw_times => "'TIMES'",
        Rule::string_literal => "a quoted string",
        Rule::timestamp_literal => "a timestamp",
        Rule::hex_literal => "a hexadecimal literal",
        Rule::binary_literal => "a binary literal",
        Rule::int_pos => "a positive integer",
        Rule::int_neg => "a negative integer",
        Rule::float_pos => "a positive number",
        Rule::float_neg => "a negative number",
        Rule::bool_literal => "a boolean",
        Rule::primitive_literal | Rule::orderable_literal => {
            "a value (number, string, timestamp, boolean, binary, or hex)"
        }
        Rule::eq_op | Rule::neq_op | Rule::order_op => "a comparison operator",
        Rule::object_path => "an object path",
        Rule::object_type => "an object type",
        Rule::first_path_component => "a property name",
        Rule::path_component => "'.' or '['",
        Rule::set_literal => "a set of values",
        Rule::qualifier => "a qualifier (WITHIN, REPEATS, or START/STOP)",
        Rule::comparison_expression | Rule::comparison_expression_and | Rule::prop_test => {
            "a comparison"
        }
        Rule::observation_expression
        | Rule::observation_expression_and
        | Rule::observation_expression_or
        | Rule::observation_expressions => "an observation expression",
        Rule::comparison_observation => "a comparison observation",
        Rule::compound_observation => "a parenthesised observation expression",
        Rule::pattern => "a STIX pattern",
        Rule::start_stop => "a START/STOP qualifier",
        Rule::within => "a WITHIN qualifier",
        Rule::repeats => "a REPEATS qualifier",
        Rule::l_bracket => "'['",
        Rule::r_bracket => "']'",
        Rule::l_paren => "'('",
        Rule::r_paren => "')'",
        Rule::colon => "':'",
        Rule::comma => "','",
        Rule::dot => "'.'",
        Rule::asterisk => "'*'",
        Rule::year | Rule::month | Rule::day | Rule::hour | Rule::minute | Rule::second => {
            "a timestamp component"
        }
        Rule::EOI => "the end of the pattern",
        Rule::WHITESPACE | Rule::COMMENT => "whitespace or a comment",
        Rule::ident_char | Rule::ident_no_hyphen | Rule::ident_with_hyphen => "a name",
        Rule::keyword => "a keyword",
        Rule::base64_char | Rule::base64_body => "a binary literal",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::Path;

    use super::*;

    fn fixture_dir(kind: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("testdata")
            .join("stix")
            .join(kind)
            .join("patterns")
    }

    fn valid_patterns() -> Vec<String> {
        let mut patterns = Vec::new();
        for entry in fs::read_dir(fixture_dir("valid")).expect("valid fixture directory") {
            let path = entry.expect("directory entry").path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("read fixture");
            let entries: Vec<serde_json::Value> =
                serde_json::from_str(&text).expect("parse fixture");
            for entry in entries {
                patterns.push(entry["pattern"].as_str().expect("pattern").to_string());
            }
        }
        patterns
    }

    #[test]
    fn every_valid_fixture_parses() {
        for pattern in valid_patterns() {
            StixParser::parse(Rule::pattern, &pattern)
                .unwrap_or_else(|error| panic!("{pattern}: {error}"));
        }
    }

    #[test]
    fn parse_failures_name_a_position_and_an_expected_construct() {
        for pattern in [
            "[file:name = ]",
            "[file:name = 'x' AND]",
            "AND [file:name = '198.51.100.1']",
            "[file:name = 'x' OR ]",
        ] {
            let error = StixParser::parse(Rule::pattern, pattern).unwrap_err();
            let message = format_parse_error(pattern, &error);
            assert!(message.contains(':'), "missing position: {message}");
            assert!(
                message.contains("expected"),
                "missing expectation: {message}"
            );
            assert!(message.contains("found"), "missing found token: {message}");
            assert!(!message.contains("kw_"), "rule name leaked: {message}");
            assert!(!message.contains("Rule::"), "rule path leaked: {message}");
            assert!(!message.contains("crate::"), "crate path leaked: {message}");
        }
    }

    #[test]
    fn diagnostics_snapshots() {
        for (pattern, expected) in [
            (
                "[file:name = ]",
                "1:14: expected a value (number, string, timestamp, boolean, binary, or hex), found ]",
            ),
            (
                "[file:name = 'x' FALLOWEDBY [domain-name:value = 'y']]",
                "1:18: expected 'AND' or 'OR' or ']', found FALLOWEDBY",
            ),
            (
                "[file:created = t'2025-13-01T00:00:00Z']",
                "1:17: expected a value (number, string, timestamp, boolean, binary, or hex), found t",
            ),
            (
                "[NOT file:name = 'x']",
                "1:6: expected 'EXISTS', found file",
            ),
            (
                "[file:name = 'x'] WITHIN -5 SECONDS",
                "1:26: expected a positive integer or a positive number, found -5",
            ),
            (
                "[file:name = 'x'] FALLOWEDBY [domain-name:value = 'y']",
                "1:19: expected the end of the pattern or a qualifier (WITHIN, REPEATS, or START/STOP) or 'AND' or 'OR' or 'FOLLOWEDBY', found FALLOWEDBY",
            ),
        ] {
            let error = StixParser::parse(Rule::pattern, pattern).unwrap_err();
            assert_eq!(format_parse_error(pattern, &error), expected, "{pattern}");
        }
    }

    fn load_fixture_ids() -> HashSet<String> {
        let mut ids = HashSet::new();
        for kind in ["valid", "invalid"] {
            for entry in fs::read_dir(fixture_dir(kind)).expect("fixture directory") {
                let path = entry.expect("directory entry").path();
                if path.extension().is_none_or(|ext| ext != "json") {
                    continue;
                }
                let text = fs::read_to_string(&path).expect("read fixture");
                let entries: Vec<serde_json::Value> =
                    serde_json::from_str(&text).expect("parse fixture");
                for entry in entries {
                    ids.insert(entry["id"].as_str().expect("fixture id").to_string());
                }
            }
        }
        ids
    }

    fn load_coverage() -> HashMap<String, Vec<String>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("testdata")
            .join("stix")
            .join("pattern_coverage.json");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }

    fn check_coverage(
        coverage: &HashMap<String, Vec<String>>,
        rules: &[Rule],
        fixture_ids: &HashSet<String>,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let mut known = HashSet::new();

        for rule in rules {
            let name = rule_name(*rule);
            known.insert(name);
            match coverage.get(name) {
                None => errors.push(format!("rule '{name}' has no fixture case")),
                Some(cases) if cases.is_empty() => {
                    errors.push(format!("rule '{name}' has an empty case list"));
                }
                Some(cases) => {
                    for case in cases {
                        if !fixture_ids.contains(case) {
                            errors.push(format!("rule '{name}' names unknown fixture '{case}'"));
                        }
                    }
                }
            }
        }

        for name in coverage.keys() {
            if !known.contains(name.as_str()) {
                errors.push(format!("coverage names unknown rule '{name}'"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    #[test]
    fn coverage_map_covers_every_rule() {
        let coverage = load_coverage();
        let fixture_ids = load_fixture_ids();
        if let Err(errors) = check_coverage(&coverage, Rule::all_rules(), &fixture_ids) {
            panic!("grammar coverage errors:\n{}", errors.join("\n"));
        }
    }

    #[test]
    fn coverage_check_rejects_an_uncovered_rule() {
        let mut coverage = load_coverage();
        coverage.remove("kw_last");
        let fixture_ids = load_fixture_ids();

        let errors = check_coverage(&coverage, Rule::all_rules(), &fixture_ids)
            .expect_err("an uncovered rule must fail the check");
        assert!(
            errors.iter().any(|error| error.contains("kw_last")),
            "expected kw_last in {errors:?}"
        );
    }
}
