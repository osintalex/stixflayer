//! Mirror of the proposed AST extension, kept local on purpose.
//!
//! This change must not edit `rust/`, so the spike proves the shape in a copy:
//! `ComparisonExpression` gains `negated`, and `BooleanOp` takes a component on
//! both sides. The semantic checks below mirror `stix_check` closely enough to
//! show that the extended shape is checkable; object-path validation is omitted
//! because it is unchanged and will be reused from the real AST.

use std::collections::HashSet;

use ordered_float::OrderedFloat;
use pest::iterators::Pair;
use pest_poc::Rule;
use stixflayer::pattern::expr::{
    BooleanOperator, ComparisonOperator, Constant, ObjectPath, ObservationOperator, Qualifier,
};
use stixflayer::types::Timestamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub object_path: ObjectPath,
    pub operator: ComparisonOperator,
    pub constant: Option<Constant>,
    pub negated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Component {
    Expression(Comparison),
    BooleanOp(Box<Component>, BooleanOperator, Box<Component>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    Comparison(Component),
    ObservationOp(Box<Observation>, ObservationOperator, Box<Observation>),
    Qualification(Box<Observation>, Qualifier),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Expression(Comparison),
    Group(Component),
}

pub fn build(pattern: &str) -> Result<Observation, String> {
    let mut pairs = pest_poc::parse_pairs(pattern).map_err(|err| err.to_string())?;
    let root = pairs.next().ok_or("empty parse tree")?;
    let expressions = root
        .into_inner()
        .find(|pair| pair.as_rule() == Rule::observation_expressions)
        .ok_or("no observation_expressions")?;
    build_observation_expressions(expressions)
}

fn build_observation_expressions(pair: Pair<Rule>) -> Result<Observation, String> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation_or(inner.next().ok_or("empty observation")?)?;
    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_followedby {
            continue;
        }
        let rhs = build_observation_or(inner.next().ok_or("dangling FOLLOWEDBY")?)?;
        acc = Observation::ObservationOp(
            Box::new(acc),
            ObservationOperator::FollowedBy,
            Box::new(rhs),
        );
    }
    Ok(acc)
}

fn build_observation_or(pair: Pair<Rule>) -> Result<Observation, String> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation_and(inner.next().ok_or("empty observation OR")?)?;
    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_or {
            continue;
        }
        let rhs = build_observation_and(inner.next().ok_or("dangling OR")?)?;
        acc = Observation::ObservationOp(Box::new(acc), ObservationOperator::Or, Box::new(rhs));
    }
    Ok(acc)
}

fn build_observation_and(pair: Pair<Rule>) -> Result<Observation, String> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation(inner.next().ok_or("empty observation AND")?)?;
    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_and {
            continue;
        }
        let rhs = build_observation(inner.next().ok_or("dangling AND")?)?;
        acc = Observation::ObservationOp(Box::new(acc), ObservationOperator::And, Box::new(rhs));
    }
    Ok(acc)
}

fn build_observation(pair: Pair<Rule>) -> Result<Observation, String> {
    let mut inner = pair.into_inner();
    let first = inner.next().ok_or("empty observation")?;
    let mut acc = match first.as_rule() {
        Rule::comparison_observation => Observation::Comparison(build_comparison_component(first)?),
        Rule::compound_observation => {
            let nested = first
                .into_inner()
                .find(|pair| pair.as_rule() == Rule::observation_expressions)
                .ok_or("empty parenthesised observation")?;
            build_observation_expressions(nested)?
        }
        other => return Err(format!("unexpected {other:?}")),
    };
    for qualifier in inner {
        if qualifier.as_rule() == Rule::qualifier {
            acc = Observation::Qualification(Box::new(acc), build_qualifier(qualifier)?);
        }
    }
    Ok(acc)
}

fn build_comparison_component(pair: Pair<Rule>) -> Result<Component, String> {
    let expression = pair
        .into_inner()
        .find(|pair| pair.as_rule() == Rule::comparison_expression)
        .ok_or("missing comparison_expression")?;
    build_comparison_expression(expression)
}

fn build_comparison_expression(pair: Pair<Rule>) -> Result<Component, String> {
    let mut terms = Vec::new();
    collect_terms(pair, &mut terms)?;

    let mut iter = terms.into_iter();
    let (_, first) = iter.next().ok_or("empty comparison")?;
    let mut acc = match first {
        Term::Expression(expression) => Component::Expression(expression),
        Term::Group(component) => component,
    };
    for (operator, term) in iter {
        let operator = operator.ok_or("missing boolean operator")?;
        let rhs = match term {
            Term::Expression(expression) => Component::Expression(expression),
            Term::Group(component) => component,
        };
        acc = Component::BooleanOp(Box::new(acc), operator, Box::new(rhs));
    }
    Ok(acc)
}

fn collect_terms(pair: Pair<Rule>, terms: &mut Vec<(Option<BooleanOperator>, Term)>) -> Result<(), String> {
    match pair.as_rule() {
        Rule::comparison_expression => {
            let mut inner = pair.into_inner();
            if let Some(first) = inner.next() {
                collect_terms(first, terms)?;
            }
            while let Some(_or) = inner.next() {
                let rhs = inner.next().ok_or("dangling OR")?;
                let start = terms.len();
                collect_terms(rhs, terms)?;
                if let Some(term) = terms.get_mut(start) {
                    term.0 = Some(BooleanOperator::Or);
                }
            }
        }
        Rule::comparison_expression_and => {
            let mut inner = pair.into_inner();
            if let Some(first) = inner.next() {
                collect_terms(first, terms)?;
            }
            while let Some(_and) = inner.next() {
                let rhs = inner.next().ok_or("dangling AND")?;
                let start = terms.len();
                collect_terms(rhs, terms)?;
                if let Some(term) = terms.get_mut(start) {
                    term.0 = Some(BooleanOperator::And);
                }
            }
        }
        Rule::prop_test => terms.push((None, build_prop_test(pair)?)),
        other => return Err(format!("unexpected {other:?} in comparison")),
    }
    Ok(())
}

fn build_prop_test(pair: Pair<Rule>) -> Result<Term, String> {
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let has = |rule: Rule| children.iter().any(|child| child.as_rule() == rule);
    let find = |rule: Rule| children.iter().find(|child| child.as_rule() == rule);

    if has(Rule::l_paren) && has(Rule::comparison_expression) {
        let inner = find(Rule::comparison_expression).ok_or("empty group")?;
        return Ok(Term::Group(build_comparison_expression(inner.clone())?));
    }

    let negated = has(Rule::kw_not);
    let path = find(Rule::object_path).ok_or("missing object path")?;
    let object_path = build_object_path(path.clone())?;

    if has(Rule::kw_exists) {
        return Ok(Term::Expression(Comparison {
            object_path,
            operator: ComparisonOperator::Exists,
            constant: None,
            negated,
        }));
    }

    let (operator, constant) = if find(Rule::eq_op).is_some() {
        (ComparisonOperator::Eq, build_literal(&children)?)
    } else if find(Rule::neq_op).is_some() {
        (ComparisonOperator::Neq, build_literal(&children)?)
    } else if let Some(op) = find(Rule::order_op) {
        let operator = match op.as_str().trim() {
            ">=" => ComparisonOperator::Gte,
            "<=" => ComparisonOperator::Lte,
            ">" => ComparisonOperator::Gt,
            "<" => ComparisonOperator::Lt,
            other => return Err(format!("unknown order operator {other}")),
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
        return Err("missing comparison operator".to_string());
    };

    Ok(Term::Expression(Comparison {
        object_path,
        operator,
        constant: Some(constant),
        negated,
    }))
}

fn build_literal(children: &[Pair<Rule>]) -> Result<Constant, String> {
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

fn build_set(pair: Pair<Rule>) -> Result<Constant, String> {
    let values = pair
        .into_inner()
        .filter(|child| child.as_rule() == Rule::primitive_literal)
        .map(build_constant)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Constant::Set(values))
}

fn build_constant(pair: Pair<Rule>) -> Result<Constant, String> {
    let text = pair.as_str().trim();
    match pair.as_rule() {
        Rule::primitive_literal | Rule::orderable_literal => {
            let inner = pair.into_inner().next().ok_or("empty literal")?;
            build_constant(inner)
        }
        Rule::bool_literal => Ok(Constant::Boolean(text == "true")),
        Rule::string_literal => Ok(Constant::String(
            text.trim_start_matches('\'')
                .trim_end_matches('\'')
                .to_string(),
        )),
        Rule::hex_literal => Ok(Constant::Hex(text.to_string())),
        Rule::binary_literal => Ok(Constant::Binary(text.to_string())),
        Rule::timestamp_literal => {
            let inner = text.trim_start_matches("t'").trim_end_matches('\'');
            Timestamp::new(inner)
                .map(Constant::Timestamp)
                .map_err(|err| format!("timestamp: {err}"))
        }
        Rule::int_pos | Rule::int_neg => text
            .parse::<i64>()
            .map(Constant::Integer)
            .map_err(|err| format!("integer: {err}")),
        Rule::float_pos | Rule::float_neg => text
            .parse::<f64>()
            .map(|value| Constant::Float(OrderedFloat(value)))
            .map_err(|err| format!("float: {err}")),
        other => Err(format!("unexpected literal {other:?}")),
    }
}

fn build_object_path(pair: Pair<Rule>) -> Result<ObjectPath, String> {
    let mut inner = pair.into_inner();
    let sco = inner
        .next()
        .ok_or("missing object type")?
        .as_str()
        .trim()
        .to_string();
    let first = inner
        .find(|child| child.as_rule() == Rule::first_path_component)
        .ok_or("missing first path component")?;
    let mut property = first.as_str().trim().to_string();

    for component in inner.filter(|child| child.as_rule() == Rule::path_component) {
        for part in component.into_inner() {
            match part.as_rule() {
                Rule::dot | Rule::l_bracket | Rule::r_bracket => property.push_str(part.as_str()),
                Rule::ident_no_hyphen
                | Rule::string_literal
                | Rule::int_pos
                | Rule::int_neg
                | Rule::asterisk => property.push_str(part.as_str().trim()),
                _ => {}
            }
        }
    }

    Ok(ObjectPath { sco, property })
}

fn build_qualifier(pair: Pair<Rule>) -> Result<Qualifier, String> {
    let inner = pair.into_inner().next().ok_or("empty qualifier")?;
    match inner.as_rule() {
        Rule::repeats => {
            let count = inner
                .into_inner()
                .find(|child| child.as_rule() == Rule::int_pos)
                .ok_or("REPEATS without count")?;
            count
                .as_str()
                .trim()
                .parse::<i64>()
                .map(Qualifier::Repeats)
                .map_err(|err| format!("REPEATS: {err}"))
        }
        Rule::within => {
            let value = inner
                .into_inner()
                .find(|child| matches!(child.as_rule(), Rule::int_pos | Rule::float_pos))
                .ok_or("WITHIN without value")?;
            value
                .as_str()
                .trim()
                .parse::<f64>()
                .map(|value| Qualifier::Within(OrderedFloat(value)))
                .map_err(|err| format!("WITHIN: {err}"))
        }
        Rule::start_stop => {
            let mut timestamps = inner
                .into_inner()
                .filter(|child| child.as_rule() == Rule::timestamp_literal)
                .map(build_constant);
            let start = timestamps.next().ok_or("START without timestamp")??;
            let stop = timestamps.next().ok_or("STOP without timestamp")??;
            match (start, stop) {
                (Constant::Timestamp(start), Constant::Timestamp(stop)) => {
                    Ok(Qualifier::StartStop(start, stop))
                }
                _ => Err("START/STOP are not timestamps".to_string()),
            }
        }
        other => Err(format!("unexpected qualifier {other:?}")),
    }
}

/// Semantic checks mirrored from `stix_check`, plus the qualifier range rules
/// that currently live in the shipped front end.
pub fn check(observation: &Observation) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut qualifiers = HashSet::new();
    validate_observation(observation, &mut errors, &mut qualifiers);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_observation(
    observation: &Observation,
    errors: &mut Vec<String>,
    qualifiers: &mut HashSet<String>,
) {
    match observation {
        Observation::Comparison(component) => validate_component(component, errors),
        Observation::ObservationOp(lhs, _, rhs) => {
            validate_observation(lhs, errors, qualifiers);
            validate_observation(rhs, errors, qualifiers);
        }
        Observation::Qualification(inner, qualifier) => {
            validate_observation(inner, errors, qualifiers);
            validate_qualifier(qualifier, errors, qualifiers);
        }
    }
}

fn validate_component(component: &Component, errors: &mut Vec<String>) {
    match component {
        Component::Expression(expression) => validate_comparison(expression, errors),
        Component::BooleanOp(lhs, operator, rhs) => {
            validate_component(lhs, errors);
            validate_component(rhs, errors);
            if *operator == BooleanOperator::And {
                let matches = matching_object(lhs).is_some()
                    && matching_object(lhs) == matching_object(rhs);
                if !matches {
                    errors.push(
                        "AND between comparisons on different object types".to_string(),
                    );
                }
            }
        }
    }
}

fn matching_object(component: &Component) -> Option<&str> {
    match component {
        Component::Expression(expression) => Some(&expression.object_path.sco),
        Component::BooleanOp(lhs, _, rhs) => {
            matching_object(lhs).filter(|object| Some(*object) == matching_object(rhs))
        }
    }
}

fn validate_comparison(expression: &Comparison, errors: &mut Vec<String>) {
    match expression.operator {
        ComparisonOperator::Exists => {
            if expression.constant.is_some() {
                errors.push("EXISTS must not carry a constant".to_string());
            }
        }
        ComparisonOperator::In => {
            if !matches!(expression.constant, Some(Constant::Set(_))) {
                errors.push("IN must be applied to a set".to_string());
            }
        }
        ComparisonOperator::Like
        | ComparisonOperator::Matches
        | ComparisonOperator::IsSubset
        | ComparisonOperator::IsSuperset => {
            if !matches!(expression.constant, Some(Constant::String(_))) {
                errors.push("operator must be applied to a string".to_string());
            }
        }
        _ => {
            if expression.constant.is_none() {
                errors.push("comparison is missing a constant".to_string());
            }
        }
    }
}

fn validate_qualifier(
    qualifier: &Qualifier,
    errors: &mut Vec<String>,
    qualifiers: &mut HashSet<String>,
) {
    let (name, in_range) = match qualifier {
        Qualifier::Repeats(count) => ("REPEATS", *count > 0),
        Qualifier::Within(seconds) => ("WITHIN", *seconds > OrderedFloat(0.0)),
        Qualifier::StartStop(start, stop) => ("START/STOP", stop > start),
    };
    if !in_range {
        errors.push(format!("{name} requires a positive range"));
    }
    if !qualifiers.insert(name.to_string()) {
        errors.push(format!("duplicate {name} qualifier"));
    }
}
