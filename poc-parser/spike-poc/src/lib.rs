//! Build the real `stixflayer::pattern::expr` AST from the pest front end.
//!
//! This is the integration rehearsal: the PoC only proved accept/reject. Here
//! the winning front end must populate the AST the semantic layer actually
//! consumes, and any shape it cannot represent is reported as a gap.

use ordered_float::OrderedFloat;
use pest::iterators::Pair;
use pest_poc::Rule;
use stixflayer::pattern::expr::{
    BooleanOperator, ComparisonComponent, ComparisonExpression, ComparisonOperator, Constant,
    ObjectPath, ObservationExpression, ObservationOperator, Qualifier,
};
use stixflayer::types::Timestamp;

pub mod mirror;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildGap {
    /// `propTestParen`: `[(a OR b) AND c]`. The AST's `BooleanOp` right-hand
    /// side is a single `ComparisonExpression`, so a nested group cannot be
    /// represented.
    ParenthesisedComparison,
    /// `NOT` between the object path and the operator. The AST has no
    /// negation flag.
    NegatedComparison,
    /// `NOT EXISTS`. Same missing negation flag.
    NegatedExists,
    Other(String),
}

impl std::fmt::Display for BuildGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildGap::ParenthesisedComparison => write!(f, "parenthesised comparison group"),
            BuildGap::NegatedComparison => write!(f, "NOT on a comparison"),
            BuildGap::NegatedExists => write!(f, "NOT EXISTS"),
            BuildGap::Other(message) => write!(f, "{message}"),
        }
    }
}

pub fn build(pattern: &str) -> Result<ObservationExpression, BuildGap> {
    let mut pairs = pest_poc::parse_pairs(pattern).map_err(|err| BuildGap::Other(err.to_string()))?;
    let root = pairs
        .next()
        .ok_or_else(|| BuildGap::Other("empty parse tree".to_string()))?;
    let expressions = root
        .into_inner()
        .find(|pair| pair.as_rule() == Rule::observation_expressions)
        .ok_or_else(|| BuildGap::Other("no observation_expressions".to_string()))?;
    build_observation_expressions(expressions)
}

fn build_observation_expressions(pair: Pair<Rule>) -> Result<ObservationExpression, BuildGap> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation_or(
        inner
            .next()
            .ok_or_else(|| BuildGap::Other("empty observation".to_string()))?,
    )?;
    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_followedby {
            continue;
        }
        let rhs = build_observation_or(
            inner
                .next()
                .ok_or_else(|| BuildGap::Other("dangling FOLLOWEDBY".to_string()))?,
        )?;
        acc = ObservationExpression::ObservationOp(
            Box::new(acc),
            ObservationOperator::FollowedBy,
            Box::new(rhs),
        );
    }
    Ok(acc)
}

fn build_observation_or(pair: Pair<Rule>) -> Result<ObservationExpression, BuildGap> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation_and(
        inner
            .next()
            .ok_or_else(|| BuildGap::Other("empty observation OR".to_string()))?,
    )?;
    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_or {
            continue;
        }
        let rhs = build_observation_and(
            inner
                .next()
                .ok_or_else(|| BuildGap::Other("dangling OR".to_string()))?,
        )?;
        acc = ObservationExpression::ObservationOp(
            Box::new(acc),
            ObservationOperator::Or,
            Box::new(rhs),
        );
    }
    Ok(acc)
}

fn build_observation_and(pair: Pair<Rule>) -> Result<ObservationExpression, BuildGap> {
    let mut inner = pair.into_inner();
    let mut acc = build_observation(
        inner
            .next()
            .ok_or_else(|| BuildGap::Other("empty observation AND".to_string()))?,
    )?;
    while let Some(operator) = inner.next() {
        if operator.as_rule() != Rule::kw_and {
            continue;
        }
        let rhs = build_observation(
            inner
                .next()
                .ok_or_else(|| BuildGap::Other("dangling AND".to_string()))?,
        )?;
        acc = ObservationExpression::ObservationOp(
            Box::new(acc),
            ObservationOperator::And,
            Box::new(rhs),
        );
    }
    Ok(acc)
}

fn build_observation(pair: Pair<Rule>) -> Result<ObservationExpression, BuildGap> {
    let mut inner = pair.into_inner();
    let first = inner
        .next()
        .ok_or_else(|| BuildGap::Other("empty observation".to_string()))?;

    let mut acc = match first.as_rule() {
        Rule::comparison_observation => {
            ObservationExpression::Comparison(build_comparison_component(first)?)
        }
        Rule::compound_observation => {
            let nested = first
                .into_inner()
                .find(|pair| pair.as_rule() == Rule::observation_expressions)
                .ok_or_else(|| BuildGap::Other("empty parenthesised observation".to_string()))?;
            build_observation_expressions(nested)?
        }
        other => return Err(BuildGap::Other(format!("unexpected {other:?}"))),
    };

    for qualifier in inner {
        if qualifier.as_rule() == Rule::qualifier {
            acc = ObservationExpression::Qualification(Box::new(acc), build_qualifier(qualifier)?);
        }
    }
    Ok(acc)
}

fn build_comparison_component(pair: Pair<Rule>) -> Result<ComparisonComponent, BuildGap> {
    let expression = pair
        .into_inner()
        .find(|pair| pair.as_rule() == Rule::comparison_expression)
        .ok_or_else(|| BuildGap::Other("missing comparison_expression".to_string()))?;
    build_comparison_expression(expression)
}

/// Flatten the two precedence levels into one left-associative chain, which is
/// all `ComparisonComponent::BooleanOp` can represent.
fn build_comparison_expression(pair: Pair<Rule>) -> Result<ComparisonComponent, BuildGap> {
    let mut terms = Vec::new();
    collect_terms(pair, &mut terms)?;

    let mut iter = terms.into_iter();
    let (_, first) = iter
        .next()
        .ok_or_else(|| BuildGap::Other("empty comparison".to_string()))?;
    let mut acc = ComparisonComponent::ComparisonExpression(first);
    for (operator, expression) in iter {
        let operator =
            operator.ok_or_else(|| BuildGap::Other("missing boolean operator".to_string()))?;
        acc = ComparisonComponent::BooleanOp(Box::new(acc), operator, expression);
    }
    Ok(acc)
}

fn collect_terms(
    pair: Pair<Rule>,
    terms: &mut Vec<(Option<BooleanOperator>, ComparisonExpression)>,
) -> Result<(), BuildGap> {
    match pair.as_rule() {
        Rule::comparison_expression => {
            let mut inner = pair.into_inner();
            if let Some(first) = inner.next() {
                collect_terms(first, terms)?;
            }
            while let Some(_or) = inner.next() {
                let rhs = inner
                    .next()
                    .ok_or_else(|| BuildGap::Other("dangling OR".to_string()))?;
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
                let rhs = inner
                    .next()
                    .ok_or_else(|| BuildGap::Other("dangling AND".to_string()))?;
                let start = terms.len();
                collect_terms(rhs, terms)?;
                if let Some(term) = terms.get_mut(start) {
                    term.0 = Some(BooleanOperator::And);
                }
            }
        }
        Rule::prop_test => terms.push((None, build_prop_test(pair)?)),
        other => return Err(BuildGap::Other(format!("unexpected {other:?} in comparison"))),
    }
    Ok(())
}

fn build_prop_test(pair: Pair<Rule>) -> Result<ComparisonExpression, BuildGap> {
    let children: Vec<Pair<Rule>> = pair.into_inner().collect();
    let has = |rule: Rule| children.iter().any(|child| child.as_rule() == rule);
    let find = |rule: Rule| children.iter().find(|child| child.as_rule() == rule);

    if has(Rule::l_paren) && has(Rule::comparison_expression) {
        return Err(BuildGap::ParenthesisedComparison);
    }

    let negated = has(Rule::kw_not);
    let path = find(Rule::object_path)
        .ok_or_else(|| BuildGap::Other("missing object path".to_string()))?;
    let object_path = build_object_path(path.clone())?;

    if has(Rule::kw_exists) {
        if negated {
            return Err(BuildGap::NegatedExists);
        }
        return Ok(ComparisonExpression {
            object_path,
            operator: ComparisonOperator::Exists,
            constant: None,
        });
    }

    if negated {
        return Err(BuildGap::NegatedComparison);
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
            other => return Err(BuildGap::Other(format!("unknown order operator {other}"))),
        };
        (operator, build_literal(&children)?)
    } else if has(Rule::kw_in) {
        let set = find(Rule::set_literal)
            .ok_or_else(|| BuildGap::Other("missing set literal".to_string()))?;
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
        return Err(BuildGap::Other("missing comparison operator".to_string()));
    };

    Ok(ComparisonExpression {
        object_path,
        operator,
        constant: Some(constant),
    })
}

fn build_literal(children: &[Pair<Rule>]) -> Result<Constant, BuildGap> {
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
        .ok_or_else(|| BuildGap::Other("missing literal".to_string()))?;
    build_constant(literal.clone())
}

fn build_set(pair: Pair<Rule>) -> Result<Constant, BuildGap> {
    let values = pair
        .into_inner()
        .filter(|child| child.as_rule() == Rule::primitive_literal)
        .map(build_constant)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Constant::Set(values))
}

fn build_constant(pair: Pair<Rule>) -> Result<Constant, BuildGap> {
    let text = pair.as_str().trim();
    match pair.as_rule() {
        Rule::primitive_literal | Rule::orderable_literal => {
            let inner = pair
                .into_inner()
                .next()
                .ok_or_else(|| BuildGap::Other("empty literal".to_string()))?;
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
            let inner = text
                .trim_start_matches("t'")
                .trim_end_matches('\'');
            Timestamp::new(inner)
                .map(Constant::Timestamp)
                .map_err(|err| BuildGap::Other(format!("timestamp: {err}")))
        }
        Rule::int_pos | Rule::int_neg => text
            .parse::<i64>()
            .map(Constant::Integer)
            .map_err(|err| BuildGap::Other(format!("integer: {err}"))),
        Rule::float_pos | Rule::float_neg => text
            .parse::<f64>()
            .map(|value| Constant::Float(OrderedFloat(value)))
            .map_err(|err| BuildGap::Other(format!("float: {err}"))),
        other => Err(BuildGap::Other(format!("unexpected literal {other:?}"))),
    }
}

fn build_object_path(pair: Pair<Rule>) -> Result<ObjectPath, BuildGap> {
    let mut inner = pair.into_inner();
    let sco = inner
        .next()
        .ok_or_else(|| BuildGap::Other("missing object type".to_string()))?
        .as_str()
        .trim()
        .to_string();
    let first = inner
        .find(|child| child.as_rule() == Rule::first_path_component)
        .ok_or_else(|| BuildGap::Other("missing first path component".to_string()))?;
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

fn build_qualifier(pair: Pair<Rule>) -> Result<Qualifier, BuildGap> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or_else(|| BuildGap::Other("empty qualifier".to_string()))?;
    match inner.as_rule() {
        Rule::repeats => {
            let count = inner
                .into_inner()
                .find(|child| child.as_rule() == Rule::int_pos)
                .ok_or_else(|| BuildGap::Other("REPEATS without count".to_string()))?;
            let count = count
                .as_str()
                .trim()
                .parse::<i64>()
                .map_err(|err| BuildGap::Other(format!("REPEATS: {err}")))?;
            Ok(Qualifier::Repeats(count))
        }
        Rule::within => {
            let value = inner
                .into_inner()
                .find(|child| matches!(child.as_rule(), Rule::int_pos | Rule::float_pos))
                .ok_or_else(|| BuildGap::Other("WITHIN without value".to_string()))?;
            let value = value
                .as_str()
                .trim()
                .parse::<f64>()
                .map_err(|err| BuildGap::Other(format!("WITHIN: {err}")))?;
            Ok(Qualifier::Within(OrderedFloat(value)))
        }
        Rule::start_stop => {
            let mut timestamps = inner
                .into_inner()
                .filter(|child| child.as_rule() == Rule::timestamp_literal)
                .map(build_constant);
            let start = timestamps
                .next()
                .ok_or_else(|| BuildGap::Other("START without timestamp".to_string()))??;
            let stop = timestamps
                .next()
                .ok_or_else(|| BuildGap::Other("STOP without timestamp".to_string()))??;
            match (start, stop) {
                (Constant::Timestamp(start), Constant::Timestamp(stop)) => {
                    Ok(Qualifier::StartStop(start, stop))
                }
                _ => Err(BuildGap::Other("START/STOP are not timestamps".to_string())),
            }
        }
        other => Err(BuildGap::Other(format!("unexpected qualifier {other:?}"))),
    }
}
