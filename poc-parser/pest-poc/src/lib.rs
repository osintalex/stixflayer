//! pest front end for the STIX Pattern grammar, exposed as a library so the
//! winner spike can build the real `stixflayer::pattern::expr` AST from it.

use pest::error::{Error as PestError, ErrorVariant};
use pest::iterators::Pairs;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "stix.pest"]
pub struct StixParser;

/// Parse a pattern and return the pair tree for AST construction.
pub fn parse_pairs(input: &str) -> Result<Pairs<'_, Rule>, PestError<Rule>> {
    StixParser::parse(Rule::pattern, input)
}

/// Map grammar rules to user-facing phrases. This is pest's cheap formatter:
/// `renamed_rules` is the whole mechanism.
pub fn rename_rule(rule: Rule) -> String {
    match rule {
        Rule::kw_and => "'AND'".to_string(),
        Rule::kw_or => "'OR'".to_string(),
        Rule::kw_not => "'NOT'".to_string(),
        Rule::kw_followedby => "'FOLLOWEDBY'".to_string(),
        Rule::kw_in => "'IN'".to_string(),
        Rule::kw_like => "'LIKE'".to_string(),
        Rule::kw_matches => "'MATCHES'".to_string(),
        Rule::kw_issubset => "'ISSUBSET'".to_string(),
        Rule::kw_issuperset => "'ISSUPERSET'".to_string(),
        Rule::kw_exists => "'EXISTS'".to_string(),
        Rule::kw_within => "'WITHIN'".to_string(),
        Rule::kw_repeats => "'REPEATS'".to_string(),
        Rule::kw_seconds => "'SECONDS'".to_string(),
        Rule::kw_times => "'TIMES'".to_string(),
        Rule::kw_start => "'START'".to_string(),
        Rule::kw_stop => "'STOP'".to_string(),
        Rule::string_literal => "a quoted string".to_string(),
        Rule::timestamp_literal => "a timestamp".to_string(),
        Rule::hex_literal => "a hex literal".to_string(),
        Rule::binary_literal => "a binary literal".to_string(),
        Rule::int_pos => "a positive integer".to_string(),
        Rule::float_pos => "a positive number".to_string(),
        Rule::bool_literal => "a boolean".to_string(),
        Rule::eq_op | Rule::neq_op | Rule::order_op => "a comparison operator".to_string(),
        Rule::primitive_literal | Rule::orderable_literal => {
            "a value (number, string, timestamp, boolean, binary, or hex)".to_string()
        }
        Rule::path_component => "'.' or '['".to_string(),
        Rule::qualifier => "a qualifier (WITHIN, REPEATS, or START/STOP)".to_string(),
        Rule::observation_expression => "an observation expression".to_string(),
        Rule::comparison_expression => "a comparison expression".to_string(),
        Rule::object_path => "an object path".to_string(),
        Rule::object_type => "an object type".to_string(),
        Rule::set_literal => "a set of values".to_string(),
        Rule::r_bracket => "']'".to_string(),
        Rule::r_paren => "')'".to_string(),
        Rule::EOI => "the end of the pattern".to_string(),
        other => format!("{other:?}"),
    }
}

fn dedup(names: impl Iterator<Item = String>) -> String {
    let mut unique: Vec<String> = Vec::new();
    for name in names {
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    unique.join(" or ")
}

pub fn format_error(err: &PestError<Rule>) -> String {
    let (line, column) = match err.line_col {
        pest::error::LineColLocation::Pos((line, column)) => (line, column),
        pest::error::LineColLocation::Span((line, column), _) => (line, column),
    };
    match &err.variant {
        ErrorVariant::ParsingError {
            positives,
            negatives,
        } => {
            let expected = if positives.is_empty() {
                "a valid pattern element".to_string()
            } else {
                dedup(positives.iter().map(|rule| rename_rule(*rule)))
            };
            let found = if negatives.is_empty() {
                String::new()
            } else {
                format!(
                    ", found {}",
                    dedup(negatives.iter().map(|rule| rename_rule(*rule)))
                )
            };
            format!("{line}:{column}: expected {expected}{found}")
        }
        ErrorVariant::CustomError { message } => format!("{line}:{column}: {message}"),
    }
}

pub fn parse_pattern(pattern: &str) -> Result<(), Vec<String>> {
    match StixParser::parse(Rule::pattern, pattern) {
        Ok(_) => Ok(()),
        Err(err) => {
            let raw = err.to_string();
            let display = err.clone().renamed_rules(|rule| rename_rule(*rule)).to_string();
            let formatted = format_error(&err);
            Err(vec![
                raw,
                format!("display: {display}"),
                format!("formatted: {formatted}"),
            ])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatted_errors_are_plain_language() {
        for pattern in [
            "[file:name = ]",
            "[file:name = 'x' FALLOWEDBY [a:b = 'c']]",
            "[NOT file:name = 'x']",
            "[file:size >= 1000",
        ] {
            let err = StixParser::parse(Rule::pattern, pattern).unwrap_err();
            let text = format_error(&err);
            assert!(!text.contains("kw_"), "{text}");
            assert!(!text.contains("Rule::"), "{text}");
            assert!(!text.contains("primitive_literal"), "{text}");
            assert!(!text.contains("path_component"), "{text}");
        }
    }
}
