//! antlr-rust front end for the STIX Pattern grammar.
//!
//! The grammar is fed to `antlr-rust-codegen` unmodified. Verdicts come from
//! the parser's syntax-error count, never from `pattern().is_ok()`: ANTLR
//! recovers and still returns a tree, so a recovered parse must count as a
//! rejection.
//!
//! Diagnostics are emitted three ways: the structured raw event, ANTLR's
//! canonical `line:col message` display, and a small plain-language formatter.

use std::error::Error;
use std::sync::{Arc, Mutex};

use antlr4_runtime::{CommonTokenStream, ErrorListener, InputStream, Parser, Recognizer, Token};
use harness::{load_corpus, run, write_outcomes, Layer};

mod generated {
    #![allow(dead_code, clippy::all, clippy::pedantic, clippy::nursery)]

    pub mod stix_pattern_lexer {
        include!(concat!(env!("OUT_DIR"), "/stix_pattern_lexer.rs"));
    }
    pub mod stix_pattern_parser {
        include!(concat!(env!("OUT_DIR"), "/stix_pattern_parser.rs"));
    }
}

use generated::stix_pattern_lexer::StixPatternLexer;
use generated::stix_pattern_parser::StixPatternParser;

#[derive(Clone)]
struct Diag {
    line: usize,
    column: usize,
    message: String,
    token: String,
    token_type: i32,
    span: String,
}

/// Collects diagnostics from both the lexer and the parser.
#[derive(Clone)]
struct Collector(Arc<Mutex<Vec<Diag>>>);

impl<'a> ErrorListener<dyn Recognizer + 'a> for Collector {
    fn syntax_error(
        &mut self,
        _recognizer: &(dyn Recognizer + 'a),
        event: &antlr4_runtime::SyntaxErrorEvent<'_>,
    ) {
        let token = event
            .offending
            .and_then(|token| token.text())
            .unwrap_or("")
            .to_string();
        let token_type = event
            .offending
            .map(|token| token.token_type())
            .unwrap_or_default();
        let span = event
            .span
            .as_ref()
            .map(|span| format!("{}..{}", span.start, span.end))
            .unwrap_or_else(|| "none".to_string());

        self.0.lock().expect("collector lock").push(Diag {
            line: event.line,
            column: event.column,
            message: event.message.to_string(),
            token,
            token_type,
            span,
        });
    }
}

/// Turn one diagnostic into plain language. Kept under 50 lines on purpose:
/// the point is to measure what the library's structured data supports.
fn humanize(diag: &Diag) -> String {
    let pos = format!("{}:{}", diag.line, diag.column);
    let found = if diag.token.is_empty() {
        "the end of the input".to_string()
    } else {
        format!("'{}'", diag.token)
    };

    if diag.token == "'" {
        return format!("{pos}: malformed quoted string (only \\' and \\\\ are valid escapes).");
    }
    if diag.message.starts_with("missing 'EXISTS'") {
        return format!(
            "{pos}: NOT must be followed by EXISTS, or placed after the object path."
        );
    }
    if diag.message.starts_with("no viable alternative") {
        return format!("{pos}: unexpected {found}; no valid pattern element starts here.");
    }
    if let Some(expected) = diag.message.split("expecting ").nth(1) {
        let expected = expected.trim();
        let what = if expected.contains("TimestampLiteral") {
            "a value (number, string, timestamp, boolean, binary, or hex)"
        } else if expected.contains("IntPosLiteral") && expected.contains("FloatPosLiteral") {
            "a positive number"
        } else if expected == "']'" {
            "']' to close the observation expression"
        } else if expected == "<EOF>" {
            "the end of the pattern"
        } else if expected.contains("EXISTS") {
            "EXISTS, or an object path (NOT is not a prefix)"
        } else {
            expected
        };
        return format!("{pos}: expected {what}, found {found}.");
    }
    format!("{pos}: {}, found {found}.", diag.message)
}

fn parse(pattern: &str) -> Result<(), Vec<String>> {
    let collected = Arc::new(Mutex::new(Vec::new()));

    let mut lexer = StixPatternLexer::new(InputStream::new(pattern));
    lexer.remove_error_listeners();
    lexer.add_error_listener(Collector(collected.clone()));

    let tokens = CommonTokenStream::new(lexer);
    let mut parser = StixPatternParser::new(tokens);
    parser.remove_error_listeners();
    parser.add_error_listener(Collector(collected.clone()));

    let tree = parser.pattern();
    let syntax_errors = Parser::number_of_syntax_errors(&parser);
    let fatal = tree.as_ref().err().map(|err| err.to_string());
    let diags = collected.lock().expect("collector lock").clone();

    if syntax_errors == 0 && fatal.is_none() && diags.is_empty() {
        return Ok(());
    }

    let mut errors = Vec::new();
    for diag in &diags {
        errors.push(format!(
            "{}:{}: {} [token={:?} type={} span={}]",
            diag.line, diag.column, diag.message, diag.token, diag.token_type, diag.span
        ));
    }
    for diag in &diags {
        errors.push(format!("display: {}:{} {}", diag.line, diag.column, diag.message));
    }
    for diag in &diags {
        errors.push(format!("formatted: {}", humanize(diag)));
    }
    if errors.is_empty() {
        errors.push(format!(
            "fatal: {}",
            fatal.unwrap_or_else(|| format!("{syntax_errors} syntax error(s)"))
        ));
    }
    Err(errors)
}

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let outcomes = run(&cases, Layer::Grammar, parse);
    let path = harness::results_dir().join("antlr.jsonl");
    write_outcomes(&path, &outcomes)?;
    println!("antlr: {} outcomes -> {}", outcomes.len(), path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(message: &str, token: &str) -> Diag {
        Diag {
            line: 1,
            column: 17,
            message: message.to_string(),
            token: token.to_string(),
            token_type: 0,
            span: "17..27".to_string(),
        }
    }

    #[test]
    fn formatted_messages_are_plain_language() {
        let cases = [
            ("mismatched input 'FALLOWEDBY' expecting ']'", "FALLOWEDBY"),
            (
                "extraneous input 't' expecting {IntPosLiteral, StringLiteral, TimestampLiteral}",
                "t",
            ),
            (
                "mismatched input '-5' expecting {IntPosLiteral, FloatPosLiteral}",
                "-5",
            ),
        ];
        for (message, token) in cases {
            let text = humanize(&diag(message, token));
            assert!(!text.contains("Error {"), "{text}");
            assert!(!text.contains("mismatched input"), "{text}");
            assert!(!text.contains("extraneous input"), "{text}");
            assert!(!text.contains("Literal"), "{text}");
        }
    }
}
