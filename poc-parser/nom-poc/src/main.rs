//! Fresh nom 8 front end using `VerboseError` and `context()`.
//!
//! This is deliberately not the shipped parser: the question is whether nom's
//! verbose-error machinery can reach acceptable messages, not whether the
//! existing grammar can be patched.

use std::error::Error;

use harness::{load_corpus, run, write_outcomes, Layer};
use nom::{
    branch::alt,
    combinator::opt,
    error::context,
    multi::{many0, separated_list0},
    sequence::{delimited, preceded},
    Parser,
};
use nom_language::error::{convert_error, VerboseError, VerboseErrorKind};

type Res<'a, O = ()> = Result<(&'a str, O), nom::Err<VerboseError<&'a str>>>;

const WS: &str = " \t\r\n\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}";

/// Consume whitespace and comments. Never fails.
fn trivia(mut input: &str) -> &str {
    loop {
        let start = input;
        input = input.trim_start_matches(|c: char| WS.contains(c));
        if let Some(rest) = input.strip_prefix("/*") {
            if let Some(end) = rest.find("*/") {
                input = &rest[end + 2..];
                continue;
            }
            return start;
        }
        if let Some(rest) = input.strip_prefix("//") {
            input = rest.split_once('\n').map(|(_, tail)| tail).unwrap_or("");
            continue;
        }
        if input.len() == start.len() {
            return input;
        }
    }
}

fn padded<'a, O, P>(mut parser: P) -> impl FnMut(&'a str) -> Res<'a, O>
where
    P: Parser<&'a str, Output = O, Error = VerboseError<&'a str>>,
{
    move |input: &'a str| {
        let rest = trivia(input);
        let (rest, output) = parser.parse(rest)?;
        Ok((trivia(rest), output))
    }
}

fn error<'a>(input: &'a str, kind: VerboseErrorKind) -> nom::Err<VerboseError<&'a str>> {
    nom::Err::Error(VerboseError {
        errors: vec![(input, kind)],
    })
}

fn sym<'a>(c: char) -> impl FnMut(&'a str) -> Res<'a> {
    let mut parser = padded(nom::character::complete::char::<&'a str, VerboseError<&'a str>>(c));
    move |input: &'a str| parser(input).map(|(rest, _)| (rest, ()))
}

fn tag<'a>(s: &'static str) -> impl FnMut(&'a str) -> Res<'a> {
    move |input: &'a str| {
        let rest = trivia(input);
        match rest.strip_prefix(s) {
            Some(after) => Ok((trivia(after), ())),
            None => Err(error(rest, VerboseErrorKind::Nom(nom::error::ErrorKind::Tag))),
        }
    }
}

fn ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn kw<'a>(s: &'static str) -> impl FnMut(&'a str) -> Res<'a> {
    move |input: &'a str| {
        let rest = trivia(input);
        match rest.strip_prefix(s) {
            Some(after) if !after.starts_with(ident_char) => Ok((trivia(after), ())),
            _ => Err(error(rest, VerboseErrorKind::Nom(nom::error::ErrorKind::Tag))),
        }
    }
}

fn ident<'a>(allow_hyphen: bool) -> impl FnMut(&'a str) -> Res<'a, ()> {
    move |input: &'a str| {
        let rest = trivia(input);
        let mut chars = rest.char_indices();
        match chars.next() {
            Some((_, c)) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return Err(error(rest, VerboseErrorKind::Context("identifier"))),
        }
        let end = rest
            .char_indices()
            .skip(1)
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || (allow_hyphen && *c == '-')))
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        Ok((&rest[end..], ()))
    }
}

fn scan_string(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    if bytes.first() != Some(&b'\'') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 1 < bytes.len() && (bytes[i + 1] == b'\'' || bytes[i + 1] == b'\\') {
                    i += 2;
                } else {
                    return None;
                }
            }
            b'\'' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn scan_hex(input: &str) -> Option<usize> {
    let rest = input.strip_prefix("h'")?;
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() && bytes[i].is_ascii_hexdigit() && bytes[i + 1].is_ascii_hexdigit() {
        i += 2;
    }
    (bytes.get(i) == Some(&b'\'')).then_some(2 + i + 1)
}

fn valid_base64(body: &str) -> bool {
    let bytes = body.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return false;
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    pad <= 2
        && bytes[..bytes.len() - pad]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

fn scan_binary(input: &str) -> Option<usize> {
    let rest = input.strip_prefix("b'")?;
    let end = rest.find('\'')?;
    valid_base64(&rest[..end]).then_some(2 + end + 1)
}

fn scan_timestamp(input: &str) -> Option<usize> {
    let rest = input.strip_prefix("t'")?;
    let bytes = rest.as_bytes();
    if bytes.len() < 21 {
        return None;
    }
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes.get(i).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let number = |i: usize| (bytes[i] - b'0') as u32 * 10 + (bytes[i + 1] - b'0') as u32;
    let month = number(5);
    let day = number(8);
    let hour = number(11);
    let minute = number(14);
    let second = number(17);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut i = 19;
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    (bytes.get(i) == Some(&b'Z') && bytes.get(i + 1) == Some(&b'\'')).then_some(2 + i + 2)
}

fn scan_int_pos(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut i = usize::from(bytes.first() == Some(&b'+'));
    match bytes.get(i) {
        Some(b'0') => Some(i + 1),
        Some(c) if (b'1'..=b'9').contains(c) => {
            i += 1;
            while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            Some(i)
        }
        _ => None,
    }
}

fn scan_float(input: &str, sign: u8) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut i = usize::from(bytes.first() == Some(&sign));
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    if bytes.get(i) != Some(&b'.') {
        return None;
    }
    i += 1;
    let fraction = i;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    (i > fraction).then_some(i)
}

fn scan_int_neg(input: &str) -> Option<usize> {
    let rest = input.strip_prefix('-')?;
    scan_int_pos(rest).map(|n| n + 1)
}

fn scanner<'a>(
    name: &'static str,
    scan: fn(&str) -> Option<usize>,
) -> impl FnMut(&'a str) -> Res<'a> {
    move |input: &'a str| {
        let rest = trivia(input);
        match scan(rest) {
            Some(len) => Ok((&rest[len..], ())),
            None => Err(error(rest, VerboseErrorKind::Context(name))),
        }
    }
}

fn string_literal<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("quoted string", scan_string)
}
fn hex_literal<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("hex literal", scan_hex)
}
fn binary_literal<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("binary literal", scan_binary)
}
fn timestamp_literal<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("timestamp", scan_timestamp)
}
fn int_pos<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("positive integer", scan_int_pos)
}
fn int_neg<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("negative integer", scan_int_neg)
}
fn float_pos<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("positive number", |s| scan_float(s, b'+'))
}
fn float_neg<'a>() -> impl FnMut(&'a str) -> Res<'a> {
    scanner("negative number", |s| scan_float(s, b'-'))
}

fn bool_literal<'a>(input: &'a str) -> Res<'a> {
    alt((kw("true"), kw("false"))).parse(input)
}

fn orderable_literal<'a>(input: &'a str) -> Res<'a> {
    context(
        "value",
        alt((
            timestamp_literal(),
            hex_literal(),
            binary_literal(),
            string_literal(),
            float_pos(),
            float_neg(),
            int_pos(),
            int_neg(),
        )),
    )
    .parse(input)
}

fn primitive_literal<'a>(input: &'a str) -> Res<'a> {
    alt((orderable_literal, bool_literal)).parse(input)
}

fn eq_op<'a>(input: &'a str) -> Res<'a> {
    context(
        "comparison operator",
        alt((tag("=="), tag("="), tag("!="), tag("<>"))),
    )
    .parse(input)
}

fn order_op<'a>(input: &'a str) -> Res<'a> {
    context(
        "comparison operator",
        alt((tag(">="), tag("<="), tag(">"), tag("<"))),
    )
    .parse(input)
}

fn path_component<'a>(input: &'a str) -> Res<'a> {
    alt((
        preceded(sym('.'), alt((ident(false), string_literal()))),
        delimited(sym('['), alt((int_pos(), int_neg(), sym('*'))), sym(']')),
    ))
    .parse(input)
}

fn object_path<'a>(input: &'a str) -> Res<'a> {
    context(
        "object path",
        (
            ident(true),
            sym(':'),
            alt((ident(false), string_literal())),
            many0(path_component),
        )
            .map(|_| ()),
    )
    .parse(input)
}

fn set_literal<'a>(input: &'a str) -> Res<'a> {
    context(
        "set of values",
        delimited(
            sym('('),
            separated_list0(sym(','), primitive_literal),
            sym(')'),
        )
        .map(|_| ()),
    )
    .parse(input)
}

fn prop_test<'a>(input: &'a str) -> Res<'a> {
    let rest = trivia(input);

    if rest.starts_with('(') {
        return delimited(sym('('), comparison_expression, sym(')')).parse(input);
    }

    if let Ok((after_not, _)) = kw("NOT")(input) {
        if let Ok((after_exists, _)) = kw("EXISTS")(after_not) {
            let (after_path, _) = object_path(after_exists)?;
            return Ok((after_path, ()));
        }
    }

    let (input, _) = object_path(input)?;
    let (input, _) = opt(kw("NOT")).parse(input)?;
    let rest = trivia(input);

    let keyword = |word: &'static str| rest.starts_with(word) && !rest[word.len()..].starts_with(ident_char);
    if keyword("IN") {
        let (input, _) = kw("IN")(input)?;
        return set_literal(input);
    }
    if keyword("LIKE") || keyword("MATCHES") || keyword("ISSUBSET") || keyword("ISSUPERSET") {
        let (input, _) = alt((kw("LIKE"), kw("MATCHES"), kw("ISSUBSET"), kw("ISSUPERSET"))).parse(input)?;
        return string_literal()(input);
    }
    if let Ok((after, _)) = eq_op(input) {
        let (after, _) = primitive_literal(after)?;
        return Ok((after, ()));
    }
    if let Ok((after, _)) = order_op(input) {
        let (after, _) = orderable_literal(after)?;
        return Ok((after, ()));
    }
    Err(error(rest, VerboseErrorKind::Context("comparison operator")))
}

fn comparison_expression<'a>(input: &'a str) -> Res<'a> {
    let (input, _) = prop_test(input)?;
    let (input, _) = repeat_op(input, kw("AND"), prop_test)?;
    repeat_op(input, kw("OR"), prop_test)
}

fn qualifier<'a>(input: &'a str) -> Res<'a> {
    context(
        "qualifier",
        alt((
            (kw("START"), timestamp_literal(), kw("STOP"), timestamp_literal()).map(|_| ()),
            (
                kw("WITHIN"),
                alt((float_pos(), int_pos())),
                kw("SECONDS"),
            )
                .map(|_| ()),
            (kw("REPEATS"), int_pos(), kw("TIMES")).map(|_| ()),
        )),
    )
    .parse(input)
}

fn qualifiers(mut input: &str) -> Res<'_> {
    loop {
        let rest = trivia(input);
        let starts = |word: &str| rest.starts_with(word) && !rest[word.len()..].starts_with(ident_char);
        if starts("WITHIN") || starts("REPEATS") || starts("START") {
            let (after, _) = qualifier(rest)?;
            input = after;
        } else {
            return Ok((input, ()));
        }
    }
}

fn observation<'a>(input: &'a str) -> Res<'a> {
    let rest = trivia(input);
    let (input, _) = if rest.starts_with('[') {
        delimited(sym('['), comparison_expression, sym(']')).parse(input)?
    } else if rest.starts_with('(') {
        delimited(sym('('), observation_expressions, sym(')')).parse(input)?
    } else {
        return Err(error(rest, VerboseErrorKind::Context("observation expression")));
    };
    qualifiers(input)
}

fn observation_and<'a>(input: &'a str) -> Res<'a> {
    let (input, _) = observation(input)?;
    repeat_op(input, kw("AND"), observation)
}

fn observation_or<'a>(input: &'a str) -> Res<'a> {
    let (input, _) = observation_and(input)?;
    repeat_op(input, kw("OR"), observation_and)
}

fn observation_expressions<'a>(input: &'a str) -> Res<'a> {
    let (input, _) = observation_or(input)?;
    repeat_op(input, kw("FOLLOWEDBY"), observation_or)
}

fn pattern(input: &str) -> Res<'_, ()> {
    let input = trivia(input);
    let (input, _) = context("pattern", observation_expressions).parse(input)?;
    let input = trivia(input);
    if input.is_empty() {
        Ok((input, ()))
    } else {
        Err(error(input, VerboseErrorKind::Context("end of pattern")))
    }
}

fn repeat_op<'a>(
    mut input: &'a str,
    mut op: impl FnMut(&'a str) -> Res<'a>,
    mut item: impl FnMut(&'a str) -> Res<'a>,
) -> Res<'a> {
    loop {
        match op(input) {
            Ok((rest, _)) => {
                let (rest, _) = item(rest)?;
                input = rest;
            }
            Err(_) => return Ok((input, ())),
        }
    }
}

fn format_verbose(source: &str, err: &VerboseError<&str>) -> String {
    let Some((input, kind)) = err.errors.iter().min_by_key(|(input, _)| input.len()) else {
        return "unknown parse failure".to_string();
    };
    let offset = source.len().saturating_sub(input.len());
    let line = source[..offset].matches('\n').count() + 1;
    let column = offset - source[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let what = match kind {
        VerboseErrorKind::Context(name) => format!("in {name}"),
        VerboseErrorKind::Char(c) => format!("expected '{c}'"),
        VerboseErrorKind::Nom(nom::error::ErrorKind::Tag) => "expected a keyword or symbol".to_string(),
        VerboseErrorKind::Nom(kind) => format!("expected {kind:?}"),
    };
    let found: String = input.chars().take(12).collect();
    let found = if found.is_empty() {
        "end of input".to_string()
    } else {
        format!("{found:?}")
    };
    format!("{line}:{column}: {what}, found {found}")
}

fn parse(source: &str) -> Result<(), Vec<String>> {
    match pattern(source) {
        Ok((rest, _)) if rest.is_empty() => Ok(()),
        Ok((rest, _)) => Err(vec![format!("unexpected trailing input: {rest:?}")]),
        Err(nom::Err::Error(err)) | Err(nom::Err::Failure(err)) => {
            let raw = format!("{err:?}");
            let display = convert_error(source, err.clone());
            let formatted = format_verbose(source, &err);
            Err(vec![
                raw,
                format!("display: {display}"),
                format!("formatted: {formatted}"),
            ])
        }
        Err(nom::Err::Incomplete(_)) => Err(vec!["incomplete input".to_string()]),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let outcomes = run(&cases, Layer::Grammar, parse);
    let path = harness::results_dir().join("nom.jsonl");
    write_outcomes(&path, &outcomes)?;
    println!("nom: {} outcomes -> {}", outcomes.len(), path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_pattern_parses() {
        let (rest, ()) = pattern("[file:name = 'x']").expect("valid pattern");
        assert_eq!(rest, "");
    }

    #[test]
    fn formatted_error_is_plain_language() {
        let source = "[file:name = ]";
        let nom::Err::Error(err) = pattern(source).unwrap_err() else {
            panic!("expected a recoverable error");
        };
        let text = format_verbose(source, &err);
        assert!(!text.contains("VerboseError"), "{text}");
        assert!(!text.contains("ErrorKind"), "{text}");
        assert!(text.contains("1:"), "{text}");
    }
}
