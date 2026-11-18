//! chumsky front end for the STIX Pattern grammar.
//!
//! Left-recursive rules are folded left in Rust. Every major rule carries a
//! `.labelled(...)` user-facing name, because labels are chumsky's error UX.

use std::error::Error;

use chumsky::prelude::*;
use harness::{load_corpus, run, write_outcomes, Layer};

type Extra<'src> = extra::Err<Rich<'src, char>>;

const IDENT_START: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
const IDENT_REST: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
const DIGITS: &str = "0123456789";
const WS: &str = " \t\r\n\u{000B}\u{000C}\u{0085}\u{00A0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}";

fn trivia<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    let ws = one_of(WS).ignored();
    let block = just("/*")
        .then(any().and_is(just("*/").not()).repeated())
        .then(just("*/"))
        .ignored();
    let line = just("//")
        .then(any().and_is(one_of("\r\n").not()).repeated())
        .ignored();
    choice((ws, block, line)).repeated().ignored().labelled("whitespace or comment")
}

fn sym<'src>(c: char) -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just(c).to(()).padded_by(trivia())
}

fn lit<'src>(s: &'static str) -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just(s).to(()).padded_by(trivia())
}

fn ident_char<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    one_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-").to(())
}

fn kw<'src>(s: &'static str) -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just(s).then(ident_char().not()).to(()).padded_by(trivia())
}

fn ident_no_hyphen<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    one_of(IDENT_START)
        .then(one_of(IDENT_REST).repeated())
        .to(())
        .padded_by(trivia())
}

fn ident_with_hyphen<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    one_of(IDENT_START)
        .then(one_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-").repeated())
        .to(())
        .padded_by(trivia())
}

fn digit<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    one_of(DIGITS).to(())
}

fn exact<'src>(n: usize) -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    digit().repeated().exactly(n).to(())
}

fn string_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just('\'')
        .ignore_then(
            choice((
                just("\\'").to(()),
                just("\\\\").to(()),
                any().and_is(one_of("'\\").not()).to(()),
            ))
            .repeated(),
        )
        .then(just('\''))
        .to(())
        .labelled("quoted string")
}

fn hex_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just("h'")
        .ignore_then(
            one_of("0123456789abcdefABCDEF")
                .then(one_of("0123456789abcdefABCDEF"))
                .repeated(),
        )
        .then(just('\''))
        .to(())
        .labelled("hex literal")
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

fn binary_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just("b'")
        .ignore_then(
            one_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=")
                .repeated()
                .to_slice(),
        )
        .then(just('\''))
        .try_map(|(body, _), span| {
            if valid_base64(body) {
                Ok(())
            } else {
                Err(Rich::custom(span, "invalid base64 literal"))
            }
        })
        .labelled("binary literal")
}

fn timestamp_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    let month = choice((
        just('0').then(one_of("123456789")).to(()),
        just('1').then(one_of("012")).to(()),
    ))
    .labelled("month");
    let day = choice((
        just('0').then(one_of("123456789")).to(()),
        one_of("12").then(digit()).to(()),
        just('3').then(one_of("01")).to(()),
    ))
    .labelled("day");
    let hour = choice((
        one_of("01").then(digit()).to(()),
        just('2').then(one_of("0123")).to(()),
    ))
    .labelled("hour");
    let minute = one_of("012345").then(digit()).to(()).labelled("minute");
    let second = choice((one_of("012345").then(digit()).to(()), just("60").to(())))
        .labelled("second");

    just("t'")
        .ignore_then(exact(4))
        .then(sym('-'))
        .then(month)
        .then(sym('-'))
        .then(day)
        .then(lit("T"))
        .then(hour)
        .then(sym(':'))
        .then(minute)
        .then(sym(':'))
        .then(second)
        .then(sym('.').then(digit().repeated().at_least(1)).or_not())
        .then(lit("Z'"))
        .to(())
        .labelled("timestamp")
}

fn int_pos<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just('+')
        .or_not()
        .then(choice((
            just('0').to(()),
            one_of("123456789").then(digit().repeated()).to(()),
        )))
        .to(())
}

fn int_neg<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just('-')
        .then(choice((
            just('0').to(()),
            one_of("123456789").then(digit().repeated()).to(()),
        )))
        .to(())
}

fn float_pos<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just('+')
        .or_not()
        .then(digit().repeated())
        .then(just('.'))
        .then(digit().repeated().at_least(1))
        .to(())
}

fn float_neg<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    just('-')
        .then(digit().repeated())
        .then(just('.'))
        .then(digit().repeated().at_least(1))
        .to(())
}

fn bool_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((kw("true"), kw("false")))
}

fn orderable_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((
        timestamp_literal(),
        hex_literal(),
        binary_literal(),
        string_literal(),
        float_pos(),
        float_neg(),
        int_pos(),
        int_neg(),
    ))
    .labelled("value")
}

fn primitive_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((orderable_literal(), bool_literal()))
}

fn eq_op<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((just("=="), just("="))).to(()) .padded_by(trivia()).labelled("comparison operator")
}

fn neq_op<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((just("!="), just("<>"))).to(()).padded_by(trivia()).labelled("comparison operator")
}

fn order_op<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((just(">="), just("<="), just(">"), just("<")))
        .to(())
        .padded_by(trivia())
        .labelled("comparison operator")
}

fn object_path<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    let first = choice((ident_no_hyphen(), string_literal()));
    let key = choice((ident_no_hyphen(), string_literal()));
    let index = choice((int_pos(), int_neg(), sym('*')));
    let component = choice((
        sym('.').ignore_then(key).to(()),
        sym('[').ignore_then(index).then(sym(']')).to(()),
    ));

    ident_with_hyphen()
        .then(sym(':'))
        .then(first)
        .then(component.repeated())
        .to(())
        .labelled("object path")
}

fn set_literal<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    sym('(')
        .ignore_then(
            primitive_literal()
                .separated_by(sym(','))
                .collect::<Vec<_>>(),
        )
        .then(sym(')'))
        .to(())
        .labelled("set of values")
}

fn prop_test<'src>(
    expr: impl Parser<'src, &'src str, (), Extra<'src>> + Clone + 'src,
) -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((
        object_path()
            .then(kw("NOT").or_not())
            .then(choice((eq_op(), neq_op())))
            .then(primitive_literal())
            .to(()),
        object_path()
            .then(kw("NOT").or_not())
            .then(order_op())
            .then(orderable_literal())
            .to(()),
        object_path()
            .then(kw("NOT").or_not())
            .then(kw("IN"))
            .then(set_literal())
            .to(()),
        object_path()
            .then(kw("NOT").or_not())
            .then(kw("LIKE"))
            .then(string_literal())
            .to(()),
        object_path()
            .then(kw("NOT").or_not())
            .then(kw("MATCHES"))
            .then(string_literal())
            .to(()),
        object_path()
            .then(kw("NOT").or_not())
            .then(kw("ISSUBSET"))
            .then(string_literal())
            .to(()),
        object_path()
            .then(kw("NOT").or_not())
            .then(kw("ISSUPERSET"))
            .then(string_literal())
            .to(()),
        sym('(').ignore_then(expr).then(sym(')')).to(()),
        kw("NOT")
            .or_not()
            .then(kw("EXISTS"))
            .then(object_path())
            .to(()),
    ))
    .labelled("comparison")
}

fn comparison_expression<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    recursive(|expr| {
        let prop = prop_test(expr.clone());
        let and = prop
            .clone()
            .foldl(kw("AND").then(prop).repeated(), |_, _| ());
        and.clone()
            .foldl(kw("OR").then(and).repeated(), |_, _| ())
    })
}

fn qualifier<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    choice((
        kw("START")
            .ignore_then(timestamp_literal())
            .then(kw("STOP"))
            .then(timestamp_literal())
            .to(()),
        kw("WITHIN")
            .ignore_then(choice((float_pos(), int_pos())))
            .then(kw("SECONDS"))
            .to(()),
        kw("REPEATS")
            .ignore_then(int_pos())
            .then(kw("TIMES"))
            .to(()),
    ))
    .labelled("qualifier")
}

fn observation_expressions<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    recursive(|expr| {
        let comparison_obs = sym('[')
            .ignore_then(comparison_expression())
            .then(sym(']'))
            .to(());
        let compound = sym('(').ignore_then(expr).then(sym(')')).to(());
        let observation = choice((comparison_obs, compound))
            .then(qualifier().repeated())
            .to(())
            .labelled("observation expression");
        let and = observation
            .clone()
            .foldl(kw("AND").then(observation).repeated(), |_, _| ());
        let or = and
            .clone()
            .foldl(kw("OR").then(and).repeated(), |_, _| ());
        or.clone()
            .foldl(kw("FOLLOWEDBY").then(or).repeated(), |_, _| ())
    })
}

fn pattern<'src>() -> impl Parser<'src, &'src str, (), Extra<'src>> + Clone {
    observation_expressions().then(end()).to(())
}

fn parse(source: &str) -> Result<(), Vec<String>> {
    let (output, errors) = pattern().parse(source).into_output_errors();
    if output.is_some() && errors.is_empty() {
        return Ok(());
    }

    let mut messages = Vec::new();
    for error in &errors {
        messages.push(format!("{error:?}"));
    }
    for error in &errors {
        messages.push(format!("display: {error}"));
    }
    if messages.is_empty() {
        messages.push("no output and no diagnostic".to_string());
    }
    Err(messages)
}

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let outcomes = run(&cases, Layer::Grammar, parse);
    let path = harness::results_dir().join("chumsky.jsonl");
    write_outcomes(&path, &outcomes)?;
    println!("chumsky: {} outcomes -> {}", outcomes.len(), path.display());
    Ok(())
}
