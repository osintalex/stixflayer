//! pest front end runner for the STIX Pattern grammar.

use std::error::Error;

use harness::{load_corpus, run, write_outcomes, Layer};
use pest_poc::parse_pattern;

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let outcomes = run(&cases, Layer::Grammar, parse_pattern);
    let path = harness::results_dir().join("pest.jsonl");
    write_outcomes(&path, &outcomes)?;
    println!("pest: {} outcomes -> {}", outcomes.len(), path.display());
    Ok(())
}
