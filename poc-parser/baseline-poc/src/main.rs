//! Baseline column: the pattern validator the repository ships today.

use std::error::Error;

use harness::{load_corpus, run, write_outcomes, Layer};

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let outcomes = run(&cases, Layer::Full, |pattern| {
        stixflayer::pattern::validate_pattern(pattern).map_err(|err| vec![format!("{err}")])
    });

    let path = harness::results_dir().join("baseline.jsonl");
    write_outcomes(&path, &outcomes)?;
    println!("baseline: {} outcomes -> {}", outcomes.len(), path.display());
    Ok(())
}
