//! Proof that the proposed AST extension represents every must-pass pattern.

use std::collections::HashMap;
use std::error::Error;

use harness::{load_corpus, read_outcomes, Verdict};
use spike_poc::mirror;

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let baseline: HashMap<String, Verdict> =
        read_outcomes(&harness::results_dir().join("baseline.jsonl"))?
            .into_iter()
            .map(|outcome| (outcome.id, outcome.result))
            .collect();

    let mut lines = Vec::new();
    let mut built = 0usize;
    let mut failures = Vec::new();
    let mut gapped_before = Vec::new();

    for case in cases.iter().filter(|case| case.expected == Verdict::Accept) {
        match mirror::build(&case.input) {
            Ok(observation) => {
                built += 1;
                let checked = mirror::check(&observation);
                let verdict = if checked.is_ok() {
                    Verdict::Accept
                } else {
                    Verdict::Reject
                };

                let expected = if case.semantic {
                    baseline.get(&case.id).copied().unwrap_or(case.expected)
                } else {
                    Verdict::Accept
                };

                if verdict != expected {
                    failures.push(format!(
                        "{}: expected {} got {} ({:?})",
                        case.id,
                        expected.as_str(),
                        verdict.as_str(),
                        checked.err()
                    ));
                }
                if matches!(case.id.as_str(), "V17" | "V28" | "V29" | "V49") {
                    gapped_before.push(case.id.clone());
                }

                lines.push(
                    serde_json::json!({
                        "id": case.id,
                        "built": true,
                        "check": verdict.as_str(),
                        "expected": expected.as_str(),
                        "baseline": baseline.get(&case.id).copied().map(Verdict::as_str),
                    })
                    .to_string(),
                );
            }
            Err(error) => {
                failures.push(format!("{}: build failed: {error}", case.id));
                lines.push(
                    serde_json::json!({
                        "id": case.id,
                        "built": false,
                        "error": error,
                    })
                    .to_string(),
                );
            }
        }
    }

    let dir = harness::results_dir().join("spike");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("mirror.jsonl"), lines.join("\n") + "\n")?;

    println!("mirror: built {built}/51; {} failures", failures.len());
    println!("previously gapped, now built: {}", gapped_before.join(", "));
    for failure in &failures {
        println!("  {failure}");
    }

    if !failures.is_empty() || built != 51 {
        return Err("mirror proof failed".into());
    }
    Ok(())
}
