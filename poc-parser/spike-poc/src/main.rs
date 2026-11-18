//! Winner spike: build the real `stixflayer::pattern::expr` AST from pest and
//! run the real semantic layer over it.

use std::collections::HashMap;
use std::error::Error;

use harness::{load_corpus, read_outcomes, Verdict};
use stixflayer::base::Stix;

fn main() -> Result<(), Box<dyn Error>> {
    let cases = load_corpus(&harness::corpus_dir())?;
    let baseline: HashMap<String, Verdict> =
        read_outcomes(&harness::results_dir().join("baseline.jsonl"))?
            .into_iter()
            .map(|outcome| (outcome.id, outcome.result))
            .collect();

    let mut lines = Vec::new();
    let mut built = 0usize;
    let mut gaps: Vec<(String, String)> = Vec::new();
    let mut semantic_mismatches = Vec::new();
    let mut unexpected_rejects = Vec::new();

    for case in &cases {
        // Invalid cases are already covered by the front-end verdicts; the
        // spike is about AST representability for must-pass patterns.
        if case.expected == Verdict::Reject {
            continue;
        }
        match spike_poc::build(&case.input) {
            Ok(ast) => {
                built += 1;
                let semantic_ok = ast.stix_check().is_ok();
                let baseline_result = baseline.get(&case.id).copied();

                if case.semantic {
                    if let Some(baseline_result) = baseline_result {
                        let expected_accept = baseline_result == Verdict::Accept;
                        if expected_accept != semantic_ok {
                            semantic_mismatches.push(format!(
                                "{}: baseline={} stix_check={}",
                                case.id,
                                baseline_result.as_str(),
                                if semantic_ok { "accept" } else { "reject" }
                            ));
                        }
                    }
                } else if case.expected == Verdict::Accept && !semantic_ok {
                    unexpected_rejects.push(case.id.clone());
                }

                lines.push(
                    serde_json::json!({
                        "id": case.id,
                        "ast": "built",
                        "semantic": if semantic_ok { "accept" } else { "reject" },
                        "baseline": baseline_result.map(Verdict::as_str),
                        "note": "",
                    })
                    .to_string(),
                );
            }
            Err(gap) => {
                gaps.push((case.id.clone(), gap.to_string()));
                lines.push(
                    serde_json::json!({
                        "id": case.id,
                        "ast": "gap",
                        "gap": gap.to_string(),
                        "semantic": null,
                        "baseline": baseline.get(&case.id).copied().map(Verdict::as_str),
                    })
                    .to_string(),
                );
            }
        }
    }

    let path = harness::results_dir().join("spike.jsonl");
    std::fs::write(&path, lines.join("\n") + "\n")?;

    println!(
        "built {built}/{} ASTs; {} gaps; {} semantic mismatches; {} unexpected rejects",
        cases.iter().filter(|case| case.expected == Verdict::Accept).count(),
        gaps.len(),
        semantic_mismatches.len(),
        unexpected_rejects.len()
    );
    for (id, gap) in &gaps {
        println!("  gap {id}: {gap}");
    }
    for mismatch in &semantic_mismatches {
        println!("  semantic mismatch {mismatch}");
    }
    for id in &unexpected_rejects {
        println!("  stix_check rejected grammar-valid case {id}");
    }

    Ok(())
}
