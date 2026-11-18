//! Render the correctness matrix and verbatim showcase from `results/*.jsonl`.

use std::path::PathBuf;

use harness::{load_corpus, read_outcomes, render_matrix, render_showcase};

fn default_showcase() -> Vec<String> {
    [
        "I01", "I02", "I04", "I05", "I06", "I10", "I12", "I13", "V24", "V31", "V35", "V37", "V38",
        "V45", "I17",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut results_dir = harness::results_dir();
    let mut ids = default_showcase();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--results" => {
                results_dir = PathBuf::from(args.next().ok_or("--results needs a path")?);
            }
            "--ids" => {
                ids = args
                    .next()
                    .ok_or("--ids needs a comma-separated list")?
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let cases = load_corpus(&harness::corpus_dir())?;

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&results_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    entries.sort();

    if entries.is_empty() {
        return Err(format!("no .jsonl results in {}", results_dir.display()).into());
    }

    let mut impls = Vec::new();
    for path in entries {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        impls.push((name, read_outcomes(&path)?));
    }

    println!("{}", render_matrix(&cases, &impls));

    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    println!("{}", render_showcase(&id_refs, &impls));

    Ok(())
}
