//! Shared corpus and result types for the STIX pattern parser comparison.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Grammar-layer verdict for a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Accept,
    Reject,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Accept => "accept",
            Verdict::Reject => "reject",
        }
    }
}

/// Why a case's expected verdict is authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Basis {
    Grammar,
    Reference,
    Spec,
    Shipped,
}

/// Which layer produced an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    /// Grammar only: the four front-end PoCs.
    Grammar,
    /// Grammar plus the shipped semantic layer.
    Full,
}

/// One corpus entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub input: String,
    pub expected: Verdict,
    pub basis: Basis,
    pub semantic: bool,
    pub note: String,
}

/// One implementation's result for one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub input: String,
    pub result: Verdict,
    pub errors: Vec<String>,
    pub layer: Layer,
}

pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../corpus")
}

pub fn results_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../results")
}

/// Load `valid.jsonl` then `invalid.jsonl`, sorted by id.
pub fn load_corpus(dir: &Path) -> std::io::Result<Vec<Case>> {
    let mut cases = Vec::new();
    for name in ["valid.jsonl", "invalid.jsonl"] {
        let file = File::open(dir.join(name))?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let case: Case = serde_json::from_str(&line).map_err(std::io::Error::other)?;
            cases.push(case);
        }
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cases)
}

pub fn write_outcomes(path: &Path, outcomes: &[Outcome]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    for outcome in outcomes {
        let line = serde_json::to_string(outcome).map_err(std::io::Error::other)?;
        writeln!(file, "{line}")?;
    }
    Ok(())
}

pub fn read_outcomes(path: &Path) -> std::io::Result<Vec<Outcome>> {
    let file = File::open(path)?;
    let mut outcomes = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let outcome: Outcome = serde_json::from_str(&line).map_err(std::io::Error::other)?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Run `parse` over every case and collect outcomes in corpus order.
///
/// `parse` returns `Err(errors)` when the pattern is rejected. The error list
/// is captured verbatim; runners may include a second entry prefixed with
/// `display:` for a library-specific rendering.
pub fn run<F>(cases: &[Case], layer: Layer, mut parse: F) -> Vec<Outcome>
where
    F: FnMut(&str) -> Result<(), Vec<String>>,
{
    cases
        .iter()
        .map(|case| {
            let parsed = parse(&case.input);
            Outcome {
                id: case.id.clone(),
                input: case.input.clone(),
                result: if parsed.is_ok() {
                    Verdict::Accept
                } else {
                    Verdict::Reject
                },
                errors: parsed.err().unwrap_or_default(),
                layer,
            }
        })
        .collect()
}

/// Render the correctness matrix for a set of implementations.
///
/// `impls` is `(name, outcomes)`; the output is ASCII-only and stable so it can
/// be snapshot-tested.
pub fn render_matrix(cases: &[Case], impls: &[(String, Vec<Outcome>)]) -> String {
    let mut out = String::new();
    out.push_str("id    expected  ");
    for (name, _) in impls {
        out.push_str(&format!("{name:<12}"));
    }
    out.push('\n');

    for case in cases {
        out.push_str(&format!("{:<5} {:<9} ", case.id, case.expected.as_str()));
        for (_, outcomes) in impls {
            let cell = outcomes
                .iter()
                .find(|o| o.id == case.id)
                .map(|o| {
                    if o.result == case.expected {
                        "ok"
                    } else if case.semantic && o.layer == Layer::Full {
                        "sem"
                    } else {
                        "WRONG"
                    }
                })
                .unwrap_or("missing");
            out.push_str(&format!("{cell:<12}"));
        }
        out.push('\n');
    }

    out.push('\n');
    for (name, outcomes) in impls {
        let wrong = outcomes
            .iter()
            .filter(|o| {
                cases.iter().find(|c| c.id == o.id).is_some_and(|c| {
                    c.expected != o.result && !(c.semantic && o.layer == Layer::Full)
                })
            })
            .count();
        let semantic = outcomes
            .iter()
            .filter(|o| {
                cases.iter().find(|c| c.id == o.id).is_some_and(|c| {
                    c.semantic && o.layer == Layer::Full && c.expected != o.result
                })
            })
            .count();
        let must_pass = cases.iter().filter(|c| c.expected == Verdict::Accept).count();
        let accepted = outcomes
            .iter()
            .filter(|o| o.result == Verdict::Accept)
            .filter(|o| {
                cases
                    .iter()
                    .find(|c| c.id == o.id)
                    .is_some_and(|c| c.expected == Verdict::Accept)
            })
            .count();
        out.push_str(&format!(
            "{name:<12} wrong={wrong:<4} sem={semantic:<4} must-pass={accepted}/{must_pass}\n"
        ));
    }
    out
}

/// Render the verbatim error showcase for selected case ids.
pub fn render_showcase(ids: &[&str], impls: &[(String, Vec<Outcome>)]) -> String {
    let mut out = String::new();
    for id in ids {
        out.push_str(&format!("\n== {id} ==\n"));
        for (name, outcomes) in impls {
            let Some(outcome) = outcomes.iter().find(|o| o.id == *id) else {
                out.push_str(&format!("{name}: missing\n"));
                continue;
            };
            out.push_str(&format!(
                "{name} [{}]:\n",
                outcome.result.as_str()
            ));
            if outcome.errors.is_empty() {
                out.push_str("  (no error)\n");
            } else {
                for error in &outcome.errors {
                    for line in error.lines() {
                        out.push_str(&format!("  {line}\n"));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str, expected: Verdict) -> Case {
        Case {
            id: id.to_string(),
            input: format!("[{id}]"),
            expected,
            basis: Basis::Grammar,
            semantic: false,
            note: String::new(),
        }
    }

    #[test]
    fn case_and_outcome_round_trip() {
        let case = Case {
            id: "V01".into(),
            input: "[file:name = 'x']".into(),
            expected: Verdict::Accept,
            basis: Basis::Reference,
            semantic: false,
            note: "note".into(),
        };
        let json = serde_json::to_string(&case).unwrap();
        assert_eq!(serde_json::from_str::<Case>(&json).unwrap(), case);

        let outcome = Outcome {
            id: "I01".into(),
            input: "[file:name = ]".into(),
            result: Verdict::Reject,
            errors: vec!["raw".into(), "display: pretty".into()],
            layer: Layer::Grammar,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
    }

    #[test]
    fn corpus_loads_and_is_consistent() {
        let cases = load_corpus(&corpus_dir()).unwrap();
        assert!(cases.len() >= 70, "unexpected corpus size: {}", cases.len());
        for case in &cases {
            if case.semantic {
                assert_eq!(case.expected, Verdict::Accept, "{}", case.id);
            }
        }
    }

    #[test]
    fn matrix_marks_wrong_and_missing() {
        let cases = vec![case("A", Verdict::Accept), case("B", Verdict::Reject)];
        let good = vec![
            Outcome {
                id: "A".into(),
                input: "[A]".into(),
                result: Verdict::Accept,
                errors: vec![],
                layer: Layer::Grammar,
            },
            Outcome {
                id: "B".into(),
                input: "[B]".into(),
                result: Verdict::Reject,
                errors: vec!["bad".into()],
                layer: Layer::Grammar,
            },
        ];
        let rendered = render_matrix(&cases, &[("good".into(), good)]);
        assert!(rendered.contains("ok"));
        assert!(!rendered.contains("WRONG"));
        assert!(rendered.contains("wrong=0"));
        assert!(rendered.contains("must-pass=1/1"));
    }
}
