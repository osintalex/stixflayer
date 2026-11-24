//! Implementation of the `stixflayer` command-line validator.
//!
//! The library is split out from the binary so input discovery, document
//! classification, report construction, and exit-code handling can be unit
//! tested without spawning a process.

pub mod cli;
pub mod discovery;
pub mod report;
pub mod validate;

use std::path::PathBuf;

use clap::Parser;
use rayon::prelude::*;

use crate::cli::Cli;
use crate::discovery::{discover, InputError};
use crate::report::{DocumentResult, Report, SkippedDocument};
use crate::validate::{validate_document, Options};

/// The checked-in JSON Schema printed by `--print-schema`.
pub const REPORT_SCHEMA: &str = include_str!("../schema/report.schema.json");

/// Runs the CLI and returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();

    if cli.print_schema {
        print!("{REPORT_SCHEMA}");
        if !REPORT_SCHEMA.ends_with('\n') {
            println!();
        }
        return 0;
    }

    match validate_inputs(&cli) {
        Ok(report) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes to JSON")
                );
            } else {
                print!("{}", report::render_human(&report));
            }
            exit_code(&report, cli.fail_on_warnings)
        }
        Err(error) => {
            eprintln!("stixflayer: {error}");
            2
        }
    }
}

/// Discovers, validates, and assembles the report for the parsed arguments.
fn validate_inputs(cli: &Cli) -> Result<Report, InputError> {
    let inputs = discover(&cli.paths)?;
    // STIX 2.1 allows custom properties, and SHOULD findings are warnings
    // rather than opt-in checks. The CLI always validates the full spec.
    let options = Options {
        allow_custom: true,
        strict: true,
    };

    let documents = run_pool(cli.jobs, || {
        inputs
            .par_iter()
            .map(|input| validate_document(&input.path, &input.content, &options))
            .collect::<Vec<_>>()
    })?;

    let mut results = Vec::new();
    let mut skipped = Vec::new();
    for (input, document) in inputs.into_iter().zip(documents) {
        match document {
            validate::Document::Skipped { reason } => skipped.push(SkippedDocument {
                path: input.path,
                reason,
            }),
            validate::Document::Result {
                valid,
                errors,
                warnings,
                objects,
            } => results.push(DocumentResult {
                path: input.path,
                valid,
                errors,
                warnings,
                objects,
            }),
        }
    }

    Ok(Report::from_documents(results, skipped))
}

/// Runs `work` on a dedicated pool when `jobs` is non-zero, or on rayon's
/// global pool (all logical cores) when it is zero.
fn run_pool<T, F>(jobs: usize, work: F) -> Result<T, InputError>
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    if jobs == 0 {
        return Ok(work());
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .map_err(|error| InputError {
            path: PathBuf::from("-j"),
            message: format!("could not start {jobs} worker threads: {error}"),
        })?;
    Ok(pool.install(work))
}

/// Maps a completed report to the documented exit code.
fn exit_code(report: &Report, fail_on_warnings: bool) -> i32 {
    let invalid = report.summary.invalid > 0;
    let warnings = fail_on_warnings && report.summary.warnings > 0;
    if invalid || warnings {
        1
    } else {
        0
    }
}
