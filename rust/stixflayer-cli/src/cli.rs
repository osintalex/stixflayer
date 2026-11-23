//! Command-line argument definitions.

use std::path::PathBuf;

use clap::Parser;

/// Validate STIX 2.1 documents from files, directories, or standard input.
#[derive(Debug, Parser)]
#[command(
    name = "stixflayer",
    version,
    about = "Validate STIX 2.1 documents from files, directories, or standard input",
    long_about = None
)]
pub struct Cli {
    /// Files or directories to validate, or `-` to read one document from stdin.
    ///
    /// Directories are walked recursively and only files ending in .json,
    /// .stix2, or .stix are selected. An explicitly named file is always
    /// validated regardless of its extension.
    #[arg(value_name = "PATH", required_unless_present = "print_schema")]
    pub paths: Vec<PathBuf>,

    /// Number of worker threads (0 uses every logical core).
    #[arg(short = 'j', long = "jobs", value_name = "N", default_value_t = 0)]
    pub jobs: usize,

    /// Write the machine-readable JSON report instead of human-readable output.
    #[arg(long)]
    pub json: bool,

    /// Print the JSON Schema for the report and exit without validating input.
    #[arg(long)]
    pub print_schema: bool,

    /// Accept custom properties such as ATT&CK's x_mitre_* fields.
    #[arg(long)]
    pub allow_custom: bool,

    /// Skip semantic (SHOULD-level) checks and report only structural errors.
    #[arg(long)]
    pub no_strict: bool,

    /// Exit 1 when any warning is reported.
    #[arg(long)]
    pub fail_on_warnings: bool,
}
