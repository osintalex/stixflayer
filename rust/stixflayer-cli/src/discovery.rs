//! Input discovery: expand directory arguments, filter extensions, and read
//! every candidate into memory before validation starts.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The path reported for a document read from standard input.
pub const STDIN_PATH: &str = "-";

/// A document read from a file or standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The path shown in reports; `-` for standard input.
    pub path: String,
    /// The document text.
    pub content: String,
}

/// An operational input failure. These map to exit code 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// The path that could not be read, or `-j` for a thread-pool failure.
    pub path: PathBuf,
    /// A human-readable description.
    pub message: String,
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for InputError {}

#[derive(Debug, Clone)]
enum Candidate {
    File(PathBuf),
    Stdin,
}

impl Candidate {
    fn sort_key(&self) -> String {
        match self {
            Self::File(path) => path.to_string_lossy().into_owned(),
            Self::Stdin => STDIN_PATH.to_string(),
        }
    }
}

/// Expands `paths`, reads every selected document, and returns the inputs in a
/// deterministic path order.
pub fn discover(paths: &[PathBuf]) -> Result<Vec<Input>, InputError> {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    discover_with_stdin(paths, &mut lock)
}

/// Testable form of [`discover`] that reads standard input from `stdin`.
pub fn discover_with_stdin<R: Read>(
    paths: &[PathBuf],
    stdin: &mut R,
) -> Result<Vec<Input>, InputError> {
    let mut candidates = Vec::new();
    for path in paths {
        if path == Path::new(STDIN_PATH) {
            candidates.push(Candidate::Stdin);
            continue;
        }

        let metadata = fs::metadata(path).map_err(|error| InputError {
            path: path.clone(),
            message: format!("cannot access path: {error}"),
        })?;
        if metadata.is_dir() {
            walk_dir(path, &mut candidates)?;
        } else if metadata.is_file() {
            // An explicitly named file bypasses the extension filter.
            candidates.push(Candidate::File(path.clone()));
        } else {
            return Err(InputError {
                path: path.clone(),
                message: "not a regular file or directory".to_string(),
            });
        }
    }

    candidates.sort_by_key(Candidate::sort_key);

    let mut inputs = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        match candidate {
            Candidate::File(path) => {
                let content = fs::read_to_string(&path).map_err(|error| InputError {
                    path: path.clone(),
                    message: format!("cannot read file: {error}"),
                })?;
                inputs.push(Input {
                    path: path.to_string_lossy().into_owned(),
                    content,
                });
            }
            Candidate::Stdin => {
                let mut content = String::new();
                stdin
                    .read_to_string(&mut content)
                    .map_err(|error| InputError {
                        path: PathBuf::from(STDIN_PATH),
                        message: format!("cannot read standard input: {error}"),
                    })?;
                inputs.push(Input {
                    path: STDIN_PATH.to_string(),
                    content,
                });
            }
        }
    }

    Ok(inputs)
}

fn walk_dir(dir: &Path, candidates: &mut Vec<Candidate>) -> Result<(), InputError> {
    let entries = fs::read_dir(dir).map_err(|error| InputError {
        path: dir.to_path_buf(),
        message: format!("cannot read directory: {error}"),
    })?;

    let mut paths = entries
        .map(|entry| {
            entry.map(|entry| entry.path()).map_err(|error| InputError {
                path: dir.to_path_buf(),
                message: format!("cannot read directory entry: {error}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();

    for path in paths {
        let metadata = fs::metadata(&path).map_err(|error| InputError {
            path: path.clone(),
            message: format!("cannot inspect path: {error}"),
        })?;
        if metadata.is_dir() {
            walk_dir(&path, candidates)?;
        } else if metadata.is_file() && is_stix_extension(&path) {
            candidates.push(Candidate::File(path));
        }
    }

    Ok(())
}

/// Returns true when the path's extension is one of the three STIX extensions.
pub fn is_stix_extension(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "json" | "jsonl" | "stix2" | "stix"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn directory_scan_selects_only_stix_extensions() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "feed.stix2", "{}");
        write(dir.path(), "bundle.json", "{}");
        write(dir.path(), "feed.jsonl", "{}");
        write(dir.path(), "notes.md", "{}");
        write(dir.path(), "config.yaml", "{}");
        fs::create_dir(dir.path().join("nested")).unwrap();
        write(&dir.path().join("nested"), "deep.stix", "{}");

        let inputs = discover(&[dir.path().to_path_buf()]).unwrap();
        let names: Vec<_> = inputs
            .iter()
            .map(|input| {
                Path::new(&input.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        // Inputs are ordered by full path, so a top-level file precedes a
        // nested one even when the nested file's basename sorts earlier.
        assert_eq!(
            names,
            ["bundle.json", "feed.jsonl", "feed.stix2", "deep.stix"]
        );
    }

    #[test]
    fn explicit_path_bypasses_the_extension_filter() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "document.txt", "{}");

        let inputs = discover(std::slice::from_ref(&path)).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, path.to_string_lossy());
    }

    #[test]
    fn standard_input_is_reported_under_dash() {
        let mut stdin = Cursor::new(b"{\"type\":\"bundle\"}".to_vec());
        let inputs = discover_with_stdin(&[PathBuf::from("-")], &mut stdin).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "-");
        assert_eq!(inputs[0].content, "{\"type\":\"bundle\"}");
    }

    #[test]
    fn missing_path_is_an_input_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let error = discover(&[missing]).unwrap_err();
        assert!(error.message.contains("cannot access path"));
    }
}
