#![cfg(unix)]
//! Scripted tests for the release `install.sh`.
//!
//! The tests replace `uname` and `curl` with small fakes so no network access
//! or platform-specific release assets are needed.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("project root exists")
}

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn fake_bin(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    write_executable(
        &dir.join("uname"),
        r#"#!/bin/sh
case "$1" in
  -s) printf '%s\n' "${FAKE_UNAME_S:-Linux}" ;;
  -m) printf '%s\n' "${FAKE_UNAME_M:-x86_64}" ;;
  *) printf 'unknown\n' ;;
esac
"#,
    );
    write_executable(
        &dir.join("curl"),
        r#"#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
[ -n "$out" ] || { echo "fake curl: no output path" >&2; exit 1; }
name="$(basename "$url")"
[ -f "${FAKE_RELEASES}/${name}" ] || { echo "fake curl: missing ${name}" >&2; exit 1; }
cp "${FAKE_RELEASES}/${name}" "$out"
"#,
    );
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        _ => Command::new("shasum")
            .arg("-a")
            .arg("256")
            .arg(path)
            .output()
            .expect("sha256sum or shasum is available"),
    };
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn make_release(releases: &Path, version: &str, target: &str, binary_body: &str) -> PathBuf {
    fs::create_dir_all(releases).unwrap();
    let staging = releases.join(format!("staging-{version}-{target}"));
    fs::create_dir_all(&staging).unwrap();
    write_executable(&staging.join("stixflayer"), binary_body);

    let archive = releases.join(format!("stixflayer-{version}-{target}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&staging)
        .arg("stixflayer")
        .status()
        .unwrap();
    assert!(status.success());

    let sums = releases.join("SHA256SUMS");
    let mut contents = fs::read_to_string(&sums).unwrap_or_default();
    contents.push_str(&format!(
        "{}  {}\n",
        sha256(&archive),
        archive.file_name().unwrap().to_string_lossy()
    ));
    fs::write(&sums, contents).unwrap();
    archive
}

struct Fixture {
    _temp: tempfile::TempDir,
    releases: PathBuf,
    install_dir: PathBuf,
    home: PathBuf,
    path: String,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    fake_bin(&bin);
    let releases = temp.path().join("releases");
    fs::create_dir_all(&releases).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Fixture {
        install_dir: temp.path().join("install"),
        home: temp.path().join("home"),
        releases,
        path,
        _temp: temp,
    }
}

fn run_install(fixture: &Fixture, version: &str, os: &str, arch: &str) -> Output {
    Command::new("sh")
        .arg(project_root().join("install.sh"))
        .env("PATH", &fixture.path)
        .env("HOME", &fixture.home)
        .env("FAKE_RELEASES", &fixture.releases)
        .env("STIXFLAYER_INSTALL_DIR", &fixture.install_dir)
        .env("STIXFLAYER_VERSION", version)
        .env("FAKE_UNAME_S", os)
        .env("FAKE_UNAME_M", arch)
        .output()
        .expect("install.sh runs")
}

#[test]
fn installs_linux_x86_64() {
    let fixture = fixture();
    make_release(
        &fixture.releases,
        "0.1.0",
        "x86_64-unknown-linux-musl",
        "#!/bin/sh\necho 'stixflayer 0.1.0'\n",
    );

    let output = run_install(&fixture, "0.1.0", "Linux", "x86_64");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let binary = fixture.install_dir.join("stixflayer");
    assert!(binary.is_file());
    let version = Command::new(&binary).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        "stixflayer 0.1.0"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("installed stixflayer 0.1.0"));
}

#[test]
fn installs_a_pinned_version() {
    let fixture = fixture();
    make_release(
        &fixture.releases,
        "0.1.0",
        "x86_64-unknown-linux-musl",
        "#!/bin/sh\necho 'stixflayer 0.1.0'\n",
    );
    make_release(
        &fixture.releases,
        "0.2.0",
        "x86_64-unknown-linux-musl",
        "#!/bin/sh\necho 'stixflayer 0.2.0'\n",
    );

    let output = run_install(&fixture, "0.2.0", "Linux", "x86_64");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let binary = fixture.install_dir.join("stixflayer");
    let version = Command::new(&binary).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        "stixflayer 0.2.0"
    );
}

#[test]
fn checksum_mismatch_aborts_without_installing() {
    let fixture = fixture();
    make_release(
        &fixture.releases,
        "0.3.0",
        "x86_64-unknown-linux-musl",
        "#!/bin/sh\necho 'stixflayer 0.3.0'\n",
    );
    fs::write(
        fixture.releases.join("SHA256SUMS"),
        format!(
            "{}  stixflayer-0.3.0-x86_64-unknown-linux-musl.tar.gz\n",
            "0".repeat(64)
        ),
    )
    .unwrap();

    let output = run_install(&fixture, "0.3.0", "Linux", "x86_64");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("checksum mismatch"), "stderr: {stderr}");
    assert!(!fixture.install_dir.join("stixflayer").exists());
}

#[test]
fn unsupported_operating_system_names_supported_platforms() {
    let fixture = fixture();
    let output = run_install(&fixture, "0.1.0", "Windows_NT", "x86_64");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Linux"), "stderr: {stderr}");
    assert!(stderr.contains("macOS"), "stderr: {stderr}");
    assert!(!fixture.install_dir.join("stixflayer").exists());
}
