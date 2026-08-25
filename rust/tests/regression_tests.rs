//! Regression tests for kebab-case / vocabulary serialization correctness.
//!
//! STIX 2.1 vocabulary values must match the exact strings defined in the
//! specification and JSON schemas.  The `convert_case` crate's default
//! `to_case(Case::Kebab)` incorrectly splits numbers (e.g. "x86" → "x-86"),
//! and `strum(serialize_all = "kebab-case")` produces wrong strings for
//! some compound identifiers (e.g. "PowerPC" → "power-pc" instead of
//! "powerpc").  These tests document the required values.

use stixflayer::domain_objects::vocab::{
    ArchitectureExecutionEnvs, ImplementationLanguage, OpinionType,
};
use stixflayer::types::{stix_case, LegalHashTypes};
use strum::IntoEnumIterator;

// ---------------------------------------------------------------------------
// 1.  stix_case()  — the helper used when normalising user input
// ---------------------------------------------------------------------------

#[test]
fn stix_case_preserves_numbers() {
    assert_eq!(stix_case("x86"), "x86");
    assert_eq!(stix_case("x86-64"), "x86-64");
    assert_eq!(stix_case("x86_64"), "x86-64");
}

#[test]
fn stix_case_handles_type_names() {
    assert_eq!(stix_case("X509Certificate"), "x509-certificate");
    assert_eq!(stix_case("Ipv4Addr"), "ipv4-addr");
    assert_eq!(stix_case("Ipv6Addr"), "ipv6-addr");
    assert_eq!(stix_case("MacAddr"), "mac-addr");
    assert_eq!(stix_case("EmailAddress"), "email-address");
    assert_eq!(stix_case("WindowsRegistryKey"), "windows-registry-key");
}

#[test]
fn stix_case_lowercases_simple_words() {
    assert_eq!(stix_case("Arm"), "arm");
    assert_eq!(stix_case("Alpha"), "alpha");
    assert_eq!(stix_case("Ransomware"), "ransomware");
}

#[test]
fn stix_case_splits_camel_case() {
    assert_eq!(stix_case("CommandAndControl"), "command-and-control");
    assert_eq!(stix_case("AntiDebugging"), "anti-debugging");
}

#[test]
fn stix_case_round_trips_existing_kebab() {
    assert_eq!(stix_case("x509-certificate"), "x509-certificate");
    assert_eq!(stix_case("email-addr"), "email-addr");
    assert_eq!(stix_case("ia-64"), "ia-64");
}

// ---------------------------------------------------------------------------
// 2.  Enum variant → string (AsRefStr)  — what strum produces
// ---------------------------------------------------------------------------

#[test]
fn architecture_execution_envs_variants() {
    let expected = &[
        (ArchitectureExecutionEnvs::Alpha, "alpha"),
        (ArchitectureExecutionEnvs::Arm, "arm"),
        (ArchitectureExecutionEnvs::Ia64, "ia-64"),
        (ArchitectureExecutionEnvs::Mips, "mips"),
        (ArchitectureExecutionEnvs::PowerPC, "powerpc"),
        (ArchitectureExecutionEnvs::Sparc, "sparc"),
        (ArchitectureExecutionEnvs::X86, "x86"),
        (ArchitectureExecutionEnvs::X86_64, "x86-64"),
    ];
    for (variant, want) in expected {
        let got = variant.as_ref();
        assert_eq!(
            got, *want,
            "ArchitectureExecutionEnvs::{:?} should serialize to '{}' but got '{}'",
            variant, want, got
        );
    }
    // Also ensure the enum is exhaustive for the test
    assert_eq!(
        ArchitectureExecutionEnvs::iter().count(),
        expected.len(),
        "new ArchitectureExecutionEnvs variant added – please update test"
    );
}

#[test]
fn implementation_language_variants() {
    let expected = &[
        (ImplementationLanguage::AppleScript, "applescript"),
        (ImplementationLanguage::Bash, "bash"),
        (ImplementationLanguage::C, "c"),
        (ImplementationLanguage::CPlusPlus, "c++"),
        (ImplementationLanguage::CSharp, "c#"),
        (ImplementationLanguage::Go, "go"),
        (ImplementationLanguage::Java, "java"),
        (ImplementationLanguage::JavaScript, "javascript"),
        (ImplementationLanguage::Lua, "lua"),
        (ImplementationLanguage::ObjectiveC, "objective-c"),
        (ImplementationLanguage::Perl, "perl"),
        (ImplementationLanguage::Php, "php"),
        (ImplementationLanguage::PowerShell, "powershell"),
        (ImplementationLanguage::Python, "python"),
        (ImplementationLanguage::Ruby, "ruby"),
        (ImplementationLanguage::Scala, "scala"),
        (ImplementationLanguage::Swift, "swift"),
        (ImplementationLanguage::TypeScript, "typescript"),
        (ImplementationLanguage::VisualBasic, "visual-basic"),
        (ImplementationLanguage::X86_32, "x86-32"),
        (ImplementationLanguage::X86_64, "x86-64"),
    ];
    for (variant, want) in expected {
        let got = variant.as_ref();
        assert_eq!(
            got, *want,
            "ImplementationLanguage::{:?} should serialize to '{}' but got '{}'",
            variant, want, got
        );
    }
    assert_eq!(
        ImplementationLanguage::iter().count(),
        expected.len(),
        "new ImplementationLanguage variant added – please update test"
    );
}

#[test]
fn legal_hash_types_variants() {
    let expected = &[
        (LegalHashTypes::MD5, "md5"),
        (LegalHashTypes::SHA1, "sha-1"),
        (LegalHashTypes::SHA256, "sha-256"),
        (LegalHashTypes::SHA512, "sha-512"),
        (LegalHashTypes::SHA3256, "sha3-256"),
        (LegalHashTypes::SHA3512, "sha3-512"),
        (LegalHashTypes::SSDEEP, "ssdeep"),
        (LegalHashTypes::TLSH, "tlsh"),
    ];
    for (variant, want) in expected {
        let got = variant.as_ref();
        assert_eq!(
            got, *want,
            "LegalHashTypes::{:?} should serialize to '{}' but got '{}'",
            variant, want, got
        );
    }
    assert_eq!(
        LegalHashTypes::iter().count(),
        expected.len(),
        "new LegalHashTypes variant added – please update test"
    );
}

#[test]
fn opinion_type_variants() {
    let expected = &[
        (OpinionType::StronglyAgree, "strongly-agree"),
        (OpinionType::Agree, "agree"),
        (OpinionType::Neutral, "neutral"),
        (OpinionType::Disagree, "disagree"),
        (OpinionType::StronglyDisagree, "strongly-disagree"),
    ];
    for (variant, want) in expected {
        let got = variant.as_ref();
        assert_eq!(
            got, *want,
            "OpinionType::{:?} should serialize to '{}' but got '{}'",
            variant, want, got
        );
    }
    assert_eq!(
        OpinionType::iter().count(),
        expected.len(),
        "new OpinionType variant added – please update test"
    );
}
