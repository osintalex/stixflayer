use std::path::Path;

use harness::{read_outcomes, render_matrix, render_showcase, Basis, Case, Verdict};

fn cases() -> Vec<Case> {
    [
        ("I01", "[file:name = ]", Verdict::Reject),
        ("V24", "[file:name='x']", Verdict::Accept),
        ("V43", "[file:name = 'x'] REPEATS 0 TIMES", Verdict::Accept),
    ]
    .into_iter()
    .map(|(id, input, expected)| Case {
        id: id.to_string(),
        input: input.to_string(),
        expected,
        basis: Basis::Grammar,
        semantic: false,
        note: String::new(),
    })
    .collect()
}

#[test]
fn renders_fixture_results() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let impls = vec![
        (
            "alpha".to_string(),
            read_outcomes(&dir.join("results-alpha.jsonl")).unwrap(),
        ),
        (
            "beta".to_string(),
            read_outcomes(&dir.join("results-beta.jsonl")).unwrap(),
        ),
    ];

    let matrix = render_matrix(&cases(), &impls);
    assert_eq!(
        matrix,
        include_str!("fixtures/expected_matrix.txt"),
        "\n--- actual matrix ---\n{matrix}"
    );

    let showcase = render_showcase(&["I01", "V43"], &impls);
    assert_eq!(
        showcase,
        include_str!("fixtures/expected_showcase.txt"),
        "\n--- actual showcase ---\n{showcase}"
    );
}
