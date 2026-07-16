//! Guard: the README's standard-rule catalogue must stay in sync with the rule
//! codes actually implemented in `src/rules/evaluator.rs`.
//!
//! The README table is hand-maintained documentation; this test fails the build
//! if a `VERICTO-*` match arm is added/removed in the evaluator without the
//! corresponding README row (or vice-versa), so the two never silently diverge.
//!
//! Both files are pulled in at compile time via `include_str!`, so the test runs
//! with no filesystem access and works from any working directory.

use std::collections::BTreeSet;

const EVALUATOR_SRC: &str = include_str!("../src/rules/evaluator.rs");
const README_SRC: &str = include_str!("../README.md");

/// Extract the `VERICTO-NNN` token starting at `start` (assumes `bytes[start..]`
/// begins with `VERICTO-`). Returns the code and the index just past it.
fn take_code(s: &str) -> Option<&str> {
    // `s` starts at "VERICTO-"; the code is "VERICTO-" followed by ASCII digits.
    let rest = s.strip_prefix("VERICTO-")?;
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    Some(&s[.."VERICTO-".len() + digits])
}

/// Rule codes that have a built-in match arm in `evaluate_builtin`.
/// A match arm is a line that, trimmed, looks like `"VERICTO-NNN" =>`.
fn codes_in_evaluator() -> BTreeSet<String> {
    EVALUATOR_SRC
        .lines()
        .filter_map(|line| {
            let t = line.trim_start();
            let inner = t.strip_prefix('"')?;
            let code = take_code(inner)?;
            // Must be an actual match arm, not a string used elsewhere.
            let after = &t[1 + code.len()..];
            if after.trim_start().starts_with("\" =>") {
                Some(code.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Rule codes documented in the README catalogue.
/// A catalogue row is a table line that, trimmed, starts with `| VERICTO-NNN `.
fn codes_in_readme() -> BTreeSet<String> {
    README_SRC
        .lines()
        .filter_map(|line| {
            let t = line.trim_start();
            let inner = t.strip_prefix("| ")?;
            let code = take_code(inner)?;
            // Next char after the code must be a column separator (space + `|`),
            // so inline mentions inside a description cell don't count.
            let after = inner[code.len()..].trim_start();
            if after.starts_with('|') {
                Some(code.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn readme_catalogue_matches_evaluator() {
    let impl_codes = codes_in_evaluator();
    let doc_codes = codes_in_readme();

    // Sanity: both extractors found a plausible number of rules. Guards against
    // a format change silently making either set empty (which would let any
    // drift pass).
    assert!(
        impl_codes.len() >= 20,
        "extracted too few evaluator codes ({}) — did the match-arm format change?",
        impl_codes.len()
    );
    assert!(
        doc_codes.len() >= 20,
        "extracted too few README codes ({}) — did the table format change?",
        doc_codes.len()
    );

    let missing_in_readme: Vec<_> = impl_codes.difference(&doc_codes).collect();
    let missing_in_impl: Vec<_> = doc_codes.difference(&impl_codes).collect();

    assert!(
        missing_in_readme.is_empty() && missing_in_impl.is_empty(),
        "README rule catalogue is out of sync with src/rules/evaluator.rs\n  \
         implemented but undocumented (add to README): {missing_in_readme:?}\n  \
         documented but not implemented (remove from README or implement): {missing_in_impl:?}"
    );
}
