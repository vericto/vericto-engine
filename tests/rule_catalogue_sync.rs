// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Guard: the README's standard-rule catalogue must stay in sync with the rule
//! codes actually implemented in `src/rules/evaluator.rs`.
//!
//! The README table is hand-maintained documentation; this test fails the build
//! if a `VERICTO-*` match arm is added/removed in the evaluator without the
//! corresponding README row (or vice-versa), so the two never silently diverge.
//!
//! Both files are pulled in at compile time via `include_str!`, so the test runs
//! with no filesystem access and works from any working directory.

//!
//! Since 4.2.0 the engine also exports the catalogue (`STANDARD_RULES` /
//! `standard_rules()`): its codes, severities and classes are checked against
//! the README's catalogue and class tables, and against the evaluator.

use std::collections::{BTreeMap, BTreeSet};

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

// ── The exported standard ruleset (4.2.0) ────────────────────────────────────

use vericto_engine::{RuleClass, STANDARD_RULES, Severity};

/// README catalogue rows with the severity of the `### <Severity>` heading they
/// sit under, inside the "Standard rules" section.
fn readme_severities() -> BTreeMap<String, Severity> {
    let mut out = BTreeMap::new();
    let mut in_section = false;
    let mut severity = None;
    for line in README_SRC.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            in_section = h.starts_with("Standard rules");
            severity = None;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(h) = line.strip_prefix("### ") {
            severity = Some(match h.trim() {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                "Informational" => Severity::Informational,
                other => panic!("unexpected severity heading `### {other}` in the catalogue"),
            });
            continue;
        }
        let Some(code) = line
            .trim_start()
            .strip_prefix("| ")
            .and_then(take_code)
            .filter(|c| {
                line.trim_start()[2 + c.len()..]
                    .trim_start()
                    .starts_with('|')
            })
        else {
            continue;
        };
        let sev = severity.unwrap_or_else(|| panic!("{code} sits under no severity heading"));
        assert!(
            out.insert(code.to_string(), sev).is_none(),
            "{code} is listed twice in the README catalogue"
        );
    }
    out
}

/// The README's "Rule classes" table: class → codes, ranges (`010–019`)
/// expanded and kept to the codes the catalogue has.
fn readme_classes(catalogue: &BTreeSet<String>) -> BTreeMap<String, RuleClass> {
    let mut out = BTreeMap::new();
    for line in README_SRC.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // `| `Class` | codes | text |` → ["", "`Class`", "codes", "text", ""]
        if cells.len() < 4 {
            continue;
        }
        let class = match cells[1] {
            "`SchemaMigration`" => RuleClass::SchemaMigration,
            "`DataMutation`" => RuleClass::DataMutation,
            "`Security`" => RuleClass::Security,
            "`Performance`" => RuleClass::Performance,
            _ => continue,
        };
        for item in cells[2].split(',').map(str::trim) {
            let (lo, hi) = item.split_once('–').unwrap_or((item, item));
            let (lo, hi): (u32, u32) = (
                lo.parse().expect("a class code"),
                hi.parse().expect("a class code"),
            );
            for n in lo..=hi {
                let code = format!("VERICTO-{n:03}");
                if catalogue.contains(&code) {
                    out.insert(code, class);
                }
            }
        }
    }
    out
}

#[test]
fn standard_rules_match_the_readme_catalogue() {
    let exported: BTreeMap<String, Severity> = STANDARD_RULES
        .iter()
        .map(|r| (r.code.to_string(), r.severity))
        .collect();
    assert_eq!(exported.len(), STANDARD_RULES.len(), "duplicate codes");
    assert_eq!(
        exported,
        readme_severities(),
        "STANDARD_RULES (code, severity) differs from the README catalogue"
    );
}

#[test]
fn standard_rules_match_the_evaluator() {
    let exported: BTreeSet<String> = STANDARD_RULES.iter().map(|r| r.code.to_string()).collect();
    assert_eq!(
        exported,
        codes_in_evaluator(),
        "STANDARD_RULES differs from the evaluator's match arms"
    );
}

#[test]
fn standard_rule_classes_match_the_readme_and_the_engine() {
    let codes: BTreeSet<String> = STANDARD_RULES.iter().map(|r| r.code.to_string()).collect();
    let readme = readme_classes(&codes);
    for r in STANDARD_RULES {
        assert_eq!(r.class, RuleClass::for_code(r.code), "{}", r.code);
        assert_eq!(
            readme.get(r.code),
            Some(&r.class),
            "{} has class {:?}; the README's class table says {:?}",
            r.code,
            r.class,
            readme.get(r.code)
        );
    }
    assert_eq!(
        readme.len(),
        codes.len(),
        "the README's class table lists every code once"
    );
}
