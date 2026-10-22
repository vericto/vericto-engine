// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Robustness of the policy language (in-suite, alongside the cargo-fuzz
//! target `fuzz/fuzz_targets/policy.rs`): arbitrary expressions, documents
//! and statements never panic, and pathological ones are refused by the
//! static bounds instead of costing the hot path.

use proptest::prelude::*;
use vericto_engine::policy::{
    EvalContext, PolicySet, Principal, PrincipalType, Trust, check_policy, run_policy_tests,
};
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate_with_context,
};

fn rule(yaml: &str) -> Rule {
    Rule {
        rule_id: "r".into(),
        code: "POL-R".into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.into()),
    }
}

fn doc(expr: &str) -> String {
    let indented: String = expr.lines().map(|l| format!("  {l}\n")).collect();
    format!("deny_if: |\n{indented}action: block\n")
}

fn agent() -> EvalContext {
    EvalContext::new().with_principal(Principal::new("a", PrincipalType::Agent, Trust::Medium))
}

const ATOMS: &[&str] = &[
    "stmt",
    ".",
    "values",
    "(",
    ")",
    "'public.t.c'",
    "[",
    "]",
    "{",
    "}",
    ",",
    ":",
    "?",
    "!",
    "-",
    "&&",
    "||",
    "==",
    "<",
    "in",
    "1",
    "1.5",
    "'x'",
    "true",
    "null",
    "principal",
    "type",
    "has",
    "all",
    "exists",
    "x",
    "map",
    "filter",
    "size",
    "matches",
    "'^a'",
    "time",
    "now",
    "duration",
    "'1h'",
    "in_window",
    "'Mon 09:00-10:00'",
    "'UTC'",
    "vars",
    "+",
    "*",
    "/",
    "%",
    "\"",
    "\\",
];

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn prop_any_text_compiles_or_is_refused(s in "\\PC{0,300}") {
        let _ = check_policy(&doc(&s));
        let rules = [rule(&doc(&s))];
        let set = PolicySet::compile(&rules);
        let _ = evaluate_with_context("UPDATE t SET c = 1 WHERE c = 2", Dialect::Postgres, &rules, &EnforcementPolicy::default(), &set, &agent());
    }

    #[test]
    fn prop_token_soup_never_panics(toks in prop::collection::vec(prop::sample::select(ATOMS.to_vec()), 0..60)) {
        let src = toks.join(" ");
        let rules = [rule(&doc(&src))];
        let set = PolicySet::compile(&rules);
        for d in [Dialect::Postgres, Dialect::Mysql] {
            let _ = evaluate_with_context("INSERT INTO t (c) VALUES (1)", d, &rules, &EnforcementPolicy::default(), &set, &agent());
        }
    }

    #[test]
    fn prop_any_document_checks(s in "\\PC{0,400}") {
        let _ = check_policy(&s);
        let _ = run_policy_tests(&s, Dialect::Postgres);
        let _ = PolicySet::compile(&[rule(&s)]);
    }

    #[test]
    fn prop_any_statement_with_policies(sql in "\\PC{0,200}") {
        let facts = r#"
deny_if: >
  stmt.values("public.t.c").exists(v, v == 1) || stmt.has_filter("t.c") ||
  stmt.lower_bound("public.t.c") > 1 || stmt.reads("public.*") || stmt.functions.size() > 2
on_unknown: flag
action: flag
"#;
        let rules = [rule(facts)];
        let set = PolicySet::compile(&rules);
        for d in [Dialect::Postgres, Dialect::Mysql, Dialect::MsSql, Dialect::Oracle, Dialect::Sqlite, Dialect::Snowflake] {
            let _ = evaluate_with_context(&sql, d, &rules, &EnforcementPolicy::default(), &set, &agent());
        }
    }
}

#[test]
fn pathological_expressions_are_refused_not_run() {
    let deep = format!("{}true{}", "(".repeat(5000), ")".repeat(5000));
    let r = check_policy(&format!("deny_if: '{deep}'"));
    assert!(!r.valid);
    let nots = format!("deny_if: '{}true'", "!".repeat(5000));
    assert!(!check_policy(&nots).valid);
    let wide = vec!["true"; 2000].join(" || ");
    assert!(!check_policy(&format!("deny_if: '{wide}'")).valid);
    let nested = "stmt.tables.all(a, stmt.tables.all(b, a == b))";
    let r = check_policy(&format!("deny_if: '{nested}'"));
    assert!(!r.valid, "{r:?}");
    assert!(r.errors[0].message.contains("cost"));
    // A refused policy fails closed in its scope (here: everything).
    let rules = [rule(&format!("deny_if: '{nested}'"))];
    let set = PolicySet::compile(&rules);
    let o = evaluate_with_context(
        "SELECT 1",
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
        &set,
        &agent(),
    );
    assert_eq!(o.decision, vericto_engine::Decision::Block);
}

#[test]
fn a_huge_statement_against_a_policy_is_bounded() {
    // 1,100 columns: the column list is truncated (UNKNOWN), never walked
    // a thousand times per element.
    let cols: Vec<String> = (0..1100).map(|i| format!("c{i}")).collect();
    let sql = format!("SELECT {} FROM t", cols.join(", "));
    let rules = [rule(
        "deny_if: stmt.columns_read.exists(c, c.endsWith('.ssn'))\non_unknown: flag\naction: block",
    )];
    let set = PolicySet::compile(&rules);
    let started = std::time::Instant::now();
    let o = evaluate_with_context(
        &sql,
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
        &set,
        &agent(),
    );
    assert_eq!(o.decision, vericto_engine::Decision::Flag);
    assert!(
        o.policy_hits[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("truncated")
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
