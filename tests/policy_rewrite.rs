// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `rewrite_limit` end to end (design "Business policy rules" §8.1, runtime
//! controls VERICTO-102): the outcome hosts see, its composition with the
//! VERICTO-085 mask, monitor modes, UNKNOWN bounds, "failure blocks", the
//! fixtures, and that nothing changes for `evaluate()` or without the policy.
//! The database half (the rewritten query returns the first n rows of the
//! original) is `tests/limit_equivalence.rs`.

use vericto_engine::policy::{
    EvalContext, HostMode, POLICY_FEATURES, PolicyAction, PolicyOutcome, PolicySet, Principal,
    PrincipalType, Trust, check_policy, run_policy_tests,
};
use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome, MaskStyle, Rule,
    RuleType, SensitiveColumn, SensitivePolicy, Severity, evaluate, evaluate_with_context,
    standard_rules,
};

const CAP: &str = "rule: cap-agent-reads\napplies_to: { principal_types: [agent] }\naction: { rewrite_limit: 1000 }";

fn pol(code: &str, yaml: &str) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.to_string(),
        severity: Severity::Low,
        default_action: EnforcementAction::Monitor,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.to_string()),
    }
}

fn agent() -> EvalContext {
    EvalContext::new().with_principal(Principal::new("bot", PrincipalType::Agent, Trust::Medium))
}

fn run_with(
    rules: &[Rule],
    sql: &str,
    d: Dialect,
    policy: &EnforcementPolicy,
    ctx: &EvalContext,
) -> EvaluationOutcome {
    let set = PolicySet::compile(rules);
    assert!(set.errors().is_empty(), "{:?}", set.errors());
    evaluate_with_context(sql, d, rules, policy, &set, ctx)
}

fn run(rules: &[Rule], sql: &str, d: Dialect) -> EvaluationOutcome {
    run_with(rules, sql, d, &EnforcementPolicy::default(), &agent())
}

#[test]
fn an_applied_rewrite_is_a_monitor_finding_with_the_text_to_execute() {
    let rules = [pol("POL-102", CAP)];
    let o = run(
        &rules,
        "SELECT id FROM orders WHERE status = 'open'",
        Dialect::Postgres,
    );
    assert_eq!(o.decision, Decision::Allow);
    assert_eq!(o.action, Some(EnforcementAction::Monitor));
    assert_eq!(o.rule_code.as_deref(), Some("POL-102"));
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some("SELECT id FROM orders WHERE status = 'open' LIMIT 1000")
    );
    let hit = &o.policy_hits[0];
    assert_eq!(hit.outcome, PolicyOutcome::Rewritten);
    assert_eq!(hit.requested, PolicyAction::RewriteLimit);
    assert!(hit.reason.as_deref().unwrap().contains("no ORDER BY"));
    assert!(o.ast_node_path.as_deref().unwrap().contains("[LIMIT 1000]"));

    let o = run(
        &rules,
        "SELECT id FROM orders ORDER BY id LIMIT 50000",
        Dialect::Mysql,
    );
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some("SELECT id FROM orders ORDER BY id LIMIT 1000")
    );
    assert_eq!(o.policy_hits[0].reason, None);
}

#[test]
fn nothing_happens_when_already_bounded_out_of_scope_or_for_others() {
    let rules = [pol("POL-102", CAP)];
    for (sql, d) in [
        ("SELECT id FROM orders LIMIT 10", Dialect::Postgres),
        ("SELECT count(*) FROM orders", Dialect::Postgres),
        ("SELECT 1", Dialect::Mysql),
        ("UPDATE orders SET a = 1 WHERE id = 2", Dialect::Postgres),
        ("SELECT id FROM orders LIMIT 5, 10", Dialect::Mysql),
    ] {
        let o = run(&rules, sql, d);
        assert_eq!(
            (o.decision, o.rewritten_query.as_deref()),
            (Decision::Allow, None),
            "{sql}"
        );
        assert!(o.policy_hits.is_empty(), "{sql}");
        assert!(o.violations.is_empty(), "{sql}");
    }
    // Not an agent: out of the policy's scope.
    let human = EvalContext::new().with_principal(Principal::new(
        "ann",
        PrincipalType::Human,
        Trust::Medium,
    ));
    let o = run_with(
        &rules,
        "SELECT id FROM orders",
        Dialect::Postgres,
        &EnforcementPolicy::default(),
        &human,
    );
    assert_eq!(o.rewritten_query, None);
}

#[test]
fn the_lowest_cap_wins_whatever_the_policy_order() {
    let a = pol("POL-1", CAP);
    let b = pol(
        "POL-2",
        "applies_to: { principal_types: [agent] }\naction: { rewrite_limit: 10 }",
    );
    for rules in [vec![a.clone(), b.clone()], vec![b, a]] {
        let o = run(&rules, "SELECT id FROM orders", Dialect::Postgres);
        assert_eq!(
            o.rewritten_query.as_deref(),
            Some("SELECT id FROM orders LIMIT 10")
        );
        assert_eq!(o.policy_hits.len(), 2);
        assert_eq!(o.rule_code.as_deref(), Some("POL-1"));
    }
}

#[test]
fn a_parameter_is_kept_on_postgres_and_unknown_on_mysql() {
    let rules = [pol("POL-102", CAP)];
    let o = run(&rules, "SELECT id FROM orders LIMIT $1", Dialect::Postgres);
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some("SELECT id FROM orders LIMIT LEAST($1::bigint, 1000)")
    );
    let o = run(&rules, "SELECT id FROM orders LIMIT ?", Dialect::Mysql);
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.rewritten_query, None);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
    assert!(o.unknowns[0].detail.contains("bind parameter"));
    // on_unknown: block blocks it; skip drops it (with explicit modes).
    let strict = [pol("POL-102", &format!("{CAP}\non_unknown: block"))];
    let o = run(&strict, "SELECT id FROM orders LIMIT ?", Dialect::Mysql);
    assert_eq!(o.decision, Decision::Block);
    let skip = [pol(
        "POL-102",
        &format!("{CAP}\nmodes: [runtime_api, mcp, ci]\non_unknown: skip"),
    )];
    let ctx = agent().with_mode(HostMode::RuntimeApi);
    let o = run_with(
        &skip,
        "SELECT id FROM orders LIMIT ?",
        Dialect::Mysql,
        &EnforcementPolicy::default(),
        &ctx,
    );
    assert_eq!(o.decision, Decision::Allow);
    assert!(o.policy_hits.is_empty());
    assert_eq!(o.unknowns.len(), 1);
}

#[test]
fn a_rewrite_that_cannot_be_verified_blocks() {
    let rules = [pol("POL-102", CAP)];
    let o = run(
        &rules,
        "SELECT a FROM t ORDER BY a FETCH FIRST 5000 ROWS WITH TIES",
        Dialect::Postgres,
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rewritten_query, None);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::RewriteFailed);
    assert!(
        o.ast_node_path
            .as_deref()
            .unwrap()
            .contains("rewrite failed")
    );
    // A MySQL text the renderer cannot reproduce.
    let o = run(&rules, "SELECT SQL_NO_CACHE id FROM t", Dialect::Mysql);
    assert_eq!(o.decision, Decision::Block);
    // Monitor mode never blocks: the failure is a flag.
    let monitor = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let o = run_with(
        &rules,
        "SELECT SQL_NO_CACHE id FROM t",
        Dialect::Mysql,
        &monitor,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Flag);
}

#[test]
fn monitor_modes_report_the_would_be_rewrite_and_apply_nothing() {
    let observed = [pol("POL-102", &format!("{CAP}\nmode: monitor"))];
    let o = run(&observed, "SELECT id FROM orders", Dialect::Postgres);
    assert_eq!(o.decision, Decision::Allow);
    assert_eq!(o.rewritten_query, None);
    assert!(
        o.policy_hits[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("would rewrite")
    );
    assert_eq!(
        o.violations[0].suggested_safe_query.as_deref(),
        Some("SELECT id FROM orders LIMIT 1000")
    );
    let monitor = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let rules = [pol("POL-102", CAP)];
    let o = run_with(
        &rules,
        "SELECT id FROM orders",
        Dialect::Postgres,
        &monitor,
        &agent(),
    );
    assert_eq!(o.rewritten_query, None);
    assert!(
        o.policy_hits[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("would rewrite")
    );
}

#[test]
fn a_blocked_statement_is_never_rewritten() {
    let rules = [
        pol("POL-102", CAP),
        pol(
            "POL-900",
            "applies_to: { principal_types: [agent], tables: [\"public.secrets\"] }\naction: block",
        ),
    ];
    let o = run(&rules, "SELECT * FROM secrets", Dialect::Postgres);
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("POL-900"));
    assert_eq!(o.rewritten_query, None);
    let hit = o
        .policy_hits
        .iter()
        .find(|h| h.outcome == PolicyOutcome::Rewritten)
        .unwrap();
    assert!(hit.reason.as_deref().unwrap().contains("blocked"));
}

#[test]
fn the_limit_composes_with_the_mask() {
    let rules = [pol("POL-102", CAP)];
    let policy = EnforcementPolicy {
        sensitive_columns: vec![SensitiveColumn {
            schema: None,
            table: "customers".into(),
            column: "email".into(),
            policy: SensitivePolicy::Mask,
            mask_style: MaskStyle::Full,
        }],
        ..EnforcementPolicy::default()
    };
    for d in [Dialect::Postgres, Dialect::Mysql] {
        let o = run_with(
            &rules,
            "SELECT id, email FROM customers",
            d,
            &policy,
            &agent(),
        );
        let sql = o.rewritten_query.expect("masked and limited");
        assert!(sql.ends_with("LIMIT 1000"), "{d:?}: {sql}");
        assert!(sql.contains("[redacted]"), "{d:?}: {sql}");
        assert!(
            !sql.contains(" email FROM") || sql.contains("AS email"),
            "{d:?}: {sql}"
        );
        // The mask is still the flagged finding (VERICTO-085 > monitor).
        assert_eq!(o.decision, Decision::Flag, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"), "{d:?}");
    }
}

#[test]
fn standard_rules_keep_their_findings() {
    let mut rules = standard_rules();
    rules.push(pol("POL-102", CAP));
    let o = run(&rules, "SELECT * FROM orders", Dialect::Postgres);
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some("SELECT * FROM orders LIMIT 1000")
    );
    // The standard findings on the client's text still decide.
    let plain = evaluate(
        "SELECT * FROM orders",
        Dialect::Postgres,
        &standard_rules(),
        &EnforcementPolicy::default(),
    );
    assert_eq!(o.decision, plain.decision);
}

#[test]
fn evaluate_ignores_the_policy_as_before() {
    let rules = [pol("POL-102", CAP)];
    let o = evaluate(
        "SELECT id FROM orders",
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
    );
    assert_eq!(o.decision, Decision::Allow);
    assert_eq!(o.rewritten_query, None);
    assert!(o.violations.is_empty());
}

#[test]
fn the_checker_and_the_fixtures_know_the_rewrite() {
    let doc = r#"
rule: cap-agent-reads
applies_to: { principal_types: [agent] }
action: { rewrite_limit: 100 }
tests:
  - name: unbounded read is capped
    sql: "SELECT id FROM orders"
    principal: { type: agent }
    expect: rewrite
    expect_reason: REWRITTEN
    expect_sql: "SELECT id FROM orders LIMIT 100"
  - name: a small LIMIT stays
    sql: "SELECT id FROM orders LIMIT 5"
    principal: { type: agent }
    expect: allow
  - name: humans are not capped
    sql: "SELECT id FROM orders"
    principal: { type: human }
    expect: allow
  - name: a MySQL placeholder is unknown
    sql: "SELECT id FROM orders LIMIT ?"
    dialect: mysql
    principal: { type: agent }
    expect: flag
    expect_reason: UNKNOWN
  - name: wrong text fails the fixture
    sql: "SELECT id FROM orders"
    principal: { type: agent }
    expect: rewrite
    expect_sql: "SELECT id FROM orders LIMIT 7"
"#;
    let report = check_policy(doc);
    assert!(report.valid, "{report:?}");
    let results = run_policy_tests(doc, Dialect::Postgres).unwrap();
    let passed: Vec<bool> = results.iter().map(|r| r.passed).collect();
    assert_eq!(passed, [true, true, true, true, false], "{results:?}");
    assert_eq!(
        results[0].rewritten_query.as_deref(),
        Some("SELECT id FROM orders LIMIT 100")
    );
    assert_eq!(results[0].actual, "rewrite");
}

#[test]
fn hosts_can_announce_the_feature() {
    assert_eq!(POLICY_FEATURES, ["rewrite_limit"]);
    assert_eq!(vericto_engine::policy::POLICY_LANGUAGE, "cel/1");
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    fn select() -> impl Strategy<Value = (String, bool)> {
        let cols = prop_oneof![
            Just("id"),
            Just("*"),
            Just("count(*)"),
            Just("a, b"),
            Just("max(a)")
        ];
        let from = prop_oneof![
            Just(" FROM t"),
            Just(" FROM t JOIN u ON u.id = t.id"),
            Just(" FROM (SELECT a FROM t LIMIT 3) s"),
            Just(""),
        ];
        let filter = prop_oneof![
            Just(""),
            Just(" WHERE a = 1"),
            Just(" WHERE a IN (SELECT a FROM u)")
        ];
        let group = prop_oneof![Just(""), Just(" GROUP BY a")];
        let setop = prop_oneof![
            Just(""),
            Just(" UNION SELECT a FROM u"),
            Just(" UNION ALL SELECT a FROM u")
        ];
        let order = prop_oneof![Just(""), Just(" ORDER BY 1")];
        let limit = prop_oneof![
            Just(""),
            Just(" LIMIT 5"),
            Just(" LIMIT 50000"),
            Just(" LIMIT ALL"),
            Just(" LIMIT $1"),
            Just(" LIMIT ?"),
            Just(" LIMIT 3, 70000"),
            Just(" OFFSET 4"),
            Just(" FETCH FIRST 9000 ROWS ONLY"),
        ];
        let with = prop_oneof![Just(""), Just("WITH w AS (SELECT a FROM t) ")];
        (
            with,
            cols,
            from,
            filter,
            group,
            setop,
            order,
            limit,
            any::<bool>(),
        )
            .prop_map(|(w, c, f, wh, g, s, o, l, pg)| {
                (format!("{w}SELECT {c}{f}{wh}{g}{s}{o}{l}"), pg)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Any SELECT: no panic; a rewrite reads back, is bounded (idempotent)
        /// and keeps the bind parameters; without a rewrite the outcome is
        /// the one without the policy.
        #[test]
        fn the_rewrite_is_total_idempotent_and_keeps_binds((sql, pg) in select()) {
            let d = if pg { Dialect::Postgres } else { Dialect::Mysql };
            let rules = [pol("POL-102", CAP)];
            let set = PolicySet::compile(&rules);
            let ctx = agent();
            let policy = EnforcementPolicy::default();
            let o = evaluate_with_context(&sql, d, &rules, &policy, &set, &ctx);
            if let Some(rw) = &o.rewritten_query {
                let again = evaluate_with_context(rw, d, &rules, &policy, &set, &ctx);
                prop_assert_eq!(again.decision, Decision::Allow, "{} -> {}", sql, rw);
                prop_assert!(again.rewritten_query.is_none(), "not idempotent: {} -> {}", sql, rw);
                let binds = |s: &str| s.matches('$').count() + s.matches('?').count();
                prop_assert_eq!(binds(&sql), binds(rw), "{} -> {}", sql, rw);
            } else if o.policy_hits.is_empty() {
                let plain = evaluate(&sql, d, &rules, &policy);
                prop_assert_eq!(o.decision, plain.decision, "{}", sql);
            }
        }
    }
}
