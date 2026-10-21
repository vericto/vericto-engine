// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Backward compatibility of business policies (design §4.5).
//!
//! 1. A custom rule with only today's keys (or with keys today's engine
//!    already ignores) is not a policy: [`PolicySet::compile`] leaves it to
//!    the rule engine, and `evaluate_with_context` gives exactly what
//!    `evaluate` gives, with or without other policies in the set and
//!    whatever the context. Golden over the editor templates and the
//!    documented examples, and a property over generated rules, statements
//!    and contexts.
//! 2. `evaluate` itself is the 4.3.0 path for every document, policy keys
//!    or not: a policy document evaluates there as the custom rule its
//!    `node_type`/`condition` describe (4.3.0 ignored the other keys), and
//!    is skipped without `node_type`, as 4.3.0 skipped it. (The corpus
//!    goldens — ORM, SQLite, Snowflake — prove `evaluate` byte for byte.)

use proptest::prelude::*;
use vericto_engine::policy::{
    DbContext, EvalContext, HostMode, PolicySet, Principal, PrincipalType, SessionContext, Ticket,
    TimeContext, Trust, is_policy_document,
};
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome, Rule, RuleType, Severity,
    evaluate, evaluate_with_context, standard_rules,
};

fn custom(code: &str, yaml: &str) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.into()),
    }
}

/// Today's custom rules: the editor's templates and the documented
/// examples, plus forms with keys 4.3.0 ignores.
const LEGACY: &[&str] = &[
    "rule: block-delete-without-where-on-orders\nnode_type: DeleteStmt\ncondition:\n  where_clause: null\n  relation: orders",
    "rule: block-delete-without-where\nnode_type: DeleteStmt\ncondition:\n  where_clause: null",
    "rule: block-update-without-where-on-users\nnode_type: UpdateStmt\ncondition:\n  where_clause: null\n  relation: users",
    "rule: block-select-star\nnode_type: SelectStmt\ncondition:\n  target_list: \"*\"",
    "rule: tautology\nnode_type: SelectStmt\ncondition:\n  where_always_true: true",
    "rule: unbounded\nnode_type: SelectStmt\ncondition:\n  has_limit: false",
    "rule: sleep\nnode_type: FuncCall\ncondition:\n  func_name: pg_sleep",
    "rule: drop-table\nnode_type: DropStmt\ncondition:\n  object_type: table",
    "rule: drop-anything\nnode_type: DropStmt",
    "rule: alter-drop-column\nnode_type: AlterTableStmt\ncondition:\n  alter_kind: drop_column",
    "rule: insert-payments\nnode_type: InsertStmt\ncondition:\n  relation: payments",
    "node_type: TruncateStmt",
    // Keys 4.3.0 ignores: still today's custom rule.
    "rule: with-metadata\nnode_type: DeleteStmt\nseverity: critical\nmetadata: {owner: payments}\ntests: []\nmessage: no\ncondition:\n  where_clause: null",
    "node_type: SelectStmt\ncondition:\n  target_list: \"*\"\n  bogus_key: 1",
    // Malformed: skipped, as before.
    "node_type: [unclosed",
    "node_type: NotANode",
    "",
];

const SQL: &[&str] = &[
    "DELETE FROM orders",
    "DELETE FROM orders WHERE id = 1",
    "UPDATE users SET a = 1",
    "UPDATE users SET a = 1 WHERE id = 2",
    "SELECT * FROM payments",
    "SELECT id FROM payments WHERE 1 = 1",
    "SELECT id FROM payments WHERE id = 1 LIMIT 1",
    "SELECT pg_sleep(1)",
    "SELECT sleep(1)",
    "DROP TABLE orders",
    "DROP INDEX i",
    "ALTER TABLE users DROP COLUMN email",
    "INSERT INTO payments (id, amount) VALUES (1, 950)",
    "INSERT INTO payments VALUES (1, 950)",
    "TRUNCATE orders",
    "SELECT 1; DELETE FROM orders",
    "WITH x AS (DELETE FROM orders RETURNING id) SELECT * FROM x",
    "SELEC broken",
    "SET search_path TO app",
    "BEGIN",
];

/// A policy that never applies to the contexts below (a `tool` scope), so
/// the set is not empty and the context path runs.
const UNRELATED: &str =
    "rule: tools-only\napplies_to: { principal_types: [tool] }\nwhen: 'true'\naction: block";

fn contexts() -> Vec<EvalContext> {
    vec![
        EvalContext::new(),
        EvalContext::new().with_principal(Principal::new("a", PrincipalType::Agent, Trust::Medium)),
        EvalContext::new()
            .with_mode(HostMode::Proxy)
            .with_principal(Principal::new("h", PrincipalType::Human, Trust::Weak))
            .with_db(DbContext::new().with_env("prod"))
            .with_time(TimeContext::utc(1_792_540_800))
            .with_ticket(Ticket::declared("OPS-1"))
            .with_session(SessionContext::new().with_tenant("t1")),
    ]
}

fn policies() -> Vec<EnforcementPolicy> {
    vec![
        EnforcementPolicy::default(),
        EnforcementPolicy {
            monitor_mode: true,
            ..EnforcementPolicy::default()
        },
        EnforcementPolicy {
            schema_migration_cap: Some(EnforcementAction::Flag),
            ..EnforcementPolicy::default()
        },
    ]
}

/// The outcome without the 4.4.0 fields, which must be empty.
fn render(o: &EvaluationOutcome) -> String {
    assert!(o.policy_hits.is_empty() && o.approval_required.is_none() && o.unknowns.is_empty());
    format!("{o:?}")
}

#[test]
fn todays_custom_rules_are_not_policies() {
    for y in LEGACY {
        assert!(!is_policy_document(y), "{y}");
    }
    let mut rules: Vec<Rule> = LEGACY
        .iter()
        .enumerate()
        .map(|(i, y)| custom(&format!("CUSTOM-{i:03}"), y))
        .collect();
    rules.extend(standard_rules());
    assert!(PolicySet::compile(&rules).is_empty());
}

#[test]
fn golden_context_path_equals_evaluate_for_todays_rules() {
    let mut rules: Vec<Rule> = LEGACY
        .iter()
        .enumerate()
        .map(|(i, y)| custom(&format!("CUSTOM-{i:03}"), y))
        .collect();
    rules.extend(standard_rules());
    let mut with_unrelated = rules.clone();
    with_unrelated.push(custom("POL-999", UNRELATED));
    let empty = PolicySet::compile(&rules);
    let unrelated = PolicySet::compile(&with_unrelated);
    assert!(empty.is_empty());
    assert_eq!(unrelated.len(), 1);
    let mut checked = 0;
    for d in [
        Dialect::Postgres,
        Dialect::Mysql,
        Dialect::MsSql,
        Dialect::Oracle,
        Dialect::Sqlite,
    ] {
        for sql in SQL {
            for policy in policies() {
                let base = render(&evaluate(sql, d, &rules, &policy));
                for ctx in contexts() {
                    let a = evaluate_with_context(sql, d, &rules, &policy, &empty, &ctx);
                    assert_eq!(render(&a), base, "{d:?} {sql}");
                    let b =
                        evaluate_with_context(sql, d, &with_unrelated, &policy, &unrelated, &ctx);
                    assert_eq!(render(&b), base, "{d:?} {sql} (unrelated policy)");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 800);
}

#[test]
fn evaluate_reads_a_policy_document_as_4_3_0_did() {
    // 4.3.0 ignored every key but node_type/condition: the same document,
    // stripped to them, evaluates the same on `evaluate`.
    let docs = [
        (
            "node_type: DeleteStmt\ncondition:\n  where_clause: null\nwhen: principal.type == 'agent'\naction: flag",
            "node_type: DeleteStmt\ncondition:\n  where_clause: null",
        ),
        (
            "node_type: SelectStmt\napplies_to: {principal_types: [tool]}\ndeny_if: 'true'",
            "node_type: SelectStmt",
        ),
    ];
    for (doc, stripped) in docs {
        assert!(is_policy_document(doc));
        for sql in SQL {
            let a = evaluate(
                sql,
                Dialect::Postgres,
                &[custom("C-1", doc)],
                &EnforcementPolicy::default(),
            );
            let b = evaluate(
                sql,
                Dialect::Postgres,
                &[custom("C-1", stripped)],
                &EnforcementPolicy::default(),
            );
            assert_eq!(render(&a), render(&b), "{sql}");
        }
    }
    // Without node_type: 4.3.0 could not deserialize it and skipped it.
    let no_node = custom("C-2", "when: 'true'\naction: block");
    for sql in SQL {
        let o = evaluate(
            sql,
            Dialect::Postgres,
            std::slice::from_ref(&no_node),
            &EnforcementPolicy::default(),
        );
        assert!(o.violations.iter().all(|v| v.rule_code != "C-2"), "{sql}");
    }
}

fn legacy_rule() -> impl Strategy<Value = String> {
    let node = prop::sample::select(vec![
        "DeleteStmt",
        "UpdateStmt",
        "DropStmt",
        "TruncateStmt",
        "InsertStmt",
        "SelectStmt",
        "AlterTableStmt",
        "FuncCall",
    ]);
    let preds = prop::collection::vec(
        prop::sample::select(vec![
            "relation: orders",
            "relation: payments",
            "where_clause: null",
            "where_always_true: true",
            "target_list: \"*\"",
            "has_limit: false",
            "has_limit: true",
            "func_name: sleep",
            "object_type: table",
            "alter_kind: drop_column",
            "unknown_pred: 1",
        ]),
        0..3,
    );
    let extra = prop::sample::select(vec![
        "",
        "severity: high\n",
        "metadata: {a: 1}\n",
        "message: hi\n",
        "tests: []\n",
    ]);
    (node, preds, extra).prop_map(|(n, p, e)| {
        let mut y = format!("rule: generated\n{e}node_type: {n}\n");
        if !p.is_empty() {
            y.push_str("condition:\n");
            for x in p {
                y.push_str(&format!("  {x}\n"));
            }
        }
        y
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Any of today's custom rules, any statement, any context, any
    /// dialect: the context path with a non-empty set is `evaluate`.
    #[test]
    fn prop_context_path_is_evaluate_for_legacy_rules(
        ys in prop::collection::vec(legacy_rule(), 1..4),
        sql in prop::sample::select(SQL.to_vec()),
        d in prop::sample::select(vec![Dialect::Postgres, Dialect::Mysql, Dialect::MsSql, Dialect::Oracle]),
        ci in 0usize..3,
        pi in 0usize..3,
    ) {
        let mut rules: Vec<Rule> = ys.iter().enumerate().map(|(i, y)| custom(&format!("CUSTOM-{i}"), y)).collect();
        rules.push(custom("POL-999", UNRELATED));
        let set = PolicySet::compile(&rules);
        prop_assert_eq!(set.len(), 1);
        let ctx = &contexts()[ci];
        let policy = &policies()[pi];
        let a = render(&evaluate(sql, d, &rules, policy));
        let b = render(&evaluate_with_context(sql, d, &rules, policy, &set, ctx));
        prop_assert_eq!(a, b);
    }
}
