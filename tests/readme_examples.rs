//! Compile-check that the code snippets in README.md match the real API.
//! If the API changes, these fail to compile and the README must be updated.

#[test]
fn quick_example() {
    use vericto_engine::{
        Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate,
    };

    let rules = vec![Rule {
        rule_id: "r1".into(),
        code: "VERICTO-001".into(),
        severity: Severity::Critical,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }];

    let policy = EnforcementPolicy::default();
    let outcome = evaluate("DELETE FROM users", Dialect::Postgres, &rules, &policy);
    assert_eq!(outcome.decision, Decision::Block);
    assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-001"));
    assert_eq!(
        outcome.ast_node_path.as_deref(),
        Some("DeleteStmt > WhereClause = NULL")
    );
}

#[test]
fn full_ruleset_example() {
    use vericto_engine::rules::engine::{Decision, Rule};
    use vericto_engine::{Dialect, EnforcementPolicy, evaluate};

    fn is_safe(sql: &str, rules: &[Rule], policy: &EnforcementPolicy) -> bool {
        evaluate(sql, Dialect::Postgres, rules, policy).decision == Decision::Allow
    }

    assert!(is_safe(
        "SELECT id FROM users WHERE id = 1 LIMIT 10",
        &[],
        &EnforcementPolicy::default()
    ));
}

#[test]
fn custom_rule_example() {
    use vericto_engine::rules::engine::{EnforcementAction, Rule, RuleType, Severity};

    let _custom = Rule {
        rule_id: "custom-1".into(),
        code: "CUSTOM-001".into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(
            r#"
rule: block_orders_delete
node_type: DeleteStmt
condition:
  relation: orders
  where_clause: null
"#
            .into(),
        ),
    };
}

#[test]
fn custom_rule_example_scopes_correctly() {
    use vericto_engine::rules::engine::{EnforcementAction, Rule, RuleType, Severity};
    use vericto_engine::{Decision, Dialect, EnforcementPolicy, evaluate};

    let custom = Rule {
        rule_id: "custom-1".into(),
        code: "CUSTOM-001".into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(
            "rule: block_orders_delete\nnode_type: DeleteStmt\ncondition:\n  relation: orders\n  where_clause: null\n".into(),
        ),
    };
    let rules = [custom];
    let p = EnforcementPolicy::default();

    // Matches: DELETE on `orders` with no WHERE.
    assert_eq!(
        evaluate("DELETE FROM orders", Dialect::Postgres, &rules, &p).decision,
        Decision::Block
    );
    // Does NOT match a different table.
    assert_eq!(
        evaluate("DELETE FROM users", Dialect::Postgres, &rules, &p).decision,
        Decision::Allow
    );
    // Does NOT match a scoped DELETE on orders (where_clause: null).
    assert_eq!(
        evaluate(
            "DELETE FROM orders WHERE id = 1",
            Dialect::Postgres,
            &rules,
            &p
        )
        .decision,
        Decision::Allow
    );
}

#[test]
fn sensitive_columns_example() {
    use vericto_engine::{
        Decision, Dialect, EnforcementPolicy, MaskStyle, SensitiveColumn, SensitivePolicy, evaluate,
    };

    let policy = EnforcementPolicy {
        sensitive_columns: vec![SensitiveColumn {
            schema: None, // any schema
            table: "customers".into(),
            column: "email".into(),
            policy: SensitivePolicy::Mask,
            mask_style: MaskStyle::Email,
        }],
        ..EnforcementPolicy::default()
    };

    let outcome = evaluate(
        "SELECT id, email FROM customers WHERE id = $1",
        Dialect::Postgres,
        &[],
        &policy,
    );
    assert_eq!(outcome.decision, Decision::Flag);
    assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-085"));
    assert_eq!(
        outcome.rewritten_query.as_deref(),
        Some(
            r"SELECT id, regexp_replace(email::text, '^(.)[^@]*(@.*)?$', E'\\1***\\2') AS email FROM customers WHERE id = $1"
        )
    );
    assert_eq!(outcome.sensitive_columns[0].column, "email");
}

#[test]
fn agent_access_example() {
    use vericto_engine::{AccessPolicy, Decision, Dialect, EnforcementPolicy, evaluate};

    let agent: AccessPolicy = serde_json::from_str(
        r#"{
        "mode": "enforce",
        "entries": [
            { "table": "orders",    "columns": "*",            "access": "read" },
            { "table": "customers", "columns": ["id", "name"], "access": "read" }
        ]
    }"#,
    )
    .unwrap();
    let policy = EnforcementPolicy {
        access_policy: Some(agent),
        ..EnforcementPolicy::default()
    };

    let ok = evaluate(
        "SELECT c.name, o.total FROM customers c JOIN orders o ON o.customer_id = c.id",
        Dialect::Postgres,
        &[],
        &policy,
    );
    assert_eq!(ok.decision, Decision::Allow);

    let probe = evaluate(
        "SELECT id FROM customers WHERE email LIKE 'a%'",
        Dialect::Postgres,
        &[],
        &policy,
    );
    assert_eq!(probe.decision, Decision::Block);
    assert_eq!(probe.rule_code.as_deref(), Some("VERICTO-087"));
    assert_eq!(
        probe.ast_node_path.as_deref(),
        Some("AccessPolicy > customers.email (read)")
    );
    assert_eq!(probe.access_denied[0].column.as_deref(), Some("email"));
}
