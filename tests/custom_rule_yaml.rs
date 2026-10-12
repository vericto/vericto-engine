//! Custom-rule YAML compatibility (`ast_condition_yaml`).
//!
//! The YAML here is the YAML users already write: the rule templates the
//! dashboard's custom-rule editor offers and the examples published in the
//! custom-rules documentation, copied verbatim. Each template is checked
//! against the statements it must fire on and the ones it must leave alone,
//! so a change of YAML parser (serde_yaml → serde_norway in 3.9.0) that read
//! any of them differently — a key, a `null`, a boolean, a quoted `"*"` —
//! fails here rather than silently changing what a workspace's rule matches.

use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate,
};

fn custom(yaml: &str) -> Rule {
    Rule {
        rule_id: "custom-1".into(),
        code: "CUSTOM-001".into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.into()),
    }
}

fn fires(yaml: &str, sql: &str) -> bool {
    let rules = [custom(yaml)];
    let outcome = evaluate(
        sql,
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
    );
    outcome.rule_code.as_deref() == Some("CUSTOM-001")
}

/// (yaml, statements it must fire on, statements it must not fire on).
type Case = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

/// The custom-rule editor's templates, YAML and samples verbatim.
const EDITOR_TEMPLATES: &[Case] = &[
    (
        "rule: block-delete-without-where-on-orders\nnode_type: DeleteStmt\ncondition:\n  where_clause: null\n  relation: orders",
        &["DELETE FROM orders", "DELETE FROM public.orders"],
        &["DELETE FROM orders WHERE id = 7", "DELETE FROM carts"],
    ),
    (
        "rule: block-delete-without-where\nnode_type: DeleteStmt\ncondition:\n  where_clause: null",
        &["DELETE FROM carts"],
        &["DELETE FROM carts WHERE id = 7"],
    ),
    (
        "rule: block-update-without-where-on-users\nnode_type: UpdateStmt\ncondition:\n  where_clause: null\n  relation: users",
        &["UPDATE users SET plan = 'free'"],
        &[
            "UPDATE users SET plan = 'free' WHERE id = 7",
            "UPDATE teams SET plan = 'free'",
        ],
    ),
    (
        "rule: block-update-without-where\nnode_type: UpdateStmt\ncondition:\n  where_clause: null",
        &["UPDATE accounts SET balance = 0"],
        &["UPDATE accounts SET balance = 0 WHERE id = 7"],
    ),
    (
        "rule: block-delete-where-always-true\nnode_type: DeleteStmt\ncondition:\n  where_always_true: true",
        &[
            "DELETE FROM orders WHERE 1 = 1",
            "DELETE FROM orders WHERE id = 5 OR 1 = 1",
        ],
        &["DELETE FROM orders WHERE id = 5"],
    ),
    (
        "rule: block-drop-table\nnode_type: DropStmt\ncondition:\n  object_type: table",
        &["DROP TABLE orders", "DROP TABLE IF EXISTS orders"],
        &["DROP INDEX idx_orders_created_at", "DROP VIEW order_totals"],
    ),
    (
        "rule: block-truncate\nnode_type: TruncateStmt",
        &["TRUNCATE orders", "TRUNCATE TABLE audit_tmp"],
        &["DELETE FROM orders WHERE id = 1"],
    ),
    (
        "rule: flag-select-without-limit\nnode_type: SelectStmt\ncondition:\n  has_limit: false",
        &["SELECT id, total FROM events"],
        &["SELECT id, total FROM events LIMIT 100"],
    ),
    (
        "rule: flag-select-star\nnode_type: SelectStmt\ncondition:\n  target_list: \"*\"",
        &["SELECT * FROM customers"],
        &["SELECT id, email FROM customers"],
    ),
    (
        "rule: block-risky-schema-change-at-runtime\nnode_type: AlterTableStmt",
        &[
            "ALTER TABLE orders DROP COLUMN note",
            "ALTER TABLE orders ALTER COLUMN total TYPE bigint",
            "ALTER TABLE orders RENAME TO orders_old",
            "ALTER TABLE orders DROP CONSTRAINT orders_pkey",
            "ALTER TABLE orders DISABLE TRIGGER ALL",
        ],
        &[
            "ALTER TABLE orders ADD COLUMN note text",
            "SELECT 1 FROM orders LIMIT 1",
        ],
    ),
    (
        "rule: block-drop-column\nnode_type: AlterTableStmt\ncondition:\n  alter_kind: drop_column",
        &["ALTER TABLE orders DROP COLUMN note"],
        &["ALTER TABLE orders ADD COLUMN note text"],
    ),
    (
        "rule: block-sleep-calls\nnode_type: FuncCall\ncondition:\n  func_name: pg_sleep",
        &["SELECT pg_sleep(5)"],
        &["SELECT now()"],
    ),
];

#[test]
fn editor_templates_match_as_documented() {
    for (yaml, fire, quiet) in EDITOR_TEMPLATES {
        for sql in *fire {
            assert!(fires(yaml, sql), "{yaml:?} must fire on {sql:?}");
        }
        for sql in *quiet {
            assert!(!fires(yaml, sql), "{yaml:?} must not fire on {sql:?}");
        }
    }
}

/// Documentation examples with comments, a `message:` and a leading newline:
/// the YAML shapes the templates do not cover.
#[test]
fn documented_examples_still_parse() {
    // Inline `#` comments after every value (the commented schema example).
    let commented = "rule: nombre-interno-de-la-regla   # identificador libre\nnode_type: DeleteStmt              # tipo de nodo AST a capturar\ncondition:\n  where_clause: null               # solo si falta WHERE";
    assert!(fires(commented, "DELETE FROM orders"));
    assert!(!fires(commented, "DELETE FROM orders WHERE id = 1"));

    // A quoted `message:` with non-ASCII text.
    let with_message = "rule: require-limit-on-select\nnode_type: SelectStmt\ncondition:\n  has_limit: false\nmessage: \"Las queries SELECT deben incluir cláusula LIMIT para evitar scans completos de tabla\"";
    assert!(fires(with_message, "SELECT id FROM events"));
    assert!(!fires(with_message, "SELECT id FROM events LIMIT 10"));

    // The README example, as a raw string with leading and trailing newlines.
    let readme = "\nrule: block_orders_delete\nnode_type: DeleteStmt\ncondition:\n  relation: orders\n  where_clause: null\n";
    assert!(fires(readme, "DELETE FROM orders"));
    assert!(!fires(readme, "DELETE FROM users"));

    // A quoted relation name.
    let quoted = "rule: ledger-append-only\nnode_type: UpdateStmt\ncondition:\n  relation: \"billing_ledgerentry\"";
    assert!(fires(
        quoted,
        "UPDATE billing_ledgerentry SET amount = 0 WHERE id = 1"
    ));
    assert!(!fires(
        quoted,
        "UPDATE invoices SET amount = 0 WHERE id = 1"
    ));
}

/// YAML the engine rejects stays rejected: the rule is skipped (it never
/// fires), as before. These are the malformed and nested shapes the editor's
/// and the API's own tests submit.
#[test]
fn rejected_yaml_stays_rejected() {
    for yaml in [
        "node_type: [this is: not valid",
        "rule:\n  node_type: SelectStmt",
        "rule:\n  node_type: SelectStmt\n  condition: x",
        "node_type: DropStmt\n  object_type: table",
        "node_type: BogusStmt",
    ] {
        for sql in [
            "DELETE FROM users",
            "SELECT * FROM users",
            "DROP TABLE users",
        ] {
            assert!(
                !fires(yaml, sql),
                "{yaml:?} must be skipped, fired on {sql:?}"
            );
        }
    }
}
