// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! 5.1.0: statements that destroy or rewrite every row with no scope, through
//! the public `evaluate` with the standard ruleset.
//!
//! - TRUNCATE (VERICTO-011) and DROP SCHEMA / DATABASE (VERICTO-012) are no
//!   longer softened by a CI channel's `schema_migration_cap`; DROP TABLE
//!   (VERICTO-010) and ALTER TABLE still are.
//! - A `WHERE` that keeps every row of the target (`id IN (SELECT id FROM
//!   <same table>)`, `EXISTS (SELECT 1 FROM <same table>)`,
//!   `x IS NULL OR x IS NOT NULL`) is always-true: VERICTO-003 / 030 / 042.
//! - SQL Server's `DELETE TOP (n)` parses, and is bounded like `LIMIT n`.

use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome, evaluate,
    standard_rules,
};

const ALL: [Dialect; 6] = [
    Dialect::Postgres,
    Dialect::Mysql,
    Dialect::MsSql,
    Dialect::Oracle,
    Dialect::Snowflake,
    Dialect::Sqlite,
];

fn ci() -> EnforcementPolicy {
    EnforcementPolicy {
        schema_migration_cap: Some(EnforcementAction::Flag),
        ..EnforcementPolicy::default()
    }
}

fn eval(sql: &str, d: Dialect, policy: &EnforcementPolicy) -> EvaluationOutcome {
    evaluate(sql, d, &standard_rules(), policy)
}

fn codes(o: &EvaluationOutcome) -> Vec<&str> {
    o.violations.iter().map(|v| v.rule_code.as_str()).collect()
}

#[test]
fn ci_cap_no_longer_softens_truncate_or_namespace_drops() {
    for (sql, dialects, code) in [
        ("TRUNCATE TABLE users", &ALL[..5], "VERICTO-011"),
        ("DROP SCHEMA analytics CASCADE", &ALL[..5], "VERICTO-012"),
        (
            "DROP DATABASE prod",
            &[
                Dialect::Postgres,
                Dialect::Mysql,
                Dialect::MsSql,
                Dialect::Snowflake,
            ][..],
            "VERICTO-012",
        ),
    ] {
        for &d in dialects {
            let o = eval(sql, d, &ci());
            assert_eq!(o.decision, Decision::Block, "{d:?}: {sql} {:?}", codes(&o));
            assert_eq!(o.rule_code.as_deref(), Some(code), "{d:?}: {sql}");
        }
    }
    // DROP DATABASE still matches VERICTO-010 too; under the CI cap it is the
    // softened one, listed after the blocking VERICTO-012.
    let o = eval("DROP DATABASE prod", Dialect::Postgres, &ci());
    assert_eq!(codes(&o), ["VERICTO-012", "VERICTO-010"]);
    assert_eq!(o.violations[1].action, EnforcementAction::Flag);
    // At run time (no cap) both block, and the reported rule is 010, as in 5.0.
    let o = eval(
        "DROP DATABASE prod",
        Dialect::Postgres,
        &EnforcementPolicy::default(),
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"));
}

#[test]
fn ci_cap_still_softens_drop_table_and_alter_table() {
    for d in ALL {
        let o = eval("DROP TABLE users", d, &ci());
        assert_eq!(o.decision, Decision::Flag, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
    }
    let o = eval(
        "ALTER TABLE users DROP COLUMN email",
        Dialect::Postgres,
        &ci(),
    );
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-015"));
}

#[test]
fn whole_table_where_blocks_like_no_where() {
    for d in ALL {
        for (sql, code) in [
            (
                "DELETE FROM users WHERE id IN (SELECT id FROM users)",
                "VERICTO-003",
            ),
            (
                "DELETE FROM users WHERE EXISTS (SELECT 1 FROM users)",
                "VERICTO-003",
            ),
            (
                "DELETE FROM users WHERE email IS NOT NULL OR email IS NULL",
                "VERICTO-003",
            ),
            (
                "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM users)",
                "VERICTO-030",
            ),
            (
                "UPDATE users SET a = 1 WHERE a IS NULL OR a IS NOT NULL",
                "VERICTO-030",
            ),
        ] {
            let o = eval(sql, d, &EnforcementPolicy::default());
            assert_eq!(o.decision, Decision::Block, "{d:?}: {sql}");
            assert_eq!(o.rule_code.as_deref(), Some(code), "{d:?}: {sql}");
            assert!(
                o.ast_node_path
                    .as_deref()
                    .is_some_and(|p| p.ends_with("WhereClause = ALWAYS_TRUE")),
                "{d:?}: {sql}: {:?}",
                o.ast_node_path
            );
            if code == "VERICTO-030" {
                assert!(codes(&o).contains(&"VERICTO-042"), "{d:?}: {sql}");
            }
            // DataMutation: a CI cap does not soften it.
            assert_eq!(
                eval(sql, d, &ci()).decision,
                Decision::Block,
                "{d:?}: {sql}"
            );
        }
    }
}

#[test]
fn real_filters_are_allowed() {
    for d in ALL {
        for sql in [
            "DELETE FROM users WHERE id IN (SELECT id FROM users WHERE banned = 1)",
            "DELETE FROM users WHERE id IN (SELECT user_id FROM orders)",
            "DELETE FROM users u WHERE id IN (SELECT id FROM users x WHERE x.id = u.id)",
            "DELETE FROM users WHERE id IN (SELECT manager_id FROM users)",
            "DELETE FROM users WHERE a IS NULL OR b IS NOT NULL",
            "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM users WHERE a = 0)",
        ] {
            let o = eval(sql, d, &EnforcementPolicy::default());
            assert_eq!(o.decision, Decision::Allow, "{d:?}: {sql} {:?}", codes(&o));
        }
    }
}

#[test]
fn mssql_delete_top_is_bounded_like_limit() {
    let p = EnforcementPolicy::default();
    // No WHERE: a bound is not a filter, as `DELETE … LIMIT 10` on MySQL.
    let top = eval("DELETE TOP (10) FROM users", Dialect::MsSql, &p);
    let limit = eval("DELETE FROM users LIMIT 10", Dialect::Mysql, &p);
    assert_eq!(top.decision, Decision::Block);
    assert_eq!(top.rule_code.as_deref(), Some("VERICTO-001"));
    assert_eq!(codes(&top), codes(&limit));
    assert_eq!(top.ast_node_path, limit.ast_node_path);
    // TOP (0) deletes nothing: VERICTO-002, as LIMIT 0.
    let o = eval("DELETE TOP (0) FROM users WHERE id = 1", Dialect::MsSql, &p);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-002"));
    // With a WHERE it is allowed, as before for the TOP-less form.
    let o = eval(
        "DELETE TOP (100) FROM sessions WHERE expires_at < GETDATE()",
        Dialect::MsSql,
        &p,
    );
    assert_eq!(o.decision, Decision::Allow, "{:?}", codes(&o));
    // UPDATE TOP: the target is `users`, not a function named TOP.
    let o = eval(
        "UPDATE TOP (10) users SET plan = 'free'",
        Dialect::MsSql,
        &p,
    );
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-030"));
    assert_eq!(
        o.suggested_safe_query.as_deref(),
        Some("UPDATE users SET {col} = $1 WHERE id = $2")
    );
    let o = eval(
        "UPDATE TOP (10) users SET plan = 'free' WHERE id = 3",
        Dialect::MsSql,
        &p,
    );
    assert_eq!(o.decision, Decision::Allow);
}
