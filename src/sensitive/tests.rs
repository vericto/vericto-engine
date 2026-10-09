//! VERICTO-085 unit tests: every evasion of design §5.2, positive and
//! negative, plus joins, set operations, CTEs, identifiers, schemas, data
//! copies, the mask rewrite and the MySQL behaviour.

use crate::parser::Dialect;
use crate::rules::engine::{
    Decision, EnforcementAction, EnforcementPolicy, EvaluationOutcome, ParseErrorAction, Rule,
    RuleType, Severity,
};
use crate::sensitive::{MaskStyle, SensitiveColumn, SensitivePolicy, TouchedColumn};

use MaskStyle::*;
use SensitivePolicy::*;

fn tag(table: &str, column: &str, policy: SensitivePolicy) -> SensitiveColumn {
    SensitiveColumn {
        schema: None,
        table: table.into(),
        column: column.into(),
        policy,
        mask_style: Full,
    }
}

fn masked(table: &str, column: &str, style: MaskStyle) -> SensitiveColumn {
    SensitiveColumn {
        mask_style: style,
        ..tag(table, column, Mask)
    }
}

fn policy(tags: Vec<SensitiveColumn>) -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: tags,
        ..EnforcementPolicy::default()
    }
}

fn eval_on(sql: &str, dialect: Dialect, tags: Vec<SensitiveColumn>) -> EvaluationOutcome {
    crate::evaluate(sql, dialect, &[], &policy(tags))
}

fn pg(sql: &str, tags: Vec<SensitiveColumn>) -> EvaluationOutcome {
    eval_on(sql, Dialect::Postgres, tags)
}

/// The column names VERICTO-085 reports as read.
fn read(o: &EvaluationOutcome) -> Vec<&str> {
    o.sensitive_columns
        .iter()
        .map(|t| t.column.as_str())
        .collect()
}

fn email_block() -> Vec<SensitiveColumn> {
    vec![tag("customers", "email", Block)]
}

#[track_caller]
fn assert_reads(sql: &str, col: &str) {
    let o = pg(sql, vec![tag("customers", col, Block)]);
    assert_eq!(o.decision, Decision::Block, "{sql} must read {col}: {o:?}");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"), "{sql}");
    assert!(read(&o).contains(&col), "{sql}: {:?}", read(&o));
}

#[track_caller]
fn assert_not_read(sql: &str, col: &str) {
    let o = pg(sql, vec![tag("customers", col, Block)]);
    assert_eq!(
        o.decision,
        Decision::Allow,
        "{sql} must NOT read {col}: {o:?}"
    );
    assert!(o.sensitive_columns.is_empty(), "{sql}: {:?}", read(&o));
}

#[track_caller]
fn rewrite(sql: &str, tags: Vec<SensitiveColumn>) -> String {
    let o = pg(sql, tags);
    assert_eq!(o.decision, Decision::Flag, "{sql}: {o:?}");
    let rw = o
        .rewritten_query
        .clone()
        .unwrap_or_else(|| panic!("{sql}: no rewrite: {o:?}"));
    // The rewrite must itself be valid Postgres.
    pg_query::parse(&rw).unwrap_or_else(|e| panic!("rewrite does not parse: {rw}: {e}"));
    rw
}

// ── §5.2 evasions ──────────────────────────────────────────────────────────

#[test]
fn plain_projection_is_a_read() {
    assert_reads("SELECT email FROM customers", "email");
    assert_reads("SELECT id, email FROM customers WHERE id = $1", "email");
}

#[test]
fn select_star_touches_every_tagged_column() {
    let tags = vec![
        tag("customers", "email", Block),
        tag("customers", "card", Flag),
    ];
    let o = pg("SELECT * FROM customers", tags);
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(read(&o), vec!["card", "email"]);
    assert!(o.ast_node_path.unwrap().contains("* over customers"));
    // TABLE t is SELECT * FROM t.
    assert_reads("TABLE customers", "email");
    assert_reads("SELECT c.* FROM customers c", "email");
}

#[test]
fn select_star_blocks_under_mask_and_flags_under_flag() {
    let o = pg(
        "SELECT * FROM customers",
        vec![masked("customers", "email", Email)],
    );
    assert_eq!(o.decision, Decision::Block);
    assert!(o.rewritten_query.is_none());
    assert!(
        o.suggested_safe_query.unwrap().contains("List the columns"),
        "the message tells the caller to list the columns"
    );

    let o = pg(
        "SELECT * FROM customers",
        vec![tag("customers", "email", Flag)],
    );
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.action, Some(EnforcementAction::Flag));
    assert!(o.rewritten_query.is_none());
}

#[test]
fn star_over_an_untagged_table_reads_nothing() {
    assert_not_read("SELECT * FROM orders", "email");
    assert_not_read(
        "SELECT o.* FROM orders o JOIN customers c ON c.id = o.cid",
        "email",
    );
}

#[test]
fn alias_is_followed_by_derivation_not_name() {
    assert_reads("SELECT email AS e FROM customers", "email");
    assert_reads("SELECT c.email AS id FROM customers c", "email");
}

#[test]
fn expressions_derive_from_their_inputs() {
    for sql in [
        "SELECT concat(email, '') FROM customers",
        "SELECT substring(email, 1, 12) FROM customers",
        "SELECT lower(email) FROM customers",
        "SELECT email || '' FROM customers",
        "SELECT email::varchar(4) FROM customers",
        "SELECT CASE WHEN id > 0 THEN email END FROM customers",
        "SELECT coalesce(email, 'x') FROM customers",
        "SELECT email = 'a@b.c' AS hit FROM customers",
        "SELECT ARRAY[email] FROM customers",
        "SELECT ROW(id, email) FROM customers",
        "SELECT (email) COLLATE \"C\" FROM customers",
        "SELECT greatest(email, 'a') FROM customers",
        "SELECT nullif(email, '') FROM customers",
        "SELECT format('%s', VARIADIC ARRAY[email]) FROM customers",
        "SELECT xmlelement(name e, email) FROM customers",
        "SELECT json_build_object('e', email) FROM customers",
    ] {
        assert_reads(sql, "email");
    }
}

#[test]
fn row_to_value_functions_touch_every_tagged_column() {
    let tags = vec![
        masked("customers", "email", Email),
        tag("customers", "card", Flag),
    ];
    for sql in [
        "SELECT to_jsonb(c) FROM customers c",
        "SELECT row_to_json(c) FROM customers c",
        "SELECT json_agg(c) FROM customers c",
        "SELECT to_jsonb(customers) FROM customers",
        "SELECT c FROM customers c",
        "SELECT (c).email FROM customers c",
        "SELECT to_jsonb(c.*) FROM customers c",
        "SELECT count(c.*) FROM customers c",
        "SELECT j FROM customers c, LATERAL to_jsonb(c) j",
    ] {
        let o = pg(sql, tags.clone());
        assert_eq!(
            o.decision,
            Decision::Block,
            "{sql}: whole-row under mask: {o:?}"
        );
        assert_eq!(read(&o), vec!["card", "email"], "{sql}");
    }
}

#[test]
fn subqueries_and_ctes_are_followed() {
    assert_reads(
        "WITH x AS (SELECT email FROM customers) SELECT * FROM x",
        "email",
    );
    assert_reads(
        "WITH x AS (SELECT email FROM customers) SELECT email FROM x",
        "email",
    );
    assert_reads(
        "SELECT e FROM (SELECT email AS e FROM customers) s",
        "email",
    );
    assert_reads(
        "SELECT s.e FROM (SELECT email AS e FROM customers) s",
        "email",
    );
    assert_reads("SELECT email FROM (SELECT * FROM customers) s", "email");
    assert_reads("SELECT (SELECT email FROM customers LIMIT 1)", "email");
    assert_reads("SELECT ARRAY(SELECT email FROM customers)", "email");
    assert_reads("SELECT x FROM (SELECT * FROM customers) x", "email");
    assert_reads("SELECT a FROM customers AS c(a)", "email");
}

#[test]
fn subquery_columns_that_are_not_tagged_are_not_reads() {
    assert_not_read(
        "SELECT id FROM (SELECT id, email FROM customers) s",
        "email",
    );
    assert_not_read(
        "WITH x AS (SELECT id, email FROM customers) SELECT id FROM x",
        "email",
    );
    assert_not_read("SELECT s.id FROM (SELECT * FROM customers) s", "email");
}

#[test]
fn aggregation_still_derives_from_the_column() {
    assert_reads("SELECT string_agg(email, ',') FROM customers", "email");
    assert_reads("SELECT array_agg(card) FROM customers", "card");
    assert_reads("SELECT max(email) FROM customers GROUP BY id", "email");
    assert_reads("SELECT count(DISTINCT email) FROM customers", "email");
}

#[test]
fn filtering_joining_grouping_and_ordering_are_not_reads() {
    for sql in [
        "SELECT id FROM customers WHERE email = $1",
        "SELECT o.id FROM orders o JOIN customers c ON c.email = o.email_hash",
        "SELECT count(*) FROM customers GROUP BY email",
        "SELECT id FROM customers ORDER BY email",
        "SELECT count(*) FILTER (WHERE email LIKE '%@x') FROM customers",
        "SELECT string_agg(id::text, ',' ORDER BY email) FROM customers",
        "SELECT id FROM orders WHERE EXISTS (SELECT email FROM customers WHERE email = 'x')",
        "SELECT EXISTS (SELECT email FROM customers)",
        "SELECT id FROM customers GROUP BY id HAVING max(email) > 'a'",
        "SELECT row_number() OVER (ORDER BY email) FROM customers",
        "SELECT id FROM customers WHERE id IN (SELECT id FROM customers WHERE email = 'x')",
        "DELETE FROM customers WHERE email = $1",
        "UPDATE customers SET name = 'x' WHERE email = $1",
        "EXPLAIN SELECT email FROM customers",
        "SELECT count(*) FROM customers",
    ] {
        assert_not_read(sql, "email");
    }
}

#[test]
fn copy_to_is_select_star() {
    assert_reads("COPY customers TO STDOUT", "email");
    assert_reads("COPY customers (id, email) TO STDOUT", "email");
    assert_reads("COPY (SELECT email FROM customers) TO STDOUT", "email");
    assert_not_read("COPY customers (id, name) TO STDOUT", "email");
    assert_not_read("COPY customers FROM STDIN", "email");

    let o = pg(
        "COPY customers TO STDOUT",
        vec![masked("customers", "email", Email)],
    );
    assert_eq!(o.decision, Decision::Block);
    let o = pg(
        "COPY customers TO STDOUT",
        vec![tag("customers", "email", Flag)],
    );
    assert_eq!(o.decision, Decision::Flag);
    let o = pg(
        "COPY customers (email) TO STDOUT",
        vec![masked("customers", "email", Email)],
    );
    assert_eq!(o.decision, Decision::Block, "no projection to rewrite");
}

// ── joins, set operations, CTEs ────────────────────────────────────────────

#[test]
fn join_with_the_same_column_name_in_two_tables_resolves_by_qualifier() {
    let j = "FROM orders o JOIN customers c ON c.id = o.customer_id";
    assert_not_read(&format!("SELECT o.email {j}"), "email");
    assert_reads(&format!("SELECT c.email {j}"), "email");
    // Unqualified: either table could have it — conservatively a read.
    assert_reads(&format!("SELECT email {j}"), "email");
    assert_reads("SELECT customers.email FROM orders, customers", "email");
    assert_not_read("SELECT orders.email FROM orders, customers", "email");
    // USING merges the columns: conservatively both sides.
    assert_reads(
        "SELECT email FROM orders JOIN customers USING (email)",
        "email",
    );
    // An aliased join: j.email may be either side.
    assert_reads(
        "SELECT j.email FROM (orders JOIN customers USING (id)) AS j",
        "email",
    );
}

#[test]
fn union_reads_from_every_arm_and_masks_only_the_tagged_one() {
    assert_reads(
        "SELECT name FROM users UNION SELECT email FROM customers",
        "email",
    );
    assert_reads(
        "SELECT email FROM customers EXCEPT SELECT name FROM users",
        "email",
    );
    assert_reads(
        "SELECT name FROM users INTERSECT SELECT email FROM customers",
        "email",
    );
    assert_reads(
        "SELECT x FROM (SELECT name AS x FROM users UNION ALL SELECT email FROM customers) u",
        "email",
    );
    assert_not_read(
        "SELECT name FROM users UNION SELECT id::text FROM customers",
        "email",
    );

    let rw = rewrite(
        "SELECT name FROM users UNION SELECT email FROM customers",
        vec![masked("customers", "email", Full)],
    );
    assert_eq!(
        rw,
        "SELECT name FROM users UNION SELECT '[redacted]'::text AS email FROM customers"
    );
}

#[test]
fn nested_ctes_are_followed_through_every_level() {
    let sql = "WITH a AS (SELECT email AS e FROM customers), \
               b AS (SELECT e AS x FROM a) SELECT x FROM b";
    assert_reads(sql, "email");
    let inner = "WITH b AS (WITH a AS (SELECT email FROM customers) SELECT email AS x FROM a) \
                 SELECT x FROM b";
    assert_reads(inner, "email");
    assert_not_read(
        "WITH a AS (SELECT id, email FROM customers), b AS (SELECT id FROM a) SELECT * FROM b",
        "email",
    );
    // Pass-through of bare references stays direct: the tag's style applies.
    let rw = rewrite(sql, vec![masked("customers", "email", Last4)]);
    assert!(
        rw.ends_with("SELECT '****' || \"right\"(x::text, 4) AS x FROM b"),
        "{rw}"
    );
}

#[test]
fn recursive_cte_is_followed() {
    assert_reads(
        "WITH RECURSIVE r(e, n) AS (SELECT email, 1 FROM customers UNION ALL \
         SELECT e, n + 1 FROM r WHERE n < 3) SELECT e FROM r",
        "email",
    );
    assert_not_read(
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r",
        "email",
    );
}

#[test]
fn data_modifying_cte_returning_is_followed() {
    assert_reads(
        "WITH d AS (DELETE FROM customers WHERE id = 1 RETURNING email) SELECT email FROM d",
        "email",
    );
    // A RETURNING nobody selects reaches no client.
    assert_not_read(
        "WITH d AS (DELETE FROM customers WHERE id = 1 RETURNING email) SELECT 1",
        "email",
    );
}

// ── identifiers and schemas ────────────────────────────────────────────────

#[test]
fn quoted_identifiers_and_case_folding_match_conservatively() {
    assert_reads("SELECT EMAIL FROM CUSTOMERS", "email");
    assert_reads("SELECT \"email\" FROM \"customers\"", "email");
    // Quoted mixed case is a different identifier to Postgres; the engine has
    // no schema, so it treats it as the tagged one (a false positive at worst).
    assert_reads("SELECT \"Email\" FROM \"Customers\"", "email");
    let o = pg(
        "SELECT email FROM customers",
        vec![tag("Customers", "EMAIL", Block)],
    );
    assert_eq!(
        o.decision,
        Decision::Block,
        "tags compare case-insensitively"
    );
}

#[test]
fn a_cte_shadows_a_table_only_under_postgres_own_rules() {
    // The CTE named `customers` IS what the query reads: not the tagged table.
    assert_not_read(
        "WITH customers AS (SELECT 1 AS email) SELECT email FROM customers",
        "email",
    );
    // A quoted "Customers" CTE does NOT shadow the folded `customers`: the
    // query reads the real, tagged table.
    assert_reads(
        "WITH \"Customers\" AS (SELECT 1 AS email) SELECT email FROM customers",
        "email",
    );
    // Schema-qualified always means the table.
    assert_reads(
        "WITH customers AS (SELECT 1 AS email) SELECT email FROM public.customers",
        "email",
    );
}

#[test]
fn schema_qualified_names() {
    let public = SensitiveColumn {
        schema: Some("public".into()),
        ..tag("customers", "email", Block)
    };
    let t = |sql: &str| pg(sql, vec![public.clone()]).decision;
    assert_eq!(t("SELECT email FROM public.customers"), Decision::Block);
    assert_eq!(t("SELECT email FROM PUBLIC.customers"), Decision::Block);
    // Unqualified: the search_path could resolve it to public.
    assert_eq!(t("SELECT email FROM customers"), Decision::Block);
    assert_eq!(
        t("SELECT public.customers.email FROM public.customers"),
        Decision::Block
    );
    // A different schema is a different table.
    assert_eq!(t("SELECT email FROM billing.customers"), Decision::Allow);
    assert_eq!(t("SELECT * FROM billing.customers"), Decision::Allow);
    // A tag without schema matches every schema.
    assert_reads("SELECT email FROM billing.customers", "email");
    assert_reads("SELECT c.email FROM mydb.billing.customers c", "email");
}

// ── data copies ────────────────────────────────────────────────────────────

#[test]
fn copying_a_tagged_column_elsewhere_is_a_read() {
    for sql in [
        "INSERT INTO archive SELECT email FROM customers",
        "INSERT INTO archive (contact) SELECT email FROM customers",
        "INSERT INTO archive SELECT * FROM customers",
        "INSERT INTO archive VALUES ((SELECT email FROM customers LIMIT 1))",
        "CREATE TABLE x AS SELECT email FROM customers",
        "CREATE MATERIALIZED VIEW x AS SELECT email FROM customers",
        "SELECT email INTO x FROM customers",
        "CREATE VIEW v AS SELECT email FROM customers",
        "UPDATE profiles p SET contact = c.email FROM customers c WHERE c.id = p.id",
        "UPDATE customers SET name = email",
        "MERGE INTO archive a USING customers c ON a.id = c.id \
         WHEN NOT MATCHED THEN INSERT (id, contact) VALUES (c.id, c.email)",
        "MERGE INTO archive a USING customers c ON a.id = c.id \
         WHEN MATCHED THEN UPDATE SET contact = c.email",
        "INSERT INTO archive (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET contact = (SELECT email FROM customers LIMIT 1)",
        "WITH ins AS (INSERT INTO archive SELECT email FROM customers RETURNING 1) SELECT 1",
        "EXPLAIN ANALYZE INSERT INTO archive SELECT email FROM customers",
    ] {
        assert_reads(sql, "email");
    }
}

#[test]
fn writing_a_tagged_column_into_itself_is_not_a_copy_out() {
    assert_not_read(
        "UPDATE customers SET email = lower(email) WHERE id = $1",
        "email",
    );
    assert_not_read(
        "INSERT INTO customers (id, email) SELECT id, email FROM customers WHERE id = 1",
        "email",
    );
    assert_not_read("INSERT INTO customers (email) VALUES ($1)", "email");
}

#[test]
fn copies_are_blocked_under_mask_because_masking_would_change_stored_data() {
    let o = pg(
        "INSERT INTO archive SELECT email FROM customers",
        vec![masked("customers", "email", Email)],
    );
    assert_eq!(o.decision, Decision::Block);
    assert!(
        o.ast_node_path
            .unwrap()
            .contains("copied into another relation")
    );
    let o = pg(
        "INSERT INTO archive SELECT email FROM customers",
        vec![tag("customers", "email", Flag)],
    );
    assert_eq!(o.decision, Decision::Flag);
}

#[test]
fn returning_cursor_and_prepare_are_client_visible() {
    assert_reads(
        "DELETE FROM customers WHERE id = 1 RETURNING email",
        "email",
    );
    assert_reads(
        "UPDATE customers SET name = 'x' WHERE id = 1 RETURNING email",
        "email",
    );
    assert_reads("INSERT INTO customers (id) VALUES (1) RETURNING *", "email");
    assert_reads("DECLARE c CURSOR FOR SELECT email FROM customers", "email");
    assert_reads(
        "PREPARE p AS SELECT email FROM customers WHERE id = $1",
        "email",
    );
    assert_not_read("DELETE FROM customers WHERE id = 1 RETURNING id", "email");
}

#[test]
fn several_statements_are_all_analysed() {
    assert_reads("SELECT 1; SELECT email FROM customers", "email");
}

#[test]
fn expressions_the_walker_does_not_model_are_assumed_to_read() {
    // XMLTABLE in FROM and an exotic expression in the list: the fallback
    // finds the column references inside.
    assert_reads(
        "SELECT x.v FROM customers c, XMLTABLE('/r' PASSING c.email COLUMNS v text PATH '.') x",
        "email",
    );
    assert_reads("SELECT xmlforest(email) FROM customers", "email");
}

// ── policy resolution ──────────────────────────────────────────────────────

#[test]
fn strictest_policy_wins() {
    let tags = vec![
        tag("customers", "email", Flag),
        masked("customers", "card", Last4),
        tag("customers", "ssn", Block),
    ];
    let o = pg("SELECT email, card, ssn FROM customers", tags.clone());
    assert_eq!(o.decision, Decision::Block);
    assert!(
        o.ast_node_path
            .as_deref()
            .unwrap()
            .contains("customers.ssn (block)")
    );
    assert_eq!(
        read(&o),
        vec!["card", "email", "ssn"],
        "every read column is audited"
    );

    let o = pg("SELECT email, card FROM customers", tags.clone());
    assert_eq!(
        o.decision,
        Decision::Flag,
        "mask beats flag, and still flags"
    );
    let rw = o.rewritten_query.unwrap();
    assert!(rw.contains("email,"), "the flagged column passes: {rw}");
    assert!(
        rw.contains("'****' || \"right\"(card::text, 4) AS card"),
        "{rw}"
    );

    let o = pg("SELECT email FROM customers", tags);
    assert_eq!(o.decision, Decision::Flag);
    assert!(o.rewritten_query.is_none());
}

#[test]
fn touched_columns_carry_the_tag_identity_sorted() {
    let t = SensitiveColumn {
        schema: Some("public".into()),
        ..tag("customers", "email", Flag)
    };
    let o = pg(
        "SELECT C.EMAIL, c.card FROM customers c",
        vec![tag("customers", "card", Flag), t],
    );
    assert_eq!(
        o.sensitive_columns,
        vec![
            TouchedColumn {
                schema: None,
                table: "customers".into(),
                column: "card".into(),
                policy: Flag
            },
            TouchedColumn {
                schema: Some("public".into()),
                table: "customers".into(),
                column: "email".into(),
                policy: Flag
            },
        ]
    );
}

#[test]
fn monitor_mode_never_blocks_and_never_rewrites() {
    let mut p = policy(email_block());
    p.monitor_mode = true;
    let o = crate::evaluate("SELECT email FROM customers", Dialect::Postgres, &[], &p);
    assert_eq!(o.decision, Decision::Flag);

    let mut p = policy(vec![masked("customers", "email", Email)]);
    p.monitor_mode = true;
    let o = crate::evaluate("SELECT email FROM customers", Dialect::Postgres, &[], &p);
    assert_eq!(o.decision, Decision::Flag);
    assert!(
        o.rewritten_query.is_none(),
        "dry-run never changes what runs"
    );
    assert!(
        o.suggested_safe_query.unwrap().contains("regexp_replace"),
        "the would-be rewrite is shown"
    );
}

fn rule(code: &str, severity: Severity) -> Rule {
    Rule {
        rule_id: code.into(),
        code: code.into(),
        severity,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }
}

#[test]
fn the_column_verdict_is_a_floor_over_the_rules() {
    // A blocking rule still blocks a query that only flags a column…
    let p = policy(vec![tag("customers", "email", Flag)]);
    let rules = [rule("VERICTO-001", Severity::Critical)];
    let o = crate::evaluate(
        "DELETE FROM customers RETURNING email",
        Dialect::Postgres,
        &rules,
        &p,
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"));
    assert_eq!(
        o.violations[0].rule_code, "VERICTO-001",
        "violations[0] is the winner"
    );
    assert!(o.violations.iter().any(|v| v.rule_code == "VERICTO-085"));
    assert_eq!(read(&o), vec!["email"]);

    // …and a column block wins over a rule the policy only flags.
    let mut p = policy(email_block());
    p.critical = EnforcementAction::Flag;
    let o = crate::evaluate(
        "DELETE FROM customers RETURNING email",
        Dialect::Postgres,
        &rules,
        &p,
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"));
    assert_eq!(o.violations[0].rule_code, "VERICTO-085");
    assert_eq!(o.violations[1].rule_code, "VERICTO-001");

    // A mask under a flagging rule: the rule keeps the flat fields, the
    // rewrite still applies.
    let p = policy(vec![masked("customers", "email", Full)]);
    let o = crate::evaluate(
        "SELECT email FROM customers",
        Dialect::Postgres,
        &[rule("VERICTO-050", Severity::Medium)],
        &p,
    );
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-050"));
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some("SELECT '[redacted]'::text AS email FROM customers")
    );

    // A mask under a blocking rule: blocked, nothing to rewrite.
    let o = crate::evaluate(
        "DELETE FROM customers RETURNING email",
        Dialect::Postgres,
        &rules,
        &p,
    );
    assert_eq!(o.decision, Decision::Block);
    assert!(o.rewritten_query.is_none());
}

#[test]
fn listing_vericto_085_in_the_rules_slice_is_a_no_op() {
    let o = crate::evaluate(
        "SELECT email FROM customers",
        Dialect::Postgres,
        &[rule("VERICTO-085", Severity::Critical)],
        &EnforcementPolicy::default(),
    );
    assert_eq!(o.decision, Decision::Allow);
}

#[test]
fn no_tags_means_exactly_todays_outcome() {
    let rules: Vec<Rule> = ["VERICTO-001", "VERICTO-050", "VERICTO-051", "VERICTO-090"]
        .iter()
        .map(|c| rule(c, Severity::High))
        .collect();
    for sql in [
        "SELECT email FROM customers",
        "SELECT * FROM customers WHERE id = 1 OR 1=1",
        "DELETE FROM customers RETURNING email",
        "COPY customers TO STDOUT",
        "NOT SQL @@@",
    ] {
        for d in [Dialect::Postgres, Dialect::Mysql] {
            let o = crate::evaluate(sql, d, &rules, &EnforcementPolicy::default());
            assert!(o.rewritten_query.is_none(), "{sql}");
            assert!(o.sensitive_columns.is_empty(), "{sql}");
            assert!(
                o.violations.iter().all(|v| v.rule_code != "VERICTO-085"),
                "{sql}"
            );
        }
    }
}

#[test]
fn the_analysis_never_runs_without_tags() {
    super::ANALYSES.with(|n| n.set(0));
    let rules = [rule("VERICTO-001", Severity::Critical)];
    for sql in [
        "SELECT email FROM customers",
        "SELECT * FROM customers",
        "WITH x AS (SELECT email FROM customers) SELECT * FROM x",
        "DELETE FROM customers",
    ] {
        for d in [Dialect::Postgres, Dialect::Mysql] {
            crate::evaluate(sql, d, &rules, &EnforcementPolicy::default());
        }
    }
    assert_eq!(
        super::ANALYSES.with(|n| n.get()),
        0,
        "zero-cost when untagged"
    );
    pg("SELECT 1", email_block());
    assert_eq!(super::ANALYSES.with(|n| n.get()), 1);
}

#[test]
fn parse_errors_fail_closed_when_a_protective_tag_exists() {
    let o = crate::evaluate(
        "SELEC email FROM customers",
        Dialect::Postgres,
        &[],
        &policy(email_block()),
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"));
    let p = policy(vec![masked("customers", "email", Full)]);
    assert_eq!(p.effective_parse_error(), ParseErrorAction::Block);

    // Flag-only tags keep the host's fail-open choice.
    let p = policy(vec![tag("customers", "email", Flag)]);
    assert_eq!(p.effective_parse_error(), ParseErrorAction::AllowReport);
    let o = crate::evaluate("SELEC email FROM customers", Dialect::Postgres, &[], &p);
    assert_eq!(o.decision, Decision::Flag);
    // And no tags: unchanged.
    assert_eq!(
        EnforcementPolicy::default().effective_parse_error(),
        ParseErrorAction::AllowReport
    );
}

#[test]
fn analysis_too_deep_fails_closed() {
    // 60 nested scalar subqueries: parses (well under the 200 textual
    // guard) but past MAX_AST_DEPTH for the walk.
    let mut sql = "SELECT email FROM customers".to_string();
    for _ in 0..60 {
        sql = format!("SELECT ({sql})");
    }
    let o = pg(&sql, email_block());
    assert_eq!(o.decision, Decision::Block, "{o:?}");
}

// ── mask rewrite ───────────────────────────────────────────────────────────

#[test]
fn each_mask_style_produces_the_design_expression() {
    let cases = [
        (
            Full,
            "SELECT id, '[redacted]'::text AS email FROM customers",
        ),
        (
            Last4,
            "SELECT id, '****' || \"right\"(email::text, 4) AS email FROM customers",
        ),
        (
            Email,
            "SELECT id, regexp_replace(email::text, '^(.)[^@]*(@.*)?$', E'\\\\1***\\\\2') AS email FROM customers",
        ),
        (
            Hash,
            "SELECT id, encode(sha256(convert_to(email::text, 'UTF8')), 'hex') AS email FROM customers",
        ),
    ];
    for (style, want) in cases {
        let rw = rewrite(
            "SELECT id, email FROM customers",
            vec![masked("customers", "email", style)],
        );
        assert_eq!(rw, want, "{style:?}");
    }
}

#[test]
fn the_output_column_keeps_its_name() {
    let t = || vec![masked("customers", "email", Email)];
    assert!(rewrite("SELECT email AS e FROM customers", t()).contains(" AS e FROM"));
    assert!(rewrite("SELECT c.email FROM customers c", t()).contains(" AS email FROM"));
    assert!(rewrite("SELECT lower(email) FROM customers", t()).contains("0)) AS lower"));
    assert!(rewrite("SELECT email::text FROM customers", t()).contains("AS email FROM"));
    assert!(rewrite("SELECT email || '' FROM customers", t()).contains("AS \"?column?\""));
}

#[test]
fn computed_expressions_are_masked_full_whatever_the_style() {
    // last4 of a caller-chosen substring would hand out any 4 characters.
    let rw = rewrite(
        "SELECT substring(card, 1, 4) AS p FROM customers",
        vec![masked("customers", "card", Last4)],
    );
    assert_eq!(
        rw,
        "SELECT concat('[redacted]'::text, \"left\"(\"substring\"(card, 1, 4)::text, 0)) AS p FROM customers"
    );
    let rw = rewrite(
        "SELECT card::varchar(4) FROM customers",
        vec![masked("customers", "card", Hash)],
    );
    assert!(rw.starts_with("SELECT concat('[redacted]'::text,"), "{rw}");
    assert!(rw.ends_with(" AS card FROM customers"), "{rw}");
    // Computed inside a CTE, then passed through bare: still computed.
    let rw = rewrite(
        "WITH x AS (SELECT left(card, 4) AS card FROM customers) SELECT card FROM x",
        vec![masked("customers", "card", Last4)],
    );
    assert!(
        rw.ends_with("SELECT '[redacted]'::text AS card FROM x"),
        "a bare reference to the CTE column is a plain value: {rw}"
    );
    // Two masked columns with different styles in one value: full.
    let rw = rewrite(
        "SELECT coalesce(email, card) AS x FROM customers",
        vec![
            masked("customers", "email", Email),
            masked("customers", "card", Last4),
        ],
    );
    assert!(
        rw.contains("concat('[redacted]'::text,") && rw.contains(" AS x"),
        "{rw}"
    );
}

#[test]
fn a_masked_aggregate_still_aggregates() {
    // 3.6.1 replaced `string_agg(email, ',')` with the constant
    // '[redacted]', which returns one row per customer instead of one row.
    // The computed value is kept and discarded, so the row count is the
    // original's (tests/mask_equivalence.rs runs it).
    let rw = rewrite(
        "SELECT string_agg(email, ',') AS all_emails FROM customers",
        vec![masked("customers", "email", Email)],
    );
    assert_eq!(
        rw,
        "SELECT concat('[redacted]'::text, \"left\"(string_agg(email, ',')::text, 0)) AS all_emails FROM customers"
    );
}

#[test]
fn prepared_statement_parameters_survive_the_rewrite() {
    let rw = rewrite(
        "SELECT id, email FROM customers WHERE id = $1 AND name = $2 LIMIT $3",
        vec![masked("customers", "email", Full)],
    );
    assert_eq!(
        rw,
        "SELECT id, '[redacted]'::text AS email FROM customers WHERE id = $1 AND name = $2 LIMIT $3"
    );
}

#[test]
fn order_by_and_group_by_keep_using_the_original_value() {
    let t = || vec![masked("customers", "email", Email)];
    let rw = rewrite("SELECT email FROM customers ORDER BY email", t());
    assert!(rw.ends_with("ORDER BY COALESCE(email)"), "{rw}");
    let rw = rewrite("SELECT email FROM customers ORDER BY 1 DESC", t());
    assert!(rw.ends_with("ORDER BY COALESCE(email) DESC"), "{rw}");
    let rw = rewrite(
        "SELECT lower(email) AS e, count(*) FROM customers GROUP BY 1",
        t(),
    );
    assert!(rw.ends_with("GROUP BY lower(email)"), "{rw}");
    let rw = rewrite(
        "SELECT lower(email) AS e, count(*) FROM customers GROUP BY e ORDER BY e",
        t(),
    );
    assert!(
        rw.ends_with("GROUP BY lower(email) ORDER BY lower(email)"),
        "{rw}"
    );
    // Unrelated sort keys are untouched.
    let rw = rewrite("SELECT id, email FROM customers ORDER BY id", t());
    assert!(rw.ends_with("ORDER BY id"), "{rw}");
    // DISTINCT: ORDER BY must name an output, so it is left alone.
    let rw = rewrite("SELECT DISTINCT email FROM customers ORDER BY email", t());
    assert!(rw.ends_with("ORDER BY email"), "{rw}");
}

#[test]
fn returning_values_and_scalar_subqueries_are_rewritten() {
    let t = || vec![masked("customers", "email", Full)];
    assert_eq!(
        rewrite(
            "DELETE FROM customers WHERE id = $1 RETURNING id, email",
            t()
        ),
        "DELETE FROM customers WHERE id = $1 RETURNING id, '[redacted]'::text AS email"
    );
    assert_eq!(
        rewrite("SELECT (SELECT email FROM customers LIMIT 1) AS e", t()),
        "SELECT '[redacted]'::text AS e"
    );
    assert_eq!(
        rewrite("VALUES ((SELECT email FROM customers LIMIT 1))", t()),
        "VALUES ('[redacted]'::text)"
    );
    assert_eq!(
        rewrite("COPY (SELECT email FROM customers) TO STDOUT", t()),
        "COPY (SELECT '[redacted]'::text AS email FROM customers) TO STDOUT"
    );
    // Only the client-visible projection changes; a CTE body is not touched.
    assert_eq!(
        rewrite(
            "WITH x AS (SELECT id, email FROM customers) SELECT id, email FROM x",
            t()
        ),
        "WITH x AS (SELECT id, email FROM customers) SELECT id, '[redacted]'::text AS email FROM x"
    );
}

#[test]
fn a_failed_deparse_blocks_and_never_returns_the_original() {
    super::pg::FORCE_DEPARSE_FAILURE.with(|f| f.set(true));
    let o = pg(
        "SELECT email FROM customers",
        vec![masked("customers", "email", Full)],
    );
    super::pg::FORCE_DEPARSE_FAILURE.with(|f| f.set(false));
    assert_eq!(o.decision, Decision::Block);
    assert!(o.rewritten_query.is_none());
    assert!(o.ast_node_path.unwrap().contains("rewrite failed"));
}

// ── MySQL (and the other sqlparser dialects) ───────────────────────────────

#[test]
fn mysql_block_and_flag_work_and_mask_rewrites() {
    let my = |sql: &str, tags| eval_on(sql, Dialect::Mysql, tags);
    let o = my("SELECT email FROM customers", email_block());
    assert_eq!(o.decision, Decision::Block);
    let o = my(
        "SELECT `email` AS e FROM `customers`",
        vec![tag("customers", "email", Flag)],
    );
    assert_eq!(o.decision, Decision::Flag);
    assert!(o.rewritten_query.is_none());

    // 3.7.0: MySQL masks are rewritten (tests/mysql_mask.rs has the rest).
    let o = my(
        "SELECT email FROM customers",
        vec![masked("customers", "email", Email)],
    );
    assert_eq!(o.decision, Decision::Flag, "{o:?}");
    let rw = o.rewritten_query.expect("MySQL mask rewrites");
    assert!(
        rw.contains("LOCATE('@'") && rw.ends_with("AS `email` FROM customers"),
        "{rw}"
    );

    for sql in [
        "SELECT * FROM customers",
        "SELECT c.* FROM customers c",
        "SELECT CONCAT(email, '') FROM customers",
        "SELECT SUBSTRING(email, 1, 3) FROM customers",
        "SELECT GROUP_CONCAT(email) FROM customers",
        "SELECT e FROM (SELECT email AS e FROM customers) s",
        "WITH x AS (SELECT email FROM customers) SELECT * FROM x",
        "SELECT (SELECT email FROM customers LIMIT 1)",
        "SELECT name FROM users UNION SELECT email FROM customers",
        "SELECT c.email FROM orders o JOIN customers c ON c.id = o.cid",
        "INSERT INTO archive SELECT email FROM customers",
        "CREATE TABLE x AS SELECT email FROM customers",
        "SELECT email INTO OUTFILE '/tmp/x' FROM customers",
        "UPDATE profiles p JOIN customers c ON c.id = p.id SET p.contact = c.email",
        "SELECT JSON_OBJECT('e', email) FROM customers",
        "SELECT CAST(email AS CHAR(4)) FROM customers",
        "SELECT CASE WHEN id > 0 THEN email END FROM customers",
        "SELECT EMAIL FROM CUSTOMERS",
        "SELECT email FROM shop.customers",
    ] {
        let o = my(sql, email_block());
        assert_eq!(o.decision, Decision::Block, "mysql: {sql}: {o:?}");
    }
    for sql in [
        "SELECT id FROM customers WHERE email = ?",
        "SELECT o.email FROM orders o JOIN customers c ON c.id = o.cid",
        "SELECT count(*) FROM customers GROUP BY email ORDER BY email",
        "SELECT id FROM (SELECT id, email FROM customers) s",
        "UPDATE customers SET email = LOWER(email) WHERE id = 1",
        "SELECT COUNT(*) FROM customers",
        "SELECT id FROM orders WHERE EXISTS (SELECT email FROM customers)",
    ] {
        let o = my(sql, email_block());
        assert_eq!(o.decision, Decision::Allow, "mysql: {sql}: {o:?}");
    }
}

#[test]
fn mysql_syntax_the_parser_rejects_cannot_smuggle_a_read() {
    // Dynamic SQL and statements sqlparser does not know: unparseable, so with
    // a block tag they block instead of being forwarded unread.
    for sql in [
        "PREPARE s FROM 'SELECT email FROM customers'",
        "HANDLER customers READ FIRST",
    ] {
        let o = eval_on(sql, Dialect::Mysql, email_block());
        assert_eq!(o.decision, Decision::Block, "{sql}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"));
    }
}

#[test]
fn mysql_text_sqlparser_reads_differently_cannot_hide_a_read() {
    // Each of these reads `email` (or `card`) in MySQL while sqlparser sees a
    // comment, because the two read comments and string escapes differently.
    // They resolve like a parse error: blocked under a block or
    // mask tag, flagged under flag-only tags. 3.6.1 allowed all of them.
    let tags = || {
        vec![
            tag("customers", "email", Block),
            tag("customers", "card", Block),
        ]
    };
    for sql in [
        "SELECT id, /*! email, */ id FROM customers",
        "SELECT id /*!50000 , email */ FROM customers",
        "SELECT id /*M! , email */ FROM customers",
        "SELECT 0 --card\n FROM customers",
        // The literal ends at a different place in each string-escape mode
        // (measured on 8.0).
        r"SELECT 'a\', email, '' FROM customers -- '",
    ] {
        let o = eval_on(sql, Dialect::Mysql, tags());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        assert!(
            o.ast_node_path
                .as_deref()
                .unwrap_or_default()
                .contains("could not be analysed"),
            "{sql}: {o:?}"
        );
        let o = eval_on(sql, Dialect::Mysql, vec![tag("customers", "email", Flag)]);
        assert_eq!(o.decision, Decision::Flag, "flag-only tags flag: {sql}");
        let o = eval_on(sql, Dialect::Mysql, vec![]);
        assert_eq!(o.decision, Decision::Allow, "no tags: unchanged: {sql}");
    }
    // MySQL and sqlparser disagree on where this comment ends, and MySQL's own
    // reading depends on context: the engine does not guess, VERICTO-086
    // blocks it whatever the tags (3.7.0).
    for cols in [tags(), vec![tag("customers", "email", Flag)], vec![]] {
        let o = eval_on(
            "SELECT id /* /* */ , email FROM customers -- */",
            Dialect::Mysql,
            cols,
        );
        assert_eq!(o.decision, Decision::Block, "{o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-086"), "{o:?}");
    }
    // A real comment, and `-- ` with a space, are fine.
    for sql in [
        "SELECT id /* email */ FROM customers",
        "SELECT id -- email\n FROM customers",
        "SELECT id # email\n FROM customers",
        r"SELECT id, 'a\\b', 'it''s' FROM customers",
    ] {
        let o = eval_on(sql, Dialect::Mysql, tags());
        assert_eq!(o.decision, Decision::Allow, "{sql}: {o:?}");
    }
}

#[test]
fn mysql_text_handling_is_inert_without_tags() {
    // The sensitive-column analysis never runs without tags, and the rule
    // engine's own reading of these forms (lexical normalization, 3.7.0)
    // finds nothing to report with no rules: no PARSE_ERROR, no block. The
    // one form the normalization cannot resolve blocks
    // with VERICTO-086 (see mysql_text_sqlparser_reads_differently_…).
    for sql in [
        r"SELECT id, 'it\'s' FROM customers",
        "SELECT id, /*! name, */ id FROM customers",
        "SELECT 0 --x\n FROM customers",
        "SELECT HIGH_PRIORITY name FROM customers",
        "SELECT SQL_CALC_FOUND_ROWS id FROM customers LIMIT 10",
        "SELECT /*+ BKA(c) */ name FROM customers",
        "SELECT b'101', name FROM customers",
        "SELECT \"name\" FROM customers",
    ] {
        super::ANALYSES.with(|n| n.set(0));
        for pe in [ParseErrorAction::AllowReport, ParseErrorAction::Block] {
            let p = EnforcementPolicy {
                parse_error: pe,
                ..EnforcementPolicy::default()
            };
            let o = crate::evaluate(sql, Dialect::Mysql, &[], &p);
            assert_eq!(o.decision, Decision::Allow, "{sql}: {o:?}");
            assert!(o.rule_code.is_none(), "{sql}: {o:?}");
            assert!(o.rewritten_query.is_none() && o.sensitive_columns.is_empty());
        }
        assert_eq!(super::ANALYSES.with(|n| n.get()), 0, "{sql}");
    }
}

#[test]
fn mysql_select_modifiers_do_not_hide_a_read() {
    // sqlparser 0.52 misreads a SELECT modifier and the column after it as a
    // column with an alias; MySQL reads the column. 3.6.1 allowed it.
    for sql in [
        "SELECT HIGH_PRIORITY email FROM customers",
        "SELECT SQL_CALC_FOUND_ROWS email FROM customers",
        "SELECT STRAIGHT_JOIN email FROM customers",
        "SELECT SQL_NO_CACHE email FROM customers",
        "SELECT DISTINCTROW email FROM customers",
        "SELECT DISTINCT SQL_BUFFER_RESULT SQL_SMALL_RESULT email FROM customers",
        "SELECT id FROM orders WHERE cid IN (SELECT SQL_NO_CACHE id FROM x) UNION SELECT HIGH_PRIORITY email FROM customers",
    ] {
        let o = eval_on(sql, Dialect::Mysql, email_block());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        // Read (or, where the original does not parse at all, a parse error,
        // which blocks too).
        assert!(
            read(&o) == vec!["email"] || o.rule_code.as_deref() == Some("VERICTO-PARSE-ERROR"),
            "{sql}: {o:?}"
        );
    }
    let o = eval_on(
        "SELECT SQL_NO_CACHE id FROM customers",
        Dialect::Mysql,
        email_block(),
    );
    assert_eq!(o.decision, Decision::Allow, "{o:?}");
}

#[test]
fn mysql_session_variables_and_upserts_are_copies() {
    for sql in [
        "SET @v = (SELECT email FROM customers LIMIT 1)",
        "SET @a = 1, @v = (SELECT MAX(email) FROM customers)",
        "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = (SELECT email FROM customers LIMIT 1)",
        "INSERT INTO archive (contact) SELECT id FROM users ON DUPLICATE KEY UPDATE contact = (SELECT email FROM customers LIMIT 1)",
    ] {
        let o = eval_on(sql, Dialect::Mysql, email_block());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        let o = eval_on(
            sql,
            Dialect::Mysql,
            vec![masked("customers", "email", Email)],
        );
        assert_eq!(o.decision, Decision::Block, "{sql}");
        assert!(o.ast_node_path.unwrap().contains("copied"), "{sql}");
    }
    // Writing a column into itself is not a copy out.
    let o = eval_on(
        "INSERT INTO customers (id, email) VALUES (1, 'x') ON DUPLICATE KEY UPDATE email = VALUES(email)",
        Dialect::Mysql,
        email_block(),
    );
    assert_eq!(o.decision, Decision::Allow, "{o:?}");
    let o = eval_on("SET @v = 1", Dialect::Mysql, email_block());
    assert_eq!(o.decision, Decision::Allow);
}

#[test]
fn mysql_double_quoted_strings_may_be_columns() {
    // Under ANSI_QUOTES (server-wide or through a SET_VAR hint) MySQL reads
    // "email" as the column; the engine cannot see the SQL mode.
    let o = eval_on(
        "SELECT \"email\" FROM customers",
        Dialect::Mysql,
        email_block(),
    );
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    let o = eval_on(
        "SELECT 'email' FROM customers",
        Dialect::Mysql,
        email_block(),
    );
    assert_eq!(o.decision, Decision::Allow, "{o:?}");
}

#[test]
fn a_failed_mysql_render_blocks_and_never_returns_the_original() {
    super::sql::FORCE_RENDER_FAILURE.with(|f| f.set(true));
    let o = eval_on(
        "SELECT email FROM customers",
        Dialect::Mysql,
        vec![masked("customers", "email", Full)],
    );
    super::sql::FORCE_RENDER_FAILURE.with(|f| f.set(false));
    assert_eq!(o.decision, Decision::Block);
    assert!(o.rewritten_query.is_none());
    assert!(o.ast_node_path.unwrap().contains("forced by test"));
}

#[test]
fn mysql_mask_full_never_reveals_null_or_the_value() {
    // `full` over a bare column: a constant, nothing of the value is read.
    let o = eval_on(
        "SELECT created FROM customers",
        Dialect::Mysql,
        vec![masked("customers", "created", Full)],
    );
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some("SELECT '[redacted]' AS `created` FROM customers")
    );
}

#[test]
fn other_sqlparser_dialects_apply_block_and_flag() {
    for d in [Dialect::Oracle, Dialect::MsSql] {
        let o = eval_on("SELECT email FROM customers", d, email_block());
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        let o = eval_on(
            "SELECT id FROM customers WHERE email = 'x'",
            d,
            email_block(),
        );
        assert_eq!(o.decision, Decision::Allow, "{d:?}");
        let o = eval_on(
            "SELECT email FROM customers",
            d,
            vec![masked("customers", "email", Full)],
        );
        assert_eq!(
            o.decision,
            Decision::Block,
            "{d:?}: mask is not rewritten here"
        );
    }
}

// ── serde contract ─────────────────────────────────────────────────────────

#[test]
fn json_shape_round_trips() {
    let json = r#"{"schema":"public","table":"customers","column":"email","policy":"mask","mask_style":"email"}"#;
    let c: SensitiveColumn = serde_json::from_str(json).unwrap();
    assert_eq!(c.schema.as_deref(), Some("public"));
    assert_eq!(c.policy, Mask);
    assert_eq!(c.mask_style, Email);
    assert_eq!(serde_json::to_string(&c).unwrap(), json);

    // Absent schema and style; DB column-name aliases; case-insensitive values.
    let c: SensitiveColumn =
        serde_json::from_str(r#"{"table_name":"t","column_name":"c","policy":"BLOCK"}"#).unwrap();
    assert_eq!((c.schema, c.policy, c.mask_style), (None, Block, Full));
    let c: SensitiveColumn = serde_json::from_str(
        r#"{"schema_name":null,"table":"t","column":"c","policy":"flag","mask_style":"Last4"}"#,
    )
    .unwrap();
    assert_eq!((c.policy, c.mask_style), (Flag, Last4));

    let t = TouchedColumn {
        schema: None,
        table: "customers".into(),
        column: "email".into(),
        policy: Mask,
    };
    assert_eq!(
        serde_json::to_string(&t).unwrap(),
        r#"{"schema":null,"table":"customers","column":"email","policy":"mask"}"#
    );
}

#[test]
fn unknown_values_deserialize_fail_safe() {
    let c: SensitiveColumn = serde_json::from_str(
        r#"{"table":"t","column":"c","policy":"redact","mask_style":"rot13"}"#,
    )
    .unwrap();
    assert_eq!(
        c.policy, Block,
        "an unknown policy never disables protection"
    );
    assert_eq!(c.mask_style, Full, "an unknown style reveals nothing");
}

#[test]
fn policy_json_without_tags_is_unchanged() {
    let p = EnforcementPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    assert!(
        !json.contains("sensitive_columns"),
        "empty tags are not serialized"
    );
    let back: EnforcementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);

    let p = policy(email_block());
    let back: EnforcementPolicy =
        serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back, p);
}

#[test]
fn verdict_is_deterministic_regardless_of_tag_order() {
    let a = vec![
        tag("customers", "email", Flag),
        masked("customers", "card", Last4),
        tag("users", "name", Flag),
    ];
    let mut b = a.clone();
    b.reverse();
    let sql = "SELECT u.name, c.email, c.card FROM customers c JOIN users u ON u.id = c.uid";
    let (x, y) = (pg(sql, a), pg(sql, b));
    assert_eq!(x.decision, y.decision);
    assert_eq!(x.sensitive_columns, y.sensitive_columns);
    assert_eq!(x.rewritten_query, y.rewritten_query);
    assert_eq!(x.ast_node_path, y.ast_node_path);
}

// ── bind parameters ────────────────────────────────────────────────────────

/// The `$n` a statement references, from Postgres's own parse tree.
fn params(sql: &str) -> std::collections::BTreeSet<i64> {
    fn walk(v: &serde_json::Value, out: &mut std::collections::BTreeSet<i64>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(n) = m.get("ParamRef").and_then(|p| p.get("number")) {
                    out.insert(n.as_i64().unwrap_or_default());
                }
                m.values().for_each(|c| walk(c, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    let tree = pg_query::parse(sql).expect("parses").protobuf;
    let mut out = std::collections::BTreeSet::new();
    walk(&serde_json::to_value(&tree).unwrap(), &mut out);
    out
}

#[test]
fn a_rewrite_never_drops_a_bind_parameter() {
    // A masked projection that is replaced wholesale (`full`, or any computed
    // value) used to drop every `$n` inside it: the client still binds them,
    // and the extended protocol fails on a parameter-count mismatch.
    for (sql, style) in [
        ("SELECT substring(card, $1, 4) FROM customers", Last4),
        (
            "SELECT id, substring(card, $1, $2) AS p FROM customers WHERE id = $3",
            Last4,
        ),
        ("SELECT card || $1 FROM customers", Hash),
        (
            "SELECT CASE WHEN id = $1 THEN card END FROM customers",
            Email,
        ),
        ("SELECT (SELECT card FROM customers WHERE id = $1)", Full),
        ("SELECT string_agg(card, $1) FROM customers", Full),
        (
            "VALUES ((SELECT left(card, $1) FROM customers LIMIT 1))",
            Full,
        ),
        ("SELECT id, card FROM customers WHERE id = $1", Full),
    ] {
        let rw = rewrite(sql, vec![masked("customers", "card", style)]);
        assert_eq!(params(sql), params(&rw), "{sql}\n  → {rw}");
    }
}

#[test]
fn a_kept_parameter_is_in_a_no_op_that_reveals_nothing() {
    let rw = rewrite(
        "SELECT substring(card, $1, 4) AS p FROM customers",
        vec![masked("customers", "card", Last4)],
    );
    assert_eq!(
        rw,
        "SELECT concat('[redacted]'::text, \"left\"(\"substring\"(card, $1, 4)::text, 0)) AS p FROM customers"
    );
    // A bare column without parameters becomes the plain constant: nothing
    // of it is evaluated.
    let rw = rewrite(
        "SELECT card AS p FROM customers",
        vec![masked("customers", "card", Full)],
    );
    assert_eq!(rw, "SELECT '[redacted]'::text AS p FROM customers");
}
