//! Conformance suite for the VERICTO-087 allowlist matcher, table-driven
//! against the access contract v3.2 (engine 3.8.1).
//!
//! Each row is `(dialect, policy, SQL, expected decision, expected
//! access_denied refs)`. Refs are written `schema.table.column:needed`
//! (schema and column omitted when absent) and checked either `exact` (the
//! whole `access_denied` list) or `has` (these refs are among them, used where
//! the contract does not pin the granularity of the list). An `Allow` row
//! always requires `access_denied` to be empty.
//!
//! Rows the contract does not decide are `#[ignore = "NEEDS DECISION: …"]`;
//! rows where the engine disagrees with the contract are
//! `#[ignore = "DEFECT: …"]`. Run them with `cargo test --test
//! access_conformance -- --ignored`.
//!
//! The fixture world (no rules in the `rules` slice, so every decision comes
//! from VERICTO-085 and VERICTO-087):
//! - `orders(id, status, total, secret, note)` in the default schema;
//! - `s2.orders`, a table with the same name in another schema;
//! - `other`, a table no policy grants.
//!
//! Tags (every policy): `orders.total` = mask, `orders.secret` = block.
//! The base policy grants read on `orders(id, status, total)` only.

use vericto_engine::{
    AccessColumns, AccessEntry, AccessLevel, AccessMode, AccessPolicy, DdlPolicy, Decision,
    Dialect, EnforcementPolicy, EvaluationOutcome, MaskStyle, SensitiveColumn, SensitivePolicy,
    evaluate,
};

use Dialect::{MsSql, Mysql, Postgres};

// ── policies ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Pol {
    /// read `orders(id, status, total)`, enforce.
    Fixture,
    /// `entries: []`.
    Empty,
    /// read `orders`, `columns: "*"`.
    Star,
    /// read_write `orders(id, status, total)`.
    Rw,
    /// read_write `orders`, `columns: "*"`.
    StarRw,
    /// `Fixture` in observe mode.
    Observe,
    /// `Fixture` with a host-set `default_schema`.
    Ds(&'static str),
}

fn orders_entry(columns: AccessColumns, access: AccessLevel) -> AccessEntry {
    AccessEntry {
        schema: None,
        table: "orders".into(),
        columns,
        access,
    }
}

fn granted() -> AccessColumns {
    AccessColumns::List(vec!["id".into(), "status".into(), "total".into()])
}

fn access_policy(p: Pol) -> AccessPolicy {
    let (mode, entries, default_schema) = match p {
        Pol::Fixture => (
            AccessMode::Enforce,
            vec![orders_entry(granted(), AccessLevel::Read)],
            None,
        ),
        Pol::Empty => (AccessMode::Enforce, vec![], None),
        Pol::Star => (
            AccessMode::Enforce,
            vec![orders_entry(AccessColumns::AllColumns, AccessLevel::Read)],
            None,
        ),
        Pol::Rw => (
            AccessMode::Enforce,
            vec![orders_entry(granted(), AccessLevel::ReadWrite)],
            None,
        ),
        Pol::StarRw => (
            AccessMode::Enforce,
            vec![orders_entry(
                AccessColumns::AllColumns,
                AccessLevel::ReadWrite,
            )],
            None,
        ),
        Pol::Observe => (
            AccessMode::Observe,
            vec![orders_entry(granted(), AccessLevel::Read)],
            None,
        ),
        Pol::Ds(s) => (
            AccessMode::Enforce,
            vec![orders_entry(granted(), AccessLevel::Read)],
            Some(s.to_string()),
        ),
    };
    AccessPolicy {
        mode,
        entries,
        ddl: DdlPolicy::Deny,
        default_schema,
    }
}

fn tag(column: &str, policy: SensitivePolicy) -> SensitiveColumn {
    SensitiveColumn {
        schema: None,
        table: "orders".into(),
        column: column.into(),
        policy,
        mask_style: MaskStyle::Full,
    }
}

fn policy(p: Pol) -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: vec![
            tag("total", SensitivePolicy::Mask),
            tag("secret", SensitivePolicy::Block),
        ],
        access_policy: Some(access_policy(p)),
        ..EnforcementPolicy::default()
    }
}

// ── expectations ────────────────────────────────────────────────────────────

enum Refs {
    Exact(&'static [&'static str]),
    Has(&'static [&'static str]),
}

const PARSE_ERROR: &str = "VERICTO-PARSE-ERROR";

enum Want {
    /// Decision and refs; `Some(code)` also pins the reported rule code. With
    /// `None`, a non-Allow row must not come from a parse error (a parse error
    /// under `enforce` blocks with no refs, which would hide what is tested).
    Decided(Decision, Refs, Option<&'static str>),
    /// The contract is silent; the row only prints what the engine does.
    Undecided,
}

fn exact(r: &'static [&'static str]) -> Refs {
    Refs::Exact(r)
}
fn has(r: &'static [&'static str]) -> Refs {
    Refs::Has(r)
}
fn allow() -> Want {
    Want::Decided(Decision::Allow, Refs::Exact(&[]), None)
}
fn flag(r: Refs) -> Want {
    Want::Decided(Decision::Flag, r, None)
}
fn block(r: Refs) -> Want {
    Want::Decided(Decision::Block, r, None)
}
/// Blocked because the statement does not parse (enforce, contract §5).
fn parse_error() -> Want {
    Want::Decided(Decision::Block, Refs::Exact(&[]), Some(PARSE_ERROR))
}
/// Allowed by the allowlist, blocked by a VERICTO-085 tag (contract §4).
fn tag_block() -> Want {
    Want::Decided(Decision::Block, Refs::Exact(&[]), Some("VERICTO-085"))
}
fn undecided() -> Want {
    Want::Undecided
}

fn refs(o: &EvaluationOutcome) -> Vec<String> {
    o.access_denied
        .iter()
        .map(|d| {
            let mut s = String::new();
            if let Some(sc) = &d.schema {
                s.push_str(sc);
                s.push('.');
            }
            s.push_str(&d.table);
            if let Some(c) = &d.column {
                s.push('.');
                s.push_str(c);
            }
            s.push(':');
            s.push_str(d.needed.as_str());
            s
        })
        .collect()
}

#[track_caller]
fn check(dialect: Dialect, p: Pol, sql: &str, want: Want) {
    let o = evaluate(sql, dialect, &[], &policy(p));
    let got = refs(&o);
    let actual = format!(
        "decision={:?} rule={:?} access_denied={got:?} path={:?}",
        o.decision, o.rule_code, o.ast_node_path
    );
    match want {
        Want::Undecided => panic!("{dialect:?} {p:?} `{sql}`: undecided; engine says {actual}"),
        Want::Decided(decision, r, rule) => {
            assert_eq!(
                o.decision, decision,
                "{dialect:?} {p:?} `{sql}`: decision; engine says {actual}"
            );
            match rule {
                Some(code) => assert_eq!(
                    o.rule_code.as_deref(),
                    Some(code),
                    "{dialect:?} {p:?} `{sql}`: rule; engine says {actual}"
                ),
                None => assert_ne!(
                    o.rule_code.as_deref(),
                    Some(PARSE_ERROR),
                    "{dialect:?} {p:?} `{sql}`: must parse; engine says {actual}"
                ),
            }
            match r {
                Refs::Exact(w) => assert_eq!(
                    got, w,
                    "{dialect:?} {p:?} `{sql}`: access_denied; engine says {actual}"
                ),
                Refs::Has(w) => assert!(
                    w.iter().all(|x| got.iter().any(|g| g == x)),
                    "{dialect:?} {p:?} `{sql}`: expected {w:?} among access_denied; engine says {actual}"
                ),
            }
        }
    }
}

macro_rules! rows {
    ($( $(#[$m:meta])* $name:ident : $d:ident, $p:expr, $sql:expr => $want:expr ; )*) => {
        $(
            $(#[$m])*
            #[test]
            fn $name() {
                check($d, $p, $sql, $want);
            }
        )*
    };
}

use Pol::*;

// ── naming ──────────────────────────────────────────────────────────────────

rows! {
    pg_unquoted: Postgres, Fixture, "SELECT id, status FROM orders" => allow();
    pg_unquoted_upper_folds: Postgres, Fixture, "SELECT ID, Status FROM ORDERS" => allow();
    pg_quoted_lower_matches: Postgres, Fixture, r#"SELECT "id", "status" FROM "orders""# => allow();
    pg_quoted_mixed_table_is_another_table: Postgres, Fixture, r#"SELECT id FROM "Orders""# => block(has(&["Orders:read"]));
    pg_quoted_upper_column_is_another_column: Postgres, Fixture, r#"SELECT "ID" FROM orders"# => block(exact(&["orders.ID:read"]));
    pg_public_qualified: Postgres, Fixture, "SELECT id FROM public.orders" => allow();
    pg_other_schema: Postgres, Fixture, "SELECT id FROM s2.orders" => block(has(&["s2.orders:read"]));
    pg_default_schema_matches_it: Postgres, Ds("s2"), "SELECT id FROM s2.orders" => allow();
    pg_default_schema_unqualified: Postgres, Ds("s2"), "SELECT id FROM orders" => allow();
    pg_default_schema_moves_off_public: Postgres, Ds("s2"), "SELECT id FROM public.orders" => block(has(&["public.orders:read"]));
    pg_default_schema_never_a_catalogue: Postgres, Ds("pg_catalog"), "SELECT id FROM pg_catalog.orders" => block(has(&["pg_catalog.orders:read"]));

    my_unquoted: Mysql, Fixture, "SELECT id, status FROM orders" => allow();
    my_column_case_insensitive: Mysql, Fixture, "SELECT ID, STATUS FROM orders" => allow();
    my_table_case_exact: Mysql, Fixture, "SELECT id FROM ORDERS" => block(has(&["ORDERS:read"]));
    my_backticks: Mysql, Fixture, "SELECT `id`, `status` FROM `orders`" => allow();
    my_backticks_qualified_column: Mysql, Fixture, "SELECT `orders`.`id` FROM `orders`" => allow();
    my_other_schema: Mysql, Fixture, "SELECT id FROM s2.orders" => block(has(&["s2.orders:read"]));
    my_db_qualified_without_default_schema: Mysql, Fixture, "SELECT id FROM `shop`.`orders`" => block(has(&["shop.orders:read"]));
    my_db_qualified_with_default_schema: Mysql, Ds("shop"), "SELECT id FROM `shop`.`orders`" => allow();
    my_default_schema_compares_exactly: Mysql, Ds("shop"), "SELECT id FROM `SHOP`.`orders`" => block(has(&["SHOP.orders:read"]));
    my_default_schema_unqualified: Mysql, Ds("shop"), "SELECT id FROM orders" => allow();

    ms_unquoted: MsSql, Fixture, "SELECT id, status FROM orders" => allow();
    ms_case_insensitive: MsSql, Fixture, "SELECT ID, STATUS FROM ORDERS" => allow();
    ms_dbo_qualified: MsSql, Fixture, "SELECT id FROM dbo.orders" => allow();
    ms_brackets: MsSql, Fixture, "SELECT [id] FROM [dbo].[orders]" => allow();
    ms_other_schema: MsSql, Fixture, "SELECT id FROM s2.orders" => block(has(&["s2.orders:read"]));
    ms_default_schema: MsSql, Ds("s2"), "SELECT id FROM s2.orders" => allow();
}

// ── shadowing ───────────────────────────────────────────────────────────────

rows! {
    pg_cte_named_like_allowed_reads_disallowed_column: Postgres, Fixture,
        "WITH orders AS (SELECT id, note FROM orders) SELECT id FROM orders" => block(has(&["orders.note:read"]));
    pg_cte_named_like_allowed_over_other: Postgres, Fixture,
        "WITH orders AS (SELECT id FROM other) SELECT id FROM orders" => block(has(&["other:read"]));
    pg_alias_named_like_allowed_over_other: Postgres, Fixture,
        "SELECT orders.id FROM other AS orders" => block(has(&["other:read"]));
    pg_alias_over_other_schema: Postgres, Fixture,
        "SELECT orders.id FROM s2.orders AS orders" => block(has(&["s2.orders:read"]));

    my_cte_named_like_allowed_reads_disallowed_column: Mysql, Fixture,
        "WITH orders AS (SELECT id, note FROM orders) SELECT id FROM orders" => block(has(&["orders.note:read"]));
    my_cte_named_like_allowed_over_other: Mysql, Fixture,
        "WITH orders AS (SELECT id FROM other) SELECT id FROM orders" => block(has(&["other:read"]));
    my_alias_named_like_allowed_over_other: Mysql, Fixture,
        "SELECT orders.id FROM other AS orders" => block(has(&["other:read"]));

    ms_cte_named_like_allowed_over_other: MsSql, Fixture,
        "WITH orders AS (SELECT id FROM other) SELECT id FROM orders" => block(has(&["other:read"]));
    ms_alias_named_like_allowed_over_other: MsSql, Fixture,
        "SELECT orders.id FROM other AS orders" => block(has(&["other:read"]));
}

// ── joins and subqueries ────────────────────────────────────────────────────

rows! {
    pg_self_join: Postgres, Fixture,
        "SELECT a.id, b.status FROM orders a JOIN orders b ON a.id = b.id" => allow();
    pg_join_other: Postgres, Fixture,
        "SELECT o.id FROM orders o JOIN other x ON x.id = o.id" => block(has(&["other:read"]));
    pg_join_on_disallowed_column: Postgres, Fixture,
        "SELECT a.id FROM orders a JOIN orders b ON a.note = b.note" => block(exact(&["orders.note:read"]));
    pg_exists_allowed: Postgres, Fixture,
        "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM orders i WHERE i.status = o.status)" => allow();
    pg_exists_other: Postgres, Fixture,
        "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM other x WHERE x.id = o.id)" => block(has(&["other:read"]));
    pg_in_other_schema: Postgres, Fixture,
        "SELECT o.id FROM orders o WHERE o.id IN (SELECT t.id FROM s2.orders t)" => block(has(&["s2.orders:read"]));
    pg_in_disallowed_column: Postgres, Fixture,
        "SELECT id FROM orders WHERE status IN (SELECT note FROM orders)" => block(exact(&["orders.note:read"]));
    pg_scalar_subquery: Postgres, Fixture,
        "SELECT o.id, (SELECT i.note FROM orders i WHERE i.id = o.id) FROM orders o" => block(exact(&["orders.note:read"]));
    pg_scalar_subquery_other: Postgres, Fixture,
        "SELECT id, (SELECT count(*) FROM other) FROM orders" => block(has(&["other:read"]));
    pg_lateral: Postgres, Fixture,
        "SELECT o.id, l.note FROM orders o, LATERAL (SELECT i.note FROM orders i WHERE i.id = o.id) l" => block(has(&["orders.note:read"]));
    pg_union_disallowed_arm: Postgres, Fixture,
        "SELECT id FROM orders UNION SELECT id FROM other" => block(has(&["other:read"]));
    pg_intersect_disallowed_arm: Postgres, Fixture,
        "SELECT id FROM orders INTERSECT SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    pg_except_disallowed_arm: Postgres, Fixture,
        "SELECT id FROM orders EXCEPT SELECT id FROM s2.orders" => block(has(&["s2.orders:read"]));
    pg_union_allowed: Postgres, Fixture,
        "SELECT id FROM orders UNION ALL SELECT status FROM orders" => allow();

    my_self_join: Mysql, Fixture,
        "SELECT a.id, b.status FROM orders a JOIN orders b ON a.id = b.id" => allow();
    my_join_other: Mysql, Fixture,
        "SELECT o.id FROM orders o JOIN other x ON x.id = o.id" => block(has(&["other:read"]));
    my_exists_other: Mysql, Fixture,
        "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM other x WHERE x.id = o.id)" => block(has(&["other:read"]));
    my_in_disallowed_column: Mysql, Fixture,
        "SELECT id FROM orders WHERE status IN (SELECT note FROM orders)" => block(exact(&["orders.note:read"]));
    my_scalar_subquery: Mysql, Fixture,
        "SELECT o.id, (SELECT i.note FROM orders i WHERE i.id = o.id) FROM orders o" => block(exact(&["orders.note:read"]));
    my_lateral: Mysql, Fixture,
        "SELECT o.id, l.note FROM orders o, LATERAL (SELECT i.note FROM orders i WHERE i.id = o.id) AS l" => block(has(&["orders.note:read"]));
    my_union_disallowed_arm: Mysql, Fixture,
        "SELECT id FROM orders UNION SELECT id FROM other" => block(has(&["other:read"]));
    my_intersect_disallowed_arm: Mysql, Fixture,
        "SELECT id FROM orders INTERSECT SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    my_except_disallowed_arm: Mysql, Fixture,
        "SELECT id FROM orders EXCEPT SELECT id FROM s2.orders" => block(has(&["s2.orders:read"]));

    ms_self_join: MsSql, Fixture,
        "SELECT a.id, b.status FROM orders a JOIN orders b ON a.id = b.id" => allow();
    ms_join_other: MsSql, Fixture,
        "SELECT o.id FROM orders o JOIN other x ON x.id = o.id" => block(has(&["other:read"]));
    ms_exists_other: MsSql, Fixture,
        "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM other x WHERE x.id = o.id)" => block(has(&["other:read"]));
    ms_cross_apply: MsSql, Fixture,
        "SELECT o.id, l.note FROM orders o CROSS APPLY (SELECT i.note FROM orders i WHERE i.id = o.id) l" => block(has(&["orders.note:read"]));
    ms_union_disallowed_arm: MsSql, Fixture,
        "SELECT id FROM orders UNION SELECT id FROM other" => block(has(&["other:read"]));
    ms_except_disallowed_arm: MsSql, Fixture,
        "SELECT id FROM orders EXCEPT SELECT note FROM orders" => block(exact(&["orders.note:read"]));
}

// ── expressions ─────────────────────────────────────────────────────────────

rows! {
    pg_count_star: Postgres, Fixture, "SELECT count(*) FROM orders" => allow();
    pg_aggregate_disallowed: Postgres, Fixture, "SELECT max(note) FROM orders" => block(exact(&["orders.note:read"]));
    pg_aggregate_filter_disallowed: Postgres, Fixture,
        "SELECT count(*) FILTER (WHERE note = 'x') FROM orders" => block(exact(&["orders.note:read"]));
    pg_where_on_masked_column: Postgres, Fixture, "SELECT id FROM orders WHERE total > 100" => allow();
    pg_coalesce: Postgres, Fixture, "SELECT COALESCE(status, note) FROM orders" => block(exact(&["orders.note:read"]));
    pg_case_allowed: Postgres, Fixture, "SELECT CASE WHEN status = 'x' THEN id END FROM orders" => allow();
    pg_case_disallowed: Postgres, Fixture,
        "SELECT CASE WHEN note IS NULL THEN 1 ELSE 0 END FROM orders" => block(exact(&["orders.note:read"]));
    pg_order_by: Postgres, Fixture, "SELECT id FROM orders ORDER BY note" => block(exact(&["orders.note:read"]));
    pg_order_by_output_alias: Postgres, Fixture, "SELECT status AS note FROM orders ORDER BY note" => allow();
    pg_group_by_allowed: Postgres, Fixture, "SELECT status, count(*) FROM orders GROUP BY status" => allow();
    pg_group_by: Postgres, Fixture, "SELECT count(*) FROM orders GROUP BY note" => block(exact(&["orders.note:read"]));
    pg_having: Postgres, Fixture,
        "SELECT status FROM orders GROUP BY status HAVING max(note) > 'a'" => block(exact(&["orders.note:read"]));
    pg_window_partition_allowed: Postgres, Fixture,
        "SELECT id, row_number() OVER (PARTITION BY status ORDER BY id) FROM orders" => allow();
    pg_window_partition_disallowed: Postgres, Fixture,
        "SELECT id, row_number() OVER (PARTITION BY note ORDER BY id) FROM orders" => block(exact(&["orders.note:read"]));
    pg_star: Postgres, Fixture, "SELECT * FROM orders" => block(has(&["orders.*:read"]));
    pg_qualified_star: Postgres, Fixture, "SELECT o.* FROM orders o" => block(has(&["orders.*:read"]));
    pg_row_to_json: Postgres, Fixture, "SELECT row_to_json(t) FROM orders t" => block(has(&["orders.*:read"]));
    pg_to_jsonb: Postgres, Fixture, "SELECT to_jsonb(t) FROM orders t" => block(has(&["orders.*:read"]));
    pg_json_agg: Postgres, Fixture, "SELECT json_agg(t) FROM orders t" => block(has(&["orders.*:read"]));
    pg_whole_row_bare: Postgres, Fixture, "SELECT t FROM orders t" => block(has(&["orders.*:read"]));
    pg_masked_allowed: Postgres, Fixture, "SELECT id, total FROM orders" => flag(exact(&[]));
    pg_block_tag_disallowed: Postgres, Fixture, "SELECT secret FROM orders" => block(exact(&["orders.secret:read"]));

    my_count_star: Mysql, Fixture, "SELECT COUNT(*) FROM orders" => allow();
    my_aggregate_disallowed: Mysql, Fixture, "SELECT MAX(note) FROM orders" => block(exact(&["orders.note:read"]));
    my_coalesce: Mysql, Fixture, "SELECT COALESCE(status, note) FROM orders" => block(exact(&["orders.note:read"]));
    my_case_disallowed: Mysql, Fixture,
        "SELECT CASE WHEN note IS NULL THEN 1 ELSE 0 END FROM orders" => block(exact(&["orders.note:read"]));
    my_order_by: Mysql, Fixture, "SELECT id FROM orders ORDER BY note" => block(exact(&["orders.note:read"]));
    my_group_by: Mysql, Fixture, "SELECT COUNT(*) FROM orders GROUP BY note" => block(exact(&["orders.note:read"]));
    my_having: Mysql, Fixture,
        "SELECT status FROM orders GROUP BY status HAVING MAX(note) > 'a'" => block(exact(&["orders.note:read"]));
    my_window_partition_disallowed: Mysql, Fixture,
        "SELECT id, ROW_NUMBER() OVER (PARTITION BY note ORDER BY id) FROM orders" => block(exact(&["orders.note:read"]));
    my_json_object_allowed: Mysql, Fixture,
        "SELECT JSON_OBJECT('id', id, 's', status) FROM orders" => allow();
    my_json_object_disallowed: Mysql, Fixture,
        "SELECT JSON_OBJECT('id', id, 'n', note) FROM orders" => block(exact(&["orders.note:read"]));
    my_star: Mysql, Fixture, "SELECT * FROM orders" => block(has(&["orders.*:read"]));
    my_masked_allowed: Mysql, Fixture, "SELECT id, total FROM orders" => flag(exact(&[]));
    my_block_tag_disallowed: Mysql, Fixture, "SELECT secret FROM orders" => block(exact(&["orders.secret:read"]));

    ms_count_star: MsSql, Fixture, "SELECT COUNT(*) FROM orders" => allow();
    ms_coalesce: MsSql, Fixture, "SELECT COALESCE(status, note) FROM orders" => block(exact(&["orders.note:read"]));
    ms_case_disallowed: MsSql, Fixture,
        "SELECT CASE WHEN note IS NULL THEN 1 ELSE 0 END FROM orders" => block(exact(&["orders.note:read"]));
    ms_order_by: MsSql, Fixture, "SELECT id FROM orders ORDER BY note" => block(exact(&["orders.note:read"]));
    ms_window_partition_disallowed: MsSql, Fixture,
        "SELECT id, ROW_NUMBER() OVER (PARTITION BY note ORDER BY id) FROM orders" => block(exact(&["orders.note:read"]));
    ms_star: MsSql, Fixture, "SELECT * FROM orders" => block(has(&["orders.*:read"]));
}

// ── writes ──────────────────────────────────────────────────────────────────

rows! {
    pg_insert_read_only_table: Postgres, Fixture,
        "INSERT INTO orders (id, status) VALUES (1, 'x')" => block(has(&["orders:write"]));
    pg_insert_values: Postgres, Rw, "INSERT INTO orders (id, status) VALUES (1, 'x')" => allow();
    pg_insert_ungranted_column: Postgres, Rw,
        "INSERT INTO orders (id, note) VALUES (1, 'x')" => block(has(&["orders.note:write"]));
    pg_insert_no_column_list: Postgres, Rw,
        "INSERT INTO orders VALUES (1, 'x', 2)" => block(has(&["orders.*:write"]));
    pg_insert_select_other: Postgres, Rw,
        "INSERT INTO orders (id, status) SELECT id, status FROM other" => block(has(&["other:read"]));
    pg_insert_select_allowed: Postgres, Rw,
        "INSERT INTO orders (id, status) SELECT id, status FROM orders" => allow();
    pg_update_read_only_table: Postgres, Fixture,
        "UPDATE orders SET status = 'x' WHERE id = 1" => block(has(&["orders:write"]));
    pg_update: Postgres, Rw, "UPDATE orders SET status = 'x' WHERE id = 1" => allow();
    pg_update_reads_disallowed: Postgres, Rw,
        "UPDATE orders SET status = note WHERE id = 1" => block(exact(&["orders.note:read"]));
    pg_update_where_disallowed: Postgres, Rw,
        "UPDATE orders SET status = 'x' WHERE note = 'y'" => block(exact(&["orders.note:read"]));
    pg_update_returning_allowed: Postgres, Rw,
        "UPDATE orders SET status = 'x' WHERE id = 1 RETURNING id" => allow();
    pg_update_returning_disallowed: Postgres, Rw,
        "UPDATE orders SET status = 'x' WHERE id = 1 RETURNING note" => block(exact(&["orders.note:read"]));
    #[ignore = "NEEDS DECISION: §3.1 gives DELETE the table-level path `orders (write)` but §5 says DELETE needs `\"*\"`; the engine reports `orders.*:write` with the `list the columns explicitly` hint. Which ref (and message) is the contract?"]
    pg_delete_needs_all_columns: Postgres, Rw,
        "DELETE FROM orders WHERE id = 1" => block(has(&["orders:write"]));
    pg_delete_star_rw: Postgres, StarRw, "DELETE FROM orders WHERE id = 1" => allow();
    pg_truncate: Postgres, StarRw, "TRUNCATE orders" => block(exact(&["TRUNCATE:ddl"]));
    pg_merge_using_other: Postgres, Rw,
        "MERGE INTO orders o USING other x ON o.id = x.id WHEN MATCHED THEN UPDATE SET status = 'x'" => block(has(&["other:read"]));
    pg_merge_allowed: Postgres, Rw,
        "MERGE INTO orders o USING orders i ON o.id = i.id WHEN MATCHED THEN UPDATE SET status = i.status" => allow();
    pg_merge_ungranted_column: Postgres, Rw,
        "MERGE INTO orders o USING orders i ON o.id = i.id WHEN MATCHED THEN UPDATE SET note = 'x'" => block(has(&["orders.note:write"]));
    pg_copy_to: Postgres, Fixture, "COPY orders TO STDOUT" => block(has(&["orders.*:read"]));
    pg_copy_columns_to: Postgres, Fixture, "COPY orders (id, status) TO STDOUT" => allow();
    pg_copy_query_to: Postgres, Fixture, "COPY (SELECT note FROM orders) TO STDOUT" => block(exact(&["orders.note:read"]));
    pg_copy_from_read_only: Postgres, Fixture, "COPY orders (id, status) FROM STDIN" => block(has(&["orders:write"]));
    pg_copy_from: Postgres, Rw, "COPY orders (id, status) FROM STDIN" => allow();
    pg_copy_from_no_columns: Postgres, Rw, "COPY orders FROM STDIN" => block(has(&["orders.*:write"]));
    #[ignore = "NEEDS DECISION: does SELECT ... FOR UPDATE (a row lock) need read_write like LOCK TABLE, or only read?"]
    pg_select_for_update: Postgres, Fixture, "SELECT id FROM orders WHERE id = 1 FOR UPDATE" => undecided();

    my_insert_read_only_table: Mysql, Fixture,
        "INSERT INTO orders (id, status) VALUES (1, 'x')" => block(has(&["orders:write"]));
    my_insert_values: Mysql, Rw, "INSERT INTO orders (id, status) VALUES (1, 'x')" => allow();
    my_insert_no_column_list: Mysql, Rw, "INSERT INTO orders VALUES (1, 'x', 2)" => block(has(&["orders.*:write"]));
    my_insert_select_other: Mysql, Rw,
        "INSERT INTO orders (id, status) SELECT id, status FROM other" => block(has(&["other:read"]));
    my_on_duplicate_key_ungranted: Mysql, Rw,
        "INSERT INTO orders (id, status) VALUES (1, 'x') ON DUPLICATE KEY UPDATE note = 'y'" => block(has(&["orders.note:write"]));
    my_update: Mysql, Rw, "UPDATE orders SET status = 'x' WHERE id = 1" => allow();
    my_update_reads_disallowed: Mysql, Rw,
        "UPDATE orders SET status = note WHERE id = 1" => block(exact(&["orders.note:read"]));
    #[ignore = "NEEDS DECISION: §3.1 gives DELETE the table-level path `orders (write)` but §5 says DELETE needs `\"*\"`; the engine reports `orders.*:write` with the `list the columns explicitly` hint. Which ref (and message) is the contract?"]
    my_delete_needs_all_columns: Mysql, Rw, "DELETE FROM orders WHERE id = 1" => block(has(&["orders:write"]));
    my_delete_star_rw: Mysql, StarRw, "DELETE FROM orders WHERE id = 1" => allow();
    my_truncate: Mysql, StarRw, "TRUNCATE TABLE orders" => block(exact(&["TRUNCATE:ddl"]));
    my_replace_needs_all_columns: Mysql, Rw,
        "REPLACE INTO orders (id, status) VALUES (1, 'x')" => block(has(&["orders.*:write"]));
    #[ignore = "NEEDS DECISION: does SELECT ... FOR UPDATE (a row lock) need read_write like LOCK TABLES, or only read?"]
    my_select_for_update: Mysql, Fixture, "SELECT id FROM orders WHERE id = 1 FOR UPDATE" => undecided();

    ms_insert_values: MsSql, Rw, "INSERT INTO orders (id, status) VALUES (1, 'x')" => allow();
    ms_insert_read_only_table: MsSql, Fixture,
        "INSERT INTO orders (id, status) VALUES (1, 'x')" => block(has(&["orders:write"]));
    ms_update_reads_disallowed: MsSql, Rw,
        "UPDATE orders SET status = note WHERE id = 1" => block(exact(&["orders.note:read"]));
    #[ignore = "NEEDS DECISION: §3.1 gives DELETE the table-level path `orders (write)` but §5 says DELETE needs `\"*\"`; the engine reports `orders.*:write` with the `list the columns explicitly` hint. Which ref (and message) is the contract?"]
    ms_delete_needs_all_columns: MsSql, Rw, "DELETE FROM orders WHERE id = 1" => block(has(&["orders:write"]));
    ms_truncate: MsSql, StarRw, "TRUNCATE TABLE orders" => block(exact(&["TRUNCATE:ddl"]));
    ms_merge_using_other: MsSql, Rw,
        "MERGE INTO orders AS o USING other AS x ON o.id = x.id WHEN MATCHED THEN UPDATE SET status = 'x';" => block(has(&["other:read"]));
}

// ── wrappers ────────────────────────────────────────────────────────────────

rows! {
    pg_prepare: Postgres, Fixture, "PREPARE p AS SELECT id FROM orders" => block(exact(&["PREPARE:ddl"]));
    pg_execute: Postgres, Fixture, "EXECUTE p" => block(exact(&["EXECUTE:ddl"]));
    pg_deallocate: Postgres, Fixture, "DEALLOCATE p" => block(exact(&["DEALLOCATE:ddl"]));
    pg_explain_execute: Postgres, Fixture, "EXPLAIN EXECUTE p" => block(exact(&["EXECUTE:ddl"]));
    pg_declare_cursor: Postgres, Fixture, "DECLARE c CURSOR FOR SELECT id FROM orders" => allow();
    pg_declare_cursor_disallowed: Postgres, Fixture,
        "DECLARE c CURSOR FOR SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    pg_fetch: Postgres, Fixture, "FETCH 10 FROM c" => allow();
    pg_close: Postgres, Fixture, "CLOSE c" => allow();
    pg_explain_allowed: Postgres, Fixture, "EXPLAIN SELECT id FROM orders" => allow();
    pg_explain_disallowed: Postgres, Fixture, "EXPLAIN SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    pg_explain_analyze_write: Postgres, Fixture,
        "EXPLAIN ANALYZE DELETE FROM orders WHERE id = 1" => block(has(&["orders:write"]));
    pg_do_block: Postgres, Fixture, "DO $$ BEGIN PERFORM 1; END $$" => block(exact(&["DO:ddl"]));
    pg_call: Postgres, Fixture, "CALL p(1)" => allow();
    pg_call_reads_disallowed: Postgres, Fixture,
        "CALL p((SELECT note FROM orders))" => block(exact(&["orders.note:read"]));
    pg_multi_allowed: Postgres, Fixture, "SELECT id FROM orders; SELECT status FROM orders" => allow();
    pg_multi_disallowed: Postgres, Fixture,
        "SELECT id FROM orders; SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    pg_multi_ddl: Postgres, Fixture, "SELECT id FROM orders; DROP TABLE orders" => block(exact(&["DROP:ddl"]));
    pg_begin: Postgres, Fixture, "BEGIN" => allow();
    pg_commit: Postgres, Fixture, "COMMIT" => allow();
    pg_rollback: Postgres, Fixture, "ROLLBACK" => allow();
    pg_savepoint: Postgres, Fixture, "SAVEPOINT a" => allow();
    pg_transaction_wrapped: Postgres, Fixture,
        "BEGIN; SELECT note FROM orders; COMMIT" => block(exact(&["orders.note:read"]));

    // MySQL `PREPARE s FROM '…'` does not parse (contract §5): parse error, blocks under enforce.
    my_prepare: Mysql, Fixture, "PREPARE s FROM 'SELECT id FROM orders'" => parse_error();
    my_execute: Mysql, Fixture, "EXECUTE s" => block(exact(&["EXECUTE:ddl"]));
    my_deallocate: Mysql, Fixture, "DEALLOCATE PREPARE s" => block(exact(&["DEALLOCATE:ddl"]));
    my_explain_disallowed: Mysql, Fixture, "EXPLAIN SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    my_explain_write: Mysql, Fixture, "EXPLAIN DELETE FROM orders WHERE id = 1" => block(has(&["orders:write"]));
    my_call: Mysql, Fixture, "CALL p(1)" => allow();
    my_multi_disallowed: Mysql, Fixture,
        "SELECT id FROM orders; SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    my_multi_ddl: Mysql, Fixture, "SELECT id FROM orders; DROP TABLE orders" => block(exact(&["DROP:ddl"]));
    my_start_transaction: Mysql, Fixture, "START TRANSACTION" => allow();
    my_commit: Mysql, Fixture, "COMMIT" => allow();

    ms_exec: MsSql, Fixture, "EXEC p" => block(exact(&["EXECUTE:ddl"]));
    ms_execute: MsSql, Fixture, "EXECUTE p 1" => block(exact(&["EXECUTE:ddl"]));
    ms_multi_disallowed: MsSql, Fixture,
        "SELECT id FROM orders; SELECT note FROM orders" => block(exact(&["orders.note:read"]));
    ms_begin_transaction: MsSql, Fixture, "BEGIN TRANSACTION" => allow();
    ms_commit: MsSql, Fixture, "COMMIT" => allow();
}

// ── system: catalogue, SHOW/DESCRIBE, built-in functions ────────────────────

rows! {
    pg_catalog_unqualified: Postgres, Fixture, "SELECT relname FROM pg_class" => block(has(&["pg_catalog.pg_class:read"]));
    pg_catalog_qualified: Postgres, Fixture, "SELECT relname FROM pg_catalog.pg_class" => block(has(&["pg_catalog.pg_class:read"]));
    pg_information_schema: Postgres, Fixture,
        "SELECT table_name FROM information_schema.tables" => block(has(&["information_schema.tables:read"]));
    pg_show_setting: Postgres, Fixture, "SHOW search_path" => allow();
    pg_fn_version: Postgres, Fixture, "SELECT version()" => allow();
    pg_fn_current_setting: Postgres, Fixture, "SELECT current_setting('work_mem')" => allow();
    pg_fn_set_config_other_setting: Postgres, Fixture, "SELECT set_config('work_mem', '64MB', false)" => allow();
    pg_fn_set_config_search_path: Postgres, Fixture, "SELECT set_config('search_path', 's2', false)" => block(has(&[]));
    pg_fn_set_config_role: Postgres, Fixture, "SELECT set_config('role', 'admin', false)" => block(has(&[]));
    pg_fn_set_config_computed: Postgres, Fixture, "SELECT set_config(current_user, 'x', false)" => block(has(&[]));
    // Contract §7: functions are not restricted by VERICTO-087.
    pg_fn_server_file: Postgres, Fixture, "SELECT pg_read_file('f')" => allow();
    pg_fn_server_dir: Postgres, Fixture, "SELECT pg_ls_dir('d')" => allow();

    my_information_schema: Mysql, Fixture,
        "SELECT table_name FROM information_schema.tables" => block(has(&[]));
    my_mysql_schema: Mysql, Fixture, "SELECT user FROM mysql.user" => block(has(&["mysql.user:read"]));
    my_show_tables: Mysql, Fixture, "SHOW TABLES" => block(exact(&["information_schema.TABLES:read"]));
    my_show_columns: Mysql, Fixture, "SHOW COLUMNS FROM orders" => block(exact(&["information_schema.COLUMNS:read"]));
    my_show_databases: Mysql, Fixture, "SHOW DATABASES" => block(exact(&["information_schema.SCHEMATA:read"]));
    my_describe: Mysql, Fixture, "DESCRIBE orders" => block(has(&["orders.*:read"]));
    my_show_variables: Mysql, Fixture, "SHOW VARIABLES" => allow();
    my_show_status: Mysql, Fixture, "SHOW STATUS" => allow();
    my_show_grants: Mysql, Fixture, "SHOW GRANTS" => block(exact(&["SHOW GRANTS:ddl"]));
    my_show_processlist: Mysql, Fixture, "SHOW PROCESSLIST" => block(has(&[]));
    my_fn_version: Mysql, Fixture, "SELECT VERSION()" => allow();
    my_var_version: Mysql, Fixture, "SELECT @@version" => allow();
    my_fn_load_file: Mysql, Fixture, "SELECT LOAD_FILE('f')" => allow();

    ms_sys_tables: MsSql, Fixture, "SELECT name FROM sys.tables" => block(has(&["sys.tables:read"]));
    ms_information_schema: MsSql, Fixture,
        "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES" => block(has(&[]));
    ms_var_version: MsSql, Fixture, "SELECT @@VERSION" => allow();
}

// ── session statements (contract v3.1) ──────────────────────────────────────

rows! {
    pg_set_statement_timeout: Postgres, Fixture, "SET statement_timeout = 5000" => allow();
    pg_set_work_mem: Postgres, Fixture, "SET work_mem = '64MB'" => allow();
    pg_set_application_name: Postgres, Fixture, "SET application_name = 'x'" => allow();
    pg_set_time_zone: Postgres, Fixture, "SET TIME ZONE 'UTC'" => allow();
    pg_set_idle_session_timeout: Postgres, Fixture, "SET idle_session_timeout = 0" => allow();
    pg_set_bytea_output: Postgres, Fixture, "SET bytea_output = 'hex'" => allow();
    pg_set_scs_on: Postgres, Fixture, "SET standard_conforming_strings = on" => allow();
    pg_set_transaction_isolation: Postgres, Fixture,
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED" => allow();
    pg_reset_all: Postgres, Fixture, "RESET ALL" => allow();
    pg_set_scs_off: Postgres, Fixture,
        "SET standard_conforming_strings = off" => block(exact(&["SET standard_conforming_strings:ddl"]));
    pg_set_search_path: Postgres, Fixture, "SET search_path = s2" => block(exact(&["SET search_path:ddl"]));
    pg_set_role: Postgres, Fixture, "SET ROLE admin" => block(exact(&["SET ROLE:ddl"]));
    pg_set_session_authorization: Postgres, Fixture, "SET SESSION AUTHORIZATION admin" => block(has(&[]));
    pg_set_unlisted: Postgres, Fixture, "SET enable_seqscan = off" => block(exact(&["SET enable_seqscan:ddl"]));

    my_set_names: Mysql, Fixture, "SET NAMES utf8mb4" => allow();
    my_set_autocommit: Mysql, Fixture, "SET autocommit = 1" => allow();
    my_set_character_set_results_null: Mysql, Fixture, "SET character_set_results = NULL" => allow();
    my_set_collation_connection_null: Mysql, Fixture, "SET collation_connection = NULL" => allow();
    my_set_sql_auto_is_null: Mysql, Fixture, "SET sql_auto_is_null = 0" => allow();
    my_set_wait_timeout: Mysql, Fixture, "SET wait_timeout = 28800" => allow();
    my_set_max_execution_time: Mysql, Fixture, "SET max_execution_time = 1000" => allow();
    my_set_session_track: Mysql, Fixture, "SET session_track_schema = 1" => allow();
    my_set_transaction_isolation_var: Mysql, Fixture, "SET transaction_isolation = 'READ-COMMITTED'" => allow();
    // Does not parse in sqlparser; on the session-boilerplate list (§8), so the
    // allowlist alone would not force a block, but the fixture's block/mask tags
    // do ("block/mask tags still do").
    my_set_session_transaction_parse_error_tags_block: Mysql, Fixture,
        "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED" => parse_error();
    my_set_user_variable: Mysql, Fixture, "SET @v = 1" => allow();
    my_set_sql_mode_literal: Mysql, Fixture, "SET sql_mode = 'STRICT_ALL_TABLES'" => allow();
    my_set_rails_setup: Mysql, Fixture,
        "SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483" => allow();
    my_set_sql_mode_ansi_quotes: Mysql, Fixture, "SET sql_mode = 'ANSI_QUOTES'" => block(exact(&["SET sql_mode:ddl"]));
    my_set_global_var: Mysql, Fixture, "SET @@GLOBAL.wait_timeout = 1" => block(exact(&["SET GLOBAL:ddl"]));
    my_set_computed: Mysql, Fixture, "SET wait_timeout = (SELECT 1)" => block(exact(&["SET (computed value):ddl"]));
    my_set_unlisted: Mysql, Fixture, "SET foreign_key_checks = 0" => block(exact(&["SET foreign_key_checks:ddl"]));
    my_use: Mysql, Fixture, "USE s2" => block(exact(&["USE:ddl"]));

    ms_use: MsSql, Fixture, "USE s2" => block(exact(&["USE:ddl"]));
}

// ── policy shape ────────────────────────────────────────────────────────────

rows! {
    pg_empty_denies_table: Postgres, Empty, "SELECT id FROM orders" => block(has(&["orders:read"]));
    pg_empty_count_star: Postgres, Empty, "SELECT count(*) FROM orders" => block(exact(&["orders:read"]));
    pg_empty_no_table: Postgres, Empty, "SELECT 1" => allow();
    pg_empty_begin: Postgres, Empty, "BEGIN" => allow();
    my_empty_denies_table: Mysql, Empty, "SELECT id FROM orders" => block(has(&["orders:read"]));
    ms_empty_denies_table: MsSql, Empty, "SELECT id FROM orders" => block(has(&["orders:read"]));

    pg_star_any_column: Postgres, Star, "SELECT id, note FROM orders" => allow();
    pg_star_whole_row_still_blocked_by_tags: Postgres, Star, "SELECT to_jsonb(t) FROM orders t" => tag_block();
    pg_star_select_star_blocked_by_tags: Postgres, Star, "SELECT * FROM orders" => tag_block();
    pg_star_block_tag_allowed: Postgres, Star, "SELECT secret FROM orders" => tag_block();
    pg_star_other_schema: Postgres, Star, "SELECT id FROM s2.orders" => block(has(&["s2.orders:read"]));
    pg_star_read_only_write: Postgres, Star, "UPDATE orders SET note = 'x' WHERE id = 1" => block(has(&["orders:write"]));
    my_star_any_column: Mysql, Star, "SELECT id, note FROM orders" => allow();
    ms_star_any_column: MsSql, Star, "SELECT id, note FROM orders" => allow();

    pg_star_rw_insert_no_column_list: Postgres, StarRw, "INSERT INTO orders VALUES (1, 'a', 2, 's', 'n')" => allow();
    pg_star_rw_update: Postgres, StarRw, "UPDATE orders SET note = 'x' WHERE id = 1" => allow();
    my_star_rw_insert_no_column_list: Mysql, StarRw, "INSERT INTO orders VALUES (1, 'a', 2, 's', 'n')" => allow();
    pg_star_rw_ddl: Postgres, StarRw, "DROP TABLE orders" => block(exact(&["DROP:ddl"]));

    pg_observe_disallowed_column_flags: Postgres, Observe, "SELECT note FROM orders" => flag(exact(&["orders.note:read"]));
    pg_observe_other_table_flags: Postgres, Observe, "SELECT id FROM other" => flag(has(&["other:read"]));
    pg_observe_ddl_flags: Postgres, Observe, "DROP TABLE orders" => flag(exact(&["DROP:ddl"]));
    pg_observe_block_tag_still_blocks: Postgres, Observe, "SELECT secret FROM orders" => block(exact(&["orders.secret:read"]));
    pg_observe_masked_allowed: Postgres, Observe, "SELECT total FROM orders" => flag(exact(&[]));
    pg_observe_allowed: Postgres, Observe, "SELECT id FROM orders" => allow();
    my_observe_disallowed_column_flags: Mysql, Observe, "SELECT note FROM orders" => flag(exact(&["orders.note:read"]));
    ms_observe_disallowed_column_flags: MsSql, Observe, "SELECT note FROM orders" => flag(exact(&["orders.note:read"]));
}
