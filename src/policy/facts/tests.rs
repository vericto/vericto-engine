// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Facts extraction: each fact on the main path, and the conservative
//! answers (UNKNOWN, over-approximation) where a fact cannot be known.

use super::*;
use crate::parser::Dialect::{self, MsSql, Mysql, Oracle, Postgres};

fn one(sql: &str, d: Dialect) -> StatementFacts {
    let mut f = statement_facts(sql, d, None).unwrap_or_else(|e| panic!("{sql}: {e}"));
    assert_eq!(f.len(), 1, "{sql}");
    f.remove(0)
}

fn assigned(f: &StatementFacts, col: &str) -> Result<Vec<String>, String> {
    f.assignments
        .iter()
        .find(|(c, _)| c == col)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn pins(f: &StatementFacts) -> Vec<String> {
    f.pins
        .iter()
        .map(|(c, k, v)| format!("{c} {k} {}", v.join(",")))
        .collect()
}

fn facts_of(sql: &str, d: Dialect) -> Facts {
    let parsed = crate::parser::parser_for(d).parse(sql).unwrap();
    let mut v = extract(
        &parsed,
        Some(sql),
        None,
        Want {
            refs: true,
            functions: true,
        },
    );
    v.remove(0)
}

#[test]
fn tables_and_columns_follow_the_087_walk() {
    let f = one(
        "SELECT i.id, c.name FROM invoices i JOIN customers c ON c.id = i.customer_id",
        Postgres,
    );
    assert_eq!(f.op, "select");
    assert_eq!(
        f.tables,
        Ok(vec!["public.customers".into(), "public.invoices".into()])
    );
    assert_eq!(f.tables_written, Ok(vec![]));
    assert!(
        f.columns_read
            .as_ref()
            .unwrap()
            .contains(&"public.invoices.customer_id".to_string())
    );
    // Default schemas: public, dbo, the host's, or none.
    assert_eq!(
        one("SELECT a FROM t", MsSql).tables,
        Ok(vec!["dbo.t".into()])
    );
    assert_eq!(one("SELECT a FROM t", Mysql).tables, Ok(vec!["t".into()]));
    let host = statement_facts("SELECT a FROM t", Mysql, Some("App")).unwrap();
    assert_eq!(host[0].tables, Ok(vec!["app.t".into()]));
    // Names fold as the dialect folds: Postgres keeps a quoted name.
    assert_eq!(
        one(r#"SELECT 1 FROM "Ledger""#, Postgres).tables,
        Ok(vec!["public.Ledger".into()])
    );
    assert_eq!(
        one("SELECT 1 FROM Ledger", Postgres).tables,
        Ok(vec!["public.ledger".into()])
    );
    assert_eq!(
        one("SELECT 1 FROM LEDGER", MsSql).tables,
        Ok(vec!["dbo.ledger".into()])
    );
    // A star reads every column.
    assert!(
        one("SELECT * FROM t", Postgres)
            .columns_read
            .unwrap()
            .contains(&"public.t.*".to_string())
    );
}

#[test]
fn writes_include_nested_and_lock_targets() {
    let f = one(
        "WITH x AS (DELETE FROM ledger RETURNING id) SELECT * FROM x",
        Postgres,
    );
    assert_eq!(f.op, "select");
    assert_eq!(f.tables_written, Ok(vec!["public.ledger".into()]));
    let f = one("SELECT * FROM accounts FOR UPDATE", Postgres);
    assert_eq!(f.tables_written, Ok(vec!["public.accounts".into()]));
    let f = one("INSERT INTO t (a) SELECT a FROM s", Mysql);
    assert_eq!(f.tables_written, Ok(vec!["t".into()]));
    assert_eq!(f.tables, Ok(vec!["s".into(), "t".into()]));
}

#[test]
fn values_assigned_on_every_dialect() {
    for d in [Postgres, Mysql, MsSql, Oracle] {
        let p = if d == Postgres { "$2" } else { "?" };
        let f = one(
            &format!("INSERT INTO app.refunds (order_id, amount) VALUES (1, 950), (2, {p})"),
            d,
        );
        assert_eq!(f.insert_rows, Some(2), "{d:?}");
        assert_eq!(
            assigned(&f, "app.refunds.amount").unwrap()[0],
            "950",
            "{d:?}"
        );
        assert!(matches!(
            assigned(&f, "app.refunds.amount").unwrap()[1].as_str(),
            "$2" | "?"
        ));
        let f = one(
            "UPDATE app.orders SET status = 'cancelled', discount_pct = -5 WHERE id = 1",
            d,
        );
        assert_eq!(
            assigned(&f, "app.orders.status"),
            Ok(vec!["'cancelled'".into()]),
            "{d:?}"
        );
        assert_eq!(
            assigned(&f, "app.orders.discount_pct"),
            Ok(vec!["-5".into()]),
            "{d:?}"
        );
    }
    // Decimals and expressions.
    let f = one(
        "UPDATE t SET amount = 200.50, note = upper('x'), n = n + 1",
        Postgres,
    );
    assert_eq!(assigned(&f, "public.t.amount"), Ok(vec!["200.5".into()]));
    assert_eq!(assigned(&f, "public.t.note"), Ok(vec!["<expr>".into()]));
    assert_eq!(assigned(&f, "public.t.n"), Ok(vec!["<expr>".into()]));
}

#[test]
fn values_that_cannot_be_seen_are_unknown() {
    let f = facts_of("INSERT INTO refunds VALUES (1, 950)", Postgres);
    assert!(f.values("public.refunds.amount").is_err(), "no column list");
    let f = facts_of(
        "INSERT INTO refunds (id, amount) SELECT id, amount FROM staged",
        Postgres,
    );
    assert!(
        f.values("public.refunds.amount").is_err(),
        "INSERT … SELECT"
    );
    let f = facts_of(
        "WITH x AS (UPDATE refunds SET amount = 999 RETURNING id) SELECT * FROM x",
        Postgres,
    );
    assert!(f.values("public.refunds.amount").is_err(), "a nested write");
    let f = facts_of(
        "MERGE INTO refunds r USING s ON r.id = s.id WHEN MATCHED THEN UPDATE SET amount = 1",
        Postgres,
    );
    assert!(f.values("public.refunds.amount").is_err(), "MERGE");
    let f = facts_of(
        "UPDATE refunds SET (amount, note) = (SELECT a, b FROM s)",
        Postgres,
    );
    assert!(
        f.values("public.refunds.amount").is_err(),
        "a tuple assignment"
    );
    let f = facts_of("INSERT INTO refunds DEFAULT VALUES", Postgres);
    assert!(f.values("public.refunds.amount").is_err(), "DEFAULT VALUES");
    let f = facts_of("COPY refunds FROM STDIN", Postgres);
    assert!(f.values("public.refunds.amount").is_err(), "COPY FROM");
    // A table the statement does not write: nothing assigned.
    let f = facts_of("UPDATE orders SET status = 'x' WHERE id = 1", Postgres);
    assert_eq!(f.values("public.refunds.amount"), Ok(vec![]));
    // `table.column` and an unknown default schema match on the table.
    let f = facts_of("INSERT INTO refunds (amount) VALUES (5)", Mysql);
    assert_eq!(f.values("shop.refunds.amount"), Ok(vec![FactVal::Int(5)]));
    let f = facts_of("INSERT INTO refunds (amount) VALUES (5)", Postgres);
    assert_eq!(f.values("refunds.amount"), Ok(vec![FactVal::Int(5)]));
}

#[test]
fn upserts() {
    let f = one(
        "INSERT INTO t (id, amount) VALUES (1, 10) ON CONFLICT (id) DO UPDATE SET amount = EXCLUDED.amount",
        Postgres,
    );
    assert_eq!(assigned(&f, "public.t.amount"), Ok(vec!["10".into()]));
    let f = one(
        "INSERT INTO t (id, amount) VALUES (1, 10) ON CONFLICT (id) DO UPDATE SET amount = 99999",
        Postgres,
    );
    assert_eq!(
        assigned(&f, "public.t.amount"),
        Ok(vec!["10".into(), "99999".into()])
    );
    let f = one(
        "INSERT INTO t (id, amount) VALUES (1, 10) ON DUPLICATE KEY UPDATE amount = VALUES(amount)",
        Mysql,
    );
    assert_eq!(assigned(&f, "t.amount"), Ok(vec!["10".into()]));
    let f = one(
        "INSERT INTO t (id, amount) VALUES (1, 10) ON DUPLICATE KEY UPDATE amount = 5000",
        Mysql,
    );
    assert_eq!(
        assigned(&f, "t.amount"),
        Ok(vec!["10".into(), "5000".into()])
    );
    let f = one("INSERT INTO t SET id = 1, amount = 7", Mysql);
    assert_eq!(assigned(&f, "t.amount"), Ok(vec!["7".into()]));
}

#[test]
fn pins_of_the_top_level_conjunction() {
    for d in [Postgres, Mysql, MsSql, Oracle] {
        let p = if d == Postgres { "$1" } else { "?" };
        let f = one(
            &format!(
                "SELECT * FROM app.invoices i WHERE i.tenant_id = 7 AND 5 = i.id AND i.status IN ('a', 'b') \
                 AND i.created_at >= '2026-01-01' AND i.amount < {p}"
            ),
            d,
        );
        assert_eq!(
            pins(&f),
            [
                "app.invoices.tenant_id = 7",
                "app.invoices.id = 5",
                "app.invoices.status = 'a','b'",
                "app.invoices.created_at >= '2026-01-01'",
                &format!("app.invoices.amount <= {p}"),
            ],
            "{d:?}"
        );
    }
}

#[test]
fn things_that_are_not_pins() {
    let none = |sql: &str| {
        let f = one(sql, Postgres);
        assert!(f.pins.is_empty(), "{sql}: {:?}", f.pins);
    };
    none("SELECT * FROM t WHERE tenant_id = 1 OR 1 = 1");
    none("SELECT * FROM t WHERE NOT (tenant_id = 1)");
    none("SELECT * FROM t WHERE tenant_id NOT IN (1, 2)");
    none("SELECT * FROM t WHERE tenant_id <> 1");
    none("SELECT * FROM a JOIN b ON true WHERE a.tenant_id = b.tenant_id");
    none("SELECT * FROM t WHERE tenant_id = (SELECT 1)");
    none("SELECT * FROM t WHERE tenant_id = lower(name)");
    none("SELECT * FROM t WHERE (tenant_id = 1 AND x = 2) OR y = 3");
    none("SELECT * FROM t WHERE tenant_id IS NULL");
    none("SELECT * FROM (SELECT * FROM t) s WHERE s.tenant_id = 1");
    // A function of literals only is a pin whose value is not known.
    let f = one(
        "SELECT * FROM t WHERE tenant_id = current_setting('app.tenant')",
        Postgres,
    );
    assert_eq!(pins(&f), ["public.t.tenant_id = <expr>"]);
    // A cast keeps the parameter.
    let f = one("SELECT * FROM t WHERE tenant_id = $1::uuid", Postgres);
    assert_eq!(pins(&f), ["public.t.tenant_id = $1"]);
    // BETWEEN gives both bounds; `= ANY(…)` is a pin with unknown values.
    let f = one(
        "SELECT * FROM t WHERE d BETWEEN '2026-01-01' AND '2026-02-01' AND k = ANY($1)",
        Postgres,
    );
    assert_eq!(
        pins(&f),
        [
            "public.t.d >= '2026-01-01'",
            "public.t.d <= '2026-02-01'",
            "public.t.k = <expr>"
        ]
    );
}

#[test]
fn ambiguous_unqualified_columns_are_unknown() {
    let f = facts_of(
        "SELECT * FROM invoices i JOIN customers c ON c.id = i.cid WHERE tenant_id = 7",
        Postgres,
    );
    assert!(f.has_filter("public.invoices.tenant_id").is_err());
    assert!(f.filter_values("public.customers.tenant_id").is_err());
    // A derived table in scope makes an unqualified column ambiguous too.
    let f = facts_of(
        "SELECT * FROM invoices, (SELECT 1 AS x) s WHERE tenant_id = 7",
        Postgres,
    );
    assert!(f.has_filter("public.invoices.tenant_id").is_err());
    // Qualified, by alias or by table name, it resolves.
    let f = facts_of(
        "SELECT * FROM invoices i JOIN customers c ON true WHERE i.tenant_id = 7",
        Postgres,
    );
    assert_eq!(f.has_filter("public.invoices.tenant_id"), Ok(true));
    assert_eq!(f.has_filter("public.customers.tenant_id"), Ok(false));
    let f = facts_of(
        "SELECT * FROM invoices JOIN customers ON true WHERE invoices.tenant_id = 7",
        Postgres,
    );
    assert_eq!(f.has_filter("public.invoices.tenant_id"), Ok(true));
    // An alias hides the table name.
    let f = facts_of(
        "SELECT * FROM invoices i JOIN customers c ON true WHERE invoices.tenant_id = 7",
        Postgres,
    );
    assert_eq!(f.has_filter("public.invoices.tenant_id"), Ok(false));
    // UPDATE / DELETE targets are in scope.
    let f = facts_of("UPDATE invoices SET x = 1 WHERE tenant_id = 7", Postgres);
    assert_eq!(
        f.filter_values("public.invoices.tenant_id"),
        Ok(vec![FactVal::Int(7)])
    );
    let f = facts_of(
        "DELETE FROM invoices USING customers c WHERE c.id = 1 AND tenant_id = 7",
        Postgres,
    );
    assert!(f.has_filter("public.invoices.tenant_id").is_err());
}

#[test]
fn bounds() {
    let f = facts_of(
        "SELECT * FROM e WHERE created_at > '2026-01-01' AND created_at >= $1",
        Postgres,
    );
    assert_eq!(f.bounds("public.e.created_at", true).unwrap().len(), 2);
    assert_eq!(f.bounds("public.e.created_at", false), Ok(vec![]));
    let f = facts_of("SELECT * FROM e WHERE created_at = '2026-01-01'", Postgres);
    assert_eq!(f.bounds("public.e.created_at", false).unwrap().len(), 1);
    // `v < col` bounds from below.
    let f = facts_of("SELECT * FROM e WHERE 10 < n", Mysql);
    assert_eq!(f.bounds("e.n", true), Ok(vec![FactVal::Int(10)]));
}

#[test]
fn limits() {
    let lim = |sql: &str, d: Dialect| one(sql, d).limit;
    assert_eq!(lim("SELECT a FROM t LIMIT 10", Postgres), Some(Ok(10)));
    assert!(matches!(
        lim("SELECT a FROM t LIMIT $1", Postgres),
        Some(Err(_))
    ));
    assert_eq!(lim("SELECT a FROM t LIMIT ALL", Postgres), None);
    assert_eq!(
        lim("SELECT a FROM t FETCH FIRST 5 ROWS ONLY", Postgres),
        Some(Ok(5))
    );
    assert_eq!(
        lim("SELECT a FROM t UNION SELECT a FROM s LIMIT 3", Postgres),
        Some(Ok(3))
    );
    assert_eq!(lim("SELECT a FROM t", Postgres), None);
    assert_eq!(lim("SELECT a FROM t LIMIT 5, 20", Mysql), Some(Ok(20)));
    assert!(matches!(
        lim("SELECT a FROM t LIMIT ?", Mysql),
        Some(Err(_))
    ));
    assert_eq!(lim("SELECT TOP 7 a FROM t", MsSql), Some(Ok(7)));
    assert_eq!(
        lim(
            "SELECT a FROM t ORDER BY a OFFSET 0 ROWS FETCH NEXT 9 ROWS ONLY",
            MsSql
        ),
        Some(Ok(9))
    );
    assert_eq!(
        lim("SELECT a FROM t FETCH FIRST 4 ROWS ONLY", Oracle),
        Some(Ok(4))
    );
    // A subquery's LIMIT is not the statement's.
    assert_eq!(
        lim("SELECT * FROM (SELECT a FROM t LIMIT 1) s", Postgres),
        None
    );
}

#[test]
fn ops_and_ddl_targets() {
    let f = one("DROP TABLE public.ledger, archive.old", Postgres);
    assert_eq!(f.op, "ddl");
    assert_eq!(
        f.tables_written,
        Ok(vec!["archive.old".into(), "public.ledger".into()])
    );
    for (sql, d) in [
        ("TRUNCATE ledger", Postgres),
        ("ALTER TABLE ledger ADD COLUMN x int", Postgres),
        ("CREATE INDEX i ON ledger (x)", Postgres),
        ("CREATE TABLE ledger (x int)", Postgres),
        ("TRUNCATE TABLE ledger", Mysql),
        ("ALTER TABLE ledger ADD x int", MsSql),
        ("DROP TABLE ledger", Oracle),
    ] {
        let f = one(sql, d);
        assert_eq!(f.op, "ddl", "{sql}");
        assert!(
            f.tables
                .as_ref()
                .unwrap()
                .iter()
                .any(|t| t.ends_with("ledger")),
            "{sql}: {:?}",
            f.tables
        );
    }
    // CREATE TABLE AS reads its query.
    let f = one("CREATE TABLE copy AS SELECT * FROM ledger", Postgres);
    assert_eq!(
        f.tables,
        Ok(vec!["public.copy".into(), "public.ledger".into()])
    );
    // DDL whose tables are not extracted: unknown, never empty.
    for (sql, d) in [
        ("DROP SCHEMA app CASCADE", Postgres),
        ("CREATE SCHEMA app", Postgres),
        ("DO $$ BEGIN DELETE FROM ledger; END $$", Postgres),
        ("DROP DATABASE shop", Mysql),
        ("PREPARE p AS DELETE FROM ledger", Postgres),
    ] {
        let f = one(sql, d);
        assert!(f.tables.is_err(), "{sql}: {:?}", f.tables);
    }
    assert_eq!(one("DO $$ BEGIN END $$", Postgres).op, "other");
    // EXPLAIN is its statement (EXPLAIN ANALYZE executes it).
    let f = one("EXPLAIN ANALYZE DELETE FROM ledger", Postgres);
    assert_eq!(
        (f.op.as_str(), f.tables_written),
        ("delete", Ok(vec!["public.ledger".into()]))
    );
    assert_eq!(one("SET search_path TO app", Postgres).op, "set");
    assert_eq!(one("SET NAMES utf8mb4", Mysql).op, "set");
    assert_eq!(one("BEGIN", Postgres).op, "other");
    assert_eq!(one("COMMIT", Mysql).op, "other");
    assert_eq!(one("CALL refund(1)", Postgres).op, "call");
    assert_eq!(one("GRANT SELECT ON ledger TO bob", Postgres).op, "ddl");
    assert_eq!(one("SELECT * INTO copy FROM ledger", Postgres).op, "ddl");
}

#[test]
fn functions_on_both_front_ends() {
    for d in [Postgres, Mysql, MsSql] {
        let f = one(
            "SELECT lower(name), count(*) FROM t WHERE coalesce(x, 1) = 1",
            d,
        );
        let fns = f.functions.unwrap();
        for want in ["lower", "count", "coalesce"] {
            assert!(fns.contains(&want.to_string()), "{d:?}: {fns:?}");
        }
    }
    let f = one("SELECT pg_catalog.pg_sleep(1)", Postgres);
    assert_eq!(
        f.functions,
        Ok(vec!["pg_catalog.pg_sleep".into(), "pg_sleep".into()])
    );
    let f = one(
        "SELECT * FROM generate_series(1, 3) AS g(n) JOIN lateral f(n) ON true",
        Postgres,
    );
    let fns = f.functions.unwrap();
    assert!(fns.contains(&"generate_series".to_string()) && fns.contains(&"f".to_string()));
    assert!(!fns.contains(&"g".to_string()));
    // Not calls: column lists, VALUES, ON CONFLICT, type modifiers.
    let f = one(
        "INSERT INTO t (a) VALUES (CAST('1' AS varchar(10))) ON CONFLICT (a) DO NOTHING",
        Postgres,
    );
    assert_eq!(f.functions, Ok(vec![]));
    // A function inside a string is not a call.
    assert_eq!(one("SELECT 'pg_sleep(1)'", Postgres).functions, Ok(vec![]));
}

#[test]
fn long_fact_lists_are_truncated_and_unknown() {
    let cols: Vec<String> = (0..1100).map(|i| format!("c{i}")).collect();
    let sql = format!("SELECT {} FROM t", cols.join(", "));
    let f = one(&sql, Postgres);
    assert!(f.truncated);
    assert!(f.columns_read.is_err());
    assert!(f.tables.is_ok());
}

#[test]
fn each_top_level_statement_has_its_facts() {
    let f = statement_facts(
        "SELECT 1 FROM a; DELETE FROM b WHERE id = 1",
        Postgres,
        None,
    )
    .unwrap();
    assert_eq!(f.len(), 2);
    assert_eq!((f[0].op.as_str(), f[1].op.as_str()), ("select", "delete"));
    assert_eq!(f[1].tables, Ok(vec!["public.b".into()]));
}
