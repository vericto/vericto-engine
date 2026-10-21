// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Parity of the policy facts across parser front ends (design §17): on SQL
//! the four dialects share, the libpg_query front end (Postgres) and the
//! sqlparser front end (MySQL, SQL Server, Oracle) extract the same facts,
//! so a policy decides alike wherever it runs.

use vericto_engine::Dialect;
use vericto_engine::policy::{StatementFacts, statement_facts};

/// Statements in the shared subset. `?` is the parameter: `$n` on Postgres.
const CORPUS: &[&str] = &[
    "SELECT id, name FROM customers WHERE tenant_id = 7",
    "SELECT c.id, i.total FROM customers c JOIN invoices i ON i.customer_id = c.id WHERE c.tenant_id = 7 AND i.tenant_id = 7",
    "SELECT * FROM invoices WHERE tenant_id IN (1, 2, 3) AND status = 'open'",
    "SELECT * FROM invoices WHERE 5 = id",
    "SELECT * FROM invoices WHERE tenant_id = ? AND id = ?",
    "SELECT * FROM events WHERE created_at >= '2026-01-01' AND created_at < '2026-02-01'",
    "SELECT * FROM events WHERE created_at BETWEEN '2026-01-01' AND '2026-02-01'",
    "SELECT * FROM events WHERE tenant_id = 1 OR 1 = 1",
    "SELECT * FROM a JOIN b ON a.id = b.id WHERE tenant_id = 1",
    "SELECT * FROM a WHERE a.tenant_id = (SELECT max(tenant_id) FROM b)",
    "SELECT count(*) FROM orders WHERE lower(status) = 'open'",
    "INSERT INTO refunds (order_id, amount) VALUES (1, 950)",
    "INSERT INTO refunds (order_id, amount) VALUES (1, 150), (2, ?)",
    "INSERT INTO refunds (order_id, amount) VALUES (1, -5)",
    "INSERT INTO refunds VALUES (1, 950)",
    "INSERT INTO refunds (order_id, amount) SELECT id, total FROM orders WHERE id = 1",
    "UPDATE orders SET status = 'cancelled' WHERE id = 1 AND status = 'pending'",
    "UPDATE orders SET discount = 25.5, note = 'x' WHERE tenant_id = 3",
    "UPDATE orders SET total = total * 2 WHERE id = 1",
    "DELETE FROM ledger WHERE id = 1",
    "DELETE FROM ledger",
    "DELETE FROM ledger WHERE 1 = 1",
    "DROP TABLE ledger",
    "TRUNCATE TABLE ledger",
    "ALTER TABLE ledger ADD note varchar(20)",
];

fn sql_for(d: Dialect, s: &str) -> String {
    if d != Dialect::Postgres {
        return s.to_string();
    }
    let mut out = String::new();
    let mut n = 0;
    for ch in s.chars() {
        if ch == '?' {
            n += 1;
            out.push_str(&format!("${n}"));
        } else {
            out.push(ch);
        }
    }
    out
}

/// The facts with parameters written alike (`$n` / `?` → `?`) and the
/// functions left out where a dialect's list differs by design.
fn normalized(f: &StatementFacts) -> String {
    let p = |v: &str| {
        if v.starts_with('$') {
            "?".to_string()
        } else {
            v.to_string()
        }
    };
    let assignments: Vec<String> = f
        .assignments
        .iter()
        .map(|(c, v)| match v {
            Ok(vals) => format!(
                "{c}={}",
                vals.iter().map(|x| p(x)).collect::<Vec<_>>().join(",")
            ),
            Err(_) => format!("{c}=UNKNOWN"),
        })
        .collect();
    let pins: Vec<String> = f
        .pins
        .iter()
        .map(|(c, k, v)| {
            format!(
                "{c}{k}{}",
                v.iter().map(|x| p(x)).collect::<Vec<_>>().join(",")
            )
        })
        .collect();
    let list = |l: &Result<Vec<String>, String>| match l {
        Ok(v) => v.join(","),
        Err(_) => "UNKNOWN".into(),
    };
    format!(
        "op={} tables={} written={} read={} cols_written={} where={} always_true={} rows={:?} assign=[{}] pins=[{}] ambiguous={:?}",
        f.op,
        list(&f.tables),
        list(&f.tables_written),
        list(&f.columns_read),
        list(&f.columns_written),
        f.has_where,
        f.where_always_true,
        f.insert_rows,
        assignments.join(" "),
        pins.join(" "),
        f.ambiguous,
    )
}

#[test]
fn facts_agree_across_front_ends() {
    let dialects = [
        Dialect::Postgres,
        Dialect::Mysql,
        Dialect::MsSql,
        Dialect::Oracle,
    ];
    let mut mismatches = Vec::new();
    for s in CORPUS {
        let base = {
            let f = statement_facts(
                &sql_for(Dialect::Postgres, s),
                Dialect::Postgres,
                Some("app"),
            )
            .unwrap_or_else(|e| panic!("postgres: {s}: {e}"));
            assert_eq!(f.len(), 1, "{s}");
            normalized(&f[0])
        };
        for d in &dialects[1..] {
            match statement_facts(&sql_for(*d, s), *d, Some("app")) {
                Ok(f) => {
                    let got = normalized(&f[0]);
                    if got != base {
                        mismatches.push(format!("{d:?}: {s}\n  postgres: {base}\n  {d:?}: {got}"));
                    }
                }
                Err(e) => mismatches.push(format!("{d:?}: {s}: {e}")),
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn function_facts_agree_where_both_read_calls() {
    let corpus = [
        "SELECT lower(name), upper(code) FROM t",
        "SELECT count(*) FROM t WHERE coalesce(a, 0) = 1",
        "SELECT * FROM t WHERE x = abs(-1)",
    ];
    for s in corpus {
        let pg = statement_facts(s, Dialect::Postgres, None).unwrap()[0]
            .functions
            .clone()
            .unwrap();
        for d in [Dialect::Mysql, Dialect::MsSql, Dialect::Oracle] {
            let other = statement_facts(s, d, None).unwrap()[0]
                .functions
                .clone()
                .unwrap();
            assert_eq!(pg, other, "{d:?}: {s}");
        }
    }
}
