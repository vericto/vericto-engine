// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Equivalence of the `rewrite_limit` rewrite (design "Business policy
//! rules" §8.1, test 2) against real databases: for every case and every cap
//! `n`, the rewritten query returns the first `min(n, rows)` rows of the
//! original under the same `ORDER BY` (the same rows, in the same order, for
//! a total order; the same sort keys and a sub-multiset of the rows when the
//! order has ties; a sub-multiset of `min(n, rows)` rows without one), and a
//! statement the rewrite leaves unchanged already returns at most `n` rows.
//! Postgres parameters keep their inferred types (`pg_prepared_statements`).
//!
//! The rewrite half always runs. The database halves need servers:
//!
//! ```sh
//! VERICTO_EQUIV_PSQL='docker exec -i some-postgres psql -U postgres' \
//! NODE_PATH=/path/to/node_modules \
//! VERICTO_EQUIV_MYSQL='[{"host":"127.0.0.1","port":3306,"user":"root","password":"…"}]' \
//!   cargo test --test limit_equivalence -- --nocapture
//! ```
//!
//! (the MySQL half runs through `tests/support/mysql_runner.cjs`, which needs
//! the `mysql2` driver). Each run creates its own databases and drops them.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use vericto_engine::policy::{
    EvalContext, PolicyOutcome, PolicySet, Principal, PrincipalType, Trust,
};
use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity,
    evaluate_with_context,
};

/// The caps every case runs with (the fixture has 2,000 orders).
const CAPS: &[u64] = &[1, 7, 250, 1999, 2000, 5000];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Order {
    /// The ORDER BY is a total order: rows compare position by position.
    Total,
    /// The ORDER BY has ties on this output column.
    Keyed(usize),
    /// No ORDER BY: an arbitrary subset.
    None,
}

/// What the rewrite must do at a cap of 7.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Bounded,
    Unchanged,
    /// Out of scope (VERICTO-102 skips it: its row count is in the text,
    /// or it is an aggregate): left as written at every cap.
    Skipped,
    Unknown,
    Failed,
}

struct Case {
    sql: &'static str,
    /// Postgres `EXECUTE p(…)` arguments, or MySQL binary-protocol values.
    params: Option<&'static str>,
    order: Order,
    kind: Kind,
}

const fn c(sql: &'static str, order: Order, kind: Kind) -> Case {
    Case {
        sql,
        params: None,
        order,
        kind,
    }
}

const fn p(sql: &'static str, params: &'static str, order: Order, kind: Kind) -> Case {
    Case {
        sql,
        params: Some(params),
        order,
        kind,
    }
}

use Kind::{Bounded, Failed, Skipped, Unchanged, Unknown};
use Order::{Keyed, Total};

const PG_CASES: &[Case] = &[
    c("SELECT id, total FROM orders ORDER BY id", Total, Bounded),
    c(
        "SELECT id, total, status FROM orders WHERE total > 500 ORDER BY total DESC, id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 3000",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 3",
        Total,
        Unchanged,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT ALL",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 2 * 1000",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id OFFSET 10",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 1500 OFFSET 10",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id FETCH FIRST 3000 ROWS ONLY",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id OFFSET 5 ROWS FETCH NEXT 1800 ROWS ONLY",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id FETCH FIRST 3000 ROWS WITH TIES",
        Total,
        Failed,
    ),
    c(
        "SELECT id FROM orders WHERE total < 300 UNION SELECT id FROM orders WHERE total > 700 ORDER BY 1",
        Total,
        Bounded,
    ),
    c(
        "(SELECT id FROM orders ORDER BY id LIMIT 900) UNION ALL (SELECT id FROM orders ORDER BY id DESC LIMIT 900) ORDER BY 1",
        Total,
        Bounded,
    ),
    c(
        "SELECT customer_id FROM orders INTERSECT SELECT id FROM customers ORDER BY 1",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders EXCEPT SELECT id FROM orders WHERE status = 'paid' ORDER BY 1",
        Total,
        Bounded,
    ),
    c(
        "WITH big AS (SELECT * FROM orders WHERE total > 100) SELECT id, total FROM big ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 3000) SELECT n FROM s ORDER BY n",
        Total,
        Bounded,
    ),
    c(
        "SELECT o.id, c.region FROM orders o JOIN customers c ON c.id = o.customer_id \
         WHERE o.customer_id IN (SELECT id FROM customers WHERE region = 'eu') ORDER BY o.id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM (SELECT id FROM orders ORDER BY id LIMIT 2500) s ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id, (SELECT max(total) FROM orders o2 WHERE o2.customer_id = o.customer_id) AS m \
         FROM orders o ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT customer_id, count(*) FROM orders GROUP BY customer_id ORDER BY customer_id",
        Total,
        Bounded,
    ),
    c(
        "SELECT DISTINCT status FROM orders ORDER BY 1",
        Total,
        Bounded,
    ),
    c(
        "SELECT DISTINCT ON (customer_id) customer_id, id FROM orders ORDER BY customer_id, id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id, row_number() OVER (ORDER BY total, id) AS rn FROM orders ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id FOR UPDATE",
        Total,
        Bounded,
    ),
    c(
        "SELECT status, id FROM orders ORDER BY status",
        Keyed(0),
        Bounded,
    ),
    c(
        "SELECT id FROM orders WHERE status = 'open'",
        Order::None,
        Bounded,
    ),
    c("SELECT generate_series(1, 3000) AS g", Order::None, Bounded),
    c("SELECT count(*) FROM orders", Total, Skipped),
    c("SELECT 1 AS one", Total, Skipped),
    c("VALUES (1), (2), (3)", Total, Skipped),
    p(
        "SELECT id FROM orders ORDER BY id LIMIT $1",
        "(3000)",
        Total,
        Bounded,
    ),
    p(
        "SELECT id FROM orders ORDER BY id LIMIT $1",
        "(5)",
        Total,
        Bounded,
    ),
    p(
        "SELECT id FROM orders ORDER BY id LIMIT $1",
        "(NULL)",
        Total,
        Bounded,
    ),
    p(
        "SELECT id FROM orders WHERE total > $2 ORDER BY id LIMIT $1 OFFSET $3",
        "(3000, 100, 7)",
        Total,
        Bounded,
    ),
    p(
        "SELECT id FROM orders WHERE total > $1 ORDER BY id",
        "(100)",
        Total,
        Bounded,
    ),
];

const MY_CASES: &[Case] = &[
    c("SELECT id, total FROM orders ORDER BY id", Total, Bounded),
    c(
        "SELECT id, total, status FROM orders WHERE total > 500 ORDER BY total DESC, id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 3000",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 3",
        Total,
        Unchanged,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 10, 3000",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 10, 3",
        Total,
        Unchanged,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 3000 OFFSET 10",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id LIMIT 18446744073709551615",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders WHERE total < 300 UNION SELECT id FROM orders WHERE total > 700 ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "(SELECT id FROM orders ORDER BY id LIMIT 900) UNION ALL (SELECT id FROM orders ORDER BY id DESC LIMIT 900) ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT customer_id FROM orders INTERSECT SELECT id FROM customers ORDER BY customer_id",
        Total,
        Bounded,
    ),
    c(
        "WITH big AS (SELECT * FROM orders WHERE total > 100) SELECT id, total FROM big ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 900) SELECT n FROM s ORDER BY n",
        Total,
        Bounded,
    ),
    c(
        "SELECT o.id, c.region FROM orders o JOIN customers c ON c.id = o.customer_id \
         WHERE o.customer_id IN (SELECT id FROM customers WHERE region = 'eu') ORDER BY o.id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM (SELECT id FROM orders ORDER BY id LIMIT 2500) s ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id, (SELECT max(total) FROM orders o2 WHERE o2.customer_id = o.customer_id) AS m \
         FROM orders o ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT customer_id, count(*) FROM orders GROUP BY customer_id ORDER BY customer_id",
        Total,
        Bounded,
    ),
    c(
        "SELECT DISTINCT status FROM orders ORDER BY status",
        Total,
        Bounded,
    ),
    c(
        "SELECT id, row_number() OVER (ORDER BY total, id) AS rn FROM orders ORDER BY id",
        Total,
        Bounded,
    ),
    c(
        "SELECT id FROM orders ORDER BY id FOR UPDATE",
        Total,
        Bounded,
    ),
    c(
        "SELECT status, id FROM orders ORDER BY status",
        Keyed(0),
        Bounded,
    ),
    c(
        "SELECT id FROM orders WHERE status = 'open'",
        Order::None,
        Bounded,
    ),
    c("SELECT count(*) FROM orders", Total, Skipped),
    c("SELECT 1 AS one", Total, Skipped),
    p(
        "SELECT id FROM orders WHERE total > ? ORDER BY id",
        "[100]",
        Total,
        Bounded,
    ),
    p(
        "SELECT id FROM orders ORDER BY id LIMIT ?, 3000",
        "[10]",
        Total,
        Bounded,
    ),
    p(
        "SELECT id FROM orders ORDER BY id LIMIT ?",
        "[3000]",
        Total,
        Unknown,
    ),
    p(
        "SELECT id FROM orders ORDER BY id LIMIT 5, ?",
        "[3000]",
        Total,
        Unknown,
    ),
];

fn rules(n: u64) -> Vec<Rule> {
    vec![Rule {
        rule_id: "cap".into(),
        code: "POL-102".into(),
        severity: Severity::Low,
        default_action: EnforcementAction::Monitor,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(format!(
            "applies_to: {{ principal_types: [agent] }}\naction: {{ rewrite_limit: {n} }}"
        )),
    }]
}

/// The rewrite of `sql` at cap `n`: what it did, and the text to execute.
fn rewrite(sql: &str, d: Dialect, n: u64) -> (Kind, String) {
    let rules = rules(n);
    let set = PolicySet::compile(&rules);
    let ctx = EvalContext::new().with_principal(Principal::new(
        "bot",
        PrincipalType::Agent,
        Trust::Medium,
    ));
    let o = evaluate_with_context(sql, d, &rules, &EnforcementPolicy::default(), &set, &ctx);
    let kind = match o.policy_hits.first().map(|h| h.outcome) {
        None => Kind::Unchanged,
        Some(PolicyOutcome::Rewritten) => Kind::Bounded,
        Some(PolicyOutcome::Inconclusive) => Kind::Unknown,
        Some(PolicyOutcome::RewriteFailed) => Kind::Failed,
        Some(other) => panic!("{sql}: unexpected {other:?}"),
    };
    match kind {
        Kind::Bounded => {
            assert_eq!(o.decision, Decision::Allow, "{sql}");
            (kind, o.rewritten_query.expect("bounded: a text to execute"))
        }
        Kind::Failed => {
            assert_eq!(o.decision, Decision::Block, "{sql}");
            assert_eq!(o.rewritten_query, None, "{sql}");
            (kind, sql.to_string())
        }
        _ => {
            assert_eq!(o.rewritten_query, None, "{sql}");
            (kind, sql.to_string())
        }
    }
}

#[test]
fn every_case_rewrites_as_expected_and_reads_back() {
    for (cases, d) in [(PG_CASES, Dialect::Postgres), (MY_CASES, Dialect::Mysql)] {
        for case in cases {
            let (kind, rw) = rewrite(case.sql, d, 7);
            let want = if case.kind == Kind::Skipped {
                Kind::Unchanged
            } else {
                case.kind
            };
            assert_eq!(kind, want, "{d:?} {}", case.sql);
            if kind == Kind::Bounded {
                assert_ne!(rw, case.sql);
                // Idempotent: the rewritten text is already bounded.
                assert_eq!(rewrite(&rw, d, 7).0, Kind::Unchanged, "{d:?} {rw}");
                if d == Dialect::Postgres {
                    pg_query::parse(&rw).unwrap_or_else(|e| panic!("{rw}: {e}"));
                }
            }
        }
    }
}

// ── checks ─────────────────────────────────────────────────────────────────

type Row = Vec<Option<String>>;

fn multiset(rows: &[Row]) -> BTreeMap<&Row, usize> {
    let mut m = BTreeMap::new();
    for r in rows {
        *m.entry(r).or_insert(0) += 1;
    }
    m
}

/// `got` is the first `n` rows of `orig` under `order`.
fn check(what: &str, order: Order, n: u64, orig: &[Row], got: &[Row]) {
    let k = orig.len().min(usize::try_from(n).unwrap_or(usize::MAX));
    assert_eq!(got.len(), k, "{what}: row count at n = {n}");
    match order {
        Order::Total => assert_eq!(got, &orig[..k], "{what}: not the first {n} rows"),
        Order::Keyed(col) => {
            let keys = |rows: &[Row]| rows.iter().map(|r| r[col].clone()).collect::<Vec<_>>();
            assert_eq!(keys(got), keys(&orig[..k]), "{what}: sort keys at n = {n}");
        }
        Order::None => {}
    }
    let (o, g) = (multiset(orig), multiset(got));
    for (row, count) in &g {
        assert!(
            o.get(row).is_some_and(|c| c >= count),
            "{what}: row {row:?} is not in the original"
        );
    }
}

// ── Postgres ───────────────────────────────────────────────────────────────

const PG_FIXTURE: &str = "
CREATE TABLE customers (id int PRIMARY KEY, region text NOT NULL, name text);
INSERT INTO customers SELECT g, CASE WHEN g % 3 = 0 THEN 'eu' ELSE 'us' END, 'c' || g
  FROM generate_series(1, 97) g;
CREATE TABLE orders (id int PRIMARY KEY, customer_id int NOT NULL, total int NOT NULL,
  status text NOT NULL, created date);
INSERT INTO orders SELECT g, g % 97 + 1, (g * 37) % 1000,
  (ARRAY['open', 'paid', 'shipped', 'cancelled'])[g % 4 + 1], DATE '2026-01-01' + (g % 300)
  FROM generate_series(1, 2000) g;
";

struct Psql {
    cmd: String,
    db: String,
}

impl Psql {
    fn run(&self, db: &str, sql: &str) -> Vec<Row> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "{} -d {db} -X -q --csv -P null='<NULL>' -v ON_ERROR_STOP=1",
                self.cmd
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn psql");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(sql.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "psql failed on {sql}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        // Header first; the cells are CSV without embedded newlines here.
        text.lines()
            .skip(1)
            .map(|l| {
                l.split(',')
                    .map(|c| (c != "<NULL>").then(|| c.trim_matches('"').to_string()))
                    .collect()
            })
            .collect()
    }
}

impl Drop for Psql {
    fn drop(&mut self) {
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "{} -d postgres -X -q -c 'DROP DATABASE IF EXISTS {}'",
                self.cmd, self.db
            ))
            .status();
    }
}

#[test]
fn postgres_returns_the_first_n_rows_of_the_original() {
    let Ok(cmd) = std::env::var("VERICTO_EQUIV_PSQL") else {
        eprintln!("VERICTO_EQUIV_PSQL not set: skipping the Postgres half");
        return;
    };
    let db = format!("vericto_limit_equiv_{}", std::process::id());
    let psql = Psql {
        cmd,
        db: db.clone(),
    };
    psql.run("postgres", &format!("CREATE DATABASE {db}"));
    psql.run(&db, PG_FIXTURE);
    let version = psql.run(&db, "SHOW server_version");
    eprintln!("Postgres {}", version[0][0].as_deref().unwrap_or("?"));
    let mut runs = 0;
    for case in PG_CASES.iter().filter(|c| c.kind != Kind::Failed) {
        let exec = |q: &str| match case.params {
            Some(args) => format!("PREPARE p AS {q};\nEXECUTE p{args};"),
            None => format!("{q};"),
        };
        let orig = psql.run(&db, &exec(case.sql));
        let types = |q: &str| {
            psql.run(
                &db,
                &format!(
                    "PREPARE p AS {q};\nSELECT parameter_types::text FROM pg_prepared_statements WHERE name = 'p';"
                ),
            )
        };
        for &n in CAPS {
            let (kind, rw) = rewrite(case.sql, Dialect::Postgres, n);
            let what = format!("{} → {rw}", case.sql);
            match kind {
                Kind::Bounded => {
                    let got = psql.run(&db, &exec(&rw));
                    check(&what, case.order, n, &orig, &got);
                    if case.params.is_some() {
                        assert_eq!(types(case.sql), types(&rw), "{what}: parameter types");
                    }
                }
                Kind::Unchanged if case.kind == Kind::Skipped => assert_eq!(rw, case.sql),
                Kind::Unchanged => {
                    assert!(orig.len() as u64 <= n, "{what}: unchanged but unbounded")
                }
                other => panic!("{what}: {other:?}"),
            }
            runs += 1;
        }
        eprintln!("ok ({} rows): {}", orig.len(), case.sql);
    }
    eprintln!("Postgres: {runs} case × cap runs");
}

// ── MySQL ──────────────────────────────────────────────────────────────────

const MY_FIXTURE: &str = "
SET SESSION cte_max_recursion_depth = 5000;
CREATE TABLE customers (id int PRIMARY KEY, region varchar(8) NOT NULL, name varchar(16));
INSERT INTO customers WITH RECURSIVE s(g) AS (SELECT 1 UNION ALL SELECT g + 1 FROM s WHERE g < 97)
  SELECT g, CASE WHEN g % 3 = 0 THEN 'eu' ELSE 'us' END, CONCAT('c', g) FROM s;
CREATE TABLE orders (id int PRIMARY KEY, customer_id int NOT NULL, total int NOT NULL,
  status varchar(16) NOT NULL, created date);
INSERT INTO orders WITH RECURSIVE s(g) AS (SELECT 1 UNION ALL SELECT g + 1 FROM s WHERE g < 2000)
  SELECT g, g % 97 + 1, (g * 37) % 1000, ELT(g % 4 + 1, 'open', 'paid', 'shipped', 'cancelled'),
         DATE_ADD(DATE '2026-01-01', INTERVAL g % 300 DAY) FROM s;
";

fn run_node(config: &Value, requests: Value) -> Vec<Value> {
    let node = std::env::var("VERICTO_EQUIV_NODE").unwrap_or_else(|_| "node".into());
    let runner = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/mysql_runner.cjs"
    );
    let mut child = Command::new(node)
        .arg(runner)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node");
    let input = json!({ "config": config, "requests": requests });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "mysql runner failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<Vec<Value>>(&out.stdout).expect("runner output")
}

struct My {
    config: Value,
    db: String,
}

impl My {
    fn with_db(&self) -> Value {
        let mut c = self.config.clone();
        c["database"] = json!(self.db);
        c
    }

    /// Runs requests `(sql, params)` in one connection.
    fn run(&self, requests: &[(&str, Option<&Value>)]) -> Vec<Vec<Row>> {
        let reqs: Vec<Value> = requests
            .iter()
            .map(|(sql, params)| json!({ "sql": sql, "params": params }))
            .collect();
        run_node(&self.with_db(), Value::Array(reqs))
            .into_iter()
            .zip(requests)
            .map(|(r, (sql, _))| {
                assert!(
                    r["ok"].as_bool() == Some(true),
                    "MySQL failed on {sql}: {}",
                    r["error"]
                );
                r["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| {
                        row.as_array()
                            .unwrap()
                            .iter()
                            .map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }
}

impl Drop for My {
    fn drop(&mut self) {
        let _ = run_node(
            &self.config,
            json!([{ "sql": format!("DROP DATABASE IF EXISTS {}", self.db), "params": null }]),
        );
    }
}

#[test]
fn mysql_returns_the_first_n_rows_of_the_original() {
    let Ok(raw) = std::env::var("VERICTO_EQUIV_MYSQL") else {
        eprintln!("VERICTO_EQUIV_MYSQL not set: skipping the MySQL half");
        return;
    };
    let servers = match serde_json::from_str::<Value>(&raw).expect("VERICTO_EQUIV_MYSQL is JSON") {
        Value::Array(a) => a,
        one => vec![one],
    };
    for (s, config) in servers.into_iter().enumerate() {
        let my = My {
            db: format!("vericto_limit_equiv_{}_{s}", std::process::id()),
            config,
        };
        let res = run_node(
            &my.config,
            json!([{ "sql": format!("CREATE DATABASE {}", my.db), "params": null }]),
        );
        assert_eq!(res[0]["ok"], json!(true), "{}", res[0]["error"]);
        my.run(&[(MY_FIXTURE, None)]);
        let version = my.run(&[("SELECT VERSION()", None)]);
        eprintln!("MySQL {}", version[0][0][0].as_deref().unwrap_or("?"));
        let mut runs = 0;
        let no_binds = Value::Array(Vec::new());
        for case in MY_CASES {
            let params: Option<Value> = case.params.map(|p| serde_json::from_str(p).unwrap());
            let orig = my.run(&[(case.sql, params.as_ref())]).remove(0);
            for &n in CAPS {
                let (kind, rw) = rewrite(case.sql, Dialect::Mysql, n);
                let what = format!("{} → {rw}", case.sql);
                match kind {
                    Kind::Bounded => {
                        // Text protocol, and the binary protocol when there are binds.
                        let mut reqs = vec![(rw.as_str(), params.as_ref())];
                        if params.is_none() {
                            reqs.push((rw.as_str(), Some(&no_binds)));
                        }
                        for got in my.run(&reqs) {
                            check(&what, case.order, n, &orig, &got);
                        }
                    }
                    Kind::Unchanged if case.kind == Kind::Skipped => assert_eq!(rw, case.sql),
                    Kind::Unchanged => {
                        assert!(orig.len() as u64 <= n, "{what}: unchanged but unbounded")
                    }
                    // The bound is the client's: nothing was rewritten.
                    Kind::Unknown => assert_eq!(rw, case.sql),
                    Kind::Failed | Kind::Skipped => panic!("{what}: {kind:?}"),
                }
                runs += 1;
            }
            eprintln!("ok ({} rows): {}", orig.len(), case.sql);
        }
        eprintln!("MySQL server {s}: {runs} case × cap runs");
    }
}

// ── the LIMIT on top of a VERICTO-085 mask ─────────────────────────────────

/// The rewrite of `sql` at cap `n` with `customers.name` masked `full`.
fn masked_rewrite(sql: &str, d: Dialect, n: u64) -> String {
    use vericto_engine::{MaskStyle, SensitiveColumn, SensitivePolicy};
    let rules = rules(n);
    let set = PolicySet::compile(&rules);
    let ctx = EvalContext::new().with_principal(Principal::new(
        "bot",
        PrincipalType::Agent,
        Trust::Medium,
    ));
    let policy = EnforcementPolicy {
        sensitive_columns: vec![SensitiveColumn {
            schema: None,
            table: "customers".into(),
            column: "name".into(),
            policy: SensitivePolicy::Mask,
            mask_style: MaskStyle::Full,
        }],
        ..EnforcementPolicy::default()
    };
    let o = evaluate_with_context(sql, d, &rules, &policy, &set, &ctx);
    assert_eq!(o.decision, Decision::Flag, "{sql}");
    o.rewritten_query.expect("masked and bounded")
}

const MASKED: &str = "SELECT id, name, region FROM customers ORDER BY id";

/// The ids and regions are the first `n` of the original, every name masked.
fn check_masked(what: &str, n: u64, orig: &[Row], got: &[Row]) {
    let k = orig.len().min(n as usize);
    assert_eq!(got.len(), k, "{what}");
    for (o, g) in orig.iter().zip(got) {
        assert_eq!((&o[0], &o[2]), (&g[0], &g[2]), "{what}");
        assert_eq!(g[1].as_deref(), Some("[redacted]"), "{what}");
    }
}

#[test]
fn the_limit_composes_with_the_mask_on_real_databases() {
    if let Ok(cmd) = std::env::var("VERICTO_EQUIV_PSQL") {
        let db = format!("vericto_limit_mask_{}", std::process::id());
        let psql = Psql {
            cmd,
            db: db.clone(),
        };
        psql.run("postgres", &format!("CREATE DATABASE {db}"));
        psql.run(&db, PG_FIXTURE);
        let orig = psql.run(&db, &format!("{MASKED};"));
        for &n in CAPS {
            let rw = masked_rewrite(MASKED, Dialect::Postgres, n);
            check_masked(&rw, n, &orig, &psql.run(&db, &format!("{rw};")));
        }
        eprintln!("Postgres: mask + LIMIT ok");
    }
    if let Ok(raw) = std::env::var("VERICTO_EQUIV_MYSQL") {
        let servers = match serde_json::from_str::<Value>(&raw).expect("JSON") {
            Value::Array(a) => a,
            one => vec![one],
        };
        for (s, config) in servers.into_iter().enumerate() {
            let my = My {
                db: format!("vericto_limit_mask_{}_{s}", std::process::id()),
                config,
            };
            let res = run_node(
                &my.config,
                json!([{ "sql": format!("CREATE DATABASE {}", my.db), "params": null }]),
            );
            assert_eq!(res[0]["ok"], json!(true), "{}", res[0]["error"]);
            my.run(&[(MY_FIXTURE, None)]);
            let orig = my.run(&[(MASKED, None)]).remove(0);
            for &n in CAPS {
                let rw = masked_rewrite(MASKED, Dialect::Mysql, n);
                check_masked(&rw, n, &orig, &my.run(&[(rw.as_str(), None)]).remove(0));
            }
            eprintln!("MySQL server {s}: mask + LIMIT ok");
        }
    }
}
