//! Equivalence of the VERICTO-085 MySQL mask rewrite (3.7.0) against a real
//! MySQL: run the original and the rewritten query on the same fixture and
//! require every non-masked column to be identical, row for row, and every
//! masked column to match its style. Queries with `?` run through the binary
//! protocol (`COM_STMT_PREPARE` + `COM_STMT_EXECUTE`) with bound values, so a
//! shifted or dropped parameter changes the rows; the rest run through both
//! the text and the binary protocol.
//!
//! The rewrite half always runs. The database half needs a server and the
//! `mysql2` Node driver, and runs only when `VERICTO_EQUIV_MYSQL` holds a JSON
//! connection object (or an array of them), e.g.
//!
//! ```sh
//! NODE_PATH=/path/to/node_modules \
//! VERICTO_EQUIV_MYSQL='[{"host":"127.0.0.1","port":33062,"user":"root","password":"…","ssl":{"rejectUnauthorized":false}},
//!                       {"host":"127.0.0.1","port":33157,"user":"root","password":"…"}]' \
//!   cargo test --test mysql_mask_equivalence -- --nocapture
//! ```
//!
//! `VERICTO_EQUIV_NODE` overrides the `node` binary. With `VERICTO_EQUIV_PSQL`
//! also set (see `tests/mask_equivalence.rs`), the masked values are compared
//! with what the Postgres rewrite returns for the same text. Each run creates
//! its own database and drops it at the end.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use vericto_engine::{
    Decision, Dialect, EnforcementPolicy, MaskStyle, SensitiveColumn, SensitivePolicy, evaluate,
};

/// (id, name, email, card, ssn, created). Covers NULL, `''`, one character,
/// multibyte and 4-byte characters, no `@`, `@` first, a full-width `＠`,
/// backslashes, quotes, duplicates.
type Row = (
    i32,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

const ROWS: &[Row] = &[
    (
        1,
        "Ann",
        Some("ann@example.com"),
        Some("4111111111111111"),
        Some("123-45-6789"),
        Some("2024-01-01"),
    ),
    (
        2,
        "bob",
        Some("bob.smith@mail.org"),
        Some("5500000000000004"),
        Some("987-65-4321"),
        Some("2024-02-01"),
    ),
    (3, "Zed", None, Some("1234"), None, Some("2024-03-01")),
    (
        4,
        "noat",
        Some("plainvalue"),
        Some("378282246310005"),
        Some(r"a\b"),
        Some("2024-04-01"),
    ),
    (
        5,
        "dup",
        Some("ann@example.com"),
        Some("12"),
        Some("123-45-6789"),
        None,
    ),
    (6, "empty", Some(""), Some(""), Some(""), Some("2024-06-01")),
    (
        7,
        "one",
        Some("x"),
        Some("9"),
        Some("é"),
        Some("2024-07-01"),
    ),
    (
        8,
        "multi",
        Some("ñandú@correo.es"),
        Some("€€€€€"),
        Some("ñ"),
        Some("2024-08-01"),
    ),
    (
        9,
        "atfirst",
        Some("@host.io"),
        Some("1"),
        Some("@"),
        Some("2024-09-01"),
    ),
    (
        10,
        "emoji",
        Some("😀x@y.io"),
        Some("x😀"),
        Some("😀"),
        Some("2024-10-01"),
    ),
    (
        11,
        "wide",
        Some("ann＠x.io"),
        Some("it's"),
        Some("q'q"),
        Some("2024-11-01"),
    ),
    (
        12,
        "two",
        Some("a@b@c"),
        Some("ab"),
        Some("a@b"),
        Some("2024-12-01"),
    ),
];

fn my_lit(v: Option<&str>) -> String {
    match v {
        None => "NULL".into(),
        Some(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''")),
    }
}

fn pg_lit(v: Option<&str>) -> String {
    match v {
        None => "NULL".into(),
        Some(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

fn fixture(lit: fn(Option<&str>) -> String, mysql: bool) -> String {
    let rows: Vec<String> = ROWS
        .iter()
        .map(|(id, n, e, c, s, d)| {
            format!(
                "({id}, {}, {}, {}, {}, {})",
                lit(Some(n)),
                lit(*e),
                lit(*c),
                lit(*s),
                lit(*d)
            )
        })
        .collect();
    // utf8mb4 with a NON-default collation: a mask that inherits the
    // connection's collation would raise "Illegal mix of collations" in the
    // UNION / DISTINCT cases below.
    let (txt, opts) = if mysql {
        (
            "VARCHAR(100)",
            " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        )
    } else {
        ("text", "")
    };
    format!(
        "CREATE TABLE customers (id int PRIMARY KEY, name {txt}, email {txt}, card {txt}, ssn {txt}, created date){opts};\n\
         INSERT INTO customers VALUES {};\n\
         CREATE TABLE orders (id int, customer_id int, total int, email {txt}){opts};\n\
         INSERT INTO orders VALUES (10, 1, 100, 'o1@x.io'), (11, 2, 250, 'o2@x.io'), (12, 1, 75, 'o3@x.io');\n\
         CREATE TABLE users (id int, name {txt}){opts};\n\
         INSERT INTO users VALUES (1, 'ann@example.com'), (2, 'Ünïcode'), (3, 'zed');\n",
        rows.join(", ")
    )
}

/// A latin1 table: the masks convert to utf8mb4 first, so they return the same
/// characters (and hash the same UTF-8 bytes) as for a utf8mb4 column.
const LATIN1: &str = "CREATE TABLE legacy (id int, email VARCHAR(100), ssn VARCHAR(30)) CHARACTER SET latin1 COLLATE latin1_swedish_ci;\n\
    INSERT INTO legacy VALUES (1, 'josé@x.es', 'déjà'), (2, 'Ångström', NULL);\n";

fn tags() -> Vec<SensitiveColumn> {
    let t = |table: &str, column: &str, mask_style| SensitiveColumn {
        schema: None,
        table: table.into(),
        column: column.into(),
        policy: SensitivePolicy::Mask,
        mask_style,
    };
    vec![
        t("customers", "email", MaskStyle::Email),
        t("customers", "card", MaskStyle::Last4),
        t("customers", "ssn", MaskStyle::Hash),
        t("customers", "created", MaskStyle::Full),
        t("legacy", "email", MaskStyle::Email),
        t("legacy", "ssn", MaskStyle::Hash),
    ]
}

struct Case {
    sql: &'static str,
    /// Bound through the binary protocol; `None` = run both protocols, no
    /// parameters.
    params: Option<Value>,
    masks: &'static [(&'static str, MaskStyle)],
    /// Masks only apply to rows whose first column is this value (UNION arms).
    only_rows: Option<&'static str>,
    /// Needs MySQL 8 (CTEs).
    mysql8: bool,
}

const fn case(sql: &'static str, masks: &'static [(&'static str, MaskStyle)]) -> Case {
    Case {
        sql,
        params: None,
        masks,
        only_rows: None,
        mysql8: false,
    }
}

fn cases() -> Vec<Case> {
    use MaskStyle::*;
    vec![
        case(
            "SELECT id, name, email, card, ssn, created FROM customers ORDER BY id",
            &[
                ("email", Email),
                ("card", Last4),
                ("ssn", Hash),
                ("created", Full),
            ],
        ),
        Case {
            params: Some(json!([2])),
            ..case(
                "SELECT id, email AS e, name FROM customers WHERE id >= ? ORDER BY id",
                &[("e", Email)],
            )
        },
        case(
            "SELECT o.id, o.total, o.email AS order_email, c.email FROM orders o \
             JOIN customers c ON c.id = o.customer_id ORDER BY o.id",
            &[("email", Email)],
        ),
        Case {
            mysql8: true,
            ..case(
                "WITH x AS (SELECT id, email, card FROM customers) SELECT id, email, card FROM x ORDER BY id",
                &[("email", Email), ("card", Last4)],
            )
        },
        case(
            "SELECT s.id, s.e FROM (SELECT id, email AS e FROM customers) s ORDER BY s.id",
            &[("e", Email)],
        ),
        case(
            "SELECT id, LOWER(email) AS le FROM customers ORDER BY id",
            &[("le", Full)],
        ),
        case(
            "SELECT id, LOWER( email ) FROM customers ORDER BY id",
            &[("LOWER( email )", Full)],
        ),
        // Ordered by the ORIGINAL email: the rewrite must keep that order.
        case(
            "SELECT id, email FROM customers ORDER BY email, id",
            &[("email", Email)],
        ),
        case(
            "SELECT id, email FROM customers ORDER BY 2 DESC, 1",
            &[("email", Email)],
        ),
        case(
            "SELECT email, COUNT(*) AS n FROM customers GROUP BY email ORDER BY email",
            &[("email", Email)],
        ),
        case(
            "SELECT c.id, (SELECT c2.card FROM customers c2 WHERE c2.id = c.id) AS card \
             FROM customers c ORDER BY 1",
            &[("card", Last4)],
        ),
        Case {
            params: Some(json!(["%@%"])),
            ..case(
                "SELECT id, ssn FROM customers WHERE email LIKE ? ORDER BY id",
                &[("ssn", Hash)],
            )
        },
        // A computed value with bind parameters: masked `full`, and each `?`
        // must stay in place with the type MySQL infers from its context.
        Case {
            params: Some(json!([2, 4, 0])),
            ..case(
                "SELECT id, SUBSTRING(card, ?, ?) AS part FROM customers WHERE id <> ? ORDER BY id",
                &[("part", Full)],
            )
        },
        // `LIMIT ?, ?` printed as `LIMIT ? OFFSET ?` would swap offset and
        // count: different rows.
        Case {
            // mysql2 binds JS numbers as DOUBLE, which MySQL 8.0.22+ refuses for
            // LIMIT; strings are converted.
            params: Some(json!([2, "1", "3"])),
            ..case(
                "SELECT id, email FROM customers WHERE id >= ? ORDER BY id LIMIT ?, ?",
                &[("email", Email)],
            )
        },
        Case {
            params: Some(json!([1, 4])),
            ..case(
                "SELECT id, (SELECT email FROM customers c2 WHERE c2.id = ?) AS e FROM customers \
                 WHERE id < ? ORDER BY id",
                &[("e", Full)],
            )
        },
        case(
            "SELECT id, JSON_OBJECT('e', email) AS j FROM customers ORDER BY id",
            &[("j", Full)],
        ),
        case(
            "SELECT GROUP_CONCAT(email ORDER BY id SEPARATOR ';') AS g FROM customers",
            &[("g", Full)],
        ),
        case(
            "SELECT id, CAST(created AS CHAR) AS d FROM customers ORDER BY id",
            &[("d", Full)],
        ),
        // Collation: the masked arm is compared with a utf8mb4_unicode_ci
        // column by UNION ALL's type aggregation, sorted with it, and
        // deduplicated by UNION.
        Case {
            only_rows: Some("c"),
            ..case(
                "SELECT 'c' AS src, id, email FROM customers UNION ALL SELECT 'u', id, name FROM users \
                 ORDER BY src, id",
                &[("email", Email)],
            )
        },
        Case {
            only_rows: Some("c"),
            ..case(
                "SELECT 'c' AS src, id, card FROM customers UNION SELECT 'u', id, name FROM users \
                 ORDER BY src, id",
                &[("card", Last4)],
            )
        },
        case(
            "SELECT id, email, ssn FROM legacy ORDER BY id",
            &[("email", Email), ("ssn", Hash)],
        ),
    ]
}

fn policy() -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: tags(),
        ..EnforcementPolicy::default()
    }
}

fn rewritten(sql: &str, dialect: Dialect) -> String {
    let o = evaluate(sql, dialect, &[], &policy());
    assert_eq!(o.decision, Decision::Flag, "{sql}: {o:?}");
    o.rewritten_query
        .unwrap_or_else(|| panic!("{sql}: no rewrite: {:?}", o.ast_node_path))
}

#[test]
fn every_case_rewrites_to_valid_mysql() {
    for c in cases() {
        let rw = rewritten(c.sql, Dialect::Mysql);
        assert_ne!(rw, c.sql);
        let o = evaluate(&rw, Dialect::Mysql, &[], &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Allow, "{rw}");
    }
}

// ── database half ──────────────────────────────────────────────────────────

/// One MySQL server, through `tests/support/mysql_runner.cjs`.
struct My {
    config: Value,
    db: String,
}

type Rows = (Vec<String>, Vec<Vec<Option<String>>>);

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

impl My {
    fn with_db(&self) -> Value {
        let mut c = self.config.clone();
        c["database"] = json!(self.db);
        c
    }

    /// Runs one statement; `params = Some` uses the binary protocol.
    fn run(&self, sql: &str, params: Option<&Value>) -> Rows {
        let res = run_node(&self.with_db(), json!([{ "sql": sql, "params": params }]));
        let r = &res[0];
        assert!(
            r["ok"].as_bool() == Some(true),
            "MySQL failed on {sql}: {}",
            r["error"]
        );
        let cols = r["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();
        let rows = r["rows"]
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
            .collect();
        (cols, rows)
    }

    fn version(&self) -> String {
        let res = run_node(
            &self.config,
            json!([{ "sql": "SELECT VERSION()", "params": null }]),
        );
        res[0]["rows"][0][0]
            .as_str()
            .unwrap_or_default()
            .to_string()
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

fn servers() -> Vec<Value> {
    let Ok(raw) = std::env::var("VERICTO_EQUIV_MYSQL") else {
        return Vec::new();
    };
    match serde_json::from_str::<Value>(&raw).expect("VERICTO_EQUIV_MYSQL is JSON") {
        Value::Array(a) => a,
        one => vec![one],
    }
}

fn connect(config: Value, tag: &str) -> My {
    let db = format!("vericto_mask_equiv_{}_{tag}", std::process::id());
    let my = My { config, db };
    let res = run_node(
        &my.config,
        json!([{ "sql": format!("CREATE DATABASE {} CHARACTER SET utf8mb4", my.db), "params": null }]),
    );
    assert_eq!(res[0]["ok"], json!(true), "{}", res[0]["error"]);
    let res = run_node(
        &my.with_db(),
        json!([{ "sql": format!("{}{LATIN1}", fixture(my_lit, true)), "params": null }]),
    );
    assert_eq!(res[0]["ok"], json!(true), "fixture: {}", res[0]["error"]);
    my
}

/// The Postgres outputs for the same text (`regexp_replace(x,
/// '^(.)[^@]*(@.*)?$', '\1***\2')`, `'****' || right(x, 4)`), written out.
fn check_masked(style: MaskStyle, orig: Option<&str>, got: Option<&str>) -> bool {
    match (style, orig) {
        (MaskStyle::Full, _) => got == Some("[redacted]"),
        (_, None) => got.is_none(),
        (MaskStyle::Last4, Some(o)) => {
            let chars: Vec<char> = o.chars().collect();
            let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
            got == Some(format!("****{tail}").as_str())
        }
        (MaskStyle::Email, Some(o)) => {
            let mut chars = o.chars();
            let Some(first) = chars.next() else {
                return got == Some("");
            };
            let rest = chars.as_str();
            let domain = rest.find('@').map(|i| &rest[i..]).unwrap_or("");
            got == Some(format!("{first}***{domain}").as_str())
        }
        (MaskStyle::Hash, Some(_)) => {
            got.is_some_and(|g| g.len() == 64 && g.chars().all(|c| c.is_ascii_hexdigit()))
        }
    }
}

fn compare(c: &Case, rw: &str, orig: &Rows, got: &Rows, how: &str) {
    let sql = c.sql;
    assert_eq!(
        orig.0, got.0,
        "column names must survive the rewrite ({how}): {rw}"
    );
    assert_eq!(orig.1.len(), got.1.len(), "row count ({how}): {rw}");
    assert!(!orig.1.is_empty(), "fixture returns rows for {sql}");
    for (r, (o_row, g_row)) in orig.1.iter().zip(&got.1).enumerate() {
        let applies = c
            .only_rows
            .is_none_or(|v| o_row.first().and_then(|x| x.as_deref()) == Some(v));
        for (k, name) in orig.0.iter().enumerate() {
            let (o, g) = (o_row[k].as_deref(), g_row[k].as_deref());
            match c.masks.iter().find(|(m, _)| m == name).filter(|_| applies) {
                Some((_, style)) => assert!(
                    check_masked(*style, o, g),
                    "{sql} ({how})\n  row {r} column {name}: {o:?} masked {style:?} as {g:?}"
                ),
                None => assert_eq!(
                    o, g,
                    "{sql} ({how})\n  row {r} column {name} must be unchanged"
                ),
            }
        }
    }
    // Equal originals hash equally (a stable pseudonym), distinct ones not.
    for (name, style) in c.masks {
        if *style != MaskStyle::Hash {
            continue;
        }
        let k = orig.0.iter().position(|h| h == name).unwrap();
        for (a, b) in orig.1.iter().zip(&got.1) {
            for (a2, b2) in orig.1.iter().zip(&got.1) {
                assert_eq!(
                    a[k] == a2[k],
                    b[k] == b2[k],
                    "{sql}: hash must be a pseudonym"
                );
            }
        }
    }
}

#[test]
fn rewritten_queries_return_the_same_rows_with_masked_values() {
    let servers = servers();
    if servers.is_empty() {
        eprintln!("VERICTO_EQUIV_MYSQL not set: skipping the database half");
        return;
    }
    for (n, config) in servers.into_iter().enumerate() {
        let my = connect(config, &n.to_string());
        let version = my.version();
        eprintln!("== MySQL {version}");
        for c in cases() {
            if c.mysql8 && version.starts_with("5.") {
                eprintln!("skip on {version} (needs MySQL 8): {}", c.sql);
                continue;
            }
            let rw = rewritten(c.sql, Dialect::Mysql);
            match &c.params {
                Some(p) => {
                    let (o, g) = (my.run(c.sql, Some(p)), my.run(&rw, Some(p)));
                    compare(&c, &rw, &o, &g, "binary protocol");
                }
                None => {
                    let (o, g) = (my.run(c.sql, None), my.run(&rw, None));
                    compare(&c, &rw, &o, &g, "text protocol");
                    let empty = json!([]);
                    let (o, g) = (my.run(c.sql, Some(&empty)), my.run(&rw, Some(&empty)));
                    compare(&c, &rw, &o, &g, "binary protocol");
                }
            }
            eprintln!("ok: {}\n    → {rw}", c.sql);
        }
        // A latin1 column hashes the UTF-8 bytes of its text, like Postgres:
        // sha256("déjà") as UTF-8.
        let rw = rewritten("SELECT ssn FROM legacy WHERE id = 1", Dialect::Mysql);
        let (_, rows) = my.run(&rw, None);
        assert_eq!(
            rows[0][0].as_deref(),
            Some("1913fb3460b7de0641842fcd677d93acd064fbac170ca4e60b2fc186cf95d5ca"),
            "{rw}"
        );
    }
}

// ── Postgres parity ────────────────────────────────────────────────────────

fn psql(cmd: &str, db: &str, sql: &str) -> Vec<Vec<Option<String>>> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{cmd} -d {db} -X -q -A -t -F '|' -P null='<NULL>' -v ON_ERROR_STOP=1"
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
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            l.split('|')
                .map(|v| (v != "<NULL>").then(|| v.to_string()))
                .collect()
        })
        .collect()
}

/// The MySQL masks return exactly what the Postgres masks return for the same
/// text: NULL, `''`, one character, multibyte, no `@`, `@` first, hashes.
#[test]
fn mysql_masks_equal_the_postgres_masks() {
    let (Some(config), Ok(pg)) = (
        servers().into_iter().next(),
        std::env::var("VERICTO_EQUIV_PSQL"),
    ) else {
        eprintln!("VERICTO_EQUIV_MYSQL and VERICTO_EQUIV_PSQL not both set: skipping");
        return;
    };
    let my = connect(config, "parity");
    let db = format!("vericto_mask_parity_{}", std::process::id());
    psql(&pg, "postgres", &format!("CREATE DATABASE {db}"));
    struct DropPg<'a>(&'a str, String);
    impl Drop for DropPg<'_> {
        fn drop(&mut self) {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "{} -d postgres -X -q -c 'DROP DATABASE IF EXISTS {}'",
                    self.0, self.1
                ))
                .status();
        }
    }
    let _guard = DropPg(&pg, db.clone());
    psql(&pg, &db, &fixture(pg_lit, false));

    let sql = "SELECT id, email, card, ssn, created FROM customers ORDER BY id";
    let pg_rows = psql(&pg, &db, &format!("{};", rewritten(sql, Dialect::Postgres)));
    let (_, my_rows) = my.run(&rewritten(sql, Dialect::Mysql), None);
    assert_eq!(pg_rows.len(), my_rows.len());
    for (p, m) in pg_rows.iter().zip(&my_rows) {
        assert_eq!(
            p,
            m,
            "Postgres and MySQL masks differ for row {:?}",
            p.first()
        );
    }
    eprintln!(
        "parity: {} rows identical across Postgres and MySQL",
        pg_rows.len()
    );
}
