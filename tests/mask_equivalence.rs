//! Equivalence of the VERICTO-085 mask rewrite (design §12): run the original
//! and the rewritten query against the same Postgres fixture and require that
//! every non-masked column is identical, row for row, and every masked column
//! matches its style.
//!
//! The rewrite half always runs: every case must produce a rewrite that
//! Postgres's own parser accepts. The database half needs a server and runs
//! only when `VERICTO_EQUIV_PSQL` names a psql command line (without `-d`), e.g.
//!
//! ```sh
//! VERICTO_EQUIV_PSQL='docker exec -i some-postgres psql -U postgres' \
//!   cargo test --test mask_equivalence -- --nocapture
//! ```
//!
//! It creates its own throwaway database, and drops it at the end.

use std::io::Write;
use std::process::{Command, Stdio};

use vericto_engine::{
    Decision, Dialect, EnforcementPolicy, MaskStyle, SensitiveColumn, SensitivePolicy, evaluate,
};

const FIXTURE: &str = r#"
CREATE TABLE customers (id int PRIMARY KEY, name text, email text, card text, ssn text, created date);
INSERT INTO customers VALUES
  (1, 'Ann',  'ann@example.com',    '4111111111111111', '123-45-6789', '2024-01-01'),
  (2, 'bob',  'bob.smith@mail.org', '5500000000000004', '987-65-4321', '2024-02-01'),
  (3, 'Zed',  NULL,                 '1234',             NULL,          '2024-03-01'),
  (4, 'noat', 'plainvalue',         '378282246310005',  'a\b',         '2024-04-01'),
  (5, 'dup',  'ann@example.com',    '12',               '123-45-6789', NULL);
CREATE TABLE orders (id int, customer_id int, total int, email text);
INSERT INTO orders VALUES (10, 1, 100, 'o1@x.io'), (11, 2, 250, 'o2@x.io'), (12, 1, 75, 'o3@x.io');
"#;

fn tags() -> Vec<SensitiveColumn> {
    let t = |column: &str, mask_style| SensitiveColumn {
        schema: None,
        table: "customers".into(),
        column: column.into(),
        policy: SensitivePolicy::Mask,
        mask_style,
    };
    vec![
        t("email", MaskStyle::Email),
        t("card", MaskStyle::Last4),
        t("ssn", MaskStyle::Hash),
        t("created", MaskStyle::Full),
    ]
}

/// (query, parameters for a prepared run, masked output columns and style).
/// Every query is ordered, so rows compare position by position.
type Case = (
    &'static str,
    Option<&'static str>,
    &'static [(&'static str, MaskStyle)],
);

const CASES: &[Case] = &[
    (
        "SELECT id, name, email, card, ssn, created FROM customers ORDER BY id",
        None,
        &[
            ("email", MaskStyle::Email),
            ("card", MaskStyle::Last4),
            ("ssn", MaskStyle::Hash),
            ("created", MaskStyle::Full),
        ],
    ),
    (
        "SELECT id, email AS e, name FROM customers WHERE id >= $1 ORDER BY id",
        Some("(2)"),
        &[("e", MaskStyle::Email)],
    ),
    (
        "SELECT o.id, o.total, o.email AS order_email, c.email FROM orders o \
         JOIN customers c ON c.id = o.customer_id ORDER BY o.id",
        None,
        &[("email", MaskStyle::Email)],
    ),
    (
        "WITH x AS (SELECT id, email, card FROM customers) SELECT id, email, card FROM x ORDER BY id",
        None,
        &[("email", MaskStyle::Email), ("card", MaskStyle::Last4)],
    ),
    (
        "SELECT id, lower(email) AS le FROM customers ORDER BY id",
        None,
        &[("le", MaskStyle::Full)],
    ),
    (
        // Ordered by the ORIGINAL email: the rewrite must keep that order.
        "SELECT id, email FROM customers ORDER BY email, id",
        None,
        &[("email", MaskStyle::Email)],
    ),
    (
        "SELECT email, count(*) AS n FROM customers GROUP BY email ORDER BY email",
        None,
        &[("email", MaskStyle::Email)],
    ),
    (
        "SELECT c.id, (SELECT c2.card FROM customers c2 WHERE c2.id = c.id) AS card \
         FROM customers c ORDER BY 1",
        None,
        &[("card", MaskStyle::Last4)],
    ),
    (
        "SELECT id, ssn FROM customers WHERE email LIKE $1 ORDER BY id",
        Some("('%@%')"),
        &[("ssn", MaskStyle::Hash)],
    ),
    (
        "SELECT id, substring(card, 1, 6) AS bin FROM customers ORDER BY id",
        None,
        &[("bin", MaskStyle::Full)],
    ),
];

fn policy() -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: tags(),
        ..EnforcementPolicy::default()
    }
}

fn rewritten(sql: &str) -> String {
    let o = evaluate(sql, Dialect::Postgres, &[], &policy());
    assert_eq!(o.decision, Decision::Flag, "{sql}: {o:?}");
    o.rewritten_query
        .unwrap_or_else(|| panic!("{sql}: no rewrite: {:?}", o.ast_node_path))
}

#[test]
fn every_case_rewrites_to_valid_postgres() {
    for (sql, _, _) in CASES {
        let rw = rewritten(sql);
        assert_ne!(&rw, sql);
        // Postgres's own parser accepts it (the engine reparses its output).
        let o = evaluate(&rw, Dialect::Postgres, &[], &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Allow, "{rw}");
    }
}

// ── database half ──────────────────────────────────────────────────────────

struct Psql {
    cmd: String,
    db: String,
}

impl Psql {
    /// Runs `sql` and returns (header, rows), NULL rendered as `<NULL>`.
    fn run(&self, db: &str, sql: &str) -> (Vec<String>, Vec<Vec<String>>) {
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
        let mut lines = parse_csv(&text).into_iter();
        let header = lines.next().unwrap_or_default();
        (header, lines.collect())
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

/// Minimal RFC 4180 reader: enough for psql's CSV output.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\n', false) => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (c, _) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

fn check_masked(style: MaskStyle, orig: &str, got: &str) -> bool {
    const NULL: &str = "<NULL>";
    match style {
        MaskStyle::Full => got == "[redacted]",
        _ if orig == NULL => got == NULL,
        MaskStyle::Last4 => {
            let chars: Vec<char> = orig.chars().collect();
            let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
            got == format!("****{tail}")
        }
        MaskStyle::Email => {
            // `^(.)[^@]*(@.*)?$` → first character, `***`, then everything from
            // the first `@` (nothing when there is none).
            let Some(first) = orig.chars().next() else {
                return got.is_empty();
            };
            let domain = orig.find('@').map(|i| &orig[i..]).unwrap_or("");
            got == format!("{first}***{domain}")
        }
        MaskStyle::Hash => got.len() == 64 && got.chars().all(|c| c.is_ascii_hexdigit()),
    }
}

#[test]
fn rewritten_queries_return_the_same_rows_with_masked_values() {
    let Ok(cmd) = std::env::var("VERICTO_EQUIV_PSQL") else {
        eprintln!("VERICTO_EQUIV_PSQL not set: skipping the database half");
        return;
    };
    let db = format!("vericto_mask_equiv_{}", std::process::id());
    let psql = Psql {
        cmd,
        db: db.clone(),
    };
    psql.run("postgres", &format!("CREATE DATABASE {db}"));
    psql.run(&db, FIXTURE);

    for (sql, params, masks) in CASES {
        let rw = rewritten(sql);
        let exec = |q: &str| match params {
            Some(p) => format!("PREPARE p AS {q};\nEXECUTE p{p};"),
            None => format!("{q};"),
        };
        let (h_orig, orig) = psql.run(&db, &exec(sql));
        let (h_rw, got) = psql.run(&db, &exec(&rw));
        assert_eq!(h_orig, h_rw, "column names must survive the rewrite: {rw}");
        assert_eq!(orig.len(), got.len(), "row count: {rw}");
        assert!(!orig.is_empty(), "fixture returns rows for {sql}");
        for (r, (o_row, g_row)) in orig.iter().zip(&got).enumerate() {
            for (c, name) in h_orig.iter().enumerate() {
                let (o, g) = (&o_row[c], &g_row[c]);
                match masks.iter().find(|(m, _)| m == name) {
                    Some((_, style)) => assert!(
                        check_masked(*style, o, g),
                        "{sql}\n  row {r} column {name}: {o:?} masked {style:?} as {g:?}"
                    ),
                    None => assert_eq!(o, g, "{sql}\n  row {r} column {name} must be unchanged"),
                }
            }
        }
        // Equal originals hash equally (the hash is a stable pseudonym).
        for (name, style) in masks.iter() {
            if *style != MaskStyle::Hash {
                continue;
            }
            let c = h_orig.iter().position(|h| h == name).unwrap();
            for (a, b) in orig.iter().zip(&got) {
                for (a2, b2) in orig.iter().zip(&got) {
                    if a[c] == a2[c] {
                        assert_eq!(b[c], b2[c], "{sql}: hash must be deterministic");
                    }
                }
            }
        }
        eprintln!("ok: {sql}\n    → {rw}");
    }
}
