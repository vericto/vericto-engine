//! VERICTO-085 on SQLite against a real SQLite (design §8, "mask equivalence:
//! SQLite in CI against a real sqlite3"): every mask rewrite is run through
//! the `sqlite3` command-line shell over values that exercise the edge cases
//! (NULL, the empty string, one character, no `@`, a leading `@`, several
//! `@`, non-ASCII text, a number, a multi-line value), and each masked value
//! is compared with what the Postgres mask returns for the same text.
//!
//! Skipped (with a note) when no `sqlite3` is found: set `VERICTO_SQLITE3` to
//! its path, or put it on `PATH`. GitHub's Ubuntu and macOS runners ship one.

use std::io::Write;
use std::process::{Command, Stdio};

use vericto_engine::{Decision, Dialect, EnforcementPolicy, SensitiveColumn, evaluate};

fn sqlite3() -> Option<String> {
    let bin = std::env::var("VERICTO_SQLITE3").unwrap_or_else(|_| "sqlite3".to_string());
    Command::new(&bin)
        .arg("-version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| bin)
}

/// The rows: `(id, value)`; the same value goes into every masked column.
const VALUES: &[(i64, Option<&str>)] = &[
    (1, None),
    (2, Some("")),
    (3, Some("a")),
    (4, Some("ab")),
    (5, Some("john.doe@example.com")),
    (6, Some("@example.com")),
    (7, Some("no-at-sign")),
    (8, Some("a@b@c.io")),
    (9, Some("ñandú@ejemplo.es")),
    (10, Some("4111111111111111")),
    (11, Some("line one\nline@two")),
    (12, Some("x@")),
];

/// Postgres's `regexp_replace(x, '^(.)[^@]*(@.*)?$', '\1***\2')`.
fn pg_email(x: &str) -> String {
    let mut chars = x.chars();
    let Some(first) = chars.next() else {
        // `(.)` needs a character: no match, the value is returned as is.
        return x.to_string();
    };
    let rest: String = chars.collect();
    match rest.find('@') {
        Some(at) => format!("{first}***{}", &rest[at..]),
        None => format!("{first}***"),
    }
}

/// Postgres's `'****' || right(x, 4)`.
fn pg_last4(x: &str) -> String {
    let chars: Vec<char> = x.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
    format!("****{tail}")
}

fn tags() -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: serde_json::from_str::<Vec<SensitiveColumn>>(
            r#"[
                {"table":"customers","column":"email","policy":"mask","mask_style":"email"},
                {"table":"customers","column":"card","policy":"mask","mask_style":"last4"},
                {"table":"customers","column":"note","policy":"mask","mask_style":"full"}
            ]"#,
        )
        .unwrap(),
        ..EnforcementPolicy::default()
    }
}

fn quote(v: Option<&str>) -> String {
    match v {
        None => "NULL".to_string(),
        Some(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

/// Runs `query` after the setup and returns the rows as JSON objects.
fn run(bin: &str, query: &str) -> Vec<serde_json::Map<String, serde_json::Value>> {
    let mut script = String::from(
        "CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, card, note TEXT);\n",
    );
    for (id, v) in VALUES {
        // `card` holds the number as an INTEGER where it is one (a card
        // number column often does): the mask casts it to text.
        let card = match v {
            Some(s) if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() => s.to_string(),
            other => quote(*other),
        };
        script.push_str(&format!(
            "INSERT INTO customers VALUES ({id}, {e}, {card}, {e});\n",
            e = quote(*v)
        ));
    }
    script.push_str(query);
    script.push_str(";\n");
    let mut child = Command::new(bin)
        .args(["-json", ":memory:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sqlite3 runs");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "sqlite3 failed on {query}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}",
            String::from_utf8_lossy(&out.stdout)
                .chars()
                .take(500)
                .collect::<String>()
        )
    })
}

fn masked(sql: &str) -> String {
    let o = evaluate(sql, Dialect::Sqlite, &[], &tags());
    assert_eq!(o.decision, Decision::Flag, "{sql}: {o:?}");
    let path = o.ast_node_path.clone();
    o.rewritten_query
        .unwrap_or_else(|| panic!("{sql} is rewritten: {path:?}"))
}

#[test]
fn sqlite_masks_match_the_postgres_masks() {
    let Some(bin) = sqlite3() else {
        eprintln!("sqlite_mask_equivalence: no sqlite3 found (VERICTO_SQLITE3 / PATH); skipped");
        return;
    };
    let text = |v: &serde_json::Value| match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    };

    // Bare columns: `email`, `last4` and `full`.
    let rows = run(
        &bin,
        &masked("SELECT id, email, card, note FROM customers ORDER BY id"),
    );
    assert_eq!(rows.len(), VALUES.len());
    for (row, (id, v)) in rows.iter().zip(VALUES) {
        assert_eq!(row["id"], serde_json::json!(id));
        let want_email = v.map(pg_email);
        let want_card = v.map(pg_last4);
        assert_eq!(text(&row["email"]), want_email, "email of {v:?}");
        assert_eq!(text(&row["card"]), want_card, "card of {v:?}");
        // `full` hides NULL-ness too.
        assert_eq!(
            text(&row["note"]).as_deref(),
            Some("[redacted]"),
            "note of {v:?}"
        );
    }

    // Output names are the client's.
    let rows = run(
        &bin,
        &masked("SELECT email AS contact, c.note FROM customers c ORDER BY c.id"),
    );
    assert!(
        rows[0].contains_key("contact") && rows[0].contains_key("note"),
        "{:?}",
        rows[0]
    );

    // A computed value under `full` and under `email` (an aggregate keeps
    // aggregating): `[redacted]` for every value, NULL included.
    for sql in [
        "SELECT lower(note) AS n FROM customers ORDER BY id",
        "SELECT email || '!' AS n FROM customers ORDER BY id",
    ] {
        let rows = run(&bin, &masked(sql));
        assert_eq!(rows.len(), VALUES.len(), "{sql}");
        for row in &rows {
            assert_eq!(text(&row["n"]).as_deref(), Some("[redacted]"), "{sql}");
        }
    }
    let rows = run(
        &bin,
        &masked("SELECT max(note) AS m, count(*) AS n FROM customers"),
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(text(&rows[0]["m"]).as_deref(), Some("[redacted]"));
    assert_eq!(rows[0]["n"], serde_json::json!(VALUES.len()));
}
