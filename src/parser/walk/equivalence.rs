// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The targeted walk (`Fast`, 4.7.1) against the 4.7.0 walk it replaces.
//!
//! `Cx::reference` keeps the 4.7.0 code path in the build for tests: every
//! clause walked by `walk_rest` alone, sqlparser's generic visit of every
//! field. Both walks run over the same parsed statements (the repository's
//! corpora, every SQL string literal of the test suites, generated statements
//! and a depth sweep up to the `MAX_AST_DEPTH` guard), on every sqlparser
//! dialect, and must produce the same `StatementInfo` records in the same
//! order, the same `unread` note, or the same error. The helpers 4.7.1 made
//! allocation-free (`SqlNumber::parse`, `same_column`) are checked against
//! their 4.7.0 forms the same way.

use proptest::prelude::*;
use sqlparser::ast::Statement;
use sqlparser::dialect::{
    Dialect as SqlDialect, GenericDialect, MsSqlDialect, MySqlDialect, PostgreSqlDialect,
    SQLiteDialect, SnowflakeDialect,
};
use sqlparser::parser::Parser as SqlAstParser;

use super::{Cx, from_statements_cx, same_column, same_column_reference};
use crate::parser::{Dialect, SqlNumber, resolve_snowflake_order_by_all};

/// Every dialect the sqlparser walker serves (Postgres runs on libpg_query in
/// production; its sqlparser dialect is walked here for the extra shapes).
fn dialects() -> [(Box<dyn SqlDialect>, Dialect); 6] {
    [
        (Box::new(MySqlDialect {}), Dialect::Mysql),
        (Box::new(PostgreSqlDialect {}), Dialect::Postgres),
        (Box::new(MsSqlDialect {}), Dialect::MsSql),
        (Box::new(GenericDialect {}), Dialect::Oracle),
        (Box::new(SnowflakeDialect {}), Dialect::Snowflake),
        (Box::new(SQLiteDialect {}), Dialect::Sqlite),
    ]
}

/// The walk's whole output: the records (every field, through `Debug`), the
/// unread note, or the error.
fn walk(statements: Vec<Statement>, dialect: Dialect, sql: &str, reference: bool) -> String {
    let cx = Cx { dialect, reference };
    match from_statements_cx(statements, cx, sql) {
        Ok(parsed) => format!("{:?} unread={:?}", parsed.statements, parsed.unread),
        Err(e) => format!("error: {e:?}"),
    }
}

/// Parses `sql` on every dialect and compares both walks wherever it parses.
/// Returns how many (statement text, dialect) pairs were compared.
fn check(sql: &str) -> usize {
    let mut compared = 0;
    for (sql_dialect, dialect) in dialects() {
        let Ok(mut statements) = SqlAstParser::parse_sql(sql_dialect.as_ref(), sql) else {
            continue;
        };
        if dialect == Dialect::Snowflake {
            resolve_snowflake_order_by_all(&mut statements);
        }
        let fast = walk(statements.clone(), dialect, sql, false);
        let reference = walk(statements, dialect, sql, true);
        assert_eq!(fast, reference, "{dialect:?}: {sql}");
        compared += 1;
    }
    compared
}

/// The entries of a `----`-separated corpus file (each after its `-- source:`
/// line).
fn corpus_entries(corpus: &str) -> impl Iterator<Item = String> + '_ {
    corpus
        .split("\n----\n")
        .skip(1)
        .map(|chunk| chunk.lines().skip(1).collect::<Vec<_>>().join("\n"))
}

/// The string literals of a Rust source file (`"…"` with its escapes,
/// `r"…"`, `r#"…"#`): the SQL the test suites send.
fn string_literals(source: &str) -> Vec<String> {
    let b = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            // A comment runs to the end of its line.
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            // A char literal such as '"' must not open a string.
            b'\'' if b.get(i + 2) == Some(&b'\'') => i += 3,
            b'\'' if b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'') => i += 4,
            b'r' if matches!(b.get(i + 1), Some(b'"' | b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
                let start = i + 1 + hashes;
                if b.get(start) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                match source[start + 1..].find(&close) {
                    Some(len) => {
                        out.push(source[start + 1..start + 1 + len].to_string());
                        i = start + 1 + len + close.len();
                    }
                    None => break,
                }
            }
            b'"' => {
                let mut text = String::new();
                let mut j = i + 1;
                let mut chars = source[j..].char_indices();
                loop {
                    let Some((k, c)) = chars.next() else {
                        j = b.len();
                        break;
                    };
                    match c {
                        '"' => {
                            j += k + 1;
                            break;
                        }
                        '\\' => match chars.next() {
                            Some((_, 'n')) => text.push('\n'),
                            Some((_, 't')) => text.push('\t'),
                            Some((_, 'r')) => text.push('\r'),
                            Some((_, '0')) => text.push('\0'),
                            // A line continuation drops the newline and the
                            // indentation after it.
                            Some((_, '\n')) => {
                                let rest = &source[j + k + 2..];
                                let skip = rest.len() - rest.trim_start().len();
                                for _ in 0..rest[..skip].chars().count() {
                                    chars.next();
                                }
                            }
                            Some((_, other)) => text.push(other),
                            None => {}
                        },
                        other => text.push(other),
                    }
                }
                out.push(text);
                i = j;
            }
            _ => i += 1,
        }
    }
    out
}

#[test]
fn corpora_walk_as_in_4_7_0() {
    let mut compared = 0;
    for corpus in [
        include_str!("../../../tests/fixtures/snowflake_corpus.sql"),
        include_str!("../../../tests/fixtures/sqlite_corpus.sql"),
    ] {
        for sql in corpus_entries(corpus) {
            compared += check(&sql);
        }
    }
    assert!(compared > 3_000, "corpora not read: {compared}");
}

#[test]
fn test_suite_statements_walk_as_in_4_7_0() {
    let sources = [
        include_str!("../../../tests/access_conformance.rs"),
        include_str!("../../../tests/audit.rs"),
        include_str!("../../../tests/custom_rule_yaml.rs"),
        include_str!("../../../tests/limit_equivalence.rs"),
        include_str!("../../../tests/mask_equivalence.rs"),
        include_str!("../../../tests/mysql_lexical.rs"),
        include_str!("../../../tests/mysql_mask.rs"),
        include_str!("../../../tests/mysql_mask_equivalence.rs"),
        include_str!("../../../tests/mysql_orm_corpus.rs"),
        include_str!("../../../tests/nesting_dos.rs"),
        include_str!("../../../tests/policy_checker.rs"),
        include_str!("../../../tests/policy_compat.rs"),
        include_str!("../../../tests/policy_determinism.rs"),
        include_str!("../../../tests/policy_parity.rs"),
        include_str!("../../../tests/policy_rewrite.rs"),
        include_str!("../../../tests/policy_robustness.rs"),
        include_str!("../../../tests/policy_semantics.rs"),
        include_str!("../../../tests/readme_examples.rs"),
        include_str!("../../../tests/snowflake.rs"),
        include_str!("../../../tests/sqlite.rs"),
        include_str!("../../../tests/sqlite_mask_equivalence.rs"),
        include_str!("../../../tests/sqlparser_upgrade.rs"),
        include_str!("../../../tests/winning_action.rs"),
        include_str!("../../../benches/policy.rs"),
        include_str!("../../rules/properties.rs"),
        include_str!("../walk.rs"),
        include_str!("../mod.rs"),
    ];
    let mut compared = 0;
    for source in sources {
        for sql in string_literals(source) {
            compared += check(&sql);
        }
    }
    assert!(compared > 5_000, "test statements not read: {compared}");
}

/// Statements around the depth guard: each shape nested `k` times, for every
/// `k` up to past the point where the walk refuses it (`AstTooDeep`). The
/// first refused depth must be the same.
#[test]
fn depth_guard_walks_as_in_4_7_0() {
    type Shape = fn(usize) -> String;
    let shapes: &[Shape] = &[
        |k| format!("SELECT {}1{}", "f(".repeat(k), ")".repeat(k)),
        |k| {
            format!(
                "SELECT a FROM t WHERE {}a{} = 1",
                "(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| format!("SELECT a FROM t WHERE a = {}1", "-".repeat(k)),
        |k| format!("SELECT {}1{}", "(SELECT ".repeat(k), ")".repeat(k)),
        |k| {
            format!(
                "SELECT * FROM {}t{}",
                "(SELECT * FROM ".repeat(k),
                ") AS x".repeat(k)
            )
        },
        |k| {
            format!(
                "SELECT a FROM t WHERE a IN {}1{}",
                "(SELECT b FROM u WHERE b IN ".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "UPDATE t SET a = {}1{} WHERE b = 1",
                "abs(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "INSERT INTO t (a) VALUES ({}1{})",
                "lower(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "DELETE FROM t WHERE a = {}1{}",
                "abs(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "SELECT a FROM t ORDER BY {}a{}",
                "abs(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "SELECT a FROM t LIMIT {}1{}",
                "abs(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "SELECT {}1{}",
                "CASE WHEN f(1) THEN ".repeat(k),
                " END".repeat(k)
            )
        },
        |k| {
            format!(
                "SELECT a FROM t JOIN u ON u.id = {}t.id{}",
                "abs(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "SELECT a FROM t GROUP BY a HAVING count(*) > {}1{}",
                "abs(".repeat(k),
                ")".repeat(k)
            )
        },
        |k| {
            format!(
                "WITH c AS ({}SELECT 1{}) SELECT * FROM c",
                "SELECT * FROM (".repeat(k),
                ") AS x".repeat(k)
            )
        },
    ];
    let mut refused = 0;
    for shape in shapes {
        for k in 1..=60 {
            let sql = shape(k);
            for (sql_dialect, dialect) in dialects() {
                // Past sqlparser's own recursion limit nothing parses.
                let Ok(statements) = SqlAstParser::parse_sql(sql_dialect.as_ref(), &sql) else {
                    continue;
                };
                let fast = walk(statements.clone(), dialect, &sql, false);
                let reference = walk(statements, dialect, &sql, true);
                assert_eq!(fast, reference, "{dialect:?}: {sql}");
                refused += fast.starts_with("error: AstTooDeep") as usize;
            }
        }
    }
    assert!(refused > 0, "the sweep never reached the depth guard");
}

/// The guard at its exact boundary: `s` nested subqueries around `k` nested
/// calls, innermost a leaf, a call without arguments or a call over `*`, so
/// that every kind of expression is, for some `(s, k)`, the deepest node.
#[test]
fn depth_guard_boundary_walks_as_in_4_7_0() {
    let mut refused = 0;
    let mut accepted = 0;
    for innermost in ["a", "now()", "count(*)", "CURRENT_TIMESTAMP", "(a)", "-a"] {
        for s in 0..=16 {
            for k in 0..=48 {
                let sql = format!(
                    "SELECT {}{}{innermost}{}{} FROM t",
                    "(SELECT ".repeat(s),
                    "abs(".repeat(k),
                    ")".repeat(k),
                    " FROM t)".repeat(s)
                );
                let (sql_dialect, dialect) = (MySqlDialect {}, Dialect::Mysql);
                let Ok(statements) = SqlAstParser::parse_sql(&sql_dialect, &sql) else {
                    continue;
                };
                let fast = walk(statements.clone(), dialect, &sql, false);
                let reference = walk(statements, dialect, &sql, true);
                assert_eq!(fast, reference, "{sql}");
                if fast.starts_with("error: AstTooDeep") {
                    refused += 1;
                } else {
                    accepted += 1;
                }
            }
        }
    }
    assert!(
        refused > 0 && accepted > 0,
        "{refused} refused, {accepted} accepted"
    );
}

// ---------------------------------------------------------------------------
// Generated statements
// ---------------------------------------------------------------------------

fn leaf() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("a".to_string()),
        Just("t.b".to_string()),
        Just("\"Q\".c".to_string()),
        Just("1".to_string()),
        Just("-2.50".to_string()),
        Just("1e3".to_string()),
        Just("'x'".to_string()),
        Just("NULL".to_string()),
        Just("TRUE".to_string()),
        Just("?".to_string()),
        Just("CURRENT_TIMESTAMP".to_string()),
        Just("now()".to_string()),
        Just("count(*)".to_string()),
        Just("(SELECT max(z) FROM v)".to_string()),
    ]
}

fn expr() -> impl Strategy<Value = String> {
    leaf().prop_recursive(5, 48, 3, |inner| {
        let i = || inner.clone();
        prop_oneof![
            (i(), i()).prop_map(|(a, b)| format!("{a} = {b}")),
            (i(), i()).prop_map(|(a, b)| format!("({a} OR {b})")),
            (i(), i()).prop_map(|(a, b)| format!("{a} AND {b}")),
            (i(), i()).prop_map(|(a, b)| format!("{a} + {b}")),
            i().prop_map(|a| format!("NOT ({a})")),
            i().prop_map(|a| format!("-({a})")),
            i().prop_map(|a| format!("({a}) IS NULL")),
            i().prop_map(|a| format!("({a}) IS NOT TRUE")),
            (i(), i()).prop_map(|(a, b)| format!("{a} IS DISTINCT FROM {b}")),
            (i(), i(), i()).prop_map(|(a, b, c)| format!("{a} IN ({b}, {c})")),
            (i(), i()).prop_map(|(a, b)| format!("{a} NOT IN (SELECT {b} FROM u)")),
            (i(), i(), i()).prop_map(|(a, b, c)| format!("{a} BETWEEN {b} AND {c}")),
            (i(), i()).prop_map(|(a, b)| format!("{a} LIKE {b}")),
            i().prop_map(|a| format!("EXISTS (SELECT 1 FROM u WHERE {a})")),
            i().prop_map(|a| format!("(SELECT {a})")),
            (i(), i()).prop_map(|(a, b)| format!("f({a}, {b})")),
            i().prop_map(|a| format!("sleep({a})")),
            i().prop_map(|a| format!("upper(lower({a}))")),
            i().prop_map(|a| format!("count(DISTINCT {a})")),
            (i(), i()).prop_map(|(a, b)| format!("sum({a}) OVER (PARTITION BY {b} ORDER BY a)")),
            (i(), i(), i()).prop_map(|(a, b, c)| format!("CASE WHEN {a} THEN {b} ELSE {c} END")),
            (i(), i()).prop_map(|(a, b)| format!("CASE {a} WHEN 1 THEN {b} END")),
            i().prop_map(|a| format!("CAST({a} AS INT)")),
            i().prop_map(|a| format!("COALESCE({a}, 0)")),
            i().prop_map(|a| format!("({a}, 1)")),
            i().prop_map(|a| format!("SUBSTRING({a} FROM 1 FOR 2)")),
            i().prop_map(|a| format!("TRIM({a})")),
            i().prop_map(|a| format!("EXTRACT(YEAR FROM {a})")),
            i().prop_map(|a| format!("{a} COLLATE \"C\"")),
            i().prop_map(|a| format!("INTERVAL '1' DAY + {a}")),
        ]
    })
}

fn statement() -> impl Strategy<Value = String> {
    let e = expr;
    prop_oneof![
        (e(), e(), e()).prop_map(|(a, b, c)| format!("SELECT {a}, {b} AS x FROM t WHERE {c}")),
        (e(), e(), e(), e()).prop_map(|(a, b, c, d)| format!(
            "SELECT {a} FROM t JOIN u ON {b} LEFT JOIN (SELECT {c} AS y FROM w) AS s ON s.y = t.a \
             WHERE {d} GROUP BY a HAVING {a} ORDER BY {b} DESC LIMIT 10 OFFSET 2"
        )),
        (e(), e()).prop_map(|(a, b)| format!(
            "WITH c AS (SELECT {a} AS v FROM t) SELECT * FROM c WHERE v = ({b}) LIMIT 5"
        )),
        (e(), e()).prop_map(|(a, b)| format!("SELECT {a} FROM t UNION SELECT {b} FROM u")),
        (e(), e()).prop_map(|(a, b)| format!("SELECT DISTINCT {a} FROM t ORDER BY {b}")),
        (e(), e(), e()).prop_map(|(a, b, c)| format!("UPDATE t SET a = {a}, b = {b} WHERE {c}")),
        (e(), e()).prop_map(|(a, b)| format!(
            "UPDATE t SET a = {a} FROM (SELECT {b} AS x) AS s WHERE t.id = s.x"
        )),
        (e(), e()).prop_map(|(a, b)| format!("DELETE FROM t WHERE {a} AND b IN (SELECT {b})")),
        (e(), e()).prop_map(|(a, b)| format!(
            "DELETE FROM t USING u WHERE t.id = u.id AND {a} RETURNING {b}"
        )),
        (e(), e()).prop_map(|(a, b)| format!("INSERT INTO t (a, b) VALUES ({a}, {b}), (1, 2)")),
        (e(), e()).prop_map(|(a, b)| format!("INSERT INTO t (a) SELECT {a} FROM u WHERE {b}")),
        (e(), e()).prop_map(|(a, b)| format!(
            "INSERT INTO t (a) VALUES ({a}) ON CONFLICT (a) DO UPDATE SET a = {b} RETURNING a"
        )),
        (e(), e()).prop_map(|(a, b)| format!(
            "INSERT INTO t (a) VALUES ({a}) ON DUPLICATE KEY UPDATE a = {b}"
        )),
        e().prop_map(|a| format!("SET @x = {a}")),
        (e(), e()).prop_map(|(a, b)| format!(
            "MERGE INTO t USING u ON t.id = u.id WHEN MATCHED THEN UPDATE SET a = {a} \
             WHEN NOT MATCHED THEN INSERT (a) VALUES ({b})"
        )),
        e().prop_map(|a| format!("SELECT TOP 5 {a} FROM t")),
        e().prop_map(|a| format!("SELECT {a} FROM t QUALIFY row_number() OVER (ORDER BY a) = 1")),
        e().prop_map(|a| format!("EXPLAIN ANALYZE SELECT {a} FROM t")),
        e().prop_map(|a| format!("CREATE TABLE c AS SELECT {a} FROM t")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn generated_statements_walk_as_in_4_7_0(sql in statement()) {
        check(&sql);
    }

    #[test]
    fn sql_number_parse_matches_reference(
        text in prop_oneof![
            "[+-]?[0-9]{0,24}(\\.[0-9]{0,24})?([eE][+-]?[0-9]{0,4})?",
            "[0-9eE.+-]{0,10}",
            "[+-]?0*[0-9]{0,3}0*(\\.0*[0-9]{0,3}0*)?[eE][+-]?[0-9]{1,9}",
            ".{0,6}",
        ]
    ) {
        prop_assert_eq!(SqlNumber::parse(&text), SqlNumber::parse_reference(&text), "{}", text);
    }

    #[test]
    fn same_column_matches_reference(
        left in prop_oneof![leaf(), COLUMN, QUOTED_COLUMN],
        right in prop_oneof![leaf(), COLUMN, QUOTED_COLUMN],
    ) {
        let parse = |s: &str| {
            SqlAstParser::new(&GenericDialect {})
                .try_with_sql(s)
                .and_then(|mut p| p.parse_expr())
        };
        if let (Ok(l), Ok(r)) = (parse(&left), parse(&right)) {
            prop_assert_eq!(same_column(&l, &r), same_column_reference(&l, &r));
        }
    }
}

/// Column references for `same_column`: plain and qualified names, and
/// quoted names holding a `.` (the 4.7.0 form compared the parts joined by
/// `.`, so `"a.b"` and `a.b` are the same column to it).
const COLUMN: &str = "\\(?[aAbB](\\.[aAbB]){0,2}\\)?";
const QUOTED_COLUMN: &str = "\\(?\"[aAbB.]{0,4}\"(\\.[aAbB]){0,2}\\)?";

#[test]
fn same_column_matches_reference_on_edges() {
    let parse = |s: &str| {
        SqlAstParser::new(&GenericDialect {})
            .try_with_sql(s)
            .and_then(|mut p| p.parse_expr())
            .expect(s)
    };
    let names = [
        "a",
        "A",
        "\"a\"",
        "a.b",
        "A.B",
        "\"a.b\"",
        "\"a\".b",
        "(a.b)",
        "((a))",
        "ab",
        "a.b.c",
        "\"a.b\".c",
        "\"\"",
        "1",
        "f(a)",
    ];
    for l in names {
        for r in names {
            let (left, right) = (parse(l), parse(r));
            assert_eq!(
                same_column(&left, &right),
                same_column_reference(&left, &right),
                "{l} = {r}"
            );
        }
    }
}

/// The numbers the 4.7.0 tests name, and the edges of the grammar.
#[test]
fn sql_number_parse_matches_reference_on_edges() {
    for text in [
        "",
        "0",
        "-0",
        "+0",
        "00",
        "0.0",
        ".0",
        "0.",
        ".",
        "1",
        "-1",
        "10",
        "100",
        "1.50",
        "001.2300",
        "1e3",
        "1E3",
        "1e+3",
        "1e-3",
        "1e",
        "1e+",
        "e3",
        "1e3e4",
        "1.2.3",
        "1..2",
        "9007199254740993",
        "1e999999999999",
        "-0.000e10",
        "12a",
        "١",
        "1_000",
        "+-1",
        "--1",
    ] {
        assert_eq!(
            SqlNumber::parse(text),
            SqlNumber::parse_reference(text),
            "{text}"
        );
    }
}
