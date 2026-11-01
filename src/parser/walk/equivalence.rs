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

use super::{Cx, from_statements_cx, not_analysed, same_column, same_column_reference};
use crate::error::MAX_AST_DEPTH;
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

// ---------------------------------------------------------------------------
// Depth guard
// ---------------------------------------------------------------------------

/// Well above `MAX_AST_DEPTH`, so that sqlparser's own recursion limit (50
/// by default, which production keeps) never stops a sweep before the walk's
/// guard: every shape below reaches `AstTooDeep` on every dialect that parses
/// it, whatever the parser counts per level.
const DEEP_PARSE_LIMIT: usize = 512;

/// The deepest nesting a boundary sweep tries. Every step of every shape
/// adds at least one walk level, so the guard is always crossed by then.
const SWEEP_MAX: usize = MAX_AST_DEPTH + 2;

/// How a walk ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Refused,
}

/// Parses `sql` with [`DEEP_PARSE_LIMIT`], walks it both ways, asserts the two
/// walks agree (records, `unread`, error) and returns how they ended, or
/// `None` when the dialect does not parse `sql` or the engine does not walk
/// what it parses to there (`not_analysed`: a parse error before any walk,
/// such as SQL Server's `BEGIN … END`).
fn deep(sql_dialect: &dyn SqlDialect, dialect: Dialect, sql: &str) -> Option<Outcome> {
    let mut statements = SqlAstParser::new(sql_dialect)
        .with_recursion_limit(DEEP_PARSE_LIMIT)
        .try_with_sql(sql)
        .and_then(|mut p| p.parse_statements())
        .ok()?;
    if statements
        .iter()
        .any(|s| not_analysed(s, dialect).is_some())
    {
        return None;
    }
    if dialect == Dialect::Snowflake {
        resolve_snowflake_order_by_all(&mut statements);
    }
    let fast = walk(statements.clone(), dialect, sql, false);
    let reference = walk(statements, dialect, sql, true);
    assert_eq!(fast, reference, "{dialect:?}: {sql}");
    if fast.starts_with("error: AstTooDeep") {
        Some(Outcome::Refused)
    } else {
        assert!(!fast.starts_with("error:"), "{dialect:?}: {sql}: {fast}");
        Some(Outcome::Accepted)
    }
}

/// `shape(k)` around the depth guard on one dialect: finds the first `k` the
/// walk refuses (both walks compared at every probe), then checks both walks
/// accept it at `k - 2` and `k - 1` and refuse it at `k`, `k + 1` and
/// `k + 2`. `None` when the dialect does not parse `shape(0)` or
/// `shape(SWEEP_MAX)` (the text reads differently there, e.g. `LIMIT 1 =
/// ANY(a)`); otherwise the first refused `k`, which must exist (the sweep has
/// to reach the guard).
fn boundary(
    shape: &dyn Fn(usize) -> String,
    sql_dialect: &dyn SqlDialect,
    dialect: Dialect,
) -> Option<usize> {
    let at = |k: usize| {
        let sql = shape(k);
        let outcome = deep(sql_dialect, dialect, &sql);
        assert!(
            outcome.is_some(),
            "{dialect:?}: parses at 0, not at {k}: {sql}"
        );
        outcome
    };
    let first = deep(sql_dialect, dialect, &shape(0))?;
    let last = deep(sql_dialect, dialect, &shape(SWEEP_MAX))?;
    if first == Outcome::Refused {
        return Some(0);
    }
    assert_eq!(
        last,
        Outcome::Refused,
        "{dialect:?}: never reaches the depth guard: {}",
        shape(SWEEP_MAX)
    );
    // Accepted at `lo`, refused at `hi`.
    let (mut lo, mut hi) = (0, SWEEP_MAX);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if at(mid) == Some(Outcome::Refused) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    for k in hi.saturating_sub(2)..=(hi + 2).min(SWEEP_MAX) {
        let expected = if k < hi {
            Outcome::Accepted
        } else {
            Outcome::Refused
        };
        assert_eq!(at(k), Some(expected), "{dialect:?}: {}", shape(k));
    }
    Some(hi)
}

/// Runs `sweep` once per dialect, each on its own thread with a large stack
/// (the deep parses and walks recurse once per level in a debug build).
fn per_dialect<T: Send>(sweep: impl Fn(&dyn SqlDialect, Dialect) -> T + Sync) -> Vec<(Dialect, T)> {
    let sweep = &sweep;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..dialects().len())
            .map(|i| {
                std::thread::Builder::new()
                    .stack_size(256 << 20)
                    .spawn_scoped(scope, move || {
                        let (sql_dialect, dialect) = dialects().into_iter().nth(i).unwrap();
                        (dialect, sweep(sql_dialect.as_ref(), dialect))
                    })
                    .unwrap()
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

/// Snowflake-specific places an expression or a query sits: `QUALIFY` (walked
/// structurally on Snowflake, by `Fast::select` elsewhere), the sources
/// `snowflake_bounded` reads (`SAMPLE (n ROWS)`, `TABLE(RESULT_SCAN(…))`),
/// scripting blocks (each statement walked one level deeper, the `EXCEPTION`
/// handlers too), `INSERT OVERWRITE`, CTAS, `COPY INTO @stage FROM (…)`.
/// Each holds `{}`.
const SNOWFLAKE_CLAUSES: &[&str] = &[
    "SELECT a FROM t QUALIFY {}",
    "SELECT a FROM t QUALIFY row_number() OVER (ORDER BY {}) = 1",
    "SELECT a FROM t QUALIFY a IN (SELECT b FROM u QUALIFY {})",
    "SELECT a FROM t SAMPLE (10 ROWS) WHERE {}",
    "SELECT {} FROM t SAMPLE (10 ROWS)",
    "SELECT a FROM t SAMPLE (10) WHERE {}",
    "SELECT a FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) WHERE {}",
    "SELECT a FROM TABLE(RESULT_SCAN({}))",
    "BEGIN SELECT {} FROM t; END",
    "BEGIN UPDATE t SET a = {} WHERE b = 1; END",
    "BEGIN SELECT 1; EXCEPTION WHEN OTHER THEN DELETE FROM t WHERE a = {}; END",
    "BEGIN BEGIN INSERT INTO t (a) VALUES ({}); END; END",
    "INSERT OVERWRITE INTO t SELECT {} FROM u",
    "CREATE OR REPLACE TABLE c AS SELECT {} FROM t",
    "COPY INTO @s FROM (SELECT {} FROM t)",
    "SELECT a FROM t ORDER BY ALL LIMIT {}",
];

/// Statements around the depth guard: each shape nested `k` times, for every
/// `k` up to past the point where the walk refuses it (`AstTooDeep`). The
/// first refused depth must be the same, and every shape must get there on
/// every dialect that parses it.
#[test]
fn depth_guard_walks_as_in_4_7_0() {
    type Shape = fn(usize) -> String;
    let mut shapes: Vec<Box<dyn Fn(usize) -> String + Sync>> = vec![];
    let plain: &[Shape] = &[
        |k| format!("SELECT {}1{}", "f(".repeat(k), ")".repeat(k)),
        |k| {
            format!(
                "SELECT a FROM t WHERE {}a{} = 1",
                "(".repeat(k),
                ")".repeat(k)
            )
        },
        // Spaced: `--` would open a comment.
        |k| format!("SELECT a FROM t WHERE a = {}1", "- ".repeat(k)),
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
                // `IN (1)`: the 4.7.1 form of this shape (`IN 1`) never
                // parsed, so it compared nothing.
                "SELECT a FROM t WHERE a IN {}(1){}",
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
        // Snowflake: nested scripting blocks, and QUALIFY over nested
        // subqueries that QUALIFY in turn.
        |k| format!("{}SELECT 1;{}", "BEGIN ".repeat(k), " END;".repeat(k)),
        |k| {
            format!(
                "SELECT a FROM t QUALIFY a IN {}(1){}",
                "(SELECT b FROM u QUALIFY b IN ".repeat(k),
                ")".repeat(k)
            )
        },
    ];
    shapes.extend(
        plain
            .iter()
            .map(|s| Box::new(*s) as Box<dyn Fn(usize) -> String + Sync>),
    );
    for clause in SNOWFLAKE_CLAUSES {
        shapes.push(Box::new(move |k| {
            clause.replace("{}", &format!("{}a{}", "abs(".repeat(k), ")".repeat(k)))
        }));
    }
    let results = per_dialect(|sql_dialect, dialect| {
        let mut reached = vec![false; shapes.len()];
        for (i, shape) in shapes.iter().enumerate() {
            let mut parsed = false;
            for k in 1..=60 {
                let outcome = deep(sql_dialect, dialect, &shape(k));
                match outcome {
                    Some(Outcome::Refused) => reached[i] = true,
                    Some(Outcome::Accepted) => {
                        assert!(
                            !reached[i],
                            "{dialect:?}: accepted past the guard: {}",
                            shape(k)
                        );
                    }
                    None => assert!(!parsed, "{dialect:?}: stopped parsing at {k}: {}", shape(k)),
                }
                parsed |= outcome.is_some();
            }
            assert!(
                !parsed || reached[i],
                "{dialect:?}: never reached the depth guard: {}",
                shape(60)
            );
        }
        reached
    });
    // Every shape reaches the guard on at least one dialect (the Snowflake
    // ones on Snowflake).
    for (i, shape) in shapes.iter().enumerate() {
        assert!(
            results.iter().any(|(_, reached)| reached[i]),
            "no dialect reached the guard: {}",
            shape(1)
        );
        if i >= plain.len() - 2 {
            assert!(
                results
                    .iter()
                    .any(|(d, reached)| *d == Dialect::Snowflake && reached[i]),
                "Snowflake did not reach the guard: {}",
                shape(1)
            );
        }
    }
}

/// The guard at its exact boundary: `s` nested subqueries around `k` nested
/// calls, innermost a leaf, a call without arguments or a call over `*`, so
/// that every kind of expression is, for some `(s, k)`, the deepest node. On
/// every dialect, and on the Snowflake-specific clauses.
#[test]
fn depth_guard_boundary_walks_as_in_4_7_0() {
    const INNERMOST: [&str; 6] = ["a", "now()", "count(*)", "CURRENT_TIMESTAMP", "(a)", "-a"];
    let results = per_dialect(|sql_dialect, dialect| {
        for innermost in INNERMOST {
            let mut transitions = 0;
            for s in 0..=16 {
                let mut previous = None;
                for k in 0..=48 {
                    let sql = format!(
                        "SELECT {}{}{innermost}{}{} FROM t",
                        "(SELECT ".repeat(s),
                        "abs(".repeat(k),
                        ")".repeat(k),
                        " FROM t)".repeat(s)
                    );
                    let outcome = deep(sql_dialect, dialect, &sql)
                        .unwrap_or_else(|| panic!("{dialect:?} does not parse {sql}"));
                    if previous == Some(Outcome::Refused) {
                        assert_eq!(outcome, Outcome::Refused, "{dialect:?}: {sql}");
                    }
                    if previous == Some(Outcome::Accepted) && outcome == Outcome::Refused {
                        transitions += 1;
                    }
                    previous = Some(outcome);
                }
                assert_eq!(previous, Some(Outcome::Refused), "{dialect:?}: s = {s}");
            }
            assert!(transitions > 0, "{dialect:?}: {innermost}: no boundary met");
        }
        // The Snowflake-specific clauses, each around nested calls and
        // around nested subqueries, with the guard met by each innermost kind.
        let mut met = 0;
        for clause in SNOWFLAKE_CLAUSES {
            for innermost in INNERMOST {
                let calls = |k: usize| {
                    clause.replace(
                        "{}",
                        &format!("{}{innermost}{}", "abs(".repeat(k), ")".repeat(k)),
                    )
                };
                let queries = |k: usize| {
                    clause.replace(
                        "{}",
                        &format!("{}{innermost}{}", "(SELECT ".repeat(k), ")".repeat(k)),
                    )
                };
                for shape in [&calls as &dyn Fn(usize) -> String, &queries] {
                    met += boundary(shape, sql_dialect, dialect).is_some() as usize;
                }
            }
        }
        met
    });
    for (dialect, met) in results {
        if dialect == Dialect::Snowflake {
            // Every clause, every innermost kind, both shapes.
            assert_eq!(met, SNOWFLAKE_CLAUSES.len() * 6 * 2);
        }
    }
}

/// Expression kinds `Fast` does not model (they fall into the last arm of
/// `Fast::inner_expr` and go to the generic visit, `walk_rest_at`, at the
/// same depth and nesting), with the `Expr` variant each one parses to.
/// Each holds `{}`, its operand.
const FALLBACK_KINDS: &[(&str, &str)] = &[
    ("Cast", "CAST({} AS INT)"),
    ("Cast", "{}::INT"),
    ("Cast", "TRY_CAST({} AS INT)"),
    ("Substring", "SUBSTRING({} FROM 1 FOR 2)"),
    ("Substring", "SUBSTRING('abc', {}, 2)"),
    ("Trim", "TRIM({})"),
    ("Trim", "TRIM(BOTH {} FROM 'x')"),
    ("Extract", "EXTRACT(YEAR FROM {})"),
    ("Ceil", "CEIL({} TO DAY)"),
    ("Floor", "FLOOR({} TO DAY)"),
    ("Position", "POSITION({} IN 'a')"),
    ("Overlay", "OVERLAY({} PLACING 'b' FROM 1)"),
    ("Collate", "{} COLLATE \"C\""),
    ("AtTimeZone", "{} AT TIME ZONE 'UTC'"),
    ("Interval", "INTERVAL {} DAY"),
    ("SimilarTo", "{} SIMILAR TO 'a'"),
    ("RLike", "{} RLIKE 'a'"),
    ("Array", "ARRAY[{}]"),
    ("CompoundFieldAccess", "({})[1]"),
    ("CompoundFieldAccess", "({}).f"),
    ("JsonAccess", "{}:k"),
    ("AnyOp", "1 = ANY({})"),
    ("AllOp", "1 = ALL({})"),
    ("Convert", "CONVERT({}, CHAR)"),
    ("Convert", "CONVERT(INT, {})"),
    ("MemberOf", "{} MEMBER OF('[1]')"),
    ("IsNormalized", "{} IS NORMALIZED"),
    ("IsJson", "{} IS JSON"),
    ("InUnnest", "{} IN UNNEST([1])"),
    ("Struct", "STRUCT({} AS f)"),
    ("Dictionary", "{'k': {}}"),
    ("Map", "MAP {'k': {}}"),
];

/// Every clause `Fast` walks (or hands to the generic visit) an expression
/// in, on the dialects that have it. Each holds `{}`.
const CLAUSES: &[&str] = &[
    "SELECT {} FROM t",
    "SELECT {} AS x FROM t",
    "SELECT a FROM t WHERE {}",
    "SELECT a FROM t GROUP BY {}",
    "SELECT a FROM t GROUP BY a HAVING {}",
    "SELECT a FROM t ORDER BY {}",
    "SELECT a FROM t LIMIT {}",
    "SELECT a FROM t LIMIT 1 OFFSET {}",
    "SELECT a FROM t LIMIT {}, 1",
    "SELECT a FROM t OFFSET {} ROWS FETCH FIRST 1 ROWS ONLY",
    "SELECT a FROM t JOIN u ON {}",
    "SELECT a FROM t, u WHERE t.id = u.id AND {}",
    "SELECT a FROM t QUALIFY {}",
    "SELECT count(*) FILTER (WHERE {}) FROM t",
    "SELECT sum(a) OVER (PARTITION BY {}) FROM t",
    "SELECT f(a, {}) FROM t",
    "SELECT CASE WHEN {} THEN 1 ELSE 2 END FROM t",
    "SELECT a FROM t WHERE a IN (SELECT b FROM u WHERE {})",
    "SELECT a FROM t WHERE EXISTS (SELECT 1 FROM u WHERE {})",
    "SELECT * FROM (SELECT {} AS x FROM t) AS s",
    "WITH c AS (SELECT {} AS x FROM t) SELECT * FROM c",
    "SELECT a FROM t UNION SELECT {} FROM u",
    "SELECT TOP 1 {} FROM t",
    "SELECT {} INTO c FROM t",
    "SELECT * FROM (VALUES ({})) AS v (x)",
    "UPDATE t SET a = {} WHERE b = 1",
    "UPDATE t SET a = 1 WHERE {}",
    "UPDATE t SET a = 1 FROM u WHERE t.id = u.id AND {}",
    "UPDATE t SET a = 1 WHERE b = 1 RETURNING {}",
    "UPDATE t SET a = 1 WHERE b = 1 ORDER BY {} LIMIT 1",
    "DELETE FROM t WHERE {}",
    "DELETE FROM t USING u WHERE t.id = u.id AND {}",
    "DELETE FROM t WHERE b = 1 RETURNING {}",
    "DELETE FROM t WHERE b = 1 ORDER BY {} LIMIT 1",
    "INSERT INTO t (a) VALUES ({})",
    "INSERT INTO t (a, b) VALUES (1, 2), ({}, 3)",
    "INSERT INTO t SET a = {}",
    "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = {}",
    "INSERT INTO t (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = {}",
    "INSERT INTO t (a) VALUES (1) RETURNING {}",
    "INSERT INTO t (a) SELECT {} FROM u",
    "MERGE INTO t USING u ON t.id = u.id WHEN MATCHED THEN UPDATE SET a = {}",
    "CREATE TABLE c AS SELECT {} FROM t",
];

/// The fallback of `Fast::inner_expr` at the depth guard: each kind
/// `Fast` does not model, in every clause, on every dialect that parses it,
/// both as the node that crosses `MAX_AST_DEPTH` and as the parent of the
/// one that does. Two sweeps per (kind, clause, dialect): the kind once,
/// below `m` modelled calls (`abs(…)`), for each innermost operand (a column,
/// a subquery, a call), so that the hand-over happens at every depth; and
/// the kind nested in itself `k` times, all of it in the generic visit. Both
/// walks must agree at every probe, and the guard must be met (accepted
/// just below, refused at and just above).
#[test]
fn fallback_kinds_at_the_depth_guard_walk_as_in_4_7_0() {
    let clauses: Vec<&str> = CLAUSES.iter().chain(SNOWFLAKE_CLAUSES).copied().collect();
    let results = per_dialect(|sql_dialect, dialect| {
        // Per kind: (series swept, series of the kind nested in itself).
        let mut swept = vec![(0usize, 0usize); FALLBACK_KINDS.len()];
        for (i, (variant, kind)) in FALLBACK_KINDS.iter().enumerate() {
            // The kind parses to the variant the last arm receives.
            let probe = format!("SELECT {} FROM t", kind.replace("{}", "a"));
            let Some(Statement::Query(query)) = SqlAstParser::parse_sql(sql_dialect, &probe)
                .ok()
                .and_then(|mut s| s.pop())
            else {
                continue;
            };
            let sqlparser::ast::SetExpr::Select(select) = query.body.as_ref() else {
                panic!("{probe}");
            };
            // Another dialect's reading of the text (an alias, a function)
            // is not this kind there.
            let sqlparser::ast::SelectItem::UnnamedExpr(expr) = &select.projection[0] else {
                continue;
            };
            let debug = format!("{expr:?}");
            if !(debug.starts_with(&format!("{variant}("))
                || debug.starts_with(&format!("{variant} {{")))
            {
                continue;
            }
            for clause in &clauses {
                for innermost in ["a", "(SELECT b FROM u)", "now()"] {
                    let below_calls = |m: usize| {
                        clause.replace(
                            "{}",
                            &format!(
                                "{}{}{}",
                                "abs(".repeat(m),
                                kind.replace("{}", innermost),
                                ")".repeat(m)
                            ),
                        )
                    };
                    swept[i].0 += boundary(&below_calls, sql_dialect, dialect).is_some() as usize;
                }
                let nested = |k: usize| {
                    let mut e = "a".to_string();
                    for _ in 0..k {
                        e = kind.replace("{}", &e);
                    }
                    clause.replace("{}", &e)
                };
                // A kind the dialect does not parse nested in itself (or
                // past sqlparser's own limits) is swept by the first form
                // only.
                let deepest_parses = deep(sql_dialect, dialect, &nested(SWEEP_MAX)).is_some();
                if deepest_parses && boundary(&nested, sql_dialect, dialect).is_some() {
                    swept[i].1 += 1;
                }
            }
        }
        swept
    });
    for (i, (variant, kind)) in FALLBACK_KINDS.iter().enumerate() {
        let (below, nested) = results
            .iter()
            .fold((0, 0), |(b, n), (_, s)| (b + s[i].0, n + s[i].1));
        assert!(below > 0, "{variant} `{kind}` never swept");
        // sqlparser does not read these nested in themselves (`a COLLATE
        // "C" COLLATE "C"`, `ANY(1 = ANY(a))`): swept below calls only.
        let self_nests = !matches!(*variant, "Collate" | "AnyOp" | "AllOp");
        assert_eq!(nested > 0, self_nests, "{variant} `{kind}`: {nested}");
    }
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
