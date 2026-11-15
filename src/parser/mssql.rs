// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Parser AST para Microsoft SQL Server (T-SQL).
//!
//! Uses `sqlparser-rs` with `MsSqlDialect`, which handles T-SQL specifics
//! such as square-bracket identifier quoting ([TableName]), TOP N clauses,
//! and GO batch separators.
//!
//! `DELETE TOP (n)` and `UPDATE TOP (n)` are read here, because sqlparser
//! (0.63, and 0.64) does not: `DELETE TOP (10) FROM t` was a parse error, and
//! `UPDATE TOP (10) t SET …` parsed as an update of a table-valued function
//! named `TOP` aliased `t`, so every analysis that reads the target (agent
//! allowlists, sensitive columns, the suggested fix) saw a table `TOP`. The
//! clause is blanked out before parsing (same number of characters, so every
//! later location is unchanged; `FROM` takes its place when T-SQL's optional
//! `FROM` was left out), and `DELETE TOP (n)`'s row count is recorded as
//! `DELETE … LIMIT n` is on MySQL. A bound is not a filter: `DELETE TOP (10)
//! FROM t` without `WHERE` is VERICTO-001 like `DELETE FROM t LIMIT 10`, and
//! `DELETE TOP (0)` is VERICTO-002 like `LIMIT 0`. `TOP (n) PERCENT` records
//! no row count. T-SQL requires the parentheses in `DELETE` / `UPDATE`, so
//! `DELETE TOP 10` stays the parse error SQL Server makes of it.

use crate::error::Result;
use crate::parser::walk::{RowBound, parse_text_bounded, parse_with_dialect};
use crate::parser::{ParsedQuery, SqlParser, byte_offsets};

use sqlparser::dialect::MsSqlDialect;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer};

pub struct MsSqlParser {
    dialect: MsSqlDialect,
}

impl MsSqlParser {
    pub fn new() -> Self {
        Self {
            dialect: MsSqlDialect {},
        }
    }
}

impl Default for MsSqlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for MsSqlParser {
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        let clauses = top_clauses(&self.dialect, sql);
        if clauses.is_empty() {
            return parse_with_dialect(&self.dialect, crate::parser::Dialect::MsSql, sql);
        }
        let text = without_top_clauses(sql, &clauses);
        let bounds: Vec<RowBound> = clauses
            .iter()
            .filter_map(|c| {
                c.rows.map(|rows| RowBound {
                    keyword: c.keyword,
                    rows,
                })
            })
            .collect();
        parse_text_bounded(
            &self.dialect,
            crate::parser::Dialect::MsSql,
            &text,
            sql,
            &bounds,
        )
    }

    fn dialect_name(&self) -> &'static str {
        "mssql"
    }
}

/// A `TOP (…) [PERCENT]` right after a statement's `DELETE` / `UPDATE`.
#[derive(Debug, PartialEq, Eq)]
struct TopClause {
    /// Where the `DELETE` / `UPDATE` keyword starts.
    keyword: sqlparser::tokenizer::Location,
    /// Byte range of `TOP … )` or `TOP … ) PERCENT`.
    start: usize,
    end: usize,
    /// The row count, for a `DELETE` with an integer literal and no `PERCENT`.
    rows: Option<i64>,
    /// A `DELETE` whose optional `FROM` was left out (`DELETE TOP (1) t`).
    needs_from: bool,
}

fn is_keyword(t: &TokenWithSpan, kw: Keyword) -> bool {
    matches!(&t.token, Token::Word(w) if w.keyword == kw && w.quote_style.is_none())
}

/// Every `DELETE TOP (…)` / `UPDATE TOP (…)` in `sql`, as the T-SQL tokenizer
/// reads it (so not inside a string, a comment or a quoted identifier).
/// Empty when there is none or the text does not tokenize (the parser then
/// reports the error).
fn top_clauses(dialect: &MsSqlDialect, sql: &str) -> Vec<TopClause> {
    // Tokenizing costs about as much as parsing: only text that can hold the
    // clause pays for it (a `SELECT TOP` alone does not).
    let has = |word: &[u8]| {
        sql.as_bytes()
            .windows(word.len())
            .any(|w| w.eq_ignore_ascii_case(word))
    };
    if !has(b"top") || !(has(b"delete") || has(b"update")) {
        return Vec::new();
    }
    let Ok(toks) = Tokenizer::new(dialect, sql)
        .with_unescape(false)
        .tokenize_with_location()
    else {
        return Vec::new();
    };
    let offs = byte_offsets(sql, &toks);
    let end_of = |i: usize| offs.get(i + 1).copied().unwrap_or(sql.len());
    // Significant tokens: no whitespace, no comment.
    let sig: Vec<usize> = (0..toks.len())
        .filter(|&i| !matches!(toks[i].token, Token::Whitespace(_)))
        .collect();
    let tok = |k: usize| sig.get(k).map(|&i| &toks[i]);
    let mut out = Vec::new();
    let mut k = 0;
    while k + 2 < sig.len() {
        let verb = &toks[sig[k]];
        let is_delete = is_keyword(verb, Keyword::DELETE);
        // `k + 2 < sig.len()`: both following tokens exist.
        let is_top =
            is_keyword(&toks[sig[k + 1]], Keyword::TOP) && toks[sig[k + 2]].token == Token::LParen;
        if !(is_delete || is_keyword(verb, Keyword::UPDATE)) || !is_top {
            k += 1;
            continue;
        }
        // The matching `)`.
        let mut depth = 0usize;
        let mut close = None;
        for (m, &i) in sig.iter().enumerate().skip(k + 2) {
            match toks[i].token {
                Token::LParen => depth += 1,
                Token::RParen => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(m);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            break; // unbalanced: the parser reports it
        };
        let rows = match &sig[k + 3..close] {
            [only] => match &toks[*only].token {
                Token::Number(n, false) => n.parse::<i64>().ok(),
                _ => None,
            },
            _ => None,
        };
        let percent = tok(close + 1).is_some_and(|t| is_keyword(t, Keyword::PERCENT));
        let last = if percent { close + 1 } else { close };
        out.push(TopClause {
            keyword: verb.span.start,
            start: offs[sig[k + 1]],
            end: end_of(sig[last]),
            rows: if is_delete && !percent { rows } else { None },
            needs_from: is_delete && !tok(last + 1).is_some_and(|t| is_keyword(t, Keyword::FROM)),
        });
        k = last + 1;
    }
    out
}

/// `sql` with every clause replaced by as many spaces as it has characters
/// (`FROM` and spaces where the `DELETE` had no `FROM`), so the line and
/// column of everything else stay where the tokenizer found them.
fn without_top_clauses(sql: &str, clauses: &[TopClause]) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut at = 0;
    for c in clauses {
        out.push_str(&sql[at..c.start]);
        let n = sql[c.start..c.end].chars().count();
        // `TOP(0)` is the shortest clause: six characters, room for `FROM `.
        let fill = if c.needs_from && n >= 5 { "FROM " } else { "" };
        out.push_str(fill);
        out.extend(std::iter::repeat_n(' ', n - fill.len()));
        at = c.end;
    }
    out.push_str(&sql[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{StatementKind, WherePresence};

    fn parse(sql: &str) -> ParsedQuery {
        MsSqlParser::new().parse(sql).expect(sql)
    }

    #[test]
    fn delete_top_parses_as_a_bounded_delete() {
        for sql in [
            "DELETE TOP (10) FROM users",
            "DELETE TOP(10) FROM users",
            "delete top ( 10 ) from dbo.users",
            "DELETE TOP (10) users",
            "DELETE TOP(10)users",
            "DELETE /* c */ TOP /* c */ (10) FROM users",
        ] {
            let p = parse(sql);
            let s = &p.statements[0];
            assert_eq!(s.kind, StatementKind::Delete, "{sql}");
            assert_eq!(s.where_presence, WherePresence::Absent, "{sql}");
            assert_eq!(s.delete_limit, Some(10), "{sql}");
            assert!(
                s.relation.as_deref().is_some_and(|r| r.ends_with("users")),
                "{sql}: {:?}",
                s.relation
            );
        }
        let p = parse("DELETE TOP (5) FROM users WHERE id = 1");
        assert_eq!(p.statements[0].where_presence, WherePresence::Present);
        assert_eq!(p.statements[0].delete_limit, Some(5));
        // PERCENT and a non-literal: still a DELETE, no row count.
        for sql in [
            "DELETE TOP (10) PERCENT FROM users",
            "DELETE TOP (@n) FROM users",
            "DELETE TOP ((SELECT 1)) FROM users",
        ] {
            let p = parse(sql);
            assert_eq!(p.statements[0].kind, StatementKind::Delete, "{sql}");
            assert_eq!(p.statements[0].delete_limit, None, "{sql}");
        }
    }

    #[test]
    fn update_top_reads_the_real_target() {
        let p = parse("UPDATE TOP (10) users SET a = 1");
        let s = &p.statements[0];
        assert_eq!(s.kind, StatementKind::Update);
        assert_eq!(s.relation.as_deref(), Some("users"));
        assert_eq!(s.where_presence, WherePresence::Absent);
        let p = parse("UPDATE TOP (10) PERCENT users SET a = 1 WHERE id = 2");
        assert_eq!(p.statements[0].relation.as_deref(), Some("users"));
        assert_eq!(p.statements[0].where_presence, WherePresence::Present);
    }

    #[test]
    fn several_statements_keep_their_own_bound() {
        let p = parse("DELETE TOP (0) FROM a;\nDELETE FROM b;\nDELETE TOP (3) FROM c WHERE x = 1;");
        let deletes: Vec<_> = p
            .statements
            .iter()
            .filter(|s| s.kind == StatementKind::Delete)
            .map(|s| (s.relation.clone().unwrap_or_default(), s.delete_limit))
            .collect();
        assert_eq!(
            deletes,
            [
                ("a".to_string(), Some(0)),
                ("b".to_string(), None),
                ("c".to_string(), Some(3))
            ]
        );
    }

    #[test]
    fn top_in_strings_comments_and_select_is_left_alone() {
        assert!(top_clauses(&MsSqlDialect {}, "SELECT TOP (1) id FROM t").is_empty());
        assert!(top_clauses(&MsSqlDialect {}, "SELECT 'DELETE TOP (1) FROM t'").is_empty());
        assert!(top_clauses(&MsSqlDialect {}, "-- DELETE TOP (1) FROM t\nSELECT 1").is_empty());
        assert!(top_clauses(&MsSqlDialect {}, "SELECT [DELETE] FROM t").is_empty());
        // SELECT TOP still parses as before.
        assert_eq!(
            parse("SELECT TOP (1) id FROM t").statements[0].kind,
            StatementKind::Select
        );
        // Not T-SQL: still a parse error.
        assert!(MsSqlParser::new().parse("DELETE TOP 10 FROM t").is_err());
        assert!(MsSqlParser::new().parse("DELETE TOP (10").is_err());
    }

    #[test]
    fn blanking_keeps_every_character_position() {
        let sql = "DELETE TOP (10) users WHERE név = 'á'";
        let c = top_clauses(&MsSqlDialect {}, sql);
        let text = without_top_clauses(sql, &c);
        assert_eq!(text.chars().count(), sql.chars().count());
        assert_eq!(text, "DELETE FROM     users WHERE név = 'á'");
    }
}
