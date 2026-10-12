//! Parser AST para Oracle SQL.
//!
//! Uses `sqlparser-rs` with `GenericDialect` as the closest approximation to
//! Oracle's SQL syntax. A dedicated OracleDialect is not yet shipped in
//! sqlparser-rs (as of 0.52), so GenericDialect covers the vast majority of
//! DML statements (SELECT, INSERT, UPDATE, DELETE, TRUNCATE, DROP) and is
//! sufficient for Vericto's rule evaluation.
//!
//! Oracle-specific syntax that diverges from standard SQL (e.g. ROWNUM,
//! CONNECT BY, hierarchical queries, MERGE) will parse as `PARSE_ERROR` and
//! be handled conservatively (fail-closed → BLOCKED).

use crate::error::Result;
use crate::parser::walk::{parse_text, parse_with_dialect};
use crate::parser::{ParsedQuery, SqlParser};

use sqlparser::dialect::GenericDialect;

pub struct OracleParser {
    dialect: GenericDialect,
}

impl OracleParser {
    pub fn new() -> Self {
        Self {
            dialect: GenericDialect {},
        }
    }
}

impl Default for OracleParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for OracleParser {
    /// Oracle never executes a `/*! … */` comment, but sqlparser's Generic
    /// dialect reads its content as code since 0.61: such a comment is
    /// turned into an ordinary one (`/* `, same length) before parsing, so it
    /// is read as Oracle reads it, as it was before the upgrade.
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        let at = crate::parser::executable_comments(&self.dialect, sql).unwrap_or_default();
        if at.is_empty() {
            return parse_with_dialect(&self.dialect, crate::parser::Dialect::Oracle, sql);
        }
        let mut text = sql.as_bytes().to_vec();
        for o in at {
            text[o + 2] = b' ';
        }
        // Only an ASCII `!` became an ASCII space: still UTF-8.
        let text = String::from_utf8(text).unwrap_or_else(|_| sql.to_string());
        parse_text(&self.dialect, crate::parser::Dialect::Oracle, &text, sql)
    }

    fn dialect_name(&self) -> &'static str {
        "oracle"
    }
}
