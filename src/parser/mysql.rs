//! MySQL AST parser.
//!
//! Uses `sqlparser-rs` with `MySqlDialect`, which understands MySQL-specific
//! syntax — for example `DELETE ... LIMIT N`, which is valid in MySQL (and
//! bounds the delete) but does not exist in PostgreSQL.

use std::sync::Arc;

use crate::error::Result;
use crate::parser::mysql_lex::{Readings, readings};
use crate::parser::walk::{parse_text, parse_with_dialect};
use crate::parser::{Dialect, MysqlReadings, ParsedQuery, SourceAst, SqlParser};

use sqlparser::dialect::MySqlDialect;

pub struct MySqlParser {
    dialect: MySqlDialect,
}

impl MySqlParser {
    pub fn new() -> Self {
        Self {
            dialect: MySqlDialect {},
        }
    }
}

impl Default for MySqlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for MySqlParser {
    /// Parses the statement MySQL executes, not the one sqlparser reads (see
    /// [`crate::parser::mysql_lex`]).
    ///
    /// - Text MySQL and sqlparser read alike: parsed as it is, exactly as
    ///   before.
    /// - Text the normalizer cannot resolve: `Ok`, with no statements and a
    ///   marker the rule engine turns into a VERICTO-086 block. Not an `Err`:
    ///   hosts map a parse error through `parse_error`, whose fail-open
    ///   default would forward it.
    /// - Otherwise the base reading is parsed (its error, if any, is the
    ///   result, as for any text sqlparser rejects), and every other reading
    ///   rides along for the rule engine, which keeps the strictest outcome.
    ///   The client's own text is kept for VERICTO-085, whose MySQL front end
    ///   re-reads it and refuses these constructs itself.
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        match readings(sql) {
            Readings::Plain => parse_with_dialect(&self.dialect, Dialect::Mysql, sql),
            Readings::Ambiguous(why) => Ok(ParsedQuery {
                statements: Vec::new(),
                ast: SourceAst::None,
                mysql: Some(Arc::new(MysqlReadings::Ambiguous(why))),
            }),
            Readings::Normalized { base, alternatives } => {
                let mut parsed = parse_text(&self.dialect, Dialect::Mysql, &base, sql)?;
                let alternatives = alternatives
                    .iter()
                    .map(|text| {
                        parse_with_dialect(&self.dialect, Dialect::Mysql, text)
                            .map_err(|e| e.to_string())
                    })
                    .collect();
                parsed.mysql = Some(Arc::new(MysqlReadings::Alternatives(alternatives)));
                Ok(parsed)
            }
        }
    }

    fn dialect_name(&self) -> &'static str {
        "mysql"
    }
}
