// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Multi-dialect AST parsers (Strategy Pattern).
//!
//! `PostgresParser`, `MySqlParser`, `OracleParser`, `MsSqlParser`,
//! `SnowflakeParser` and `SqliteParser` implement the same [`SqlParser`]
//! trait and produce a normalized [`ParsedQuery`] that the rule engine
//! evaluates dialect-agnostically.

pub mod mssql;
pub mod mysql;
pub(crate) mod mysql_lex;
pub mod oracle;
pub mod pg_ast;
pub mod postgres;
pub mod snowflake;
pub mod sqlite;
pub(crate) mod walk;

use crate::error::{MAX_QUERY_SIZE_BYTES, ProxyError, Result};

/// Supported SQL dialect.
///
/// `#[non_exhaustive]` since 4.0.0: a dialect added later is not a breaking
/// change, so a `match` outside this crate needs a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dialect {
    Postgres,
    Mysql,
    Oracle,
    MsSql,
    /// Snowflake (sqlparser's `SnowflakeDialect`, with a keyword
    /// pre-classifier and an allowlist for the statements it does not read;
    /// see [`snowflake`]).
    Snowflake,
    /// SQLite (sqlparser's `SQLiteDialect`, with a keyword pre-classifier
    /// and an allowlist for the statements it does not read; see
    /// [`sqlite`]). Since 4.1.0.
    Sqlite,
}

impl Dialect {
    /// The canonical lowercase name (`postgres`, `mysql`, `oracle`, `mssql`,
    /// `snowflake`, `sqlite`), accepted back by [`Dialect::parse_dialect`].
    /// Since 4.0.0, so a host reporting the dialect does not need its own
    /// `match`.
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Postgres => "postgres",
            Dialect::Mysql => "mysql",
            Dialect::Oracle => "oracle",
            Dialect::MsSql => "mssql",
            Dialect::Snowflake => "snowflake",
            Dialect::Sqlite => "sqlite",
        }
    }

    pub fn parse_dialect(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Dialect::Postgres),
            "mysql" => Ok(Dialect::Mysql),
            "oracle" => Ok(Dialect::Oracle),
            "mssql" | "sqlserver" | "tsql" => Ok(Dialect::MsSql),
            "snowflake" => Ok(Dialect::Snowflake),
            "sqlite" | "sqlite3" => Ok(Dialect::Sqlite),
            other => Err(ProxyError::UnsupportedDialect(other.to_string())),
        }
    }
}

/// Statement type detected in the AST. `#[non_exhaustive]` since 4.0.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatementKind {
    Delete,
    Update,
    Drop,
    Truncate,
    Select,
    Insert,
    /// ALTER TABLE (DROP COLUMN, RENAME, ADD CONSTRAINT, …)
    AlterTable,
    /// Function call detected inside a query (SLEEP, PG_SLEEP, …)
    FunctionCall,
    /// `COPY … TO/FROM` (PostgreSQL). `PROGRAM` form is an RCE/exfiltration vector.
    Copy,
    /// `DO $$ … $$` anonymous PL/pgSQL block — can hide arbitrary DML/DDL.
    DoBlock,
    /// `GRANT` / `REVOKE` — privilege escalation / lockout.
    Grant,
    /// `MERGE INTO …` — can mass-mutate rows like an UPDATE/DELETE without WHERE.
    Merge,
    /// `CREATE TABLE … AS SELECT …`, materialized-view creation or
    /// `SELECT … INTO` — bulk data copy.
    /// On Snowflake also `CREATE TABLE|SCHEMA|DATABASE … CLONE`.
    CreateTableAs,
    Other,
}

/// What a Snowflake statement does that only Snowflake can do, for the
/// Snowflake rules (VERICTO-091 to VERICTO-097). Set by the Snowflake walker
/// and the Snowflake pre-classifier only, so these rules never fire on
/// another dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnowflakeRisk {
    /// Data or files leave through a stage: `COPY INTO @stage | 's3://…'`
    /// (unload), `GET`, `PUT` (VERICTO-091).
    StageTransfer,
    /// An external location or integration: `CREATE|ALTER STAGE` with
    /// `URL =` or inline `CREDENTIALS`, `CREATE STORAGE | EXTERNAL ACCESS |
    /// API INTEGRATION`, an egress `NETWORK RULE` (VERICTO-092).
    ExternalAccess,
    /// Data leaves the account: `GRANT … TO SHARE`, `CREATE SHARE`, `ALTER
    /// SHARE … ADD|SET ACCOUNTS`, `CREATE LISTING` (VERICTO-093).
    Share,
    /// Recovery reduced: `DATA_RETENTION_TIME_IN_DAYS = 0`, `ALTER ACCOUNT`,
    /// `CREATE OR REPLACE TABLE|SCHEMA|DATABASE`, `INSERT OVERWRITE`,
    /// `UNDROP` (VERICTO-094).
    RecoveryReduced,
    /// Warehouse cost: `CREATE|ALTER WAREHOUSE` setting its size, cluster
    /// count, type or a never-suspend `AUTO_SUSPEND`, `ALTER RESOURCE
    /// MONITOR` (VERICTO-095).
    WarehouseCost,
    /// Code that runs later, outside any check: `CREATE TASK | STREAM | PIPE |
    /// PROCEDURE | FUNCTION | ALERT`, `ALTER TASK … RESUME` (VERICTO-096).
    Persistence,
    /// Privilege context switch: `USE ROLE`, `USE SECONDARY ROLES ALL`
    /// (VERICTO-097).
    RoleSwitch,
}

/// What a SQLite statement does that only SQLite can do, for the SQLite rules
/// (VERICTO-098 to VERICTO-101) and the SQLite reading of VERICTO-070. Set by
/// the SQLite walker and the SQLite pre-classifier only, so these rules never
/// fire on another dialect. Since 4.1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqliteRisk {
    /// `ATTACH [DATABASE] <file> AS <name>`: opens, or creates, another
    /// database file on the connection (VERICTO-098).
    Attach,
    /// A `PRAGMA` write that turns a safety off: `writable_schema`,
    /// `trusted_schema = ON`, `foreign_keys = OFF`, `journal_mode = OFF`, …
    /// (VERICTO-099).
    SafetyPragma,
    /// `load_extension()`, `fts3_tokenizer()` and the shell's `readfile()`,
    /// `writefile()`, `edit()`: native code or the file system (VERICTO-100).
    NativeCode,
    /// `VACUUM [schema] INTO <file>`: a full copy of the database written to
    /// a path (VERICTO-101).
    VacuumInto,
    /// `randomblob(N)` / `zeroblob(N)` with a huge constant `N`: SQLite has
    /// no sleep, and this is its time-based blind-injection probe
    /// (VERICTO-070).
    TimeProbe,
}

/// Object type in a DROP statement. `#[non_exhaustive]` since 4.0.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropObjectKind {
    Table,
    Database,
    Schema,
    Index,
    /// `DROP TRIGGER`: removes a data-integrity or audit protection for good,
    /// so VERICTO-019 reports it alongside `DISABLE TRIGGER`. Not accepted by
    /// the custom-rule `object_type:` predicate.
    Trigger,
    Other,
}

impl DropObjectKind {
    /// Parses the value of a custom-rule `object_type:` predicate
    /// (case-insensitive). `None` for an unrecognized value, so a typo becomes
    /// a validation error rather than a silently non-matching rule.
    pub fn from_yaml(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "table" => Some(DropObjectKind::Table),
            "database" => Some(DropObjectKind::Database),
            "schema" => Some(DropObjectKind::Schema),
            "index" => Some(DropObjectKind::Index),
            _ => None,
        }
    }
}

/// Subtype of an ALTER TABLE command. `#[non_exhaustive]` since 4.0.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlterTableKind {
    DropColumn,
    Rename,
    /// `DROP CONSTRAINT` — removes a FK/PK/CHECK; silently breaks data integrity.
    DropConstraint,
    /// `ALTER COLUMN … TYPE …` — table rewrite, potentially lossy cast.
    AlterColumnType,
    /// `DISABLE TRIGGER` / `DISABLE ROW LEVEL SECURITY` — disables a protection.
    DisableTrigger,
    Other,
}

impl AlterTableKind {
    /// Parses the value of a custom-rule `alter_kind:` predicate
    /// (case-insensitive). `None` for an unrecognized value.
    pub fn from_yaml(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "drop_column" => Some(AlterTableKind::DropColumn),
            "rename" => Some(AlterTableKind::Rename),
            "drop_constraint" => Some(AlterTableKind::DropConstraint),
            "alter_column_type" => Some(AlterTableKind::AlterColumnType),
            "disable_trigger" => Some(AlterTableKind::DisableTrigger),
            _ => None,
        }
    }
}

/// Presence and quality of a WHERE clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WherePresence {
    /// No WHERE clause present.
    Absent,
    /// WHERE with an effective predicate (can be false for some value).
    Present,
    /// WHERE with a trivially-true predicate (1=1, true, …).
    /// Semantically equivalent to no WHERE.
    AlwaysTrue,
}

/// Normalized information for a single AST statement. `#[non_exhaustive]`
/// since 4.0.0: built by the parsers; read its fields, or start from
/// `StatementInfo::default()`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StatementInfo {
    pub kind: StatementKind,
    /// Name of the primary relation affected, if extractable.
    pub relation: Option<String>,
    /// WHERE clause state (relevant for DELETE / UPDATE / SELECT).
    pub where_presence: WherePresence,
    /// Object type for DROP statements.
    pub drop_object: Option<DropObjectKind>,
    /// Subtype for ALTER TABLE statements.
    pub alter_table_kind: Option<AlterTableKind>,
    /// `true` when nested inside a CTE or subquery.
    pub is_nested: bool,
    /// AST node path, e.g. `DeleteStmt > WhereClause = NULL`.
    pub ast_node_path: String,
    // --- extra attributes used by specific rules ---
    /// DELETE LIMIT value, if present (MySQL/SQLite extension).
    pub delete_limit: Option<i64>,
    /// Whether DROP INDEX includes IF EXISTS.
    pub drop_index_if_exists: bool,
    /// Number of rows in an INSERT … VALUES batch.
    pub insert_row_count: Option<usize>,
    /// Whether INSERT specifies explicit column list.
    pub insert_has_columns: bool,
    /// Whether INSERT uses a SELECT as its source.
    pub insert_has_select: bool,
    /// Whether the SELECT sourcing an `INSERT … SELECT` carries a filter that
    /// stops it from copying every source row: an *effective* WHERE (a
    /// tautology like `WHERE 1=1` does not count) or a row limit
    /// (`LIMIT`/`FETCH`). Used by VERICTO-040.
    ///
    /// Lives on the INSERT's own `StatementInfo` because the source SELECT is
    /// recorded as a separate (nested) statement, so the rule predicate cannot
    /// reach its `where_presence` from the INSERT entry.
    ///
    /// Set operations and parenthesized queries are inspected recursively.
    /// UNION requires every SELECT/TABLE arm to be bounded unless an enclosing
    /// row limit applies; INTERSECT/EXCEPT are structural filters. Literal
    /// VALUES arms are ignored because they do not copy table rows.
    pub insert_select_has_filter: bool,
    /// Whether SELECT uses LIMIT.
    pub select_has_limit: bool,
    /// Whether SELECT target list is `*` (star).
    pub select_is_star: bool,
    /// Name of a called function (for VERICTO-070).
    pub function_name: Option<String>,
    /// Whether a `COPY` statement uses the `PROGRAM` form (`COPY … TO/FROM
    /// PROGRAM '…'`), which executes a shell command on the server (RCE /
    /// data exfiltration). Used by VERICTO-080.
    pub copy_is_program: bool,
    /// Whether a `COPY` statement loads rows from a file on the database
    /// server (`COPY t FROM '/path'`). `false` for `FROM STDIN` (the client
    /// sends the rows), for `FROM PROGRAM` (`copy_is_program`) and for every
    /// `COPY … TO`. Used by VERICTO-061.
    pub copy_from_file: bool,
    /// Whether the WHERE clause contains a trivially-true OR branch
    /// (e.g. `WHERE id = 1 OR 1=1`). Used by VERICTO-090 to detect
    /// SQL injection tautologies. Populated for all statement types that
    /// have a WHERE clause (DELETE, UPDATE, SELECT).
    pub has_or_tautology: bool,
    /// The Snowflake-only risk this entry records (Snowflake rules). `None`
    /// on every other dialect.
    pub snowflake: Option<SnowflakeRisk>,
    /// The SQLite-only risk this entry records (SQLite rules, and the SQLite
    /// reading of VERICTO-070). `None` on every other dialect. Since 4.1.0.
    pub sqlite: Option<SqliteRisk>,
}

impl Default for StatementInfo {
    fn default() -> Self {
        Self {
            kind: StatementKind::Other,
            relation: None,
            where_presence: WherePresence::Absent,
            drop_object: None,
            alter_table_kind: None,
            is_nested: false,
            ast_node_path: String::new(),
            delete_limit: None,
            drop_index_if_exists: false,
            insert_row_count: None,
            insert_has_columns: false,
            insert_has_select: false,
            insert_select_has_filter: false,
            select_has_limit: false,
            select_is_star: false,
            function_name: None,
            copy_is_program: false,
            copy_from_file: false,
            has_or_tautology: false,
            snowflake: None,
            sqlite: None,
        }
    }
}

/// Result of parsing a complete query (may contain multiple statements).
#[derive(Debug, Clone)]
pub struct ParsedQuery {
    pub statements: Vec<StatementInfo>,
    /// The syntax tree the statements were read from, kept for the
    /// sensitive-column analysis (VERICTO-085), which needs the projections
    /// themselves rather than the flattened `StatementInfo`. Moved in from
    /// the parser, not copied, so keeping it costs nothing; it is only walked
    /// when the policy carries tags.
    pub(crate) ast: SourceAst,
    /// MySQL only, and only when the text holds a construct MySQL reads
    /// differently from sqlparser (see [`mysql_lex`]): `statements` and `ast`
    /// are then the base reading, and this carries the rest. `None` for every
    /// other text, which is evaluated exactly as before.
    pub(crate) mysql: Option<std::sync::Arc<MysqlReadings>>,
    /// Snowflake and SQLite only: part of the text is code the engine does
    /// not read (a scripting block, `EXECUTE IMMEDIATE`, a statement only the
    /// pre-classifier recognised). The rule engine then keeps the stricter of
    /// the rules' outcome and the parse-error outcome, so whatever the
    /// engine cannot read is never treated more leniently than a parse
    /// error. `None` everywhere else.
    pub(crate) unread: Option<String>,
}

impl ParsedQuery {
    /// The dialect the statements were read in; `None` for MySQL text that
    /// cannot be read with certainty.
    pub(crate) fn dialect(&self) -> Option<Dialect> {
        match &self.ast {
            SourceAst::None => None,
            SourceAst::Pg(_) => Some(Dialect::Postgres),
            SourceAst::Sql { dialect, .. } => Some(*dialect),
            SourceAst::Classified { dialect, .. } => Some(*dialect),
        }
    }
}

/// The other statements MySQL may execute for the client's text.
#[derive(Debug)]
pub(crate) enum MysqlReadings {
    /// The text cannot be read with certainty (VERICTO-086). `statements` is
    /// empty.
    Ambiguous(String),
    /// Each other reading (another server version, or the other escape
    /// mode): parsed, or the parse error.
    Alternatives(Vec<std::result::Result<ParsedQuery, String>>),
}

/// The parser's own tree, behind an `Arc` so cloning a `ParsedQuery` stays cheap.
#[derive(Debug, Clone)]
pub(crate) enum SourceAst {
    /// No tree kept: MySQL text that cannot be read with certainty
    /// ([`MysqlReadings::Ambiguous`]), which is never analysed.
    None,
    Pg(std::sync::Arc<pg_query::protobuf::ParseResult>),
    Sql {
        statements: std::sync::Arc<Vec<sqlparser::ast::Statement>>,
        dialect: Dialect,
        /// The client's text, kept for MySQL, Snowflake and SQLite only: the
        /// sensitive-column analysis re-reads it the way MySQL does (comments,
        /// `?` order, string literals verbatim), which the tree alone cannot
        /// tell; on Snowflake and SQLite it is the reference a mask rewrite
        /// must print back to, and on Snowflake the access analysis folds its
        /// identifiers. One copy of the query, only walked when the policy
        /// carries tags or an allowlist.
        sql: Option<std::sync::Arc<str>>,
    },
    /// Snowflake or SQLite text sqlparser rejects but the pre-classifier
    /// recognised by its keywords (`UNDROP`, `CREATE TASK`, `VACUUM INTO`,
    /// …): no tree. `what` names the statement (`CREATE TASK`); an allowlist
    /// denies it.
    Classified {
        what: String,
        dialect: Dialect,
    },
}

/// Byte offset of every token start (tokenizer locations are 1-based line and
/// character column).
pub(crate) fn byte_offsets(sql: &str, toks: &[sqlparser::tokenizer::TokenWithSpan]) -> Vec<usize> {
    let mut out = Vec::with_capacity(toks.len());
    let mut chars = sql.char_indices().peekable();
    let (mut line, mut col) = (1u64, 1u64);
    for t in toks {
        let want = (t.span.start.line, t.span.start.column);
        while (line, col) < want {
            match chars.next() {
                Some((_, '\n')) => {
                    line += 1;
                    col = 1;
                }
                Some(_) => col += 1,
                None => break,
            }
        }
        out.push(chars.peek().map_or(sql.len(), |(b, _)| *b));
    }
    out
}

/// Byte offsets of the `/*! … */` comments in `sql`, as `dialect`'s
/// tokenizer reads comments. `None` when the text does not tokenize.
///
/// Since sqlparser 0.61 the MySQL and Generic tokenizers no longer return
/// such a comment: they splice its content into the token stream as code,
/// whatever its version number (`/*!99999 … */` included), so the comment
/// cannot be seen in the tokens any more. It is found here by tokenizing the
/// text with every `/*!` turned into `/* ` (same length, so offsets carry
/// over): a comment that starts where the original text has `/*!` is one.
/// A `/*!` inside a string literal or a quoted identifier stays inside it.
pub(crate) fn executable_comments<D: sqlparser::dialect::Dialect>(
    dialect: &D,
    sql: &str,
) -> Option<Vec<usize>> {
    use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};
    if !sql.contains("/*!") {
        return Some(Vec::new());
    }
    let masked = sql.replace("/*!", "/* ");
    let toks = Tokenizer::new(dialect, &masked)
        .with_unescape(false)
        .tokenize_with_location()
        .ok()?;
    let offs = byte_offsets(&masked, &toks);
    Some(
        toks.iter()
            .zip(offs)
            .filter(|(t, o)| {
                matches!(t.token, Token::Whitespace(Whitespace::MultiLineComment(_)))
                    && sql[*o..].starts_with("/*!")
            })
            .map(|(_, o)| o)
            .collect(),
    )
}

/// Common interface for dialect-specific parsers (Strategy Pattern).
pub trait SqlParser: Send + Sync {
    /// Parses the query and returns the normalized representation.
    /// Returns `ProxyError::ParseError` for invalid syntax.
    fn parse(&self, sql: &str) -> Result<ParsedQuery>;

    fn dialect_name(&self) -> &'static str;
}

/// Factory: returns the parser for the given dialect.
pub fn parser_for(dialect: Dialect) -> Box<dyn SqlParser> {
    match dialect {
        Dialect::Postgres => Box::new(postgres::PostgresParser::new()),
        Dialect::Mysql => Box::new(mysql::MySqlParser::new()),
        Dialect::Oracle => Box::new(oracle::OracleParser::new()),
        Dialect::MsSql => Box::new(mssql::MsSqlParser::new()),
        Dialect::Snowflake => Box::new(snowflake::SnowflakeParser::new()),
        Dialect::Sqlite => Box::new(sqlite::SqliteParser::new()),
    }
}

/// Sleep-family functions used for DoS or time-based blind SQL injection
/// (VERICTO-070). `name` must already be lowercased.
///
/// Lives here rather than in either walker because both `pg_ast` (PostgreSQL)
/// and `walk` (sqlparser dialects) need it, and keeping two lists in sync by
/// convention already failed: the sqlparser walker was missing
/// `pg_sleep_until`, so the rule fired on PostgreSQL but not on MySQL, Oracle,
/// or MS SQL. One definition makes that drift impossible.
///
/// `system$wait` is Snowflake's: it suspends the statement for up to an hour
/// while the warehouse keeps running (and billing).
pub(crate) fn is_sleep_function(name: &str) -> bool {
    matches!(
        name,
        "sleep" | "pg_sleep" | "pg_sleep_for" | "pg_sleep_until" | "system$wait"
    )
}

// ---------------------------------------------------------------------------
// Constant predicates, shared by both walkers
// ---------------------------------------------------------------------------
//
// `is_always_true` and its `truth` exist once per walker because they walk
// two different ASTs, but what a literal comparison *means* does not depend on
// the parser. That part lives here, once: each walker only turns its own
// literal nodes into a [`Const`] and asks [`compare`]. Two copies of the
// comparison already drifted (a negative literal was decided on PostgreSQL
// only, because libpg_query folds `-1` and sqlparser does not), and both
// copies compared NULL like any value.

/// The truth value of a predicate the engine evaluates without a row, under
/// SQL's three-valued logic.
///
/// `SqlNull` is SQL UNKNOWN produced by a known NULL expression. `Unknown`
/// means the analysis cannot decide, for example because comparison depends on
/// collation or a row. Keeping them separate lets `IS UNKNOWN` fold known NULL
/// expressions without turning an unresolved expression into a tautology. Only
/// [`Truth::True`] makes a tautology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Truth {
    True,
    False,
    SqlNull,
    Unknown,
}

impl Truth {
    pub(crate) fn from_bool(b: bool) -> Self {
        if b { Truth::True } else { Truth::False }
    }

    /// SQL `NOT`: true and false swap; SQL NULL and unresolved stay as-is.
    pub(crate) fn not(self) -> Self {
        match self {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            Truth::SqlNull => Truth::SqlNull,
            Truth::Unknown => Truth::Unknown,
        }
    }

    pub(crate) fn tested_as(self, expected: Truth, negated: bool) -> Truth {
        match self {
            Truth::Unknown => Truth::Unknown,
            known => Truth::from_bool((known == expected) != negated),
        }
    }

    pub(crate) fn and(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::False, _) | (_, Truth::False) => Truth::False,
            (Truth::True, value) | (value, Truth::True) => value,
            (Truth::SqlNull, Truth::SqlNull) => Truth::SqlNull,
            _ => Truth::Unknown,
        }
    }

    pub(crate) fn or(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::True, _) | (_, Truth::True) => Truth::True,
            (Truth::False, value) | (value, Truth::False) => value,
            (Truth::SqlNull, Truth::SqlNull) => Truth::SqlNull,
            _ => Truth::Unknown,
        }
    }

    /// Conservative helper for forms where only a proof of TRUE is kept.
    pub(crate) fn true_or_unknown(b: bool) -> Self {
        if b { Truth::True } else { Truth::Unknown }
    }
}

/// Exact base-10 number used for proofs. SQL integer and decimal literals are
/// exact on the target engines, so converting them to `f64` can collapse
/// distinct values above 2^53 and manufacture a tautology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SqlNumber {
    negative: bool,
    digits: String,
    /// `digits × 10^-scale`, after leading and trailing zero normalization.
    scale: i128,
}

impl SqlNumber {
    fn parse(text: &str) -> Option<Self> {
        // The 4.7.0 grammar, read in one pass with a single allocation (the
        // significant digits).
        let (negative, unsigned) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        let is_e = |b: u8| b == b'e' || b == b'E';
        let (mantissa, exponent) = match unsigned.bytes().position(is_e) {
            // A second `e` fails the integer parse.
            Some(at) => (&unsigned[..at], unsigned[at + 1..].parse::<i128>().ok()?),
            None => (unsigned, 0),
        };
        if !(-(MAX_QUERY_SIZE_BYTES as i128)..=MAX_QUERY_SIZE_BYTES as i128).contains(&exponent) {
            return None;
        }

        let (whole, fraction) = match mantissa.bytes().position(|b| b == b'.') {
            Some(at) => (&mantissa[..at], &mantissa[at + 1..]),
            None => (mantissa, ""),
        };
        if (whole.is_empty() && fraction.is_empty())
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
        {
            // A second `.` is not a digit either.
            return None;
        }

        let significant = whole
            .bytes()
            .chain(fraction.bytes())
            .skip_while(|&b| b == b'0');
        let mut digits = String::with_capacity(whole.len() + fraction.len());
        digits.extend(significant.map(char::from));
        if digits.is_empty() {
            return Some(Self {
                negative: false,
                digits: "0".to_string(),
                scale: 0,
            });
        }

        let mut scale = i128::try_from(fraction.len()).ok()?.checked_sub(exponent)?;
        while digits.ends_with('0') {
            digits.pop();
            scale = scale.checked_sub(1)?;
        }
        Some(Self {
            negative,
            digits,
            scale,
        })
    }

    /// The 4.7.0 reading, which [`SqlNumber::parse`] must reproduce exactly
    /// (checked by `sql_number_parse_matches_reference`).
    #[cfg(test)]
    fn parse_reference(text: &str) -> Option<Self> {
        let (negative, unsigned) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        let mut exponent_parts = unsigned.split(['e', 'E']);
        let mantissa = exponent_parts.next()?;
        let exponent = exponent_parts
            .next()
            .map(|value| value.parse::<i128>())
            .transpose()
            .ok()?
            .unwrap_or(0);
        if exponent_parts.next().is_some()
            || !(-(MAX_QUERY_SIZE_BYTES as i128)..=MAX_QUERY_SIZE_BYTES as i128).contains(&exponent)
        {
            return None;
        }

        let mut decimal_parts = mantissa.split('.');
        let whole = decimal_parts.next()?;
        let fraction = decimal_parts.next().unwrap_or_default();
        if decimal_parts.next().is_some()
            || (whole.is_empty() && fraction.is_empty())
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit())
        {
            return None;
        }

        let combined = format!("{whole}{fraction}");
        let significant = combined.trim_start_matches('0');
        if significant.is_empty() {
            return Some(Self {
                negative: false,
                digits: "0".to_string(),
                scale: 0,
            });
        }

        let mut digits = significant.to_string();
        let mut scale = i128::try_from(fraction.len()).ok()?.checked_sub(exponent)?;
        while digits.ends_with('0') {
            digits.pop();
            scale = scale.checked_sub(1)?;
        }
        Some(Self {
            negative,
            digits,
            scale,
        })
    }

    fn negated(mut self) -> Self {
        if !self.is_zero() {
            self.negative = !self.negative;
        }
        self
    }

    fn is_zero(&self) -> bool {
        self.digits == "0"
    }

    /// Position of the leading digit relative to the decimal point:
    /// `digits.len() - scale`. Both terms are bounded by the query size (see
    /// `parse`), so the saturating arithmetic never actually saturates; it
    /// only keeps this runtime path free of a panic.
    fn magnitude(&self) -> i128 {
        i128::try_from(self.digits.len())
            .unwrap_or(i128::MAX)
            .saturating_sub(self.scale)
    }

    fn cmp_abs(&self, other: &Self) -> std::cmp::Ordering {
        match (self.is_zero(), other.is_zero()) {
            (true, true) => return std::cmp::Ordering::Equal,
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            (false, false) => {}
        }
        self.magnitude().cmp(&other.magnitude()).then_with(|| {
            let len = self.digits.len().max(other.digits.len());
            (0..len)
                .map(|index| {
                    self.digits
                        .as_bytes()
                        .get(index)
                        .copied()
                        .unwrap_or(b'0')
                        .cmp(&other.digits.as_bytes().get(index).copied().unwrap_or(b'0'))
                })
                .find(|ordering| !ordering.is_eq())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

impl Ord for SqlNumber {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.negative, other.negative) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => self.cmp_abs(other),
            (true, true) => self.cmp_abs(other).reverse(),
        }
    }
}

impl PartialOrd for SqlNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A literal operand, as both walkers read it for constant comparisons.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Const {
    /// `NULL`.
    Null,
    /// An exact integer, decimal or exponent-form number literal.
    Num(SqlNumber),
    /// `TRUE` / `FALSE`.
    Bool(bool),
    /// The text of a string literal.
    Text(String),
    /// Any other unambiguous literal (a bit or hex string, or a number outside
    /// the supported decimal grammar), by an identity key: equal to itself,
    /// undecided against anything else. Ambiguous syntax such as MySQL's
    /// `"…"` is not a constant because `ANSI_QUOTES` can make it a column.
    Opaque(String),
}

impl Const {
    /// A number literal's text, parsed without precision loss or kept opaque
    /// when it falls outside the supported decimal grammar.
    pub(crate) fn number(text: &str) -> Const {
        SqlNumber::parse(text).map_or_else(|| Const::Opaque(text.to_string()), Const::Num)
    }

    /// Unary minus over a literal: the one fold both walkers use.
    ///
    /// libpg_query already folds `-1` into a negative constant; sqlparser
    /// reads it as `UnaryOp(Minus, 1)`. Without this fold `-1 < 0` was a
    /// tautology on PostgreSQL and a real filter on every other dialect.
    /// Only a number negates: `-'1'` and `-TRUE` are left undecided (their
    /// coercion is the dialect's).
    pub(crate) fn negated(self) -> Option<Const> {
        match self {
            Const::Num(x) => Some(Const::Num(x.negated())),
            _ => None,
        }
    }

    /// The literal as a bare predicate: `WHERE 1`, `WHERE 0`, `WHERE TRUE`.
    /// A string is undecided here (SQLite's reading of text as a number is
    /// the sqlparser walker's, behind its `sqlite` flag), and `WHERE NULL`
    /// matches no row, so it is never true.
    pub(crate) fn truth(&self) -> Truth {
        match self {
            Const::Null => Truth::SqlNull,
            Const::Num(x) => Truth::from_bool(!x.is_zero()),
            Const::Bool(b) => Truth::from_bool(*b),
            _ => Truth::Unknown,
        }
    }
}

/// A comparison operator between two constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CmpOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

impl CmpOp {
    /// PostgreSQL's operator name (`A_Expr.name`).
    pub(crate) fn from_symbol(op: &str) -> Option<CmpOp> {
        Some(match op {
            "=" => CmpOp::Eq,
            "<>" | "!=" => CmpOp::NotEq,
            "<" => CmpOp::Lt,
            "<=" => CmpOp::LtEq,
            ">" => CmpOp::Gt,
            ">=" => CmpOp::GtEq,
            _ => return None,
        })
    }

    fn holds(self, o: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::{Equal, Greater, Less};
        match self {
            CmpOp::Eq => o == Equal,
            CmpOp::NotEq => o != Equal,
            CmpOp::Lt => o == Less,
            CmpOp::LtEq => o != Greater,
            CmpOp::Gt => o == Greater,
            CmpOp::GtEq => o != Less,
        }
    }
}

/// `<a> <op> <b>` over two literals, under three-valued logic.
///
/// - Any comparison with NULL is SQL UNKNOWN ([`Truth::SqlNull`]), never true: `NULL = NULL` and
///   `NULL <> 1` match no row (the IN-list readings already excluded NULL).
/// - Numbers compare numerically, under every operator.
/// - Strings and booleans decide only `=` and `<>`; an ordering between
///   strings depends on the collation and stays undecided, so its `NOT` does
///   too.
/// - Literals of different kinds (`1 = '1'`, `TRUE = 1`) are undecided: whether
///   and how they coerce is the dialect's call, and `1 = '1'` is true on
///   PostgreSQL and MySQL, so reading it as false made `NOT (1 = '1')` a
///   tautology.
pub(crate) fn compare(a: &Const, op: CmpOp, b: &Const) -> Truth {
    let eq = match (a, b) {
        (Const::Null, _) | (_, Const::Null) => return Truth::SqlNull,
        (Const::Num(x), Const::Num(y)) => {
            return Truth::from_bool(op.holds(x.cmp(y)));
        }
        (Const::Bool(x), Const::Bool(y)) => Truth::from_bool(x == y),
        (Const::Text(x), Const::Text(y)) => text_equality(x, y),
        (Const::Opaque(x), Const::Opaque(y)) if x == y => Truth::True,
        _ => Truth::Unknown,
    };
    match op {
        CmpOp::Eq => eq,
        CmpOp::NotEq => eq.not(),
        _ => Truth::Unknown,
    }
}

/// SQL `IS [NOT] DISTINCT FROM` over constants. Unlike ordinary equality,
/// NULL is a value here: two NULLs are not distinct, one NULL and one non-NULL
/// are distinct. Non-NULL constants reuse [`compare`], preserving its
/// collation/coercion conservatism; `not_distinct` negates the distinct result.
pub(crate) fn compare_distinct(a: &Const, b: &Const, not_distinct: bool) -> Truth {
    let distinct = match (a, b) {
        (Const::Null, Const::Null) => Truth::False,
        (Const::Null, _) | (_, Const::Null) => Truth::True,
        _ => compare(a, CmpOp::Eq, b).not(),
    };
    if not_distinct {
        distinct.not()
    } else {
        distinct
    }
}

/// Equality of two string literals, as far as it holds under any collation
/// the dialects ship.
///
/// Identical text is equal under every collation (`'a' = 'a'`). Different
/// text is *provably* different only when nothing a collation may ignore
/// separates it: case- and accent-insensitive collations are the defaults on
/// MySQL and SQL Server (`'a' = 'A'` is true there), PAD SPACE ones ignore
/// trailing spaces, and Snowflake's collation specifiers can ignore case,
/// accents, punctuation and leading or trailing spaces. So two strings are
/// different only when both are non-empty ASCII letters and digits and they
/// differ beyond case (`'a'` and `'b'`); anything else is undecided.
fn text_equality(x: &str, y: &str) -> Truth {
    if x == y {
        return Truth::True;
    }
    let plain = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric());
    if plain(x) && plain(y) && !x.eq_ignore_ascii_case(y) {
        Truth::False
    } else {
        Truth::Unknown
    }
}

// ---------------------------------------------------------------------------
// Snowflake `ORDER BY ALL`
// ---------------------------------------------------------------------------

/// Snowflake's `ORDER BY ALL`, which sqlparser 0.63 does not read: its
/// Snowflake dialect leaves `supports_order_by_all` false, so `ALL` comes
/// back as an ORDER BY item naming a column `ALL`. Every query in the tree
/// whose ORDER BY is exactly one bare, unquoted `ALL` (any case, with its
/// `ASC`/`DESC` and `NULLS FIRST/LAST`) is set to [`OrderByKind::All`], which
/// is what the dialects that do read it produce.
///
/// The one place that reading happens, for every Snowflake tree the engine
/// walks: the parse (`walk::parse_text`), the access analysis's folded text
/// (`access::sql::fold_snowflake`) and the mask rewrite's re-parse
/// (`sensitive::snowflake::render`). The sensitive and access walkers then
/// take it as ordering by every output, as they already do for
/// `OrderByKind::All`: a mask rewrite is refused when any output is masked,
/// and an allowlist sees no column beyond the outputs.
///
/// Why only this shape: `ALL` is a reserved word in Snowflake, so an
/// unquoted `ALL` can never be a column, while a quoted `"ALL"` is one and
/// stays one. Snowflake does not combine `ALL` with other items; such a list
/// is left as parsed (the server rejects it). No other dialect Vericto
/// supports has `ORDER BY ALL` (PostgreSQL, MySQL, SQL Server, Oracle and
/// SQLite reject it), so this runs on Snowflake trees only.
///
/// Temporary: upstream fixed the parse in apache/datafusion-sqlparser-rs#2502
/// (Snowflake's `supports_order_by_all`), which is not in 0.63.0. Remove this
/// and its three calls when the engine moves to a sqlparser release that
/// contains it; the tests that pin `"ALL"` and `all_col` as columns stay, as
/// the regression check for that upgrade.
///
/// [`OrderByKind::All`]: sqlparser::ast::OrderByKind::All
pub(crate) fn resolve_snowflake_order_by_all(statements: &mut [sqlparser::ast::Statement]) {
    use sqlparser::ast::{Expr, OrderByKind, Query, VisitMut, VisitorMut};
    use std::ops::ControlFlow;

    struct OrderByAll;
    impl VisitorMut for OrderByAll {
        type Break = ();
        fn pre_visit_query(&mut self, q: &mut Query) -> ControlFlow<()> {
            let Some(ob) = q.order_by.as_mut() else {
                return ControlFlow::Continue(());
            };
            if let OrderByKind::Expressions(items) = &ob.kind {
                if let [item] = &items[..] {
                    let bare_all = matches!(
                        &item.expr,
                        Expr::Identifier(id)
                            if id.quote_style.is_none() && id.value.eq_ignore_ascii_case("ALL")
                    );
                    if bare_all && item.with_fill.is_none() {
                        ob.kind = OrderByKind::All(item.options.clone());
                    }
                }
            }
            ControlFlow::Continue(())
        }
    }
    for s in statements.iter_mut() {
        let _ = s.visit(&mut OrderByAll);
    }
}

#[cfg(test)]
mod constant_tests {
    use super::{CmpOp, Const, Truth, compare, compare_distinct};

    #[test]
    fn null_is_never_compared() {
        let one = Const::number("1");
        for op in [
            CmpOp::Eq,
            CmpOp::NotEq,
            CmpOp::Lt,
            CmpOp::LtEq,
            CmpOp::Gt,
            CmpOp::GtEq,
        ] {
            assert_eq!(compare(&Const::Null, op, &Const::Null), Truth::SqlNull);
            assert_eq!(compare(&Const::Null, op, &one), Truth::SqlNull);
            assert_eq!(compare(&one, op, &Const::Null), Truth::SqlNull);
        }
    }

    #[test]
    fn distinct_comparison_treats_null_as_a_value() {
        let one = Const::number("1");
        assert_eq!(compare_distinct(&Const::Null, &one, false), Truth::True);
        assert_eq!(compare_distinct(&Const::Null, &one, true), Truth::False);
        assert_eq!(
            compare_distinct(&Const::Null, &Const::Null, false),
            Truth::False
        );
        assert_eq!(
            compare_distinct(&Const::Null, &Const::Null, true),
            Truth::True
        );
        assert_eq!(compare_distinct(&one, &one, true), Truth::True);
    }

    #[test]
    fn numbers_compare_and_strings_only_by_equality() {
        let n = |x: &str| Const::number(x);
        let t = |s: &str| Const::Text(s.to_string());
        assert_eq!(compare(&n("-1"), CmpOp::Lt, &n("0")), Truth::True);
        assert_eq!(compare(&n("1"), CmpOp::GtEq, &n("2")), Truth::False);
        assert_eq!(compare(&n("1"), CmpOp::LtEq, &n("1.0")), Truth::True);
        assert_eq!(
            compare(&n("9007199254740992"), CmpOp::Eq, &n("9007199254740993")),
            Truth::False
        );
        assert_eq!(compare(&n("1.25e2"), CmpOp::Eq, &n("125")), Truth::True);
        assert_eq!(compare(&n("0"), CmpOp::Lt, &n("0.5")), Truth::True);
        assert_eq!(compare(&n("0.5"), CmpOp::Gt, &n("0")), Truth::True);
        assert_eq!(compare(&n("-0.5"), CmpOp::Lt, &n("0")), Truth::True);
        assert_eq!(compare(&t("a"), CmpOp::Eq, &t("a")), Truth::True);
        assert_eq!(compare(&t("a"), CmpOp::NotEq, &t("b")), Truth::True);
        assert_eq!(compare(&t("a"), CmpOp::Lt, &t("b")), Truth::Unknown);
        // Collations may ignore case, trailing spaces, accents, punctuation.
        for (x, y) in [
            ("a", "A"),
            ("a", "a "),
            ("e", "é"),
            ("a-b", "ab"),
            ("", "a"),
        ] {
            assert_eq!(compare(&t(x), CmpOp::Eq, &t(y)), Truth::Unknown, "{x} {y}");
            assert_eq!(
                compare(&t(x), CmpOp::NotEq, &t(y)),
                Truth::Unknown,
                "{x} {y}"
            );
        }
        // Different kinds coerce per dialect.
        assert_eq!(compare(&n("1"), CmpOp::Eq, &t("1")), Truth::Unknown);
        assert_eq!(
            compare(&Const::Bool(true), CmpOp::Eq, &n("1")),
            Truth::Unknown
        );
        assert_eq!(
            compare(&Const::Bool(true), CmpOp::NotEq, &Const::Bool(false)),
            Truth::True
        );
        assert_eq!(
            compare(&Const::Bool(true), CmpOp::Gt, &Const::Bool(false)),
            Truth::Unknown
        );
        let o = |s: &str| Const::Opaque(s.to_string());
        assert_eq!(compare(&o("x"), CmpOp::Eq, &o("x")), Truth::True);
        assert_eq!(compare(&o("x"), CmpOp::NotEq, &o("y")), Truth::Unknown);
    }

    #[test]
    fn only_numbers_negate_and_truth_survives_not() {
        assert_eq!(Const::number("1").negated(), Some(Const::number("-1")));
        assert_eq!(Const::Text("1".into()).negated(), None);
        assert_eq!(
            Const::number("1e999999999999999999999999999999999999999"),
            Const::Opaque("1e999999999999999999999999999999999999999".into())
        );
        assert_eq!(Const::Null.truth(), Truth::SqlNull);
        assert_eq!(Const::number("-1").truth(), Truth::True);
        assert_eq!(Const::number("0").truth(), Truth::False);
        assert_eq!(Truth::SqlNull.not(), Truth::SqlNull);
        assert_eq!(Truth::Unknown.not(), Truth::Unknown);
        assert_eq!(Truth::False.not(), Truth::True);
        assert_eq!(Truth::true_or_unknown(false), Truth::Unknown);
    }

    #[test]
    fn extreme_exponents_and_long_digit_strings_compare_exactly() {
        use crate::error::MAX_QUERY_SIZE_BYTES;
        let n = |x: &str| Const::number(x);
        let max = MAX_QUERY_SIZE_BYTES;
        let huge = format!("1e{max}");
        let tiny = format!("1e-{max}");
        assert!(matches!(n(&huge), Const::Num(_)));
        assert!(matches!(n(&tiny), Const::Num(_)));
        assert_eq!(compare(&n(&huge), CmpOp::Gt, &n("1")), Truth::True);
        assert_eq!(compare(&n(&tiny), CmpOp::Lt, &n("1")), Truth::True);
        assert_eq!(compare(&n(&tiny), CmpOp::Gt, &n("0")), Truth::True);
        assert_eq!(
            compare(&n(&format!("-{huge}")), CmpOp::Lt, &n(&format!("-{tiny}"))),
            Truth::True
        );
        assert_eq!(
            compare(&n(&huge), CmpOp::Eq, &n(&format!("10e{}", max - 1))),
            Truth::True
        );

        // A digit string as long as the size limit allows, against values that
        // differ only in its last digit or in its magnitude.
        let long = "9".repeat(max - 2);
        let long_minus_one = format!("{}8", "9".repeat(max - 3));
        assert_eq!(
            compare(&n(&long), CmpOp::Gt, &n(&long_minus_one)),
            Truth::True
        );
        assert_eq!(
            compare(&n(&long), CmpOp::Eq, &n(&format!("{long}.0"))),
            Truth::True
        );
        assert_eq!(
            compare(&n(&long), CmpOp::Lt, &n(&format!("1e{}", max - 2))),
            Truth::True
        );
        assert_eq!(
            compare(&n(&format!("0.{long}")), CmpOp::Lt, &n("1")),
            Truth::True
        );
        assert_eq!(
            compare(&n(&format!("{long}e-{max}")), CmpOp::Gt, &n(&tiny)),
            Truth::True
        );
        assert_eq!(
            compare(&n(&format!("{long}e{max}")), CmpOp::Gt, &n(&huge)),
            Truth::True
        );
    }
}
