//! Multi-dialect AST parsers (Strategy Pattern).
//!
//! `PostgresParser`, `MySqlParser`, `OracleParser`, `MsSqlParser` and
//! `SnowflakeParser` implement the same [`SqlParser`] trait and produce a
//! normalized [`ParsedQuery`] that the rule engine evaluates
//! dialect-agnostically.

pub mod mssql;
pub mod mysql;
pub(crate) mod mysql_lex;
pub mod oracle;
pub mod pg_ast;
pub mod postgres;
pub mod snowflake;
pub(crate) mod walk;

use crate::error::{ProxyError, Result};

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
}

impl Dialect {
    /// The canonical lowercase name (`postgres`, `mysql`, `oracle`, `mssql`,
    /// `snowflake`), accepted back by [`Dialect::parse_dialect`]. Since 4.0.0,
    /// so a host reporting the dialect does not need its own `match`.
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Postgres => "postgres",
            Dialect::Mysql => "mysql",
            Dialect::Oracle => "oracle",
            Dialect::MsSql => "mssql",
            Dialect::Snowflake => "snowflake",
        }
    }

    pub fn parse_dialect(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Dialect::Postgres),
            "mysql" => Ok(Dialect::Mysql),
            "oracle" => Ok(Dialect::Oracle),
            "mssql" | "sqlserver" | "tsql" => Ok(Dialect::MsSql),
            "snowflake" => Ok(Dialect::Snowflake),
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
    /// `CREATE TABLE … AS SELECT …` / `SELECT … INTO` — bulk data copy.
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
    /// Conservatively `false` when the source is a set operation
    /// (`UNION`/`INTERSECT`/`EXCEPT`), even if every arm is filtered: the
    /// set-op node carries no WHERE of its own and the arms are not inspected.
    /// Over-reporting is the safe direction for a blocking rule.
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
    /// Snowflake only: part of the text is code the engine does not read (a
    /// scripting block, `EXECUTE IMMEDIATE`, a statement only the
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
            SourceAst::Classified { .. } => Some(Dialect::Snowflake),
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
        /// The client's text, kept for MySQL and Snowflake only: the
        /// sensitive-column analysis re-reads it the way MySQL does (comments,
        /// `?` order, string literals verbatim), which the tree alone cannot
        /// tell; on Snowflake it is the reference a mask rewrite must print
        /// back to, and the access analysis folds its identifiers. One copy of
        /// the query, only walked when the policy carries tags or an allowlist.
        sql: Option<std::sync::Arc<str>>,
    },
    /// Snowflake text sqlparser rejects but the pre-classifier recognised by
    /// its keywords (`UNDROP`, `CREATE TASK`, `ALTER WAREHOUSE`, …): no tree.
    /// `what` names the statement (`CREATE TASK`); an allowlist denies it.
    Classified {
        what: String,
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
