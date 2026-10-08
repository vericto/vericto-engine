//! Multi-dialect AST parsers (Strategy Pattern).
//!
//! `PostgresParser`, `MySqlParser`, `OracleParser`, and `MsSqlParser` implement
//! the same [`SqlParser`] trait and produce a normalized [`ParsedQuery`] that
//! the rule engine evaluates dialect-agnostically.

pub mod mssql;
pub mod mysql;
pub mod oracle;
pub mod pg_ast;
pub mod postgres;
pub(crate) mod walk;

use crate::error::{ProxyError, Result};

/// Supported SQL dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Mysql,
    Oracle,
    MsSql,
}

impl Dialect {
    pub fn parse_dialect(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Ok(Dialect::Postgres),
            "mysql" => Ok(Dialect::Mysql),
            "oracle" => Ok(Dialect::Oracle),
            "mssql" | "sqlserver" | "tsql" => Ok(Dialect::MsSql),
            other => Err(ProxyError::UnsupportedDialect(other.to_string())),
        }
    }
}

/// Statement type detected in the AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    CreateTableAs,
    Other,
}

/// Object type in a DROP statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropObjectKind {
    Table,
    Database,
    Schema,
    Index,
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

/// Subtype of an ALTER TABLE command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Normalized information for a single AST statement.
#[derive(Debug, Clone)]
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
    /// Whether the WHERE clause contains a trivially-true OR branch
    /// (e.g. `WHERE id = 1 OR 1=1`). Used by VERICTO-090 to detect
    /// SQL injection tautologies. Populated for all statement types that
    /// have a WHERE clause (DELETE, UPDATE, SELECT).
    pub has_or_tautology: bool,
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
            has_or_tautology: false,
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
}

/// The parser's own tree, behind an `Arc` so cloning a `ParsedQuery` stays cheap.
#[derive(Debug, Clone)]
pub(crate) enum SourceAst {
    /// No tree kept (never produced by the built-in parsers).
    #[allow(dead_code)]
    None,
    Pg(std::sync::Arc<pg_query::protobuf::ParseResult>),
    Sql {
        statements: std::sync::Arc<Vec<sqlparser::ast::Statement>>,
        dialect: Dialect,
    },
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
pub(crate) fn is_sleep_function(name: &str) -> bool {
    matches!(
        name,
        "sleep" | "pg_sleep" | "pg_sleep_for" | "pg_sleep_until"
    )
}
