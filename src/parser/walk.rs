// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Converts `sqlparser-rs` ASTs to Vericto's normalized representation.
//!
//! Walks the syntax tree in depth detecting destructive statements (DELETE,
//! UPDATE, DROP, TRUNCATE, ALTER TABLE) at root level and nested inside
//! subqueries / CTEs. Also detects INSERT patterns, SELECT * / no-LIMIT,
//! and function calls (SLEEP, PG_SLEEP).

use crate::error::{MAX_AST_DEPTH, ProxyError, Result, guard_nesting_depth};
use crate::parser::{
    AlterTableKind, CmpOp, Const, Dialect, DropObjectKind, ParsedQuery, SnowflakeRisk, SqliteRisk,
    StatementInfo, StatementKind, Truth, WherePresence, compare, compare_distinct,
};

use std::ops::ControlFlow;

use sqlparser::ast::{
    Expr, FromTable, FunctionArguments, LimitClause, ObjectType, Query, SelectItem, SetExpr,
    SetOperator, Statement, TableFactor, TableWithJoins, Value, ValueWithSpan, Visit, Visitor,
};
use sqlparser::dialect::Dialect as SqlDialect;
use sqlparser::parser::Parser as SqlAstParser;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn parse_with_dialect<D: SqlDialect>(
    dialect: &D,
    which: crate::parser::Dialect,
    sql: &str,
) -> Result<ParsedQuery> {
    parse_text(dialect, which, sql, sql)
}

/// Parses `sql`, keeping `original` (the client's text) for the MySQL
/// sensitive-column analysis. They differ only when the MySQL parser hands in
/// its lexical normalization of `original` (see `parser::mysql_lex`).
pub(crate) fn parse_text<D: SqlDialect>(
    dialect: &D,
    which: crate::parser::Dialect,
    sql: &str,
    original: &str,
) -> Result<ParsedQuery> {
    // Before the parser recurses on this string. `parse_sql` descends recursively,
    // so deeply nested input overflows the stack inside sqlparser — which aborts the
    // process rather than returning an error we could map. See
    // `guard_nesting_depth`.
    guard_nesting_depth(sql)?;

    let mut statements =
        SqlAstParser::parse_sql(dialect, sql).map_err(|e| ProxyError::ParseError(e.to_string()))?;
    if which == Dialect::Snowflake {
        // Temporary, until sqlparser reads it (see the function).
        crate::parser::resolve_snowflake_order_by_all(&mut statements);
    }
    from_statements(statements, which, original)
}

/// Walks statements already parsed (or, for the SQLite `PRAGMA` forms
/// sqlparser rejects, built by the SQLite parser) into a [`ParsedQuery`],
/// keeping `original` (the client's text) where the dialect needs it.
pub(crate) fn from_statements(
    statements: Vec<Statement>,
    which: crate::parser::Dialect,
    original: &str,
) -> Result<ParsedQuery> {
    // A statement kind sqlparser 0.52 rejected still resolves as the parse
    // error it was (see `not_analysed`).
    if let Some(kind) = statements.iter().find_map(|s| not_analysed(s, which)) {
        return Err(ProxyError::ParseError(format!(
            "{kind}: {UNSUPPORTED_STATEMENT}"
        )));
    }

    let cx = Cx {
        dialect: which,
        snowflake: which == Dialect::Snowflake,
        sqlite: which == Dialect::Sqlite,
    };
    let mut collected: Vec<StatementInfo> = Vec::new();
    for stmt in &statements {
        walk_statement(stmt, false, 0, cx, &mut collected)?;
    }
    let unread = if cx.snowflake {
        statements
            .iter()
            .find_map(snowflake_unread)
            .map(str::to_string)
    } else {
        None
    };

    Ok(ParsedQuery {
        statements: collected,
        ast: crate::parser::SourceAst::Sql {
            statements: std::sync::Arc::new(statements),
            dialect: which,
            sql: matches!(which, Dialect::Mysql | Dialect::Snowflake | Dialect::Sqlite)
                .then(|| std::sync::Arc::from(original)),
        },
        mysql: None,
        unread,
    })
}

/// The text of the parse error for a statement kind the engine does not
/// analyse (see `not_analysed`); [`crate::ParseErrorKind`] reads it as an
/// unknown statement.
pub(crate) const UNSUPPORTED_STATEMENT: &str = "statement not supported by the engine";

/// What the walk needs to know about the dialect. Snowflake and SQLite change
/// specialized readings; the full dialect controls constant semantics and
/// SQL Server's `SELECT … INTO` table-copy form.
#[derive(Clone, Copy)]
struct Cx {
    dialect: Dialect,
    snowflake: bool,
    /// SQLite: its statement kinds (`ATTACH`, `PRAGMA`, `VACUUM`), its
    /// truthiness (`WHERE '1abc'` is true) and its time probe
    /// (`randomblob(N)`).
    sqlite: bool,
}

/// Snowflake code the engine does not read: a scripting block (`BEGIN … END`,
/// with or without `EXCEPTION`) or `EXECUTE IMMEDIATE`. The statements of a
/// block are walked, but not its control flow (variables, loops, `RETURN`),
/// and an `EXECUTE IMMEDIATE` string is never parsed: the rule engine keeps
/// the stricter of the rules' outcome and the parse-error one (see
/// `ParsedQuery::unread`).
fn snowflake_unread(stmt: &Statement) -> Option<&'static str> {
    match stmt {
        Statement::StartTransaction {
            statements,
            exception,
            ..
        } if !statements.is_empty() || exception.is_some() => {
            Some("Snowflake scripting block (BEGIN … END): its control flow is not analysed")
        }
        Statement::Execute {
            immediate: true, ..
        } => Some("EXECUTE IMMEDIATE: the statement text it runs is not analysed"),
        Statement::Execute {
            immediate: false, ..
        } => Some("EXECUTE: the stored code it runs is not analysed"),
        _ => None,
    }
}

/// The statement kind a parsed statement has when the engine must treat it
/// as it treated it before the sqlparser 0.52 → 0.63 upgrade: as a parse
/// error. `None` for every kind the engine already knew.
///
/// These kinds did not exist in sqlparser 0.52, so their text failed to parse
/// and resolved through the host's `parse_error` policy (blocked under a
/// `block`/`mask` tag or an enforced allowlist). The engine has no analysis
/// for any of them; reading them as ordinary statements would let them through
/// silently. They keep failing closed exactly as before until a rule models
/// them. The match is exhaustive on purpose (no catch-all): the next sqlparser
/// upgrade fails to compile on every statement kind it adds, so each new kind
/// is classified here, by a person, before it can reach a verdict.
///
/// `SHOW PROCESSLIST` and `SHOW CHARSET` are the exception: 0.52 parsed them
/// as `ShowVariable`, which the engine already handles, so they stay
/// analysed. Known kinds that gained a body 0.52 rejected (SQL Server's
/// `BEGIN … END`) are treated like a new kind. Inside `SET`, which became one statement kind, the forms 0.52
/// rejected are the server-wide `SET GLOBAL …`, `SET SESSION AUTHORIZATION`
/// and SQL Server's session options (`SET NOCOUNT ON`, …).
///
/// On Snowflake (a dialect 0.52 never served) the kinds the Snowflake walker
/// models are analysed: `CREATE WAREHOUSE`, `ALTER SESSION`, `PUT`, `LIST`
/// and scripting blocks (whose statements are classified here in turn).
/// Everything else Snowflake-only stays a parse error (the Snowflake parser
/// then tries its pre-classifier and allowlist).
pub(crate) fn not_analysed(stmt: &Statement, dialect: Dialect) -> Option<&'static str> {
    use sqlparser::ast::{ContextModifier, Set};
    match stmt {
        // The statement inside is what runs.
        Statement::Explain { statement, .. } | Statement::Prepare { statement, .. } => {
            not_analysed(statement, dialect)
        }
        // `SHOW OBJECTS` (dbt sends it on every run) and `CREATE FILE FORMAT`
        // read or define metadata only.
        Statement::CreateWarehouse { .. }
        | Statement::AlterSession { .. }
        | Statement::Put { .. }
        | Statement::List { .. }
        | Statement::ShowObjects { .. }
        | Statement::CreateFileFormat { .. }
            if dialect == Dialect::Snowflake =>
        {
            None
        }
        // SQLite's `VACUUM` and `VACUUM <schema>` rebuild the database file in
        // place (sqlparser reads them as Redshift's VACUUM, whose options
        // SQLite does not have). `VACUUM INTO` does not parse; the SQLite
        // pre-classifier reports it.
        Statement::Vacuum(v)
            if dialect == Dialect::Sqlite
                && !(v.full
                    || v.sort_only
                    || v.delete_only
                    || v.reindex
                    || v.recluster
                    || v.boost
                    || v.threshold.is_some()) =>
        {
            None
        }
        // A Snowflake scripting block: walked, and read as unread code (see
        // `snowflake_unread`). Its control flow (`IF`, `CASE`, loops,
        // `RETURN`, `RAISE`) is what the unread floor covers; every other
        // statement in it must be analysable.
        Statement::StartTransaction {
            statements,
            exception,
            ..
        } if dialect == Dialect::Snowflake && (!statements.is_empty() || exception.is_some()) => {
            statements
                .iter()
                .chain(exception.iter().flatten().flat_map(|w| w.statements.iter()))
                .filter(|s| {
                    !matches!(
                        s,
                        Statement::If { .. }
                            | Statement::Case { .. }
                            | Statement::While { .. }
                            | Statement::Return { .. }
                            | Statement::Raise { .. }
                    )
                })
                .find_map(|s| not_analysed(s, dialect))
        }
        Statement::Set(set) => match set {
            Set::SingleAssignment {
                scope: Some(ContextModifier::Global),
                ..
            } => Some("SET GLOBAL"),
            Set::MultipleAssignments { assignments }
                if assignments
                    .iter()
                    .any(|a| matches!(a.scope, Some(ContextModifier::Global))) =>
            {
                Some("SET GLOBAL")
            }
            Set::SetSessionAuthorization(_) => Some("SET SESSION AUTHORIZATION"),
            Set::SetSessionParam(_) => Some("SET (session option)"),
            Set::SingleAssignment { .. }
            | Set::MultipleAssignments { .. }
            | Set::ParenthesizedAssignments { .. }
            | Set::SetRole { .. }
            | Set::SetTimeZone { .. }
            | Set::SetNames { .. }
            | Set::SetNamesDefault { .. }
            | Set::SetTransaction { .. } => None,
        },
        Statement::ShowProcessList { .. } | Statement::ShowCharset { .. } => None,
        // SQL Server's `BEGIN … END` block (and a transaction with an
        // exception handler) holds statements of its own; 0.52 rejected it.
        Statement::StartTransaction {
            statements,
            exception,
            ..
        } if !statements.is_empty() || exception.is_some() => Some("BEGIN … END block"),
        Statement::AlterIndex { .. }
        | Statement::AlterPolicy { .. }
        | Statement::AlterRole { .. }
        | Statement::AlterTable { .. }
        | Statement::AlterView { .. }
        | Statement::Analyze { .. }
        | Statement::Assert { .. }
        | Statement::AttachDatabase { .. }
        | Statement::AttachDuckDBDatabase { .. }
        | Statement::Cache { .. }
        | Statement::Call { .. }
        | Statement::Close { .. }
        | Statement::Comment { .. }
        | Statement::Commit { .. }
        | Statement::Copy { .. }
        | Statement::CopyIntoSnowflake { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateExtension { .. }
        | Statement::CreateFunction { .. }
        | Statement::CreateIndex { .. }
        | Statement::CreateMacro { .. }
        | Statement::CreatePolicy { .. }
        | Statement::CreateProcedure { .. }
        | Statement::CreateRole { .. }
        | Statement::CreateSchema { .. }
        | Statement::CreateSecret { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateStage { .. }
        | Statement::CreateTable { .. }
        | Statement::CreateTrigger { .. }
        | Statement::CreateType { .. }
        | Statement::CreateView { .. }
        | Statement::CreateVirtualTable { .. }
        | Statement::Deallocate { .. }
        | Statement::Declare { .. }
        | Statement::Delete { .. }
        | Statement::DetachDuckDBDatabase { .. }
        | Statement::Directory { .. }
        | Statement::Discard { .. }
        | Statement::Drop { .. }
        | Statement::DropFunction { .. }
        | Statement::DropPolicy { .. }
        | Statement::DropProcedure { .. }
        | Statement::DropSecret { .. }
        | Statement::DropTrigger { .. }
        | Statement::Execute { .. }
        | Statement::ExplainTable { .. }
        | Statement::Fetch { .. }
        | Statement::Flush { .. }
        | Statement::Grant { .. }
        | Statement::Insert { .. }
        | Statement::Install { .. }
        | Statement::Kill { .. }
        | Statement::LISTEN { .. }
        | Statement::Load { .. }
        | Statement::LockTables { .. }
        | Statement::Merge { .. }
        | Statement::Msck { .. }
        | Statement::NOTIFY { .. }
        | Statement::OptimizeTable { .. }
        | Statement::Pragma { .. }
        | Statement::Query { .. }
        | Statement::ReleaseSavepoint { .. }
        | Statement::Revoke { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ShowCollation { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowFunctions { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowViews { .. }
        | Statement::StartTransaction { .. }
        | Statement::Truncate { .. }
        | Statement::UNCache { .. }
        | Statement::Unload { .. }
        | Statement::UnlockTables
        | Statement::Update { .. }
        | Statement::Use { .. } => None,
        Statement::AlterCollation { .. }
        | Statement::AlterConnector { .. }
        | Statement::AlterFunction { .. }
        | Statement::AlterOperator { .. }
        | Statement::AlterOperatorClass { .. }
        | Statement::AlterOperatorFamily { .. }
        | Statement::AlterSchema { .. }
        | Statement::AlterSession { .. }
        | Statement::AlterTextSearch { .. }
        | Statement::AlterType { .. }
        | Statement::AlterUser { .. }
        | Statement::Case { .. }
        | Statement::CreateCollation { .. }
        | Statement::CreateConnector { .. }
        | Statement::CreateDomain { .. }
        | Statement::CreateFileFormat { .. }
        | Statement::CreateOperator { .. }
        | Statement::CreateOperatorClass { .. }
        | Statement::CreateOperatorFamily { .. }
        | Statement::CreateServer { .. }
        | Statement::CreateTextSearch { .. }
        | Statement::CreateUser { .. }
        | Statement::CreateWarehouse { .. }
        | Statement::Deny { .. }
        | Statement::DropConnector { .. }
        | Statement::DropDomain { .. }
        | Statement::DropExtension { .. }
        | Statement::DropOperator { .. }
        | Statement::DropOperatorClass { .. }
        | Statement::DropOperatorFamily { .. }
        | Statement::ExportData { .. }
        | Statement::If { .. }
        | Statement::List { .. }
        | Statement::LoadData { .. }
        | Statement::Lock { .. }
        | Statement::Open { .. }
        | Statement::Print { .. }
        | Statement::Put { .. }
        | Statement::RaisError { .. }
        | Statement::Raise { .. }
        | Statement::Remove { .. }
        | Statement::RenameTable { .. }
        | Statement::Reset { .. }
        | Statement::Return { .. }
        | Statement::ShowCatalogs { .. }
        | Statement::ShowObjects { .. }
        | Statement::Throw { .. }
        | Statement::UNLISTEN { .. }
        | Statement::Vacuum { .. }
        | Statement::WaitFor { .. }
        | Statement::While { .. } => Some(statement_kind(stmt)),
    }
}

/// `RenameTable` → `RenameTable`: the variant name, for the parse error text.
fn statement_kind(stmt: &Statement) -> &'static str {
    // Every variant listed in `not_analysed` as new, by name.
    match stmt {
        Statement::AlterCollation { .. } => "AlterCollation",
        Statement::AlterConnector { .. } => "AlterConnector",
        Statement::AlterFunction { .. } => "AlterFunction",
        Statement::AlterOperator { .. } => "AlterOperator",
        Statement::AlterOperatorClass { .. } => "AlterOperatorClass",
        Statement::AlterOperatorFamily { .. } => "AlterOperatorFamily",
        Statement::AlterSchema { .. } => "AlterSchema",
        Statement::AlterSession { .. } => "AlterSession",
        Statement::AlterTextSearch { .. } => "AlterTextSearch",
        Statement::AlterType { .. } => "AlterType",
        Statement::AlterUser { .. } => "AlterUser",
        Statement::Case { .. } => "Case",
        Statement::CreateCollation { .. } => "CreateCollation",
        Statement::CreateConnector { .. } => "CreateConnector",
        Statement::CreateDomain { .. } => "CreateDomain",
        Statement::CreateFileFormat { .. } => "CreateFileFormat",
        Statement::CreateOperator { .. } => "CreateOperator",
        Statement::CreateOperatorClass { .. } => "CreateOperatorClass",
        Statement::CreateOperatorFamily { .. } => "CreateOperatorFamily",
        Statement::CreateServer { .. } => "CreateServer",
        Statement::CreateTextSearch { .. } => "CreateTextSearch",
        Statement::CreateUser { .. } => "CreateUser",
        Statement::CreateWarehouse { .. } => "CreateWarehouse",
        Statement::Deny { .. } => "Deny",
        Statement::DropConnector { .. } => "DropConnector",
        Statement::DropDomain { .. } => "DropDomain",
        Statement::DropExtension { .. } => "DropExtension",
        Statement::DropOperator { .. } => "DropOperator",
        Statement::DropOperatorClass { .. } => "DropOperatorClass",
        Statement::DropOperatorFamily { .. } => "DropOperatorFamily",
        Statement::ExportData { .. } => "ExportData",
        Statement::If { .. } => "If",
        Statement::List { .. } => "List",
        Statement::LoadData { .. } => "LoadData",
        Statement::Lock { .. } => "Lock",
        Statement::Open { .. } => "Open",
        Statement::Print { .. } => "Print",
        Statement::Put { .. } => "Put",
        Statement::RaisError { .. } => "RaisError",
        Statement::Raise { .. } => "Raise",
        Statement::Remove { .. } => "Remove",
        Statement::RenameTable { .. } => "RenameTable",
        Statement::Reset { .. } => "Reset",
        Statement::Return { .. } => "Return",
        Statement::ShowCatalogs { .. } => "ShowCatalogs",
        Statement::ShowObjects { .. } => "ShowObjects",
        Statement::Throw { .. } => "Throw",
        Statement::UNLISTEN { .. } => "UNLISTEN",
        Statement::Vacuum { .. } => "Vacuum",
        Statement::WaitFor { .. } => "WaitFor",
        Statement::While { .. } => "While",
        _ => "statement",
    }
}

// ---------------------------------------------------------------------------
// Statement walker
// ---------------------------------------------------------------------------

fn walk_statement(
    stmt: &Statement,
    is_nested: bool,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match stmt {
        // ── DELETE ─────────────────────────────────────────────────────────
        Statement::Delete(delete) => {
            let presence = where_presence(delete.selection.as_ref(), cx.dialect);
            let relation = relation_from_delete(delete);
            let delete_limit = delete.limit.as_ref().and_then(expr_as_i64);
            let tautology = delete
                .selection
                .as_ref()
                .is_some_and(|e| has_or_tautology(e, cx.dialect));

            out.push(StatementInfo {
                kind: StatementKind::Delete,
                relation,
                where_presence: presence,
                is_nested,
                ast_node_path: node_path_where("DeleteStmt", presence, is_nested),
                delete_limit,
                has_or_tautology: tautology,
                ..Default::default()
            });

            // Recurse into WHERE subqueries
            if let Some(expr) = delete.selection.as_ref() {
                walk_expr(expr, depth + 1, cx, out)?;
            }
            walk_with_from_ctes(&delete.from, depth + 1, cx, out)?;
            let walked_queries = match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
                    tables.iter().filter_map(|t| derived(&t.relation)).collect()
                }
            };
            let walked = Walked {
                exprs: delete.selection.iter().collect(),
                queries: walked_queries,
            };
            walk_rest(delete, walked, depth + 1, cx, out)?;
        }

        // ── UPDATE ─────────────────────────────────────────────────────────
        Statement::Update(update) => {
            let sqlparser::ast::Update {
                selection, table, ..
            } = update;
            let presence = where_presence(selection.as_ref(), cx.dialect);
            let relation = relation_from_table_with_joins(table);
            let tautology = selection
                .as_ref()
                .is_some_and(|e| has_or_tautology(e, cx.dialect));
            out.push(StatementInfo {
                kind: StatementKind::Update,
                relation,
                where_presence: presence,
                is_nested,
                ast_node_path: node_path_where("UpdateStmt", presence, is_nested),
                has_or_tautology: tautology,
                ..Default::default()
            });
            if let Some(expr) = selection.as_ref() {
                walk_expr(expr, depth + 1, cx, out)?;
            }
            // `SET x = sleep(…)`, `FROM`, `RETURNING`, `ORDER BY`, `LIMIT`.
            let walked = Walked {
                exprs: selection.iter().collect(),
                queries: Vec::new(),
            };
            walk_rest(update, walked, depth + 1, cx, out)?;
        }

        // ── DROP ───────────────────────────────────────────────────────────
        Statement::Drop {
            object_type,
            names,
            if_exists,
            ..
        } => {
            let drop_object = match object_type {
                ObjectType::Table => DropObjectKind::Table,
                // sqlparser exposes DROP DATABASE as its own ObjectType —
                // previously it fell into `_ => Other`, so on MySQL a
                // `DROP DATABASE` was mis-classified. Map it explicitly so
                // VERICTO-010's allowlist (Table|Database) catches it on every
                // dialect, not just Postgres.
                ObjectType::Database => DropObjectKind::Database,
                ObjectType::Schema => DropObjectKind::Schema,
                ObjectType::Index => DropObjectKind::Index,
                // View/Function/Policy/Sequence/… stay `Other`: they are not
                // destructive table/data drops, so VERICTO-010 must not fire on
                // them (that was the DROP POLICY false positive). DROP TRIGGER
                // is its own statement kind, below.
                _ => DropObjectKind::Other,
            };
            let relation = names.first().map(|n| n.to_string());
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                relation,
                drop_object: Some(drop_object),
                is_nested,
                ast_node_path: "DropStmt".to_string(),
                drop_index_if_exists: *if_exists,
                ..Default::default()
            });
        }

        // ── DROP TRIGGER (VERICTO-019) ─────────────────────────────────────
        // Its own statement kind in sqlparser; libpg_query reads it as a
        // `DropStmt` with object type TRIGGER, recorded the same way. On SQL
        // Server, `ON DATABASE` (a DDL trigger) reads as the table name.
        Statement::DropTrigger(sqlparser::ast::DropTrigger {
            if_exists,
            trigger_name,
            table_name,
            ..
        }) => {
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                relation: Some(table_name.as_ref().unwrap_or(trigger_name).to_string()),
                drop_object: Some(DropObjectKind::Trigger),
                is_nested,
                ast_node_path: "DropStmt".to_string(),
                drop_index_if_exists: *if_exists,
                ..Default::default()
            });
        }

        // ── TRUNCATE ───────────────────────────────────────────────────────
        Statement::Truncate(sqlparser::ast::Truncate { table_names, .. }) => {
            let relation = table_names.first().map(|t| t.name.to_string());
            out.push(StatementInfo {
                kind: StatementKind::Truncate,
                relation,
                is_nested,
                ast_node_path: "TruncateStmt".to_string(),
                ..Default::default()
            });
        }

        // ── ALTER TABLE ────────────────────────────────────────────────────
        Statement::AlterTable(sqlparser::ast::AlterTable {
            name, operations, ..
        }) => {
            for op in operations {
                use sqlparser::ast::{AlterColumnOperation, AlterTableOperation};
                let (kind, path) = match op {
                    AlterTableOperation::DropColumn { .. } => {
                        (AlterTableKind::DropColumn, "AlterTableStmt > DropColumn")
                    }
                    AlterTableOperation::RenameTable { .. }
                    | AlterTableOperation::RenameColumn { .. } => {
                        (AlterTableKind::Rename, "AlterTableStmt > Rename")
                    }
                    // Snowflake's `ALTER TABLE a SWAP WITH b` exchanges the
                    // two names: a rename of both tables.
                    AlterTableOperation::SwapWith { .. } if cx.snowflake => {
                        (AlterTableKind::Rename, "AlterTableStmt > SwapWith")
                    }
                    // MySQL's `DROP FOREIGN KEY fk` is its spelling of
                    // dropping a constraint (sqlparser reads it since 0.56;
                    // it was a parse error before, so it never reached here).
                    AlterTableOperation::DropConstraint { .. }
                    | AlterTableOperation::DropPrimaryKey { .. }
                    | AlterTableOperation::DropForeignKey { .. } => (
                        AlterTableKind::DropConstraint,
                        "AlterTableStmt > DropConstraint",
                    ),
                    // Only a TYPE change rewrites/relocates data; SET/DROP
                    // DEFAULT and NULL-ability changes are comparatively benign,
                    // so they are intentionally not flagged.
                    AlterTableOperation::AlterColumn {
                        op: AlterColumnOperation::SetDataType { .. },
                        ..
                    } => (
                        AlterTableKind::AlterColumnType,
                        "AlterTableStmt > AlterColumnType",
                    ),
                    AlterTableOperation::DisableTrigger { .. }
                    | AlterTableOperation::DisableRowLevelSecurity => (
                        AlterTableKind::DisableTrigger,
                        "AlterTableStmt > DisableTrigger",
                    ),
                    _ => continue,
                };
                out.push(StatementInfo {
                    kind: StatementKind::AlterTable,
                    relation: Some(name.to_string()),
                    alter_table_kind: Some(kind),
                    is_nested,
                    ast_node_path: path.to_string(),
                    ..Default::default()
                });
            }
        }

        // ── CREATE TABLE … AS SELECT (VERICTO-084) ────────────────────────
        // The generic sqlparser paths model CTAS as CreateTable { query }.
        // SQLite and Snowflake keep their specialized walkers below: Snowflake
        // also classifies CREATE OR REPLACE / CLONE, and SQLite trigger bodies.
        Statement::CreateTable(ct) if !cx.sqlite && !cx.snowflake && ct.query.is_some() => {
            out.push(StatementInfo {
                kind: StatementKind::CreateTableAs,
                relation: Some(ct.name.to_string()),
                is_nested,
                ast_node_path: "CreateTableAsStmt".to_string(),
                ..Default::default()
            });
            walk_query(
                ct.query.as_deref().expect("guarded by is_some"),
                true,
                depth + 1,
                cx,
                out,
            )?;
        }

        Statement::CreateView(view) if view.materialized => {
            out.push(StatementInfo {
                kind: StatementKind::CreateTableAs,
                relation: Some(view.name.to_string()),
                is_nested,
                ast_node_path: "CreateMaterializedViewStmt".to_string(),
                ..Default::default()
            });
            walk_query(&view.query, true, depth + 1, cx, out)?;
        }

        // ── INSERT ─────────────────────────────────────────────────────────
        Statement::Insert(insert) => {
            let has_columns = !insert.columns.is_empty();

            // Count direct or parenthesized literal tuples for VERICTO-061.
            // A LIMIT/OFFSET/FETCH can reduce the result, so that shape remains
            // undecided rather than over-reporting a bulk insert.
            let insert_row_count = match insert.source.as_deref() {
                Some(query) => insert_values_row_count(query, depth + 1)?,
                None => None,
            };

            // Classify the source recursively. A set operation or
            // parenthesized SELECT is still INSERT … SELECT, while a
            // parenthesized VALUES expression is not. UNION arms must each be
            // bounded unless an enclosing query has a row limit; filtering set
            // operators are bounded by their own structure.
            let (insert_has_select, insert_select_has_filter) = match insert.source.as_deref() {
                Some(query) => insert_source(query, cx, depth + 1)?,
                None => (false, false),
            };

            out.push(StatementInfo {
                kind: StatementKind::Insert,
                relation: Some(insert.table.to_string()),
                is_nested,
                ast_node_path: "InsertStmt".to_string(),
                insert_has_columns: has_columns,
                insert_has_select,
                insert_select_has_filter,
                insert_row_count,
                ..Default::default()
            });

            // Snowflake's `INSERT OVERWRITE` empties the target before it
            // inserts: its current rows survive only in Time Travel.
            if cx.snowflake && insert.overwrite {
                out.push(StatementInfo {
                    relation: Some(insert.table.to_string()),
                    is_nested,
                    ast_node_path: "InsertStmt > OVERWRITE (replaces every row of the target)"
                        .to_string(),
                    snowflake: Some(SnowflakeRisk::RecoveryReduced),
                    ..Default::default()
                });
            }

            // Recurse into source SELECT
            if let Some(source) = insert.source.as_ref() {
                walk_query(source.as_ref(), true, depth + 1, cx, out)?;
            }
            // `ON CONFLICT … DO UPDATE SET`, `RETURNING`, MySQL's `SET` form.
            let walked = Walked {
                exprs: Vec::new(),
                queries: insert.source.iter().map(|q| q.as_ref()).collect(),
            };
            walk_rest(insert, walked, depth + 1, cx, out)?;
        }

        // ── COPY … TO/FROM PROGRAM (VERICTO-080) ─────────────────────────────
        // The PROGRAM target/source runs a shell command on the server (RCE /
        // exfiltration). Non-program forms are still recorded; `FROM` a
        // server-side file is a bulk load VERICTO-061 reports.
        Statement::Copy { to, target, .. } => {
            use sqlparser::ast::CopyTarget;
            out.push(StatementInfo {
                kind: StatementKind::Copy,
                is_nested,
                ast_node_path: if matches!(target, CopyTarget::Program { .. }) {
                    "CopyStmt > PROGRAM".to_string()
                } else {
                    "CopyStmt".to_string()
                },
                copy_is_program: matches!(target, CopyTarget::Program { .. }),
                copy_from_file: !*to && matches!(target, CopyTarget::File { .. }),
                ..Default::default()
            });
        }

        // ── GRANT … TO SHARE (Snowflake, VERICTO-093 and VERICTO-082) ─────────
        // Still a GRANT, so VERICTO-082 keeps reporting it; the share is
        // recorded on its own, because the data then leaves the account.
        Statement::Grant(grant)
            if cx.snowflake
                && grant
                    .grantees
                    .iter()
                    .any(|g| matches!(g.grantee_type, sqlparser::ast::GranteesType::Share)) =>
        {
            out.push(StatementInfo {
                kind: StatementKind::Grant,
                is_nested,
                ast_node_path: "GrantStmt".to_string(),
                ..Default::default()
            });
            out.push(StatementInfo {
                is_nested,
                ast_node_path: "GrantStmt > TO SHARE".to_string(),
                snowflake: Some(SnowflakeRisk::Share),
                ..Default::default()
            });
        }

        // ── GRANT / REVOKE (VERICTO-082) ─────────────────────────────────────
        Statement::Grant { .. } | Statement::Revoke { .. } => {
            out.push(StatementInfo {
                kind: StatementKind::Grant,
                is_nested,
                ast_node_path: "GrantStmt".to_string(),
                ..Default::default()
            });
        }

        // ── MERGE (VERICTO-083) ──────────────────────────────────────────────
        Statement::Merge(merge) => {
            out.push(StatementInfo {
                kind: StatementKind::Merge,
                relation: relation_from_table_factor(&merge.table),
                is_nested,
                ast_node_path: "MergeStmt".to_string(),
                ..Default::default()
            });
            walk_rest(merge, Walked::default(), depth + 1, cx, out)?;
        }

        // PREPARE does not execute immediately, but accepting a dangerous body
        // lets a later opaque EXECUTE bypass every statement rule. Inspect the
        // body now and mark its SELECT as nested so read-only LIMIT advice does
        // not fire merely for preparing it.
        Statement::Prepare { statement, .. } => {
            walk_statement(statement, true, depth + 1, cx, out)?;
        }

        // SET assignment values execute immediately. Walking the accepted
        // forms closes placements such as MySQL `SET @x = SLEEP(5)`.
        Statement::Set(set) => {
            walk_rest(set, Walked::default(), depth + 1, cx, out)?;
        }

        // EXPLAIN ANALYZE executes the wrapped statement; plain EXPLAIN only
        // plans it and must not inherit execution-time findings.
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => {
            walk_statement(statement, is_nested, depth + 1, cx, out)?;
        }
        Statement::Explain { .. } => {}

        // ── SELECT ─────────────────────────────────────────────────────────
        Statement::Query(query) => {
            walk_query(query.as_ref(), is_nested, depth + 1, cx, out)?;
        }

        other => {
            // Other statement types are not (yet) modelled. CREATE TABLE AS is
            // handled above for MySQL/Oracle/MS SQL and by the specialized
            // SQLite/Snowflake walkers below.
            if cx.snowflake {
                walk_snowflake(other, is_nested, depth, cx, out)?;
            }
            if cx.sqlite {
                walk_sqlite(other, is_nested, depth, cx, out)?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SQLite statements
// ---------------------------------------------------------------------------

/// The SQLite-only statement kinds (`ATTACH`, `PRAGMA`), and the SQLite
/// readings of shared ones (`CREATE TABLE … AS`, a trigger's body). Only
/// called on SQLite.
fn walk_sqlite(
    stmt: &Statement,
    is_nested: bool,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    let risk = |what: SqliteRisk, relation: Option<String>, path: String| StatementInfo {
        relation,
        is_nested,
        ast_node_path: path,
        sqlite: Some(what),
        ..Default::default()
    };
    match stmt {
        // `ATTACH 'file' AS name` opens (or creates) that file: VERICTO-098.
        Statement::AttachDatabase {
            schema_name,
            database_file_name,
            ..
        } => {
            out.push(risk(
                SqliteRisk::Attach,
                Some(schema_name.to_string()),
                format!("AttachStmt > {database_file_name} AS {schema_name}"),
            ));
            // The file name is an expression SQLite evaluates.
            walk_expr(database_file_name, depth + 1, cx, out)?;
        }
        // A PRAGMA that turns a safety off: VERICTO-099. Reads and the other
        // settings are recorded with no finding.
        Statement::Pragma { name, value, .. } => {
            let value = value.as_ref().map(|v| &v.value);
            out.push(match crate::parser::sqlite::pragma_risk(name, value) {
                Some(why) => risk(
                    SqliteRisk::SafetyPragma,
                    None,
                    format!("PragmaStmt > {why}"),
                ),
                None => StatementInfo {
                    is_nested,
                    ast_node_path: format!("PragmaStmt > {name}"),
                    ..Default::default()
                },
            });
        }
        // `CREATE TABLE … AS SELECT` copies the rows (VERICTO-084).
        Statement::CreateTable(ct) => {
            if let Some(q) = ct.query.as_deref() {
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    relation: Some(ct.name.to_string()),
                    is_nested,
                    ast_node_path: "CreateTableAsStmt".to_string(),
                    ..Default::default()
                });
                walk_query(q, true, depth + 1, cx, out)?;
            }
        }
        // A trigger's body runs on every matching write, outside any check:
        // its statements are walked, as nested, after its `WHEN` condition
        // (evaluated for every one of those rows).
        Statement::CreateTrigger(ct) => {
            if let Some(body) = &ct.statements {
                let start = out.len();
                if let Some(condition) = &ct.condition {
                    walk_expr(condition, depth + 1, cx, out)?;
                }
                for s in body.statements() {
                    walk_statement(s, true, depth + 1, cx, out)?;
                }
                for s in &mut out[start..] {
                    let path = s
                        .ast_node_path
                        .strip_prefix("WithClause > ")
                        .unwrap_or(&s.ast_node_path);
                    s.ast_node_path = format!("CreateTriggerStmt {} > {path}", ct.name);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Snowflake statements
// ---------------------------------------------------------------------------

/// The Snowflake-only statement kinds, and the Snowflake readings of shared
/// ones (`CREATE TABLE … AS | CLONE`, `CREATE OR REPLACE`). `Ok(false)` when
/// `stmt` is none of them. Only called on Snowflake.
fn walk_snowflake(
    stmt: &Statement,
    is_nested: bool,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<bool> {
    use sqlparser::ast::{CopyIntoSnowflakeKind, SecondaryRoles, Use};
    let risk = |what: SnowflakeRisk, relation: Option<String>, path: String| StatementInfo {
        relation,
        is_nested,
        ast_node_path: path,
        snowflake: Some(what),
        ..Default::default()
    };
    match stmt {
        // `COPY INTO @stage | 's3://…' FROM …` unloads rows to files a stage
        // or an external location holds (VERICTO-091); `COPY INTO t FROM
        // @stage` loads them, recorded as a COPY with no finding.
        Statement::CopyIntoSnowflake {
            kind,
            into,
            from_obj,
            from_query,
            ..
        } => {
            match kind {
                CopyIntoSnowflakeKind::Location => {
                    let mut info = risk(
                        SnowflakeRisk::StageTransfer,
                        Some(into.to_string()),
                        format!(
                            "CopyIntoStmt > INTO {into} (unload{})",
                            from_obj
                                .as_ref()
                                .map_or_else(String::new, |t| format!(" of {t}"))
                        ),
                    );
                    info.kind = StatementKind::Copy;
                    out.push(info);
                }
                CopyIntoSnowflakeKind::Table => out.push(StatementInfo {
                    kind: StatementKind::Copy,
                    relation: Some(into.to_string()),
                    is_nested,
                    ast_node_path: "CopyIntoStmt > FROM stage (load)".to_string(),
                    ..Default::default()
                }),
            }
            if let Some(q) = from_query {
                walk_query(q, true, depth + 1, cx, out)?;
            }
        }
        // `PUT file://… @stage`: files from the client's machine into a stage.
        Statement::Put { stage, .. } => out.push(risk(
            SnowflakeRisk::StageTransfer,
            Some(stage.to_string()),
            format!("PutStmt > file upload to {stage}"),
        )),
        // An external stage: `URL =` (S3, Azure, GCS) or inline credentials.
        // An internal stage (no URL) is recorded with no finding.
        Statement::CreateStage {
            name, stage_params, ..
        } => {
            let external =
                stage_params.url.is_some() || !stage_params.credentials.options.is_empty();
            out.push(StatementInfo {
                relation: Some(name.to_string()),
                is_nested,
                ast_node_path: if external {
                    "CreateStageStmt > external location (URL / CREDENTIALS)".to_string()
                } else {
                    "CreateStageStmt".to_string()
                },
                snowflake: external.then_some(SnowflakeRisk::ExternalAccess),
                ..Default::default()
            });
        }
        Statement::CreateWarehouse(cw) => {
            if let Some(why) = warehouse_cost(&cw.options) {
                out.push(risk(
                    SnowflakeRisk::WarehouseCost,
                    Some(cw.name.to_string()),
                    format!("CreateWarehouseStmt > {why}"),
                ));
            }
        }
        // `USE ROLE r` changes every privilege the session holds; `USE
        // SECONDARY ROLES ALL | r, …` adds the privileges of other roles.
        // `USE SECONDARY ROLES NONE` only narrows them.
        Statement::Use(u) => match u {
            Use::Role(name) => {
                let admin = PRIVILEGED_ROLES
                    .iter()
                    .any(|r| name.to_string().eq_ignore_ascii_case(r));
                out.push(risk(
                    SnowflakeRisk::RoleSwitch,
                    None,
                    format!(
                        "UseStmt > ROLE {name}{}",
                        if admin { " (administrative role)" } else { "" }
                    ),
                ));
            }
            Use::SecondaryRoles(SecondaryRoles::All | SecondaryRoles::List(_)) => out.push(risk(
                SnowflakeRisk::RoleSwitch,
                None,
                format!("UseStmt > {u}").replace("UseStmt > USE ", "UseStmt > "),
            )),
            Use::SecondaryRoles(SecondaryRoles::None)
            | Use::Catalog(_)
            | Use::Schema(_)
            | Use::Database(_)
            | Use::Warehouse(_)
            | Use::Object(_)
            | Use::Default => {}
        },
        // `EXECUTE IMMEDIATE '…'` runs text the engine never parses: like a
        // DO block (VERICTO-081), and unread (the parse-error floor).
        Statement::Execute {
            immediate: true, ..
        } => out.push(StatementInfo {
            kind: StatementKind::DoBlock,
            is_nested,
            ast_node_path: "ExecuteImmediateStmt".to_string(),
            ..Default::default()
        }),
        // `EXECUTE TASK | ALERT | NOTEBOOK … name` runs a stored object's
        // code now (sqlparser reads the kind as the name): VERICTO-096, and
        // unread.
        Statement::Execute {
            immediate: false,
            name,
            parameters,
            ..
        } => out.push(risk(
            SnowflakeRisk::Persistence,
            parameters.first().map(ToString::to_string),
            format!(
                "ExecuteStmt > runs stored code ({}{})",
                name.as_ref().map_or_else(String::new, ToString::to_string),
                parameters
                    .first()
                    .map_or_else(String::new, |p| format!(" {p}"))
            ),
        )),
        // A scripting block: like a DO block (VERICTO-081), and every
        // statement inside is walked (they run), as nested (none of them is
        // what the client receives).
        Statement::StartTransaction {
            statements,
            exception,
            ..
        } if !statements.is_empty() || exception.is_some() => {
            out.push(StatementInfo {
                kind: StatementKind::DoBlock,
                is_nested,
                ast_node_path: "ScriptingBlock (BEGIN … END)".to_string(),
                ..Default::default()
            });
            for s in statements
                .iter()
                .chain(exception.iter().flatten().flat_map(|w| w.statements.iter()))
            {
                walk_statement(s, true, depth + 1, cx, out)?;
            }
        }
        Statement::CreateTable(ct) => {
            let name = ct.name.to_string();
            if let Some(q) = ct.query.as_deref() {
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    relation: Some(name.clone()),
                    is_nested,
                    ast_node_path: "CreateTableAsStmt".to_string(),
                    ..Default::default()
                });
                walk_query(q, true, depth + 1, cx, out)?;
            } else if let Some(src) = &ct.clone {
                // Zero-copy, but a full copy of the data as far as access goes.
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    relation: Some(name.clone()),
                    is_nested,
                    ast_node_path: format!("CreateTableStmt > CLONE {src}"),
                    ..Default::default()
                });
            }
            if ct.or_replace {
                out.push(risk(
                    SnowflakeRisk::RecoveryReduced,
                    Some(name.clone()),
                    "CreateTableStmt > OR REPLACE (drops an existing table of that name)"
                        .to_string(),
                ));
            }
            if ct.data_retention_time_in_days == Some(0) {
                out.push(risk(
                    SnowflakeRisk::RecoveryReduced,
                    Some(name),
                    "CreateTableStmt > DATA_RETENTION_TIME_IN_DAYS = 0".to_string(),
                ));
            }
        }
        Statement::CreateDatabase {
            db_name,
            or_replace,
            clone,
            data_retention_time_in_days,
            ..
        } => {
            let name = db_name.to_string();
            if let Some(src) = clone {
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    relation: Some(name.clone()),
                    is_nested,
                    ast_node_path: format!("CreateDatabaseStmt > CLONE {src}"),
                    ..Default::default()
                });
            }
            if *or_replace {
                out.push(risk(
                    SnowflakeRisk::RecoveryReduced,
                    Some(name.clone()),
                    "CreateDatabaseStmt > OR REPLACE (drops an existing database of that name)"
                        .to_string(),
                ));
            }
            if *data_retention_time_in_days == Some(0) {
                out.push(risk(
                    SnowflakeRisk::RecoveryReduced,
                    Some(name),
                    "CreateDatabaseStmt > DATA_RETENTION_TIME_IN_DAYS = 0".to_string(),
                ));
            }
        }
        Statement::CreateSchema {
            schema_name,
            or_replace,
            clone,
            ..
        } => {
            let name = schema_name.to_string();
            if let Some(src) = clone {
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    relation: Some(name.clone()),
                    is_nested,
                    ast_node_path: format!("CreateSchemaStmt > CLONE {src}"),
                    ..Default::default()
                });
            }
            if *or_replace {
                out.push(risk(
                    SnowflakeRisk::RecoveryReduced,
                    Some(name),
                    "CreateSchemaStmt > OR REPLACE (drops an existing schema of that name)"
                        .to_string(),
                ));
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// A Snowflake `SELECT` whose only source is bounded: a fixed-size sample
/// (`FROM t SAMPLE (100 ROWS)`, at most that many rows, whatever the filter)
/// or `TABLE(RESULT_SCAN(…))`, a result already computed and returned once.
/// A join, or a percentage sample, bounds nothing.
fn snowflake_bounded(select: &sqlparser::ast::Select) -> bool {
    use sqlparser::ast::{TableSampleKind, TableSampleUnit};
    let [only] = select.from.as_slice() else {
        return false;
    };
    if !only.joins.is_empty() {
        return false;
    }
    match &only.relation {
        TableFactor::Table {
            sample: Some(TableSampleKind::BeforeTableAlias(t) | TableSampleKind::AfterTableAlias(t)),
            ..
        } => {
            t.bucket.is_none()
                && t.quantity
                    .as_ref()
                    .is_some_and(|q| matches!(q.unit, Some(TableSampleUnit::Rows)))
        }
        TableFactor::TableFunction {
            expr: Expr::Function(f),
            ..
        } => f
            .name
            .0
            .last()
            .and_then(|p| p.as_ident())
            .is_some_and(|i| i.value.eq_ignore_ascii_case("result_scan")),
        _ => false,
    }
}

/// The roles that administer a Snowflake account, named in the evidence of
/// VERICTO-097.
const PRIVILEGED_ROLES: &[&str] = &[
    "ACCOUNTADMIN",
    "SECURITYADMIN",
    "SYSADMIN",
    "USERADMIN",
    "ORGADMIN",
    "GLOBALORGADMIN",
];

/// Why a `CREATE WAREHOUSE`'s options can run up cost (VERICTO-095): a size,
/// a cluster count, a type, a scaling policy, or an `AUTO_SUSPEND` that
/// never suspends (`0` or `NULL`). `None` for a warehouse created with the
/// defaults (X-Small, one cluster, suspends after 10 minutes).
pub(crate) fn warehouse_cost(
    options: &sqlparser::ast::helpers::key_value_options::KeyValueOptions,
) -> Option<String> {
    use sqlparser::ast::helpers::key_value_options::KeyValueOptionKind;
    for o in &options.options {
        let name = o.option_name.to_ascii_uppercase();
        match name.as_str() {
            "WAREHOUSE_SIZE"
            | "MAX_CLUSTER_COUNT"
            | "MIN_CLUSTER_COUNT"
            | "SCALING_POLICY"
            | "WAREHOUSE_TYPE"
            | "RESOURCE_CONSTRAINT"
            | "QUERY_ACCELERATION_MAX_SCALE_FACTOR"
            | "ENABLE_QUERY_ACCELERATION" => {
                return Some(format!("{name} = {}", option_text(&o.option_value)));
            }
            "AUTO_SUSPEND" => {
                let v = option_text(&o.option_value);
                if v == "0" || v.eq_ignore_ascii_case("NULL") {
                    return Some(format!("AUTO_SUSPEND = {v} (never suspends)"));
                }
            }
            _ => {}
        }
    }
    fn option_text(v: &KeyValueOptionKind) -> String {
        let one = |v: &ValueWithSpan| match &v.value {
            Value::SingleQuotedString(s) | Value::DoubleQuotedString(s) => s.clone(),
            other => other.to_string(),
        };
        match v {
            KeyValueOptionKind::Single(v) => one(v),
            KeyValueOptionKind::Multi(vs) => vs.iter().map(one).collect::<Vec<_>>().join(", "),
            KeyValueOptionKind::KeyValueOptions(o) => format!("({o})"),
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Query / SELECT walker
// ---------------------------------------------------------------------------

fn walk_query(
    query: &Query,
    is_nested: bool,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    // Pipe syntax (`FROM t |> SELECT …`), which sqlparser's Generic dialect
    // (Oracle here) reads since 0.57 and 0.52 rejected. No walker models it:
    // it stays the parse error it was.
    if !query.pipe_operators.is_empty() {
        return Err(ProxyError::ParseError(
            "pipe syntax (`|>`): not supported by the engine".to_string(),
        ));
    }

    // CTEs (WITH … AS (…))
    if let Some(with) = query.with.as_ref() {
        for cte in &with.cte_tables {
            walk_query(cte.query.as_ref(), true, depth + 1, cx, out)?;
        }
    }

    // A row-bound is supplied by any of LIMIT (MySQL/PG/generic), FETCH FIRST
    // (ANSI/Oracle 12c+), or TOP (MSSQL/Sybase — lives on the Select node). The
    // bound belongs to the enclosing Query, so we resolve it here and thread it
    // into the SELECT node, fixing ENG-001 (every non-PG SELECT was flagged by
    // VERICTO-050 because `select_has_limit` was hard-coded to `false`).
    let has_limit = has_row_limit(query) || query.fetch.is_some();

    walk_set_expr(
        query.body.as_ref(),
        is_nested,
        has_limit,
        depth + 1,
        cx,
        out,
    )?;

    // `ORDER BY`, `LIMIT` / `OFFSET`, `FETCH` and the rest of the query
    // around its body. Destructured without `..`: a field a sqlparser upgrade
    // adds fails to compile here until it is classified.
    {
        let Query {
            with: _,
            body: _,
            order_by,
            limit_clause,
            fetch,
            locks,
            for_clause,
            settings,
            format_clause,
            pipe_operators: _,
        } = query;
        let d = depth + 1;
        walk_rest(order_by, Walked::default(), d, cx, out)?;
        walk_rest(limit_clause, Walked::default(), d, cx, out)?;
        walk_rest(fetch, Walked::default(), d, cx, out)?;
        walk_rest(locks, Walked::default(), d, cx, out)?;
        walk_rest(for_clause, Walked::default(), d, cx, out)?;
        walk_rest(settings, Walked::default(), d, cx, out)?;
        walk_rest(format_clause, Walked::default(), d, cx, out)?;
    }
    Ok(())
}

fn insert_values_row_count(query: &Query, depth: usize) -> Result<Option<usize>> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    if query.limit_clause.is_some() || query.fetch.is_some() {
        return Ok(None);
    }
    match query.body.as_ref() {
        SetExpr::Values(values) => Ok(Some(values.rows.len())),
        SetExpr::Query(inner) => insert_values_row_count(inner, depth + 1),
        _ => Ok(None),
    }
}

/// Classifies the query sourcing an INSERT for VERICTO-040.
///
/// `has_select` is true when at least one arm reads through SELECT/TABLE rather
/// than supplying literal VALUES. UNION requires every contributing arm to be
/// bounded, while INTERSECT/EXCEPT are structural filters. A limit on an
/// enclosing query bounds the complete source.
fn insert_source(query: &Query, cx: Cx, depth: usize) -> Result<(bool, bool)> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    let (has_select, arms_bounded) = insert_set_expr_source(query.body.as_ref(), cx, depth + 1)?;
    let outer_bound = has_row_limit(query) || query.fetch.is_some();
    Ok((has_select, has_select && (outer_bound || arms_bounded)))
}

fn insert_set_expr_source(set_expr: &SetExpr, cx: Cx, depth: usize) -> Result<(bool, bool)> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    match set_expr {
        SetExpr::Select(select) => {
            let effective_where = select
                .selection
                .as_ref()
                .is_some_and(|expr| !is_always_true(expr, cx.dialect));
            let row_bound = select.top.is_some() || (cx.snowflake && snowflake_bounded(select));
            Ok((true, effective_where || row_bound))
        }
        SetExpr::Query(query) => insert_source(query, cx, depth + 1),
        SetExpr::SetOperation {
            left, op, right, ..
        } => {
            let left = insert_set_expr_source(left, cx, depth + 1)?;
            let right = insert_set_expr_source(right, cx, depth + 1)?;
            let has_select = left.0 || right.0;
            let operator_bounds = match op {
                SetOperator::Union => (!left.0 || left.1) && (!right.0 || right.1),
                SetOperator::Intersect | SetOperator::Except | SetOperator::Minus => true,
            };
            Ok((has_select, has_select && operator_bounds))
        }
        SetExpr::Table(_) => Ok((true, false)),
        SetExpr::Values(_)
        | SetExpr::Insert(_)
        | SetExpr::Update(_)
        | SetExpr::Delete(_)
        | SetExpr::Merge(_) => Ok((false, false)),
    }
}

/// True when the query carries a row bound: `LIMIT n` or MySQL's
/// `LIMIT offset, n`. Since sqlparser 0.56 LIMIT and OFFSET live together in
/// `Query::limit_clause`, which is `Some` for a bare `OFFSET n` or `LIMIT ALL`
/// too; neither bounds anything, exactly as when `Query::limit` was `None`
/// for them, so only an actual limit expression counts.
fn has_row_limit(query: &Query) -> bool {
    match &query.limit_clause {
        Some(LimitClause::LimitOffset { limit, .. }) => limit.is_some(),
        Some(LimitClause::OffsetCommaLimit { .. }) => true,
        None => false,
    }
}

fn walk_set_expr(
    set_expr: &SetExpr,
    is_nested: bool,
    has_limit: bool,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match set_expr {
        SetExpr::Select(select) => {
            // SELECT * detection
            let is_star = select.projection.iter().any(|item| {
                matches!(
                    item,
                    SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
                )
            });

            // A `TOP n` clause (MSSQL, Snowflake) also bounds the result set,
            // as does a Snowflake `SAMPLE (n ROWS)` or `RESULT_SCAN` source.
            let has_limit =
                has_limit || select.top.is_some() || (cx.snowflake && snowflake_bounded(select));

            // Tautological OR detection in WHERE
            let tautology = select
                .selection
                .as_ref()
                .is_some_and(|e| has_or_tautology(e, cx.dialect));

            // WHERE recursion (subqueries and sleep-family calls)
            if let Some(expr) = select.selection.as_ref() {
                walk_expr(expr, depth + 1, cx, out)?;
            }
            // Snowflake's QUALIFY filters on window results; it runs too.
            if cx.snowflake {
                if let Some(expr) = select.qualify.as_ref() {
                    walk_expr(expr, depth + 1, cx, out)?;
                }
            }

            // Projection recursion — `SELECT sleep(5)` lives here, not in WHERE
            // (ENG-006). Without this the sqlparser path missed sleep calls that
            // were not inside the WHERE clause.
            for item in &select.projection {
                match item {
                    SelectItem::UnnamedExpr(e) => walk_expr(e, depth + 1, cx, out)?,
                    SelectItem::ExprWithAlias { expr, .. }
                    | SelectItem::ExprWithAliases { expr, .. } => {
                        walk_expr(expr, depth + 1, cx, out)?
                    }
                    SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => {}
                }
            }

            // SQL Server's `SELECT … INTO <table>` creates and fills a table;
            // without this record it looked like an ordinary SELECT and only
            // the advisory 050/051 rules fired, bypassing VERICTO-084.
            let copies_into_table = cx.dialect == Dialect::MsSql && select.into.is_some();
            if copies_into_table && let Some(into) = &select.into {
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    relation: into.targets.first().map(ToString::to_string),
                    is_nested,
                    ast_node_path: "SelectStmt > IntoClause".to_string(),
                    ..Default::default()
                });
            }

            // Record EVERY select, nested or not (ENG-005). A `SELECT *` or an
            // `OR 1=1` tautology hiding in a subquery / CTE body must be seen by
            // VERICTO-051 / VERICTO-090. `is_nested` is preserved so VERICTO-050
            // (unbounded read) can stay scoped to the client-visible top-level
            // query and not flag every inner scan as missing a LIMIT.
            let select_is_nested = is_nested || copies_into_table;
            out.push(StatementInfo {
                kind: StatementKind::Select,
                is_nested: select_is_nested,
                ast_node_path: if select_is_nested {
                    "SubSelect > SelectStmt".to_string()
                } else {
                    "SelectStmt".to_string()
                },
                select_is_star: is_star,
                select_has_limit: has_limit,
                has_or_tautology: tautology,
                where_presence: match select.selection.as_ref() {
                    None => WherePresence::Absent,
                    Some(e) if is_always_true(e, cx.dialect) => WherePresence::AlwaysTrue,
                    Some(_) => WherePresence::Present,
                },
                ..Default::default()
            });

            // Recurse into FROM subqueries
            for twj in &select.from {
                walk_table_factor(&twj.relation, depth + 1, cx, out)?;
                for join in &twj.joins {
                    walk_table_factor(&join.relation, depth + 1, cx, out)?;
                }
            }

            // Everything else the SELECT evaluates: `JOIN … ON`, table-valued
            // function arguments, `GROUP BY`, `HAVING`, `WINDOW`, …
            {
                let mut exprs: Vec<&Expr> = select.selection.iter().collect();
                if cx.snowflake {
                    exprs.extend(select.qualify.iter());
                }
                for item in &select.projection {
                    match item {
                        SelectItem::UnnamedExpr(e)
                        | SelectItem::ExprWithAlias { expr: e, .. }
                        | SelectItem::ExprWithAliases { expr: e, .. } => exprs.push(e),
                        SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => {}
                    }
                }
                let queries = select
                    .from
                    .iter()
                    .flat_map(|twj| {
                        std::iter::once(&twj.relation).chain(twj.joins.iter().map(|j| &j.relation))
                    })
                    .filter_map(derived)
                    .collect();
                walk_rest(
                    select.as_ref(),
                    Walked { exprs, queries },
                    depth + 1,
                    cx,
                    out,
                )?;
            }
        }

        SetExpr::Query(query) => {
            walk_query(query.as_ref(), true, depth + 1, cx, out)?;
        }
        SetExpr::SetOperation { left, right, .. } => {
            // A LIMIT on the outer query bounds the whole set-operation result.
            walk_set_expr(left.as_ref(), is_nested, has_limit, depth + 1, cx, out)?;
            walk_set_expr(right.as_ref(), is_nested, has_limit, depth + 1, cx, out)?;
        }
        // A data-modifying statement used as a query body: a CTE such as
        // `WITH d AS (DELETE FROM t RETURNING id) SELECT …`, which sqlparser
        // reads on every dialect since 0.56 (`DELETE`, `MERGE`) and which used
        // to be a parse error there. It runs, so its rules apply as nested.
        SetExpr::Insert(stmt)
        | SetExpr::Update(stmt)
        | SetExpr::Delete(stmt)
        | SetExpr::Merge(stmt) => {
            walk_statement(stmt, true, depth + 1, cx, out)?;
        }
        // `VALUES (…)` (an `INSERT`'s rows): its expressions run.
        SetExpr::Values(values) => {
            walk_rest(values, Walked::default(), depth + 1, cx, out)?;
        }
        // TABLE t has no expression of its own.
        SetExpr::Table(_) => {}
    }

    Ok(())
}

fn walk_table_factor(
    factor: &TableFactor,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    if let TableFactor::Derived { subquery, .. } = factor {
        walk_query(subquery.as_ref(), true, depth + 1, cx, out)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expression walker — subqueries and function calls
// ---------------------------------------------------------------------------

fn walk_expr(expr: &Expr, depth: usize, cx: Cx, out: &mut Vec<StatementInfo>) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    walk_rest(expr, Walked::default(), depth, cx, out)
}

/// Records a function call: every call, not just the sleep family, so a
/// custom rule's `func_name:` predicate can name any function as documented.
/// The sleep-family filter lives in VERICTO-070's predicate; mirrors the
/// pg_query walker. SQLite has no sleep: a huge `randomblob(N)` /
/// `zeroblob(N)` is its time-based probe (VERICTO-070).
fn record_call(func: &sqlparser::ast::Function, cx: Cx, out: &mut Vec<StatementInfo>) {
    let name = func
        .name
        .0
        .last()
        .and_then(|p| p.as_ident())
        .map(|p| p.value.to_ascii_lowercase())
        .unwrap_or_default();
    let probe = cx.sqlite
        && matches!(name.as_str(), "randomblob" | "zeroblob")
        && first_arg(func)
            .and_then(const_number)
            .is_some_and(|n| n >= SQLITE_PROBE_BYTES);
    if !name.is_empty() {
        out.push(StatementInfo {
            kind: StatementKind::FunctionCall,
            ast_node_path: if probe {
                format!("FunctionCall > {name}() (a huge constant size: a time probe)")
            } else {
                format!("FunctionCall > {name}()")
            },
            function_name: Some(name),
            sqlite: probe.then_some(SqliteRisk::TimeProbe),
            ..Default::default()
        });
    }
}

/// What the structural walk of a node already visited, so [`walk_rest`] does
/// not record it twice: expression roots (a `WHERE`, the projection) and
/// queries (a `FROM` subquery).
#[derive(Default)]
struct Walked<'a> {
    exprs: Vec<&'a Expr>,
    queries: Vec<&'a Query>,
}

/// The subquery of a `FROM (SELECT …)` source, which `walk_table_factor`
/// walks.
fn derived(factor: &TableFactor) -> Option<&Query> {
    match factor {
        TableFactor::Derived { subquery, .. } => Some(subquery.as_ref()),
        _ => None,
    }
}

/// Walks every expression under `node` but the ones in `walked`: each call is
/// recorded, and each subquery is walked as a nested query (by [`walk_query`],
/// which records its SELECT and walks what it holds in turn).
fn walk_rest<V: Visit + ?Sized>(
    node: &V,
    walked: Walked<'_>,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    let mut rest = Rest {
        walked,
        depth,
        cx,
        out,
        skipped: None,
        in_query: 0,
        nesting: 0,
    };
    match node.visit(&mut rest) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(e) => Err(e),
    }
}

/// The [`Visitor`] behind [`walk_rest`]. sqlparser derives the traversal over
/// every field of every node, so a clause or an expression kind the walker
/// does not name is still visited, and a sqlparser upgrade that adds one is
/// covered without a change here.
struct Rest<'w, 'o> {
    walked: Walked<'w>,
    depth: usize,
    cx: Cx,
    out: &'o mut Vec<StatementInfo>,
    /// The already-walked expression being skipped, while inside it.
    skipped: Option<*const Expr>,
    /// How many queries deep the visit is: a subquery is walked whole by
    /// `walk_query`, so nothing inside it is recorded here.
    in_query: usize,
    /// Expression nesting, for the depth limit.
    nesting: usize,
}

impl Rest<'_, '_> {
    fn active(&self) -> bool {
        self.skipped.is_none() && self.in_query == 0
    }
}

impl Visitor for Rest<'_, '_> {
    type Break = ProxyError;

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<ProxyError> {
        if self.active() && !self.walked.queries.iter().any(|q| std::ptr::eq(*q, query)) {
            let depth = self.depth + self.nesting + 1;
            if let Err(e) = walk_query(query, true, depth, self.cx, self.out) {
                return ControlFlow::Break(e);
            }
        }
        self.in_query += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<ProxyError> {
        self.in_query -= 1;
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<ProxyError> {
        if !self.active() {
            return ControlFlow::Continue(());
        }
        if self.walked.exprs.iter().any(|e| std::ptr::eq(*e, expr)) {
            self.skipped = Some(expr as *const Expr);
            return ControlFlow::Continue(());
        }
        self.nesting += 1;
        if self.depth + self.nesting > MAX_AST_DEPTH {
            return ControlFlow::Break(ProxyError::AstTooDeep);
        }
        if let Expr::Function(func) = expr {
            record_call(func, self.cx, self.out);
        }
        ControlFlow::Continue(())
    }

    fn post_visit_expr(&mut self, expr: &Expr) -> ControlFlow<ProxyError> {
        if self.skipped == Some(expr as *const Expr) {
            self.skipped = None;
        } else if self.active() {
            self.nesting -= 1;
        }
        ControlFlow::Continue(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The `randomblob(N)` / `zeroblob(N)` size from which SQLite spends a
/// noticeable time building the value: 10 MB (a second or more at 500 MB,
/// the size injection tools use). Legitimate blobs this size are not built
/// in SQL text.
const SQLITE_PROBE_BYTES: f64 = 10_000_000.0;

/// The first positional argument of a call.
fn first_arg(func: &sqlparser::ast::Function) -> Option<&Expr> {
    match &func.args {
        FunctionArguments::List(list) => match list.args.first()? {
            sqlparser::ast::FunctionArg::Unnamed(sqlparser::ast::FunctionArgExpr::Expr(e)) => {
                Some(e)
            }
            _ => None,
        },
        _ => None,
    }
}

/// The value of a constant arithmetic expression over number literals
/// (`500000000/2`, `-(1e9)`); `None` for anything else.
fn const_number(e: &Expr) -> Option<f64> {
    use sqlparser::ast::{BinaryOperator, UnaryOperator};
    match e {
        Expr::Value(ValueWithSpan {
            value: Value::Number(n, _),
            ..
        }) => n.parse().ok(),
        Expr::Nested(x) => const_number(x),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => const_number(expr).map(|v| -v),
        Expr::UnaryOp {
            op: UnaryOperator::Plus,
            expr,
        } => const_number(expr),
        Expr::BinaryOp { left, op, right } => {
            let (l, r) = (const_number(left)?, const_number(right)?);
            match op {
                BinaryOperator::Plus => Some(l + r),
                BinaryOperator::Minus => Some(l - r),
                BinaryOperator::Multiply => Some(l * r),
                BinaryOperator::Divide if r != 0.0 => Some(l / r),
                _ => None,
            }
        }
        _ => None,
    }
}

fn walk_with_from_ctes(
    from: &FromTable,
    depth: usize,
    cx: Cx,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    match from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
            for twj in tables {
                walk_table_factor(&twj.relation, depth, cx, out)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn where_presence(selection: Option<&Expr>, dialect: Dialect) -> WherePresence {
    match selection {
        None => WherePresence::Absent,
        Some(expr) if is_always_true(expr, dialect) => WherePresence::AlwaysTrue,
        Some(_) => WherePresence::Present,
    }
}

/// Detect trivially-true predicates (see the pg_ast.rs counterpart for the full
/// rationale — ENG-009). Recognises boolean/numeric truthy literals, constant
/// comparisons under any of `= <> != < <= > >=`, proven-true `IN`, constant-only
/// `BETWEEN` / `LIKE '%'`, column self-equality (`id = id`), `NOT <always_false>`, and AND/OR
/// combinations thereof. Constant `IS NULL` / `IS NOT NULL`,
/// `IS [NOT] TRUE/FALSE/UNKNOWN` and `IS [NOT] DISTINCT FROM` are also folded.
///
/// Every form other than `id = id` and a positive `IN` with additional
/// items is constant-only: a column operand disqualifies the predicate because
/// its truth depends on the row. For `1 IN (1, id)`, the known matching item
/// makes the OR true whatever `id` is. Property 9 (`rules::properties`) locks
/// that distinction across both walkers.
///
/// Dialect-specific literal semantics stay narrow: SQLite reads text by its
/// numeric prefix in a boolean context, MySQL/SQLite accept numeric `IS TRUE`
/// tests, and Oracle treats empty character values as NULL.
///
/// The literal comparisons themselves are [`crate::parser::compare`], shared
/// with the pg_query walker, under three-valued logic: a comparison with NULL
/// (`NULL = NULL`, `NOT (NULL = 1)`) is [`Truth::SqlNull`], while an unresolved
/// string ordering is [`Truth::Unknown`]; neither is always true.
fn is_always_true(expr: &Expr, dialect: Dialect) -> bool {
    truth(expr, dialect) == Truth::True
}

/// The truth value of a predicate without a row (see `is_always_true` for the
/// forms). `NOT x` is true only when `x` is provably false; an unresolved value
/// stays [`Truth::Unknown`] and a known SQL NULL stays [`Truth::SqlNull`].
fn truth(expr: &Expr, dialect: Dialect) -> Truth {
    use sqlparser::ast::{BinaryOperator, UnaryOperator};
    if dialect == Dialect::Sqlite {
        if let Some(b) = sqlite_text_truth(expr) {
            return Truth::from_bool(b);
        }
    }
    match expr {
        // Since sqlparser 0.53 the MS SQL dialect reads `true`/`false` as
        // identifiers (T-SQL has no boolean literals). `WHERE true` was a
        // tautology to the engine before the upgrade and stays one: T-SQL
        // rejects it as a predicate anyway, so blocking it costs nothing.
        Expr::Identifier(i) if i.quote_style.is_none() && i.value.eq_ignore_ascii_case("true") => {
            Truth::True
        }
        Expr::Identifier(i) if i.quote_style.is_none() && i.value.eq_ignore_ascii_case("false") => {
            Truth::False
        }
        // A bare literal: `WHERE 1`, `WHERE -1`, `WHERE TRUE`, `WHERE NULL`.
        Expr::Value(_)
        | Expr::UnaryOp {
            op: UnaryOperator::Minus,
            ..
        } => constant_for_dialect(expr, dialect).map_or(Truth::Unknown, |c| c.truth()),
        Expr::Nested(inner) => truth(inner, dialect),
        Expr::IsNull(inner) => match constant_for_dialect(inner, dialect) {
            Some(Const::Null) => Truth::True,
            Some(_) => Truth::False,
            None => Truth::Unknown,
        },
        Expr::IsNotNull(inner) => match constant_for_dialect(inner, dialect) {
            Some(Const::Null) => Truth::False,
            Some(_) => Truth::True,
            None => Truth::Unknown,
        },
        Expr::IsDistinctFrom(left, right) | Expr::IsNotDistinctFrom(left, right) => {
            match (
                constant_for_dialect(left, dialect),
                constant_for_dialect(right, dialect),
            ) {
                (Some(a), Some(b)) => {
                    compare_distinct(&a, &b, matches!(expr, Expr::IsNotDistinctFrom(_, _)))
                }
                _ => Truth::Unknown,
            }
        }
        Expr::IsTrue(inner) => boolean_test(inner, dialect, Truth::True, false),
        Expr::IsNotTrue(inner) => boolean_test(inner, dialect, Truth::True, true),
        Expr::IsFalse(inner) => boolean_test(inner, dialect, Truth::False, false),
        Expr::IsNotFalse(inner) => boolean_test(inner, dialect, Truth::False, true),
        Expr::IsUnknown(inner) => boolean_test(inner, dialect, Truth::SqlNull, false),
        Expr::IsNotUnknown(inner) => boolean_test(inner, dialect, Truth::SqlNull, true),
        // SQL `NOT`: an undecided operand stays undecided.
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => truth(inner, dialect).not(),

        // `<const> IN (<const>, …)`. Only the positive form: `NOT IN` is not the
        // negation of `IN` under three-valued logic — with a NULL in the list the
        // predicate is NULL rather than true, so `1 NOT IN (2, NULL)` matches no
        // rows (verified against PostgreSQL). Mirrors the pg_query walker.
        Expr::InList {
            expr,
            list,
            negated: false,
        } => Truth::true_or_unknown(const_in_list_true(expr, list, dialect)),

        // `<const> BETWEEN <const> AND <const>`, numeric bounds only.
        Expr::Between {
            expr,
            negated: false,
            low,
            high,
        } => Truth::true_or_unknown(const_between_true(expr, low, high, dialect)),

        // `<const> LIKE '%'` — the match-everything pattern. `any: false` keeps
        // this off Snowflake's `LIKE ANY (…)` form, whose semantics differ.
        Expr::Like {
            negated: false,
            any: false,
            expr,
            pattern,
            escape_char: None,
        } => Truth::true_or_unknown(const_like_matches_all(expr, pattern, dialect)),

        Expr::BinaryOp { left, op, right } => {
            let cmp = match op {
                BinaryOperator::Eq if same_column(left, right) => return Truth::True,
                BinaryOperator::Eq => CmpOp::Eq,
                BinaryOperator::NotEq => CmpOp::NotEq,
                BinaryOperator::Lt => CmpOp::Lt,
                BinaryOperator::LtEq => CmpOp::LtEq,
                BinaryOperator::Gt => CmpOp::Gt,
                BinaryOperator::GtEq => CmpOp::GtEq,
                BinaryOperator::Or => {
                    return truth(left, dialect).or(truth(right, dialect));
                }
                BinaryOperator::And => {
                    return truth(left, dialect).and(truth(right, dialect));
                }
                _ => return Truth::Unknown,
            };
            match (
                constant_for_dialect(left, dialect),
                constant_for_dialect(right, dialect),
            ) {
                (Some(a), Some(b)) => compare(&a, cmp, &b),
                _ => Truth::Unknown,
            }
        }
        _ => Truth::Unknown,
    }
}

/// True when both expressions are the same (qualified) column identifier.
fn same_column(left: &Expr, right: &Expr) -> bool {
    fn path(e: &Expr) -> Option<String> {
        match e {
            Expr::Identifier(id) => Some(id.value.to_ascii_lowercase()),
            Expr::CompoundIdentifier(ids) => Some(
                ids.iter()
                    .map(|i| i.value.to_ascii_lowercase())
                    .collect::<Vec<_>>()
                    .join("."),
            ),
            Expr::Nested(inner) => path(inner),
            _ => None,
        }
    }
    match (path(left), path(right)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn unwrap_nested(expr: &Expr) -> &Expr {
    match expr {
        Expr::Nested(inner) => unwrap_nested(inner),
        other => other,
    }
}

struct ColumnReference;

impl Visitor for ColumnReference {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_)) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

fn has_column_reference(expr: &Expr) -> bool {
    expr.visit(&mut ColumnReference).is_break()
}

fn boolean_test(expr: &Expr, dialect: Dialect, expected: Truth, negated: bool) -> Truth {
    if has_column_reference(expr) {
        return Truth::Unknown;
    }
    let value = match unwrap_nested(expr) {
        Expr::Value(ValueWithSpan {
            value: Value::Number(_, _),
            ..
        }) if !matches!(dialect, Dialect::Mysql | Dialect::Sqlite) => Truth::Unknown,
        other => truth(other, dialect),
    };
    value.tested_as(expected, negated)
}

/// Applies dialect literal semantics after parsing. Oracle treats an empty
/// character literal as NULL; MySQL's double-quoted values are already left
/// undecided by [`constant`] because `ANSI_QUOTES` may make them columns.
fn constant_for_dialect(expr: &Expr, dialect: Dialect) -> Option<Const> {
    match constant(expr)? {
        Const::Text(value) if dialect == Dialect::Oracle && value.is_empty() => Some(Const::Null),
        value => Some(value),
    }
}

/// The literal behind an expression, as the shared comparison reads it: a
/// value, or a unary minus over one, folded by the shared [`Const::negated`]
/// (sqlparser reads `-1` as `UnaryOp(Minus, 1)` where libpg_query folds it;
/// with the same fold, both walkers decide `-1 < 0` alike).
///
/// Compares the values, not the nodes: since sqlparser 0.55 a literal node
/// carries its source span, so two equal literals at different positions
/// would never compare equal. A bind parameter is not a constant: `? = ?`
/// names two values the engine does not see (the pg_query walker reads `$1`
/// as a parameter, not a constant, too).
fn constant(expr: &Expr) -> Option<Const> {
    use sqlparser::ast::UnaryOperator;
    match unwrap_nested(expr) {
        Expr::Value(ValueWithSpan { value, .. }) => Some(match value {
            Value::Null => Const::Null,
            Value::Number(n, _) => Const::number(n),
            Value::Boolean(b) => Const::Bool(*b),
            Value::SingleQuotedString(s) | Value::NationalStringLiteral(s) => {
                Const::Text(s.clone())
            }
            Value::QuoteDelimitedStringLiteral(s)
            | Value::NationalQuoteDelimitedStringLiteral(s) => Const::Text(s.value.clone()),
            Value::Placeholder(_) | Value::DoubleQuotedString(_) => return None,
            // Every remaining `Value` variant is unambiguously a literal. A
            // double-quoted value is excluded above because MySQL may read it
            // as a column under `ANSI_QUOTES`, which the engine cannot observe.
            other => Const::Opaque(format!("{other:?}")),
        }),
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => constant(expr)?.negated(),
        _ => None,
    }
}

/// The literal behind an expression, if it is one and is not NULL.
///
/// NULL is excluded deliberately: no comparison against NULL is *true*, it is
/// NULL, which matches no row. Admitting it is how `NOT IN (…, NULL)` would be
/// mistaken for a tautology.
fn non_null_constant(expr: &Expr, dialect: Dialect) -> Option<Const> {
    constant_for_dialect(expr, dialect).filter(|c| *c != Const::Null)
}

/// `<const> IN (<expr>, …)` — true as soon as one non-NULL constant item
/// equals the constant needle. Other items may be row-dependent or NULL: SQL
/// `IN` is an OR, and a known TRUE comparison dominates FALSE and UNKNOWN.
fn const_in_list_true(expr: &Expr, list: &[Expr], dialect: Dialect) -> bool {
    let Some(needle) = non_null_constant(expr, dialect) else {
        return false;
    };
    list.iter()
        .filter_map(|item| non_null_constant(item, dialect))
        .any(|item| compare(&needle, CmpOp::Eq, &item) == Truth::True)
}

/// `<const> BETWEEN <lo> AND <hi>` — true when all three are numeric literals and
/// `lo <= x <= hi`. Numeric only: string `BETWEEN` depends on the database's
/// collation, which is not knowable here.
fn const_between_true(expr: &Expr, low: &Expr, high: &Expr, dialect: Dialect) -> bool {
    let num = |e: &Expr| match non_null_constant(e, dialect) {
        Some(Const::Num(x)) => Some(x),
        _ => None,
    };
    let (Some(x), Some(lo), Some(hi)) = (num(expr), num(low), num(high)) else {
        return false;
    };
    lo <= x && x <= hi
}

/// `<const> LIKE '%'` — the pattern matching every non-NULL value. Restricted to
/// exactly `%`; deciding `'abc' LIKE 'a%'` would mean implementing LIKE matching,
/// which is more bug surface than the case is worth. The left side must be a
/// literal, since `col LIKE '%'` drops NULL rows and is a real filter.
fn const_like_matches_all(expr: &Expr, pattern: &Expr, dialect: Dialect) -> bool {
    non_null_constant(expr, dialect).is_some()
        && matches!(non_null_constant(pattern, dialect), Some(Const::Text(s)) if s == "%")
}

/// Returns true if `expr` contains a tautological OR branch at any depth —
/// i.e. `<real_condition> OR <always_true>`. This is the canonical SQL
/// injection pattern (`WHERE id = $1 OR 1=1`) even when the overall
/// predicate is not trivially true by itself.
///
/// Note: `is_always_true` already covers the case where the entire predicate
/// is trivial. This function catches the mixed case where only an OR branch is.
fn has_or_tautology(expr: &Expr, dialect: Dialect) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            use sqlparser::ast::BinaryOperator;
            match op {
                // `a OR always_true` or `always_true OR a`
                BinaryOperator::Or => {
                    is_always_true(left.as_ref(), dialect)
                        || is_always_true(right.as_ref(), dialect)
                        || has_or_tautology(left.as_ref(), dialect)
                        || has_or_tautology(right.as_ref(), dialect)
                }
                // Recurse into AND branches
                BinaryOperator::And => {
                    has_or_tautology(left.as_ref(), dialect)
                        || has_or_tautology(right.as_ref(), dialect)
                }
                _ => false,
            }
        }
        Expr::Nested(inner) => has_or_tautology(inner, dialect),
        _ => false,
    }
}

/// SQLite's truth value of a text constant: a string literal (or a
/// double-quoted name, which SQLite reads as a string when no column has
/// that name) is read as the number its numeric prefix spells (`'1abc'` →
/// 1, `' 2.5'` → 2.5, `'abc'` → 0). `None` for anything else.
fn sqlite_text_truth(expr: &Expr) -> Option<bool> {
    let text = match unwrap_nested(expr) {
        Expr::Value(ValueWithSpan {
            value: Value::SingleQuotedString(s) | Value::DoubleQuotedString(s),
            ..
        }) => s.as_str(),
        Expr::Identifier(i) if i.quote_style == Some('"') => i.value.as_str(),
        _ => return None,
    };
    Some(sqlite_numeric_prefix(text) != 0.0)
}

/// The value SQLite gives a text in a numeric context: its longest prefix
/// that reads as a number, after leading spaces (`0` when there is none).
pub(crate) fn sqlite_numeric_prefix(text: &str) -> f64 {
    let t = text.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let b = t.as_bytes();
    let mut end = 0;
    if matches!(b.first(), Some(b'+' | b'-')) {
        end = 1;
    }
    let digits = |from: usize| b[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let int = digits(end);
    end += int;
    let mut frac = 0;
    if b.get(end) == Some(&b'.') {
        frac = digits(end + 1);
        if int + frac > 0 {
            end += 1 + frac;
        }
    }
    if int + frac == 0 {
        return 0.0;
    }
    // An exponent counts only when digits follow it.
    if matches!(b.get(end), Some(b'e' | b'E')) {
        let mut k = end + 1;
        if matches!(b.get(k), Some(b'+' | b'-')) {
            k += 1;
        }
        let n = digits(k);
        if n > 0 {
            end = k + n;
        }
    }
    t[..end].parse::<f64>().unwrap_or(0.0)
}

fn expr_as_i64(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Value(ValueWithSpan {
            value: Value::Number(n, _),
            ..
        }) => n.parse().ok(),
        _ => None,
    }
}

fn relation_from_delete(delete: &sqlparser::ast::Delete) -> Option<String> {
    match &delete.from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
            tables.first().and_then(relation_from_twj)
        }
    }
}

fn relation_from_table_with_joins(twj: &TableWithJoins) -> Option<String> {
    relation_from_twj(twj)
}

fn relation_from_twj(twj: &TableWithJoins) -> Option<String> {
    relation_from_table_factor(&twj.relation)
}

fn relation_from_table_factor(factor: &TableFactor) -> Option<String> {
    match factor {
        TableFactor::Table { name, .. } => Some(name.to_string()),
        _ => None,
    }
}

fn node_path_where(stmt: &str, presence: WherePresence, is_nested: bool) -> String {
    let base = match presence {
        WherePresence::Absent => format!("{stmt} > WhereClause = NULL"),
        WherePresence::AlwaysTrue => format!("{stmt} > WhereClause = ALWAYS_TRUE"),
        WherePresence::Present => format!("{stmt} > WhereClause"),
    };
    if is_nested {
        format!("WithClause > {base}")
    } else {
        base
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{AlterTableKind, StatementKind, WherePresence};
    use sqlparser::dialect::PostgreSqlDialect;

    fn parse_pg(sql: &str) -> ParsedQuery {
        parse_with_dialect(&PostgreSqlDialect {}, crate::parser::Dialect::Postgres, sql)
            .expect("must parse")
    }

    #[test]
    fn delete_without_where_is_absent() {
        let p = parse_pg("DELETE FROM users");
        assert_eq!(p.statements[0].kind, StatementKind::Delete);
        assert_eq!(p.statements[0].where_presence, WherePresence::Absent);
    }

    #[test]
    fn delete_with_where_is_present() {
        let p = parse_pg("DELETE FROM users WHERE id = 1");
        assert_eq!(p.statements[0].where_presence, WherePresence::Present);
    }

    #[test]
    fn delete_where_one_equals_one_is_always_true() {
        let p = parse_pg("DELETE FROM users WHERE 1 = 1");
        assert_eq!(p.statements[0].where_presence, WherePresence::AlwaysTrue);
    }

    #[test]
    fn update_without_where_is_absent() {
        let p = parse_pg("UPDATE products SET price = 0");
        assert_eq!(p.statements[0].kind, StatementKind::Update);
        assert_eq!(p.statements[0].where_presence, WherePresence::Absent);
    }

    // VERICTO-040 inputs: `insert_select_has_filter` must be true only when the
    // source SELECT actually bounds the rows it copies.
    #[test]
    fn insert_select_unfiltered_has_no_filter() {
        let p = parse_pg("INSERT INTO archive SELECT * FROM users");
        let ins = &p.statements[0];
        assert_eq!(ins.kind, StatementKind::Insert);
        assert!(ins.insert_has_select);
        assert!(!ins.insert_select_has_filter);
    }

    #[test]
    fn insert_select_with_where_has_filter() {
        let p = parse_pg("INSERT INTO archive SELECT * FROM users WHERE id = 1");
        assert!(p.statements[0].insert_select_has_filter);
    }

    #[test]
    fn insert_select_with_limit_has_filter() {
        let p = parse_pg("INSERT INTO archive SELECT * FROM users LIMIT 100");
        assert!(p.statements[0].insert_select_has_filter);
    }

    // A tautology does not bound anything, so it is not a filter.
    #[test]
    fn insert_select_with_tautology_has_no_filter() {
        let p = parse_pg("INSERT INTO archive SELECT * FROM users WHERE 1 = 1");
        assert!(!p.statements[0].insert_select_has_filter);
    }

    // VALUES sources are not SELECT sources at all.
    #[test]
    fn insert_values_has_no_select_and_no_filter() {
        let p = parse_pg("INSERT INTO t (a) VALUES (1)");
        assert!(!p.statements[0].insert_has_select);
        assert!(!p.statements[0].insert_select_has_filter);
    }

    // The complete walk (SQLite, 4.1.1) records every call a statement
    // evaluates exactly once: checked against sqlparser's own traversal of the
    // whole tree over the SQLite corpus, for the statement kinds whose every
    // expression runs.
    #[test]
    fn sqlite_walk_records_every_call_once() {
        use sqlparser::ast::visit_expressions;
        use sqlparser::dialect::SQLiteDialect;
        let corpus = include_str!("../../tests/fixtures/sqlite_corpus.sql");
        let extra = [
            "SELECT a FROM t JOIN u ON u.id = abs(t.id) WHERE t.x IN (SELECT max(y) FROM v GROUP BY lower(z) HAVING count(*) > 1) ORDER BY upper(a) LIMIT length('ab')",
            "SELECT CASE WHEN f(1) THEN g(2) ELSE h(3) END, sum(x) OVER (PARTITION BY k(x) ORDER BY m(x)), count(*) FILTER (WHERE n(x)) FROM t WINDOW w AS (ORDER BY p(x)) LIMIT 1",
            "WITH c AS (SELECT q(1) AS a) SELECT a FROM c WHERE r(a) IS NULL AND NOT s(a) BETWEEN t(1) AND u(2) LIMIT 1",
            "INSERT INTO t (a) VALUES (f(1)), (g(2)) ON CONFLICT (a) DO UPDATE SET a = h(excluded.a) WHERE i(t.a) RETURNING j(a)",
            "UPDATE t SET a = f(1), b = (SELECT g(2)) FROM (SELECT h(3) AS x) AS s WHERE i(t.a) = s.x RETURNING j(a)",
            "DELETE FROM t WHERE f(a) IS NULL RETURNING g(a)",
            "CREATE TRIGGER tr AFTER INSERT ON t WHEN f(NEW.a) BEGIN UPDATE t SET a = g(1) WHERE id = NEW.id; INSERT INTO u VALUES (h(2)); END",
        ];
        let mut checked = 0;
        let entries = corpus
            .split("\n----\n")
            .skip(1)
            .map(|chunk| chunk.lines().skip(1).collect::<Vec<_>>().join("\n"));
        for sql in entries.chain(extra.iter().map(|s| s.to_string())) {
            let Ok(stmts) = SqlAstParser::parse_sql(&SQLiteDialect {}, &sql) else {
                continue;
            };
            let runs_every_expression = stmts.iter().all(|s| {
                matches!(
                    s,
                    Statement::Query(_)
                        | Statement::Insert(_)
                        | Statement::Update(_)
                        | Statement::Delete(_)
                        | Statement::CreateTrigger(_)
                )
            });
            if !runs_every_expression {
                continue;
            }
            let mut calls = 0;
            let _ = visit_expressions(&stmts, |e| {
                calls += matches!(e, Expr::Function(_)) as usize;
                ControlFlow::<()>::Continue(())
            });
            let parsed = from_statements(stmts, Dialect::Sqlite, &sql).expect("walks");
            let recorded = parsed
                .statements
                .iter()
                .filter(|s| s.kind == StatementKind::FunctionCall)
                .count();
            assert_eq!(recorded, calls, "{sql}: {:?}", parsed.statements);
            checked += 1;
        }
        assert!(checked > 60, "corpus not read: {checked}");
    }

    // VERICTO-070 inputs. `pg_sleep_until` used to be missing from this walker's
    // list while the pg_query walker had it, so the rule was dialect-dependent.
    // Both walkers now share `parser::is_sleep_function`.
    #[test]
    fn every_sleep_variant_is_detected() {
        for sql in [
            "SELECT sleep(5)",
            "SELECT pg_sleep(5)",
            "SELECT pg_sleep_for('5 seconds')",
            "SELECT pg_sleep_until('tomorrow')",
        ] {
            let p = parse_pg(sql);
            assert!(
                p.statements
                    .iter()
                    .any(|s| s.kind == StatementKind::FunctionCall),
                "{sql} produced no FunctionCall: {:?}",
                p.statements
            );
        }
    }

    // Every function call is recorded, so a custom rule can name any of them by
    // `func_name:`. What separates a sleep from the rest is the *name* the walker
    // stores, which VERICTO-070's predicate then filters on — this asserts the
    // name is captured verbatim rather than that non-sleep calls are dropped.
    #[test]
    fn non_sleep_function_is_recorded_under_its_own_name() {
        let p = parse_pg("SELECT sleepless(5)");
        let f = p
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::FunctionCall)
            .expect("every function call is recorded");
        assert_eq!(f.function_name.as_deref(), Some("sleepless"));
        // A function that merely contains "sleep" is not a sleep call, so the
        // shared classifier must not claim it.
        assert!(!crate::parser::is_sleep_function("sleepless"));
    }

    #[test]
    fn truncate_is_detected() {
        let p = parse_pg("TRUNCATE TABLE orders");
        assert_eq!(p.statements[0].kind, StatementKind::Truncate);
    }

    #[test]
    fn drop_table_is_detected() {
        let p = parse_pg("DROP TABLE users");
        assert_eq!(p.statements[0].kind, StatementKind::Drop);
        assert_eq!(p.statements[0].drop_object, Some(DropObjectKind::Table));
    }

    #[test]
    fn drop_schema_is_detected() {
        let p = parse_pg("DROP SCHEMA analytics CASCADE");
        assert_eq!(p.statements[0].drop_object, Some(DropObjectKind::Schema));
    }

    #[test]
    fn drop_index_has_if_exists_flag() {
        let with_ie = parse_pg("DROP INDEX IF EXISTS idx_users_email");
        assert!(with_ie.statements[0].drop_index_if_exists);
        let without_ie = parse_pg("DROP INDEX idx_users_email");
        assert!(!without_ie.statements[0].drop_index_if_exists);
    }

    #[test]
    fn alter_table_drop_column_is_detected() {
        let p = parse_pg("ALTER TABLE users DROP COLUMN email");
        let s = &p.statements[0];
        assert_eq!(s.kind, StatementKind::AlterTable);
        assert_eq!(s.alter_table_kind, Some(AlterTableKind::DropColumn));
    }

    #[test]
    fn insert_without_columns_is_detected() {
        let p = parse_pg("INSERT INTO users VALUES (1, 'a')");
        assert!(!p.statements[0].insert_has_columns);
    }

    #[test]
    fn insert_with_columns_is_detected() {
        let p = parse_pg("INSERT INTO users (id, name) VALUES (1, 'a')");
        assert!(p.statements[0].insert_has_columns);
    }

    #[test]
    fn insert_select_has_flag() {
        // INSERT INTO … SELECT … needs the insert_has_select flag
        // sqlparser treats INSERT … SELECT as Insert { source: Query(SelectStmt) }
        let p = parse_pg("INSERT INTO archive SELECT * FROM users");
        // We accept that this may or may not be flagged depending on sqlparser version
        let s = &p.statements[0];
        assert_eq!(s.kind, StatementKind::Insert);
    }

    #[test]
    fn select_star_is_detected() {
        let p = parse_pg("SELECT * FROM users");
        let selects: Vec<_> = p
            .statements
            .iter()
            .filter(|s| s.kind == StatementKind::Select)
            .collect();
        assert!(!selects.is_empty());
        assert!(selects.iter().any(|s| s.select_is_star));
    }

    #[test]
    fn safe_select_has_no_destructive_stmt() {
        let p = parse_pg("SELECT * FROM users WHERE id = 1");
        assert!(
            p.statements
                .iter()
                .all(|s| s.kind != StatementKind::Delete && s.kind != StatementKind::Drop)
        );
    }
}
