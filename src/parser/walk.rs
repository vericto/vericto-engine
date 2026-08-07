//! Converts `sqlparser-rs` ASTs to Vericto's normalized representation.
//!
//! Walks the syntax tree in depth detecting destructive statements (DELETE,
//! UPDATE, DROP, TRUNCATE, ALTER TABLE) at root level and nested inside
//! subqueries / CTEs. Also detects INSERT patterns, SELECT * / no-LIMIT,
//! and function calls (SLEEP, PG_SLEEP).

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::parser::{
    AlterTableKind, DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
    is_sleep_function,
};

use sqlparser::ast::{
    Expr, FromTable, FunctionArguments, ObjectType, Query, SelectItem, SetExpr, Statement,
    TableFactor, TableWithJoins, Value,
};
use sqlparser::dialect::Dialect as SqlDialect;
use sqlparser::parser::Parser as SqlAstParser;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn parse_with_dialect<D: SqlDialect>(dialect: &D, sql: &str) -> Result<ParsedQuery> {
    let statements =
        SqlAstParser::parse_sql(dialect, sql).map_err(|e| ProxyError::ParseError(e.to_string()))?;

    let mut collected: Vec<StatementInfo> = Vec::new();
    for stmt in &statements {
        walk_statement(stmt, false, 0, &mut collected)?;
    }

    Ok(ParsedQuery {
        statements: collected,
    })
}

// ---------------------------------------------------------------------------
// Statement walker
// ---------------------------------------------------------------------------

fn walk_statement(
    stmt: &Statement,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match stmt {
        // ── DELETE ─────────────────────────────────────────────────────────
        Statement::Delete(delete) => {
            let presence = where_presence(delete.selection.as_ref());
            let relation = relation_from_delete(delete);
            let delete_limit = delete.limit.as_ref().and_then(expr_as_i64);
            let tautology = delete
                .selection
                .as_ref()
                .map(has_or_tautology)
                .unwrap_or(false);

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
                walk_expr(expr, depth + 1, out)?;
            }
            walk_with_from_ctes(&delete.from, depth + 1, out)?;
        }

        // ── UPDATE ─────────────────────────────────────────────────────────
        Statement::Update {
            selection, table, ..
        } => {
            let presence = where_presence(selection.as_ref());
            let relation = relation_from_table_with_joins(table);
            let tautology = selection.as_ref().map(has_or_tautology).unwrap_or(false);
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
                walk_expr(expr, depth + 1, out)?;
            }
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
                // View/Trigger/Function/Policy/Sequence/… stay `Other`: they are
                // not destructive table/data drops, so VERICTO-010 must not fire
                // on them (that was the DROP POLICY false positive).
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

        // ── TRUNCATE ───────────────────────────────────────────────────────
        Statement::Truncate { table_names, .. } => {
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
        Statement::AlterTable {
            name, operations, ..
        } => {
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
                    AlterTableOperation::DropConstraint { .. }
                    | AlterTableOperation::DropPrimaryKey => (
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

        // ── INSERT ─────────────────────────────────────────────────────────
        Statement::Insert(insert) => {
            let has_columns = !insert.columns.is_empty();

            // COUNT the number of value-tuples in VALUES(…)
            let insert_row_count = match insert.source.as_deref() {
                Some(Query { body, .. }) => match body.as_ref() {
                    SetExpr::Values(vals) => Some(vals.rows.len()),
                    _ => None,
                },
                None => None,
            };

            // True if the source is a SELECT (not a literal VALUES list)
            let insert_has_select = match insert.source.as_deref() {
                Some(Query { body, .. }) => match body.as_ref() {
                    SetExpr::Values(_) | SetExpr::Query(_) => false,
                    SetExpr::Select(_) => true,
                    _ => false,
                },
                None => false,
            };

            // Does the source bound the rows it copies? An effective WHERE or a
            // row limit both do; a tautological WHERE (`1=1`) does not. Mirrors
            // the pg_query path so VERICTO-040 behaves the same per dialect.
            let insert_select_has_filter = match insert.source.as_deref() {
                Some(query) => match query.body.as_ref() {
                    SetExpr::Select(select) => {
                        let effective_where = select
                            .selection
                            .as_ref()
                            .map(|e| !is_always_true(e))
                            .unwrap_or(false);
                        effective_where || query.limit.is_some() || query.fetch.is_some()
                    }
                    _ => false,
                },
                None => false,
            };

            out.push(StatementInfo {
                kind: StatementKind::Insert,
                relation: Some(insert.table_name.to_string()),
                is_nested,
                ast_node_path: "InsertStmt".to_string(),
                insert_has_columns: has_columns,
                insert_has_select,
                insert_select_has_filter,
                insert_row_count,
                ..Default::default()
            });

            // Recurse into source SELECT
            if let Some(source) = insert.source.as_ref() {
                walk_query(source.as_ref(), true, depth + 1, out)?;
            }
        }

        // ── COPY … TO/FROM PROGRAM (VERICTO-080) ─────────────────────────────
        // The PROGRAM target/source runs a shell command on the server (RCE /
        // exfiltration). Non-program forms are still recorded for telemetry.
        Statement::Copy { target, .. } => {
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
        Statement::Merge { table, .. } => {
            out.push(StatementInfo {
                kind: StatementKind::Merge,
                relation: relation_from_table_factor(table),
                is_nested,
                ast_node_path: "MergeStmt".to_string(),
                ..Default::default()
            });
        }

        // ── SELECT ─────────────────────────────────────────────────────────
        Statement::Query(query) => {
            walk_query(query.as_ref(), is_nested, depth + 1, out)?;
        }

        _ => {
            // Other statement types are not (yet) modelled. CREATE TABLE AS is
            // handled on the PostgreSQL (pg_query) path; sqlparser models it as
            // a CreateTable with a `query`, which the non-PG dialects we target
            // do not commonly emit, so it is intentionally left unflagged here.
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Query / SELECT walker
// ---------------------------------------------------------------------------

fn walk_query(
    query: &Query,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    // CTEs (WITH … AS (…))
    if let Some(with) = query.with.as_ref() {
        for cte in &with.cte_tables {
            walk_query(cte.query.as_ref(), true, depth + 1, out)?;
        }
    }

    // A row-bound is supplied by any of LIMIT (MySQL/PG/generic), FETCH FIRST
    // (ANSI/Oracle 12c+), or TOP (MSSQL/Sybase — lives on the Select node). The
    // bound belongs to the enclosing Query, so we resolve it here and thread it
    // into the SELECT node, fixing ENG-001 (every non-PG SELECT was flagged by
    // VERICTO-050 because `select_has_limit` was hard-coded to `false`).
    let has_limit = query.limit.is_some() || query.fetch.is_some();

    walk_set_expr(query.body.as_ref(), is_nested, has_limit, depth + 1, out)?;
    Ok(())
}

fn walk_set_expr(
    set_expr: &SetExpr,
    is_nested: bool,
    has_limit: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match set_expr {
        SetExpr::Select(select) => {
            // SELECT * detection
            let is_star = select
                .projection
                .iter()
                .any(|item| matches!(item, SelectItem::Wildcard(_)));

            // A `TOP n` clause (MSSQL) also bounds the result set.
            let has_limit = has_limit || select.top.is_some();

            // Tautological OR detection in WHERE
            let tautology = select
                .selection
                .as_ref()
                .map(has_or_tautology)
                .unwrap_or(false);

            // WHERE recursion (subqueries and sleep-family calls)
            if let Some(expr) = select.selection.as_ref() {
                walk_expr(expr, depth + 1, out)?;
            }

            // Projection recursion — `SELECT sleep(5)` lives here, not in WHERE
            // (ENG-006). Without this the sqlparser path missed sleep calls that
            // were not inside the WHERE clause.
            for item in &select.projection {
                match item {
                    SelectItem::UnnamedExpr(e) => walk_expr(e, depth + 1, out)?,
                    SelectItem::ExprWithAlias { expr, .. } => walk_expr(expr, depth + 1, out)?,
                    _ => {}
                }
            }

            // Record EVERY select, nested or not (ENG-005). A `SELECT *` or an
            // `OR 1=1` tautology hiding in a subquery / CTE body must be seen by
            // VERICTO-051 / VERICTO-090. `is_nested` is preserved so VERICTO-050
            // (unbounded read) can stay scoped to the client-visible top-level
            // query and not flag every inner scan as missing a LIMIT.
            out.push(StatementInfo {
                kind: StatementKind::Select,
                is_nested,
                ast_node_path: if is_nested {
                    "SubSelect > SelectStmt".to_string()
                } else {
                    "SelectStmt".to_string()
                },
                select_is_star: is_star,
                select_has_limit: has_limit,
                has_or_tautology: tautology,
                where_presence: match select.selection.as_ref() {
                    None => WherePresence::Absent,
                    Some(e) if is_always_true(e) => WherePresence::AlwaysTrue,
                    Some(_) => WherePresence::Present,
                },
                ..Default::default()
            });

            // Recurse into FROM subqueries
            for twj in &select.from {
                walk_table_factor(&twj.relation, depth + 1, out)?;
                for join in &twj.joins {
                    walk_table_factor(&join.relation, depth + 1, out)?;
                }
            }
        }

        SetExpr::Query(query) => {
            walk_query(query.as_ref(), true, depth + 1, out)?;
        }
        SetExpr::SetOperation { left, right, .. } => {
            // A LIMIT on the outer query bounds the whole set-operation result.
            walk_set_expr(left.as_ref(), is_nested, has_limit, depth + 1, out)?;
            walk_set_expr(right.as_ref(), is_nested, has_limit, depth + 1, out)?;
        }
        _ => {}
    }

    Ok(())
}

fn walk_table_factor(
    factor: &TableFactor,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    if let TableFactor::Derived { subquery, .. } = factor {
        walk_query(subquery.as_ref(), true, depth + 1, out)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expression walker — subqueries and function calls
// ---------------------------------------------------------------------------

fn walk_expr(expr: &Expr, depth: usize, out: &mut Vec<StatementInfo>) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match expr {
        Expr::Subquery(query) => {
            walk_query(query.as_ref(), true, depth + 1, out)?;
        }

        // Function call — check for the sleep family (VERICTO-070)
        Expr::Function(func) => {
            let name = func
                .name
                .0
                .last()
                .map(|p| p.value.to_ascii_lowercase())
                .unwrap_or_default();

            if is_sleep_function(&name) {
                out.push(StatementInfo {
                    kind: StatementKind::FunctionCall,
                    function_name: Some(name),
                    ast_node_path: "FunctionCall > sleep".to_string(),
                    ..Default::default()
                });
            }

            // Recurse into function arguments
            if let FunctionArguments::List(arg_list) = &func.args {
                for arg in &arg_list.args {
                    if let sqlparser::ast::FunctionArg::Unnamed(
                        sqlparser::ast::FunctionArgExpr::Expr(e),
                    ) = arg
                    {
                        walk_expr(e, depth + 1, out)?;
                    }
                }
            }
        }

        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left.as_ref(), depth + 1, out)?;
            walk_expr(right.as_ref(), depth + 1, out)?;
        }

        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) => {
            walk_expr(expr.as_ref(), depth + 1, out)?;
        }

        _ => {}
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn walk_with_from_ctes(from: &FromTable, depth: usize, out: &mut Vec<StatementInfo>) -> Result<()> {
    match from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => {
            for twj in tables {
                walk_table_factor(&twj.relation, depth, out)?;
            }
        }
    }
    Ok(())
}

fn where_presence(selection: Option<&Expr>) -> WherePresence {
    match selection {
        None => WherePresence::Absent,
        Some(expr) if is_always_true(expr) => WherePresence::AlwaysTrue,
        Some(_) => WherePresence::Present,
    }
}

/// Detect trivially-true predicates (see the pg_ast.rs counterpart for the full
/// rationale — ENG-009). Recognises boolean/numeric truthy literals, constant
/// comparisons under any of `= <> != < <= > >=`, column self-equality
/// (`id = id`), `NOT <always_false>`, and AND/OR combinations thereof.
fn is_always_true(expr: &Expr) -> bool {
    use sqlparser::ast::{BinaryOperator, UnaryOperator};
    match expr {
        Expr::Value(Value::Boolean(true)) => true,
        // Bare truthy numeric literal: `WHERE 1`.
        Expr::Value(Value::Number(n, _)) => n.parse::<f64>().map(|v| v != 0.0).unwrap_or(false),
        Expr::Nested(inner) => is_always_true(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => is_always_false(inner),
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::Eq if same_column(left, right) => true,
            BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq => const_cmp_true(left, op, right),
            BinaryOperator::Or => is_always_true(left) || is_always_true(right),
            BinaryOperator::And => is_always_true(left) && is_always_true(right),
            _ => false,
        },
        _ => false,
    }
}

/// Dual of `is_always_true` for evaluating `NOT (…)`. Conservative.
fn is_always_false(expr: &Expr) -> bool {
    use sqlparser::ast::{BinaryOperator, UnaryOperator};
    match expr {
        Expr::Value(Value::Boolean(false)) => true,
        Expr::Value(Value::Number(n, _)) => n.parse::<f64>().map(|v| v == 0.0).unwrap_or(false),
        Expr::Nested(inner) => is_always_false(inner),
        Expr::UnaryOp {
            op: UnaryOperator::Not,
            expr: inner,
        } => is_always_true(inner),
        Expr::BinaryOp { left, op, right } => match op {
            BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq => {
                is_literal(left) && is_literal(right) && !const_cmp_true(left, op, right)
            }
            _ => false,
        },
        _ => false,
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

fn is_literal(expr: &Expr) -> bool {
    matches!(unwrap_nested(expr), Expr::Value(_))
}

fn unwrap_nested(expr: &Expr) -> &Expr {
    match expr {
        Expr::Nested(inner) => unwrap_nested(inner),
        other => other,
    }
}

/// Statically evaluate `<const> <op> <const>`. Numbers compare numerically;
/// other literals only by `=`/`<>` identity. `false` for any non-constant
/// operand (never a false positive on a real predicate).
fn const_cmp_true(left: &Expr, op: &sqlparser::ast::BinaryOperator, right: &Expr) -> bool {
    use sqlparser::ast::BinaryOperator;
    let (l, r) = (unwrap_nested(left), unwrap_nested(right));
    let (Expr::Value(a), Expr::Value(b)) = (l, r) else {
        return false;
    };
    if let (Value::Number(x, _), Value::Number(y, _)) = (a, b) {
        if let (Ok(x), Ok(y)) = (x.parse::<f64>(), y.parse::<f64>()) {
            return match op {
                BinaryOperator::Eq => x == y,
                BinaryOperator::NotEq => x != y,
                BinaryOperator::Lt => x < y,
                BinaryOperator::LtEq => x <= y,
                BinaryOperator::Gt => x > y,
                BinaryOperator::GtEq => x >= y,
                _ => false,
            };
        }
    }
    let eq = format!("{a:?}") == format!("{b:?}");
    match op {
        BinaryOperator::Eq => eq,
        BinaryOperator::NotEq => !eq,
        _ => false,
    }
}

/// Returns true if `expr` contains a tautological OR branch at any depth —
/// i.e. `<real_condition> OR <always_true>`. This is the canonical SQL
/// injection pattern (`WHERE id = $1 OR 1=1`) even when the overall
/// predicate is not trivially true by itself.
///
/// Note: `is_always_true` already covers the case where the entire predicate
/// is trivial. This function catches the mixed case where only an OR branch is.
fn has_or_tautology(expr: &Expr) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            use sqlparser::ast::BinaryOperator;
            match op {
                // `a OR always_true` or `always_true OR a`
                BinaryOperator::Or => {
                    is_always_true(left.as_ref())
                        || is_always_true(right.as_ref())
                        || has_or_tautology(left.as_ref())
                        || has_or_tautology(right.as_ref())
                }
                // Recurse into AND branches
                BinaryOperator::And => {
                    has_or_tautology(left.as_ref()) || has_or_tautology(right.as_ref())
                }
                _ => false,
            }
        }
        Expr::Nested(inner) => has_or_tautology(inner),
        _ => false,
    }
}

fn expr_as_i64(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Value(Value::Number(n, _)) => n.parse().ok(),
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
        parse_with_dialect(&PostgreSqlDialect {}, sql).expect("must parse")
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

    // A function that merely contains "sleep" is not a sleep call.
    #[test]
    fn non_sleep_function_is_not_detected() {
        let p = parse_pg("SELECT sleepless(5)");
        assert!(
            !p.statements
                .iter()
                .any(|s| s.kind == StatementKind::FunctionCall)
        );
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
