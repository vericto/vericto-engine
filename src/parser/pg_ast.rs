//! Walker of the `pg_query` protobuf AST (libpg_query, PostgreSQL's internal
//! parser) into Vericto's normalized representation.
//!
//! Unlike `walk.rs` (which uses the sqlparser-rs AST), this module operates on
//! the exact syntax tree PostgreSQL would produce, guaranteeing that what Vericto
//! analyses is identical to what the engine would execute. It detects DELETE,
//! UPDATE, DROP, and TRUNCATE — including those nested inside data-modifying
//! CTEs (`WITH x AS (DELETE ...)`), which sqlparser-rs does not handle.

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::parser::{
    AlterTableKind, DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
};

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{Node, ObjectType, RangeVar, WithClause};

/// Parse a PostgreSQL query with libpg_query and return the normalized
/// representation. Returns `ParseError` on invalid syntax.
pub fn parse_postgres(sql: &str) -> Result<ParsedQuery> {
    let result = pg_query::parse(sql).map_err(|e| ProxyError::ParseError(e.to_string()))?;

    let mut out: Vec<StatementInfo> = Vec::new();
    for raw in &result.protobuf.stmts {
        if let Some(node) = raw.stmt.as_ref() {
            if let Some(inner) = node.node.as_ref() {
                walk_node(inner, false, 0, &mut out)?;
            }
        }
    }

    Ok(ParsedQuery { statements: out })
}

/// Walk an AST node, recording destructive statements and recursing into
/// WITH clauses (CTEs) and sub-selects.
fn walk_node(
    node: &NodeEnum,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    match node {
        NodeEnum::DeleteStmt(stmt) => {
            let presence = where_presence(stmt.where_clause.as_deref());
            out.push(StatementInfo {
                kind: StatementKind::Delete,
                relation: relname(stmt.relation.as_ref()),
                where_presence: presence,
                is_nested,
                ast_node_path: node_path("DeleteStmt", presence, is_nested),
                has_or_tautology: where_has_or_tautology(stmt.where_clause.as_deref()),
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        }

        NodeEnum::UpdateStmt(stmt) => {
            let presence = where_presence(stmt.where_clause.as_deref());
            out.push(StatementInfo {
                kind: StatementKind::Update,
                relation: relname(stmt.relation.as_ref()),
                where_presence: presence,
                is_nested,
                ast_node_path: node_path("UpdateStmt", presence, is_nested),
                has_or_tautology: where_has_or_tautology(stmt.where_clause.as_deref()),
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        }

        NodeEnum::DropStmt(stmt) => {
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                is_nested,
                ast_node_path: "DropStmt".to_string(),
                drop_object: Some(drop_kind(stmt.remove_type)),
                // `missing_ok` is libpg_query's representation of IF EXISTS.
                drop_index_if_exists: stmt.missing_ok,
                ..Default::default()
            });
        }

        // ALTER TABLE … DROP COLUMN (VERICTO-015). libpg_query emits an
        // AlterTableStmt whose `cmds` carry the subtype; RENAME is a separate
        // RenameStmt node handled below.
        NodeEnum::AlterTableStmt(stmt) => {
            use pg_query::protobuf::AlterTableType;
            for cmd in &stmt.cmds {
                let Some(NodeEnum::AlterTableCmd(c)) = cmd.node.as_ref() else {
                    continue;
                };
                // Map the libpg_query subtype to our normalized kind. Trigger
                // disabling has several subtypes (single/all/user); all of them
                // disable a protection and map to DisableTrigger.
                let (kind, path) = match AlterTableType::try_from(c.subtype) {
                    Ok(AlterTableType::AtDropColumn) => {
                        (AlterTableKind::DropColumn, "AlterTableStmt > DropColumn")
                    }
                    Ok(AlterTableType::AtDropConstraint) => (
                        AlterTableKind::DropConstraint,
                        "AlterTableStmt > DropConstraint",
                    ),
                    Ok(AlterTableType::AtAlterColumnType) => (
                        AlterTableKind::AlterColumnType,
                        "AlterTableStmt > AlterColumnType",
                    ),
                    Ok(AlterTableType::AtDisableTrig)
                    | Ok(AlterTableType::AtDisableTrigAll)
                    | Ok(AlterTableType::AtDisableTrigUser) => (
                        AlterTableKind::DisableTrigger,
                        "AlterTableStmt > DisableTrigger",
                    ),
                    _ => continue,
                };
                out.push(StatementInfo {
                    kind: StatementKind::AlterTable,
                    relation: relname(stmt.relation.as_ref()),
                    alter_table_kind: Some(kind),
                    is_nested,
                    ast_node_path: path.to_string(),
                    ..Default::default()
                });
            }
        }

        // ALTER TABLE … RENAME TO / RENAME COLUMN (VERICTO-016). PostgreSQL
        // models renames as a dedicated RenameStmt rather than an
        // AlterTableCmd subtype.
        NodeEnum::RenameStmt(stmt) => {
            if matches!(
                ObjectType::try_from(stmt.rename_type),
                Ok(ObjectType::ObjectTable) | Ok(ObjectType::ObjectColumn)
            ) {
                out.push(StatementInfo {
                    kind: StatementKind::AlterTable,
                    relation: relname(stmt.relation.as_ref()),
                    alter_table_kind: Some(AlterTableKind::Rename),
                    is_nested,
                    ast_node_path: "AlterTableStmt > Rename".to_string(),
                    ..Default::default()
                });
            }
        }

        NodeEnum::TruncateStmt(_) => {
            out.push(StatementInfo {
                kind: StatementKind::Truncate,
                is_nested,
                ast_node_path: "TruncateStmt".to_string(),
                ..Default::default()
            });
        }

        NodeEnum::SelectStmt(stmt) => {
            walk_select_stmt(stmt, is_nested, depth, out)?;
        }

        // ── DROP DATABASE (VERICTO-010) ──────────────────────────────────────
        // libpg_query models `DROP DATABASE` as its own `DropdbStmt`, *not* a
        // `DropStmt`, so it previously fell through to `_ => {}` and was
        // silently allowed (ENG-004).
        NodeEnum::DropdbStmt(_) => {
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                is_nested,
                ast_node_path: "DropdbStmt".to_string(),
                drop_object: Some(DropObjectKind::Database),
                ..Default::default()
            });
        }

        // ── COPY … TO/FROM PROGRAM (VERICTO-080) ─────────────────────────────
        // `COPY t TO PROGRAM 'cmd'` / `COPY t FROM PROGRAM 'cmd'` executes a
        // shell command on the database host — remote code execution and a
        // data-exfiltration channel. The plain file/STDIN forms are recorded
        // too (as a non-program Copy) for completeness/telemetry.
        NodeEnum::CopyStmt(stmt) => {
            out.push(StatementInfo {
                kind: StatementKind::Copy,
                relation: relname(stmt.relation.as_ref()),
                is_nested,
                ast_node_path: if stmt.is_program {
                    "CopyStmt > PROGRAM".to_string()
                } else {
                    "CopyStmt".to_string()
                },
                copy_is_program: stmt.is_program,
                ..Default::default()
            });
            // A `COPY (SELECT …) TO …` carries an inner query worth scanning.
            if let Some(q) = stmt.query.as_deref() {
                if let Some(inner) = q.node.as_ref() {
                    walk_node(inner, true, depth + 1, out)?;
                }
            }
        }

        // ── DO $$ … $$ anonymous code block (VERICTO-081) ────────────────────
        // A `DO` block runs an arbitrary PL/pgSQL body that can perform any
        // DML/DDL (e.g. `DO $$ BEGIN DELETE FROM users; END $$`). The body is
        // an opaque string to the SQL parser, so we cannot see *what* it does —
        // we flag the construct itself as a high-risk bypass.
        NodeEnum::DoStmt(_) => {
            out.push(StatementInfo {
                kind: StatementKind::DoBlock,
                is_nested,
                ast_node_path: "DoStmt".to_string(),
                ..Default::default()
            });
        }

        // ── GRANT / REVOKE (VERICTO-082) ─────────────────────────────────────
        // Privilege changes (escalation or accidental lockout). `is_grant`
        // distinguishes GRANT from REVOKE; both are recorded.
        NodeEnum::GrantStmt(_) => {
            out.push(StatementInfo {
                kind: StatementKind::Grant,
                is_nested,
                ast_node_path: "GrantStmt".to_string(),
                ..Default::default()
            });
        }

        // ── MERGE (VERICTO-083) ──────────────────────────────────────────────
        // `MERGE INTO t USING s … WHEN MATCHED THEN UPDATE/DELETE` can mutate
        // every row of the target, like an UPDATE/DELETE with no effective
        // WHERE. The join condition is walked so nested tautologies still trip.
        NodeEnum::MergeStmt(stmt) => {
            out.push(StatementInfo {
                kind: StatementKind::Merge,
                relation: relname(stmt.relation.as_ref()),
                is_nested,
                ast_node_path: "MergeStmt".to_string(),
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        }

        // ── CREATE TABLE … AS SELECT … / SELECT … INTO (VERICTO-084) ─────────
        // Bulk data copy that can duplicate an entire table. The inner query is
        // walked so an unbounded/`SELECT *` source is also surfaced.
        NodeEnum::CreateTableAsStmt(stmt) => {
            let relation = stmt
                .into
                .as_deref()
                .and_then(|into| relname(into.rel.as_ref()));
            out.push(StatementInfo {
                kind: StatementKind::CreateTableAs,
                relation,
                is_nested,
                ast_node_path: "CreateTableAsStmt".to_string(),
                ..Default::default()
            });
            if let Some(q) = stmt.query.as_deref() {
                if let Some(inner) = q.node.as_ref() {
                    walk_node(inner, true, depth + 1, out)?;
                }
            }
        }

        NodeEnum::InsertStmt(stmt) => {
            let has_cols = !stmt.cols.is_empty();

            // libpg_query models BOTH `INSERT … VALUES (…)` and
            // `INSERT … SELECT …` as `select_stmt = Some(SelectStmt)`. The two
            // are distinguished by whether that SelectStmt is a pure VALUES list
            // (`values_lists` non-empty, no FROM/targets) or a real query.
            //   - VALUES → count the tuples for VERICTO-061 (insert_row_count).
            //   - real SELECT → set insert_has_select for VERICTO-040.
            let mut insert_has_select = false;
            let mut insert_row_count = None;
            if let Some(sel) = stmt.select_stmt.as_deref() {
                if let Some(NodeEnum::SelectStmt(inner)) = sel.node.as_ref() {
                    if !inner.values_lists.is_empty() {
                        insert_row_count = Some(inner.values_lists.len());
                    } else {
                        insert_has_select = true;
                    }
                }
            }

            out.push(StatementInfo {
                kind: StatementKind::Insert,
                relation: relname(stmt.relation.as_ref()),
                is_nested,
                ast_node_path: "InsertStmt".to_string(),
                insert_has_columns: has_cols,
                insert_has_select,
                insert_row_count,
                ..Default::default()
            });
            walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
            // Always descend into the source so nested tautologies / sleeps /
            // sub-selects inside `INSERT … SELECT …` are still detected.
            if let Some(sel) = stmt.select_stmt.as_deref() {
                if let Some(inner) = sel.node.as_ref() {
                    walk_node(inner, true, depth + 1, out)?;
                }
            }
        }

        _ => {}
    }

    Ok(())
}

/// Walk the CTEs of a WITH clause. Each CTE body (`ctequery`) can be a
/// data-modifying statement (DELETE/UPDATE) that must be evaluated.
fn walk_with_clause(
    with: Option<&WithClause>,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    let Some(with) = with else { return Ok(()) };

    for cte_node in &with.ctes {
        let Some(NodeEnum::CommonTableExpr(cte)) = cte_node.node.as_ref() else {
            continue;
        };
        if let Some(ctequery) = cte.ctequery.as_deref() {
            if let Some(inner) = ctequery.node.as_ref() {
                walk_node(inner, true, depth + 1, out)?;
            }
        }
    }
    Ok(())
}

/// Record a SELECT (top-level or nested) and recurse into every place a
/// further statement/expression can hide: set-operation arms, FROM-clause
/// subqueries and joins, WHERE-clause sub-links, and the projection list.
///
/// Previously only the top-level SELECT was recorded (`if !is_nested`), so a
/// tautology or `SELECT *` buried in a subquery / CTE body / `INSERT … SELECT`
/// source was never seen (ENG-005). We now push a `StatementInfo` for *every*
/// SELECT, preserving `is_nested` so rule scoping (e.g. VERICTO-050) can still
/// distinguish the client-visible top-level read from inner scans.
fn walk_select_stmt(
    stmt: &pg_query::protobuf::SelectStmt,
    is_nested: bool,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }

    // A set-operation node (UNION/INTERSECT/EXCEPT) has empty target/from and
    // carries its real SELECTs in `larg`/`rarg`. Recurse into both arms and do
    // not record the synthetic set-op node itself.
    if stmt.larg.is_some() || stmt.rarg.is_some() {
        if let Some(larg) = stmt.larg.as_deref() {
            walk_select_stmt(larg, is_nested, depth + 1, out)?;
        }
        if let Some(rarg) = stmt.rarg.as_deref() {
            walk_select_stmt(rarg, is_nested, depth + 1, out)?;
        }
        walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;
        return Ok(());
    }

    let presence = where_presence(stmt.where_clause.as_deref());
    out.push(StatementInfo {
        kind: StatementKind::Select,
        where_presence: presence,
        is_nested,
        ast_node_path: if is_nested {
            "SubSelect > SelectStmt".to_string()
        } else {
            "SelectStmt".to_string()
        },
        select_has_limit: stmt.limit_count.is_some(),
        select_is_star: target_list_has_star(&stmt.target_list),
        has_or_tautology: where_has_or_tautology(stmt.where_clause.as_deref()),
        ..Default::default()
    });

    walk_with_clause(stmt.with_clause.as_ref(), depth + 1, out)?;

    // Projection list (VERICTO-070: `SELECT pg_sleep(5)`) and any expression
    // sub-selects inside it.
    for target in &stmt.target_list {
        scan_expr(target.node.as_ref(), depth + 1, out)?;
    }
    // WHERE clause: sleep calls and correlated sub-selects with tautologies.
    if let Some(wc) = stmt.where_clause.as_deref() {
        scan_expr(wc.node.as_ref(), depth + 1, out)?;
    }
    // FROM clause: derived tables (`FROM (SELECT …) x`) and joins.
    for from in &stmt.from_clause {
        scan_from_item(from.node.as_ref(), depth + 1, out)?;
    }

    Ok(())
}

/// Recurse a FROM-clause item, descending into derived-table subqueries and
/// both sides of a join (plus its ON-condition, which may carry a sub-link).
fn scan_from_item(
    node: Option<&NodeEnum>,
    depth: usize,
    out: &mut Vec<StatementInfo>,
) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    match node {
        Some(NodeEnum::RangeSubselect(rs)) => {
            if let Some(sub) = rs.subquery.as_deref() {
                if let Some(NodeEnum::SelectStmt(inner)) = sub.node.as_ref() {
                    walk_select_stmt(inner, true, depth + 1, out)?;
                }
            }
        }
        Some(NodeEnum::JoinExpr(je)) => {
            scan_from_item(
                je.larg.as_deref().and_then(|n| n.node.as_ref()),
                depth + 1,
                out,
            )?;
            scan_from_item(
                je.rarg.as_deref().and_then(|n| n.node.as_ref()),
                depth + 1,
                out,
            )?;
            if let Some(q) = je.quals.as_deref() {
                scan_expr(q.node.as_ref(), depth + 1, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Recursively scan an expression node for (a) sleep-family function calls
/// (VERICTO-070) and (b) sub-link sub-selects (so a tautology/star inside a
/// scalar/IN/EXISTS subquery is recorded). Bounded by `MAX_AST_DEPTH`.
fn scan_expr(node: Option<&NodeEnum>, depth: usize, out: &mut Vec<StatementInfo>) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    let Some(node) = node else { return Ok(()) };
    match node {
        NodeEnum::ResTarget(rt) => {
            if let Some(val) = rt.val.as_deref() {
                scan_expr(val.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::FuncCall(fc) => {
            if let Some(name) = func_call_name(&fc.funcname) {
                if is_sleep_function(&name) {
                    out.push(StatementInfo {
                        kind: StatementKind::FunctionCall,
                        function_name: Some(name),
                        ast_node_path: "FunctionCall > sleep".to_string(),
                        ..Default::default()
                    });
                }
            }
            for arg in &fc.args {
                scan_expr(arg.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::AExpr(e) => {
            if let Some(l) = e.lexpr.as_deref() {
                scan_expr(l.node.as_ref(), depth + 1, out)?;
            }
            if let Some(r) = e.rexpr.as_deref() {
                scan_expr(r.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::BoolExpr(b) => {
            for arg in &b.args {
                scan_expr(arg.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::TypeCast(tc) => {
            if let Some(arg) = tc.arg.as_deref() {
                scan_expr(arg.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::SubLink(sl) => {
            if let Some(tx) = sl.testexpr.as_deref() {
                scan_expr(tx.node.as_ref(), depth + 1, out)?;
            }
            if let Some(sub) = sl.subselect.as_deref() {
                if let Some(NodeEnum::SelectStmt(inner)) = sub.node.as_ref() {
                    walk_select_stmt(inner, true, depth + 1, out)?;
                }
            }
        }
        NodeEnum::List(list) => {
            for item in &list.items {
                scan_expr(item.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::CaseExpr(c) => {
            for arg in &c.args {
                scan_expr(arg.node.as_ref(), depth + 1, out)?;
            }
            if let Some(d) = c.defresult.as_deref() {
                scan_expr(d.node.as_ref(), depth + 1, out)?;
            }
        }
        NodeEnum::CoalesceExpr(c) => {
            for arg in &c.args {
                scan_expr(arg.node.as_ref(), depth + 1, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Extract the (unqualified) function name from a `FuncCall.funcname` list of
/// String nodes, e.g. `pg_catalog.pg_sleep` → `pg_sleep`.
fn func_call_name(funcname: &[Node]) -> Option<String> {
    funcname.last().and_then(|n| match n.node.as_ref() {
        Some(NodeEnum::String(s)) => Some(s.sval.to_ascii_lowercase()),
        _ => None,
    })
}

/// Sleep-family functions used for DoS / time-based blind SQL injection.
/// Mirrors the list in `walk.rs` so detection is dialect-consistent.
fn is_sleep_function(name: &str) -> bool {
    matches!(
        name,
        "sleep" | "pg_sleep" | "pg_sleep_for" | "pg_sleep_until"
    )
}

/// Determine WHERE clause state from a protobuf node.
fn where_presence(where_clause: Option<&Node>) -> WherePresence {
    match where_clause {
        None => WherePresence::Absent,
        Some(node) => match node.node.as_ref() {
            Some(inner) if is_always_true(inner) => WherePresence::AlwaysTrue,
            _ => WherePresence::Present,
        },
    }
}

/// Detect trivially-true predicates in the pg_query AST. A WHERE clause that is
/// always true is semantically equivalent to no WHERE at all, so a DELETE /
/// UPDATE guarded only by such a predicate is just as destructive (ENG-009).
///
/// Recognised forms:
/// - boolean constant `TRUE`
/// - a bare truthy numeric literal (`WHERE 1`, MySQL-style — also valid as a
///   filter expression in some contexts)
/// - `<const> <cmp> <const>` for `=`, `<>`/`!=`, `<`, `<=`, `>`, `>=`
///   evaluated over numeric/boolean literals (`1=1`, `2 > 1`, `'a'='a'`)
/// - column self-comparison `col = col` (always true for non-null rows; the
///   canonical WHERE-stripping trick `WHERE id = id`)
/// - `NOT <always_false>` (e.g. `NOT FALSE`, `NOT 1=2`)
/// - AND where every operand is always-true; OR where any operand is
fn is_always_true(node: &NodeEnum) -> bool {
    match node {
        NodeEnum::AConst(c) => const_is_truthy(c),
        NodeEnum::AExpr(expr) => {
            let op = operator_name(&expr.name);
            let (Some(l), Some(r)) = (expr.lexpr.as_deref(), expr.rexpr.as_deref()) else {
                return false;
            };
            // Column self-comparison: `id = id`.
            if op.as_deref() == Some("=") && same_column_ref(l, r) {
                return true;
            }
            // Constant-vs-constant comparison evaluated at parse time.
            match op.as_deref() {
                Some(o @ ("=" | "<>" | "!=" | "<" | "<=" | ">" | ">=")) => const_cmp_true(l, r, o),
                _ => false,
            }
        }
        NodeEnum::BoolExpr(b) => {
            use pg_query::protobuf::BoolExprType;
            match BoolExprType::try_from(b.boolop) {
                Ok(BoolExprType::AndExpr) => {
                    !b.args.is_empty()
                        && b.args
                            .iter()
                            .filter_map(|n| n.node.as_ref())
                            .all(is_always_true)
                }
                Ok(BoolExprType::OrExpr) => b
                    .args
                    .iter()
                    .filter_map(|n| n.node.as_ref())
                    .any(is_always_true),
                // `NOT x` is always true when `x` is always false.
                Ok(BoolExprType::NotExpr) => b
                    .args
                    .iter()
                    .filter_map(|n| n.node.as_ref())
                    .all(is_always_false),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Dual of `is_always_true`, used to evaluate `NOT (…)`. Conservative: only a
/// handful of provably-false forms qualify (`FALSE`, `0`, a false constant
/// comparison). Anything unknown is treated as *not* provably false.
fn is_always_false(node: &NodeEnum) -> bool {
    match node {
        NodeEnum::AConst(c) => const_is_falsey(c),
        NodeEnum::AExpr(expr) => {
            let op = operator_name(&expr.name);
            let (Some(l), Some(r)) = (expr.lexpr.as_deref(), expr.rexpr.as_deref()) else {
                return false;
            };
            match op.as_deref() {
                Some(o @ ("=" | "<>" | "!=" | "<" | "<=" | ">" | ">=")) => {
                    // `<const> <op> <const>` is false ⇔ the comparison does not hold.
                    is_const(l) && is_const(r) && !const_cmp_true(l, r, o)
                }
                _ => false,
            }
        }
        NodeEnum::BoolExpr(b) => {
            use pg_query::protobuf::BoolExprType;
            matches!(BoolExprType::try_from(b.boolop), Ok(BoolExprType::NotExpr))
                && b.args
                    .iter()
                    .filter_map(|n| n.node.as_ref())
                    .all(is_always_true)
        }
        _ => false,
    }
}

/// A constant is "truthy" as a bare predicate: boolean `TRUE`, or a non-zero
/// number (`WHERE 1`).
fn const_is_truthy(c: &pg_query::protobuf::AConst) -> bool {
    use pg_query::protobuf::a_const::Val;
    match c.val.as_ref() {
        Some(Val::Boolval(b)) => b.boolval,
        Some(Val::Ival(i)) => i.ival != 0,
        Some(Val::Fval(f)) => f.fval.parse::<f64>().map(|n| n != 0.0).unwrap_or(false),
        _ => false,
    }
}

/// A constant is "falsey" as a bare predicate: boolean `FALSE`, or zero.
fn const_is_falsey(c: &pg_query::protobuf::AConst) -> bool {
    use pg_query::protobuf::a_const::Val;
    match c.val.as_ref() {
        Some(Val::Boolval(b)) => !b.boolval,
        Some(Val::Ival(i)) => i.ival == 0,
        Some(Val::Fval(f)) => f.fval.parse::<f64>().map(|n| n == 0.0).unwrap_or(false),
        _ => false,
    }
}

/// Is this node a literal constant?
fn is_const(node: &Node) -> bool {
    matches!(node.node.as_ref(), Some(NodeEnum::AConst(_)))
}

/// Compare two literal constants under `op`, returning whether the comparison
/// is statically true. Returns `false` for any non-constant operand or any
/// pair whose types we cannot compare (conservative — never a false positive
/// on a real predicate). Numbers compare numerically; everything else (strings,
/// booleans) compares by the same debug-string identity used elsewhere.
fn const_cmp_true(left: &Node, right: &Node, op: &str) -> bool {
    let (Some(NodeEnum::AConst(a)), Some(NodeEnum::AConst(b))) =
        (left.node.as_ref(), right.node.as_ref())
    else {
        return false;
    };
    // Try a numeric comparison first.
    if let (Some(x), Some(y)) = (aconst_as_f64(a), aconst_as_f64(b)) {
        return match op {
            "=" => x == y,
            "<>" | "!=" => x != y,
            "<" => x < y,
            "<=" => x <= y,
            ">" => x > y,
            ">=" => x >= y,
            _ => false,
        };
    }
    // Non-numeric (string/bool): only equality / inequality are decidable by
    // identity. Ordering comparisons are left undecided (false).
    let eq = format!("{:?}", a.val) == format!("{:?}", b.val);
    match op {
        "=" => eq,
        "<>" | "!=" => !eq,
        _ => false,
    }
}

/// Numeric value of an integer/float `A_Const`, if it is one.
fn aconst_as_f64(c: &pg_query::protobuf::AConst) -> Option<f64> {
    use pg_query::protobuf::a_const::Val;
    match c.val.as_ref() {
        Some(Val::Ival(i)) => Some(i.ival as f64),
        Some(Val::Fval(f)) => f.fval.parse::<f64>().ok(),
        _ => None,
    }
}

/// True when both nodes are the *same* column reference (`id` and `id`, or
/// `t.id` and `t.id`). Used to catch the `WHERE id = id` self-comparison.
fn same_column_ref(left: &Node, right: &Node) -> bool {
    match (left.node.as_ref(), right.node.as_ref()) {
        (Some(NodeEnum::ColumnRef(a)), Some(NodeEnum::ColumnRef(b))) => {
            column_ref_path(a) == column_ref_path(b) && !column_ref_path(a).is_empty()
        }
        _ => false,
    }
}

/// Dotted path of a `ColumnRef` (`["t", "id"]` → `"t.id"`); empty for `*`.
fn column_ref_path(col: &pg_query::protobuf::ColumnRef) -> String {
    col.fields
        .iter()
        .filter_map(|f| match f.node.as_ref() {
            Some(NodeEnum::String(s)) => Some(s.sval.clone()),
            _ => None, // A_Star or anything else → not a plain column path
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Returns `true` when a WHERE predicate contains a trivially-true OR branch
/// at any depth (e.g. `id = $1 OR 1=1`). Used by VERICTO-090 to detect the
/// canonical SQL injection tautology on the PostgreSQL path. Mirrors the
/// sqlparser walker so behaviour is identical across dialects.
fn where_has_or_tautology(where_clause: Option<&Node>) -> bool {
    where_clause
        .and_then(|n| n.node.as_ref())
        .map(has_or_tautology)
        .unwrap_or(false)
}

/// Recursively detect a tautological OR branch: an `OR` whose any operand is
/// always true, or an `AND` containing such an `OR` deeper down.
fn has_or_tautology(node: &NodeEnum) -> bool {
    use pg_query::protobuf::BoolExprType;
    let NodeEnum::BoolExpr(b) = node else {
        return false;
    };
    let children = || b.args.iter().filter_map(|n| n.node.as_ref());
    match BoolExprType::try_from(b.boolop) {
        Ok(BoolExprType::OrExpr) => {
            children().any(is_always_true) || children().any(has_or_tautology)
        }
        Ok(BoolExprType::AndExpr) => children().any(has_or_tautology),
        _ => false,
    }
}

/// Extract the operator name from an `A_Expr` (list of String nodes).
fn operator_name(name: &[Node]) -> Option<String> {
    let first = name.first()?;
    match first.node.as_ref()? {
        NodeEnum::String(s) => Some(s.sval.clone()),
        _ => None,
    }
}

/// Extract the relation name from a `RangeVar`.
fn relname(range_var: Option<&RangeVar>) -> Option<String> {
    range_var
        .map(|rv| rv.relname.clone())
        .filter(|s| !s.is_empty())
}

/// Returns `true` when a SELECT target list contains a `*` wildcard
/// (e.g. `SELECT *` or `SELECT t.*`). pg_query represents this as a
/// `ResTarget` whose value is a `ColumnRef` containing an `A_Star` field.
fn target_list_has_star(target_list: &[Node]) -> bool {
    target_list.iter().any(|node| {
        let Some(NodeEnum::ResTarget(res)) = node.node.as_ref() else {
            return false;
        };
        let Some(val) = res.val.as_deref() else {
            return false;
        };
        let Some(NodeEnum::ColumnRef(col)) = val.node.as_ref() else {
            return false;
        };
        col.fields
            .iter()
            .any(|f| matches!(f.node.as_ref(), Some(NodeEnum::AStar(_))))
    })
}

/// Map the `remove_type` integer (ObjectType protobuf enum) to `DropObjectKind`.
/// An unrecognized discriminant maps to `Other`, so an unknown DROP target is
/// never mistaken for a table/schema/index.
fn drop_kind(remove_type: i32) -> DropObjectKind {
    match ObjectType::try_from(remove_type) {
        Ok(ObjectType::ObjectTable) => DropObjectKind::Table,
        Ok(ObjectType::ObjectSchema) => DropObjectKind::Schema,
        Ok(ObjectType::ObjectIndex) => DropObjectKind::Index,
        _ => DropObjectKind::Other,
    }
}

/// Build the AST node path string included in the block response.
fn node_path(stmt: &str, presence: WherePresence, is_nested: bool) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::StatementKind;

    #[test]
    fn delete_without_where() {
        let parsed = parse_postgres("DELETE FROM users").unwrap();
        assert_eq!(parsed.statements[0].kind, StatementKind::Delete);
        assert_eq!(parsed.statements[0].where_presence, WherePresence::Absent);
    }

    #[test]
    fn delete_with_where() {
        let parsed = parse_postgres("DELETE FROM users WHERE id = 1").unwrap();
        assert_eq!(parsed.statements[0].where_presence, WherePresence::Present);
    }

    #[test]
    fn delete_one_equals_one() {
        let parsed = parse_postgres("DELETE FROM users WHERE 1 = 1").unwrap();
        assert_eq!(
            parsed.statements[0].where_presence,
            WherePresence::AlwaysTrue
        );
    }

    #[test]
    fn update_in_cte_without_where_is_nested() {
        let sql = "WITH x AS (UPDATE sessions SET status = 'e' RETURNING id) SELECT * FROM x";
        let parsed = parse_postgres(sql).unwrap();
        let update = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Update)
            .expect("must detect the nested UPDATE");
        assert!(update.is_nested);
        assert_eq!(update.where_presence, WherePresence::Absent);
    }

    #[test]
    fn invalid_syntax_is_parse_error() {
        assert!(parse_postgres("DELETE FORM users").is_err());
    }

    // ── SELECT attribute population (VERICTO-050 / VERICTO-051) ─────────────────

    #[test]
    fn select_with_limit_sets_has_limit() {
        // `SELECT 1 LIMIT 1` must record a LIMIT so VERICTO-050 does not fire.
        let parsed = parse_postgres("SELECT 1 LIMIT 1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.select_has_limit, "LIMIT 1 must set select_has_limit");
    }

    #[test]
    fn select_without_limit_has_no_limit() {
        let parsed = parse_postgres("SELECT id FROM users WHERE id = 1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(!select.select_has_limit);
    }

    #[test]
    fn select_star_is_detected() {
        let parsed = parse_postgres("SELECT * FROM users").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.select_is_star, "SELECT * must set select_is_star");
        assert_eq!(select.where_presence, WherePresence::Absent);
    }

    #[test]
    fn select_explicit_columns_is_not_star() {
        let parsed = parse_postgres("SELECT id, name FROM users").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(!select.select_is_star);
    }

    #[test]
    fn select_with_where_records_presence() {
        let parsed = parse_postgres("SELECT * FROM users WHERE id = 1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert_eq!(select.where_presence, WherePresence::Present);
    }

    // ── ALTER TABLE / RENAME / DROP INDEX / OR-tautology ───────────────────

    #[test]
    fn alter_table_drop_column_is_detected() {
        let parsed = parse_postgres("ALTER TABLE users DROP COLUMN email").unwrap();
        let s = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::AlterTable)
            .expect("must detect ALTER TABLE");
        assert_eq!(
            s.alter_table_kind,
            Some(crate::parser::AlterTableKind::DropColumn)
        );
    }

    #[test]
    fn alter_table_rename_is_detected() {
        let parsed = parse_postgres("ALTER TABLE users RENAME TO accounts").unwrap();
        let s = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::AlterTable)
            .expect("must detect ALTER TABLE RENAME");
        assert_eq!(
            s.alter_table_kind,
            Some(crate::parser::AlterTableKind::Rename)
        );
    }

    #[test]
    fn drop_index_if_exists_flag() {
        let with_ie = parse_postgres("DROP INDEX IF EXISTS idx_users_email").unwrap();
        assert!(with_ie.statements[0].drop_index_if_exists);
        let without_ie = parse_postgres("DROP INDEX idx_users_email").unwrap();
        assert!(!without_ie.statements[0].drop_index_if_exists);
    }

    #[test]
    fn or_tautology_is_detected() {
        let parsed = parse_postgres("SELECT * FROM users WHERE id = 1 OR 1=1").unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.has_or_tautology);
    }

    #[test]
    fn nested_or_tautology_is_detected() {
        let parsed = parse_postgres(
            "SELECT * FROM users WHERE status = 'active' AND (role = 'user' OR 1=1)",
        )
        .unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(select.has_or_tautology);
    }

    #[test]
    fn legitimate_or_is_not_tautology() {
        let parsed =
            parse_postgres("SELECT * FROM products WHERE category = 'A' OR category = 'B'")
                .unwrap();
        let select = parsed
            .statements
            .iter()
            .find(|s| s.kind == StatementKind::Select)
            .expect("must detect the SELECT");
        assert!(!select.has_or_tautology);
    }
}
