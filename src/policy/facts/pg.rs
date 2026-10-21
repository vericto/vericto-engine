// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The `pg_query` front end of the policy facts: one [`Shape`] per
//! top-level statement of a Postgres parse tree.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{self, Node, ObjectType};

use super::{Assign, ColRef, FactVal, LimitFact, Name, Pred, ScopeItem, Shape};
use crate::parser::WherePresence;
use crate::parser::pg_ast::where_presence;

/// The reference walk of a statement: not run, failed, or its references.
type Refs = Option<Result<Vec<crate::sensitive::Ref>, String>>;

/// Shapes of every top-level statement, each with its reference walk.
pub(crate) fn shapes(
    tree: &protobuf::ParseResult,
    sql: Option<&str>,
    want: super::Want,
) -> Vec<(Shape, Refs)> {
    let mut out = Vec::new();
    for raw in &tree.stmts {
        let Some(node) = raw.stmt.as_deref().and_then(|n| n.node.as_ref()) else {
            continue;
        };
        let text = sql.and_then(|s| statement_text(s, raw.stmt_location, raw.stmt_len));
        out.push(statement(node, text, want));
    }
    out
}

fn statement_text(sql: &str, location: i32, len: i32) -> Option<&str> {
    let start = usize::try_from(location).ok()?;
    let end = if len <= 0 {
        sql.len()
    } else {
        start.checked_add(usize::try_from(len).ok()?)?
    };
    sql.get(start..end.min(sql.len()))
}

fn walk(node: &NodeEnum) -> Refs {
    Some(crate::access::refs_pg(node))
}

fn statement(node: &NodeEnum, text: Option<&str>, want: super::Want) -> (Shape, Refs) {
    // The statement inside is what runs (EXPLAIN ANALYZE executes it).
    if let NodeEnum::ExplainStmt(e) = node {
        if let Some(inner) = e.query.as_deref().and_then(|n| n.node.as_ref()) {
            return statement(inner, text, want);
        }
    }
    let mut shape = shape_of(node);
    shape.functions = match (want.functions, text) {
        (false, _) => Err("not extracted"),
        (true, Some(t)) => functions(t),
        (true, None) => Err("the statement text was not available"),
    };
    let refs = if !want.refs {
        None
    } else if shape.refs_from_walk {
        match node {
            // Walk the query a SELECT INTO / CREATE TABLE AS reads.
            NodeEnum::SelectStmt(s) if s.into_clause.is_some() => {
                let mut s = s.clone();
                s.into_clause = None;
                walk(&NodeEnum::SelectStmt(s))
            }
            NodeEnum::CreateTableAsStmt(c) => c
                .query
                .as_deref()
                .and_then(|q| q.node.as_ref())
                .and_then(walk),
            NodeEnum::ViewStmt(v) => v
                .query
                .as_deref()
                .and_then(|q| q.node.as_ref())
                .and_then(walk),
            other => walk(other),
        }
    } else {
        None
    };
    (shape, refs)
}

fn range_name(rv: &protobuf::RangeVar) -> Name {
    let mut parts = Vec::new();
    if !rv.catalogname.is_empty() {
        parts.push(rv.catalogname.clone());
    }
    if !rv.schemaname.is_empty() {
        parts.push(rv.schemaname.clone());
    }
    parts.push(rv.relname.clone());
    Name::new(parts)
}

fn alias_of(rv: &protobuf::RangeVar) -> Option<String> {
    rv.alias.as_ref().map(|a| a.aliasname.clone())
}

fn strings(list: &[Node]) -> Vec<String> {
    list.iter()
        .filter_map(|n| match n.node.as_ref() {
            Some(NodeEnum::String(s)) => Some(s.sval.clone()),
            _ => None,
        })
        .collect()
}

fn nested_writes(with: Option<&protobuf::WithClause>) -> bool {
    with.is_some_and(|w| {
        w.ctes.iter().any(|c| match c.node.as_ref() {
            Some(NodeEnum::CommonTableExpr(cte)) => matches!(
                cte.ctequery.as_deref().and_then(|q| q.node.as_ref()),
                Some(
                    NodeEnum::InsertStmt(_)
                        | NodeEnum::UpdateStmt(_)
                        | NodeEnum::DeleteStmt(_)
                        | NodeEnum::MergeStmt(_)
                )
            ),
            _ => false,
        })
    })
}

fn shape_of(node: &NodeEnum) -> Shape {
    match node {
        NodeEnum::SelectStmt(s) if s.into_clause.is_some() => {
            let mut sh = Shape::new("ddl", "SelectStmt");
            sh.ddl_targets = s
                .into_clause
                .as_ref()
                .and_then(|i| i.rel.as_ref())
                .map(|r| vec![range_name(r)]);
            sh.refs_from_walk = true;
            sh
        }
        NodeEnum::SelectStmt(s) => {
            let mut sh = Shape::new("select", "SelectStmt");
            sh.refs_from_walk = true;
            sh.nested_writes = nested_writes(s.with_clause.as_ref());
            sh.limit = limit(s.limit_count.as_deref());
            // A set operation has no WHERE or FROM of its own.
            for item in &s.from_clause {
                scope_item(item, &mut sh.scope);
            }
            set_where(&mut sh, s.where_clause.as_deref());
            sh
        }
        NodeEnum::InsertStmt(i) => {
            let mut sh = Shape::new("insert", "InsertStmt");
            sh.refs_from_walk = true;
            sh.nested_writes = nested_writes(i.with_clause.as_ref());
            sh.has_returning = !i.returning_list.is_empty();
            if let Some(rv) = &i.relation {
                sh.target = Some(range_name(rv));
            }
            let columns: Vec<String> = i
                .cols
                .iter()
                .filter_map(|c| match c.node.as_ref() {
                    Some(NodeEnum::ResTarget(rt)) => Some(rt.name.clone()),
                    _ => None,
                })
                .collect();
            sh.assign = match i.select_stmt.as_deref().and_then(|n| n.node.as_ref()) {
                None => {
                    Assign::Unknown("INSERT … DEFAULT VALUES: the values are the column defaults")
                }
                Some(NodeEnum::SelectStmt(sel)) if !sel.values_lists.is_empty() => {
                    let rows: Vec<Vec<FactVal>> = sel
                        .values_lists
                        .iter()
                        .map(|row| match row.node.as_ref() {
                            Some(NodeEnum::List(l)) => l.items.iter().map(fact_val).collect(),
                            _ => vec![FactVal::Expr],
                        })
                        .collect();
                    sh.insert_rows = Some(rows.len() as i64);
                    Assign::Rows {
                        columns: (!columns.is_empty()).then_some(columns),
                        rows,
                    }
                }
                Some(_) => Assign::Unknown("INSERT … SELECT: the values come from a query"),
            };
            if let Some(oc) = &i.on_conflict_clause {
                if oc.action == protobuf::OnConflictAction::OnconflictUpdate as i32 {
                    for t in &oc.target_list {
                        if let Some(NodeEnum::ResTarget(rt)) = t.node.as_ref() {
                            let v = rt.val.as_deref();
                            // `SET c = EXCLUDED.c` is the inserted value.
                            let same = v.and_then(|v| v.node.as_ref()).is_some_and(|n| {
                                matches!(n, NodeEnum::ColumnRef(c)
                                    if strings(&c.fields) == ["excluded".to_string(), rt.name.clone()])
                            });
                            if !same {
                                sh.upsert
                                    .push((rt.name.clone(), v.map_or(FactVal::Expr, fact_val)));
                            }
                        }
                    }
                }
            }
            sh
        }
        NodeEnum::UpdateStmt(u) => {
            let mut sh = Shape::new("update", "UpdateStmt");
            sh.refs_from_walk = true;
            sh.nested_writes = nested_writes(u.with_clause.as_ref());
            sh.has_returning = !u.returning_list.is_empty();
            if let Some(rv) = &u.relation {
                sh.target = Some(range_name(rv));
                sh.scope.push(ScopeItem {
                    alias: alias_of(rv),
                    table: Some(range_name(rv)),
                });
            }
            let mut pairs = Vec::new();
            let mut tuple = false;
            for t in &u.target_list {
                if let Some(NodeEnum::ResTarget(rt)) = t.node.as_ref() {
                    match rt.val.as_deref().and_then(|n| n.node.as_ref()) {
                        Some(NodeEnum::MultiAssignRef(_)) => tuple = true,
                        _ => pairs.push((
                            rt.name.clone(),
                            rt.val.as_deref().map_or(FactVal::Expr, fact_val),
                        )),
                    }
                }
            }
            sh.assign = if tuple {
                Assign::Unknown("a tuple assignment `SET (a, b) = …`")
            } else {
                Assign::Set(pairs)
            };
            for item in &u.from_clause {
                scope_item(item, &mut sh.scope);
            }
            set_where(&mut sh, u.where_clause.as_deref());
            sh
        }
        NodeEnum::DeleteStmt(d) => {
            let mut sh = Shape::new("delete", "DeleteStmt");
            sh.refs_from_walk = true;
            sh.nested_writes = nested_writes(d.with_clause.as_ref());
            sh.has_returning = !d.returning_list.is_empty();
            if let Some(rv) = &d.relation {
                sh.target = Some(range_name(rv));
                sh.scope.push(ScopeItem {
                    alias: alias_of(rv),
                    table: Some(range_name(rv)),
                });
            }
            for item in &d.using_clause {
                scope_item(item, &mut sh.scope);
            }
            set_where(&mut sh, d.where_clause.as_deref());
            sh
        }
        NodeEnum::MergeStmt(m) => {
            let mut sh = Shape::new("merge", "MergeStmt");
            sh.refs_from_walk = true;
            sh.nested_writes = nested_writes(m.with_clause.as_ref());
            if let Some(rv) = &m.relation {
                sh.target = Some(range_name(rv));
            }
            sh.assign = Assign::Unknown("MERGE: the values depend on the matched rows");
            sh
        }
        NodeEnum::CopyStmt(c) => {
            let mut sh = Shape::new("copy", "CopyStmt");
            sh.refs_from_walk = true;
            if c.is_from {
                if let Some(rv) = &c.relation {
                    sh.target = Some(range_name(rv));
                }
                sh.assign = Assign::Unknown("COPY FROM: the rows come from outside the statement");
            }
            sh
        }
        NodeEnum::CallStmt(_) => walked("call", "CallStmt"),
        NodeEnum::VariableSetStmt(_) => walked("set", "VariableSetStmt"),
        NodeEnum::VariableShowStmt(_) => walked("set", "VariableShowStmt"),
        NodeEnum::DeclareCursorStmt(_) => walked("select", "DeclareCursorStmt"),
        NodeEnum::LockStmt(_) => walked("other", "LockStmt"),
        NodeEnum::TransactionStmt(_)
        | NodeEnum::ClosePortalStmt(_)
        | NodeEnum::FetchStmt(_)
        | NodeEnum::ListenStmt(_)
        | NodeEnum::UnlistenStmt(_)
        | NodeEnum::NotifyStmt(_)
        | NodeEnum::DiscardStmt(_) => walked("other", node_name(node)),
        // Runs code the engine does not read.
        NodeEnum::DoStmt(_) => Shape::new("other", "DoStmt"),
        // Prepared statements: what EXECUTE runs is not this text.
        NodeEnum::PrepareStmt(_) | NodeEnum::ExecuteStmt(_) | NodeEnum::DeallocateStmt(_) => {
            Shape::new("other", node_name(node))
        }
        NodeEnum::DropStmt(d) => {
            let mut sh = Shape::new("ddl", "DropStmt");
            let tablelike = [
                ObjectType::ObjectTable,
                ObjectType::ObjectView,
                ObjectType::ObjectMatview,
                ObjectType::ObjectForeignTable,
            ]
            .iter()
            .any(|t| *t as i32 == d.remove_type);
            if tablelike {
                sh.ddl_targets = Some(
                    d.objects
                        .iter()
                        .filter_map(|o| match o.node.as_ref() {
                            Some(NodeEnum::List(l)) => Some(Name::new(strings(&l.items))),
                            _ => None,
                        })
                        .collect(),
                );
            }
            sh
        }
        NodeEnum::TruncateStmt(t) => {
            let mut sh = Shape::new("ddl", "TruncateStmt");
            sh.ddl_targets = Some(
                t.relations
                    .iter()
                    .filter_map(|r| match r.node.as_ref() {
                        Some(NodeEnum::RangeVar(rv)) => Some(range_name(rv)),
                        _ => None,
                    })
                    .collect(),
            );
            sh
        }
        NodeEnum::AlterTableStmt(a) => ddl_on("AlterTableStmt", a.relation.as_ref()),
        NodeEnum::IndexStmt(i) => ddl_on("IndexStmt", i.relation.as_ref()),
        NodeEnum::CreateStmt(c) => ddl_on("CreateStmt", c.relation.as_ref()),
        NodeEnum::RenameStmt(r) => ddl_on("RenameStmt", r.relation.as_ref()),
        NodeEnum::CreateTableAsStmt(c) => {
            let mut sh = ddl_on(
                "CreateTableAsStmt",
                c.into.as_ref().and_then(|i| i.rel.as_ref()),
            );
            sh.refs_from_walk = sh.ddl_targets.is_some();
            sh
        }
        NodeEnum::ViewStmt(v) => {
            let mut sh = ddl_on("ViewStmt", v.view.as_ref());
            sh.refs_from_walk = sh.ddl_targets.is_some();
            sh
        }
        NodeEnum::GrantStmt(g) => {
            let mut sh = Shape::new("ddl", "GrantStmt");
            if g.objtype == ObjectType::ObjectTable as i32
                && g.targtype == protobuf::GrantTargetType::AclTargetObject as i32
            {
                sh.ddl_targets = Some(
                    g.objects
                        .iter()
                        .filter_map(|o| match o.node.as_ref() {
                            Some(NodeEnum::RangeVar(rv)) => Some(range_name(rv)),
                            _ => None,
                        })
                        .collect(),
                );
            }
            sh
        }
        // Any other kind is DDL whose tables are not extracted (deny by
        // default, as the access analysis does).
        other => Shape::new("ddl", node_name(other)),
    }
}

fn walked(op: &'static str, kind: impl Into<String>) -> Shape {
    let mut sh = Shape::new(op, kind);
    sh.refs_from_walk = true;
    sh
}

fn ddl_on(kind: &str, rv: Option<&protobuf::RangeVar>) -> Shape {
    let mut sh = Shape::new("ddl", kind);
    sh.ddl_targets = rv.map(|r| vec![range_name(r)]);
    sh
}

/// `DropStmt`, `CreateSchemaStmt`, …: the protobuf variant name.
fn node_name(node: &NodeEnum) -> String {
    let debug = format!("{node:?}");
    debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or("Statement")
        .to_string()
}

fn scope_item(n: &Node, out: &mut Vec<ScopeItem>) {
    match n.node.as_ref() {
        Some(NodeEnum::RangeVar(rv)) => out.push(ScopeItem {
            alias: alias_of(rv),
            table: Some(range_name(rv)),
        }),
        Some(NodeEnum::JoinExpr(j)) => {
            if let Some(l) = j.larg.as_deref() {
                scope_item(l, out);
            }
            if let Some(r) = j.rarg.as_deref() {
                scope_item(r, out);
            }
        }
        Some(NodeEnum::RangeSubselect(rs)) => out.push(ScopeItem {
            alias: rs.alias.as_ref().map(|a| a.aliasname.clone()),
            table: None,
        }),
        Some(NodeEnum::RangeFunction(rf)) => out.push(ScopeItem {
            alias: rf.alias.as_ref().map(|a| a.aliasname.clone()),
            table: None,
        }),
        _ => out.push(ScopeItem {
            alias: None,
            table: None,
        }),
    }
}

fn set_where(sh: &mut Shape, w: Option<&Node>) {
    let Some(w) = w else { return };
    sh.where_always_true = where_presence(Some(w)) == WherePresence::AlwaysTrue;
    sh.where_pred = Some(pred(w, 0));
}

const MAX_PRED_DEPTH: usize = 64;

fn pred(n: &Node, depth: usize) -> Pred {
    use protobuf::{AExprKind, BoolExprType};
    if depth > MAX_PRED_DEPTH {
        return Pred::Other;
    }
    match n.node.as_ref() {
        Some(NodeEnum::BoolExpr(b)) if b.boolop == BoolExprType::AndExpr as i32 => {
            Pred::And(b.args.iter().map(|a| pred(a, depth + 1)).collect())
        }
        Some(NodeEnum::AExpr(e)) => {
            let op = strings(&e.name).last().cloned().unwrap_or_default();
            let (Some(l), Some(r)) = (e.lexpr.as_deref(), e.rexpr.as_deref()) else {
                return Pred::Other;
            };
            let kind = AExprKind::try_from(e.kind).ok();
            match kind {
                Some(AExprKind::AexprOp) => {
                    let (col, val, col_left) = match (column(l), column(r)) {
                        (Some(c), None) => match value(r) {
                            Some(v) => (c, v, true),
                            None => return Pred::Other,
                        },
                        (None, Some(c)) => match value(l) {
                            Some(v) => (c, v, false),
                            None => return Pred::Other,
                        },
                        _ => return Pred::Other,
                    };
                    match op.as_str() {
                        "=" => Pred::Eq(col, val),
                        ">" | ">=" => Pred::Bound {
                            col,
                            lower: col_left,
                            val,
                        },
                        "<" | "<=" => Pred::Bound {
                            col,
                            lower: !col_left,
                            val,
                        },
                        _ => Pred::Other,
                    }
                }
                // `col IN (…)` carries "="; `NOT IN` carries "<>".
                Some(AExprKind::AexprIn) if op == "=" => {
                    let (Some(col), Some(NodeEnum::List(list))) = (column(l), r.node.as_ref())
                    else {
                        return Pred::Other;
                    };
                    let mut vals = Vec::new();
                    for item in &list.items {
                        match value(item) {
                            Some(v) => vals.push(v),
                            None => return Pred::Other,
                        }
                    }
                    Pred::In(col, vals)
                }
                // `col = ANY(…)`: pinned to a set the engine does not see.
                Some(AExprKind::AexprOpAny) if op == "=" => match (column(l), value(r)) {
                    (Some(col), Some(_)) => Pred::In(col, vec![FactVal::Expr]),
                    _ => Pred::Other,
                },
                Some(AExprKind::AexprBetween) => {
                    let (Some(col), Some(NodeEnum::List(list))) = (column(l), r.node.as_ref())
                    else {
                        return Pred::Other;
                    };
                    match (
                        list.items.first().and_then(value),
                        list.items.get(1).and_then(value),
                    ) {
                        (Some(lo), Some(hi)) if list.items.len() == 2 => Pred::Between(col, lo, hi),
                        _ => Pred::Other,
                    }
                }
                _ => Pred::Other,
            }
        }
        _ => Pred::Other,
    }
}

/// A column reference (not `*`).
fn column(n: &Node) -> Option<ColRef> {
    let n = strip_cast(n);
    match n.node.as_ref()? {
        NodeEnum::ColumnRef(c) => {
            if c.fields
                .iter()
                .any(|f| matches!(f.node.as_ref(), Some(NodeEnum::AStar(_))))
            {
                return None;
            }
            let mut parts = strings(&c.fields);
            let column = parts.pop()?;
            Some(ColRef {
                qualifier: parts,
                column,
            })
        }
        _ => None,
    }
}

/// `col::type` is still the column for a pin.
fn strip_cast(n: &Node) -> &Node {
    match n.node.as_ref() {
        Some(NodeEnum::TypeCast(tc)) => tc.arg.as_deref().map_or(n, strip_cast),
        _ => n,
    }
}

/// The value side of a pin: a literal, a parameter, a cast of either, or an
/// expression free of columns and subqueries (its value is fixed for the
/// statement but not known here). `None` for anything that reads a row.
fn value(n: &Node) -> Option<FactVal> {
    if !row_free(n, 0) {
        return None;
    }
    Some(fact_val(n))
}

fn row_free(n: &Node, depth: usize) -> bool {
    if depth > MAX_PRED_DEPTH {
        return false;
    }
    let ok = |o: Option<&Node>| o.is_none_or(|x| row_free(x, depth + 1));
    match n.node.as_ref() {
        None => true,
        Some(NodeEnum::AConst(_) | NodeEnum::ParamRef(_)) => true,
        Some(NodeEnum::TypeCast(tc)) => ok(tc.arg.as_deref()),
        Some(NodeEnum::AExpr(e)) => ok(e.lexpr.as_deref()) && ok(e.rexpr.as_deref()),
        Some(NodeEnum::FuncCall(f)) => {
            f.agg_filter.is_none()
                && f.over.is_none()
                && !f.agg_star
                && f.args.iter().all(|a| row_free(a, depth + 1))
        }
        Some(NodeEnum::List(l)) => l.items.iter().all(|a| row_free(a, depth + 1)),
        Some(NodeEnum::AArrayExpr(a)) => a.elements.iter().all(|x| row_free(x, depth + 1)),
        Some(NodeEnum::CoalesceExpr(c)) => c.args.iter().all(|a| row_free(a, depth + 1)),
        Some(NodeEnum::SqlvalueFunction(_)) => true,
        // Column references, subqueries and everything not modelled.
        _ => false,
    }
}

/// The value a node stands for.
pub(crate) fn fact_val(n: &Node) -> FactVal {
    use protobuf::a_const::Val;
    match n.node.as_ref() {
        Some(NodeEnum::AConst(c)) => {
            if c.isnull {
                return FactVal::Null;
            }
            match c.val.as_ref() {
                None => FactVal::Null,
                Some(Val::Ival(i)) => FactVal::Int(i64::from(i.ival)),
                Some(Val::Fval(f)) => number(&f.fval),
                Some(Val::Boolval(b)) => FactVal::Bool(b.boolval),
                Some(Val::Sval(s)) => FactVal::Str(s.sval.clone()),
                Some(Val::Bsval(_)) => FactVal::Expr,
            }
        }
        Some(NodeEnum::ParamRef(p)) => FactVal::Param(u32::try_from(p.number).unwrap_or(0)),
        Some(NodeEnum::TypeCast(tc)) => {
            let Some(arg) = tc.arg.as_deref() else {
                return FactVal::Expr;
            };
            match fact_val(arg) {
                // `$1::uuid` is still the parameter; `'2026-01-01'::date` and
                // `DATE '…'` keep the text (a bound reads it as a timestamp).
                p @ FactVal::Param(_) => p,
                s @ FactVal::Str(_) if is_date_type(tc.type_name.as_ref()) => s,
                _ => FactVal::Expr,
            }
        }
        // libpg_query folds `-<number>`; this covers `- <expr>` forms.
        Some(NodeEnum::AExpr(e)) if e.lexpr.is_none() && strings(&e.name) == ["-"] => {
            match e.rexpr.as_deref().map(fact_val) {
                Some(FactVal::Int(i)) => i.checked_neg().map_or(FactVal::Expr, FactVal::Int),
                Some(FactVal::Double(d)) => FactVal::Double(-d),
                _ => FactVal::Expr,
            }
        }
        _ => FactVal::Expr,
    }
}

fn is_date_type(t: Option<&protobuf::TypeName>) -> bool {
    t.is_some_and(|t| {
        strings(&t.names).last().is_some_and(|n| {
            matches!(
                n.as_str(),
                "date" | "timestamp" | "timestamptz" | "time" | "timetz"
            )
        })
    })
}

pub(crate) fn number(text: &str) -> FactVal {
    if let Ok(i) = text.parse::<i64>() {
        return FactVal::Int(i);
    }
    match text.parse::<f64>() {
        Ok(d) if d.is_finite() => FactVal::Double(d),
        _ => FactVal::Expr,
    }
}

fn limit(n: Option<&Node>) -> LimitFact {
    let Some(n) = n else {
        return LimitFact::Absent;
    };
    match fact_val(n) {
        FactVal::Int(i) => LimitFact::Int(i),
        // `LIMIT ALL` / `LIMIT NULL`: no limit.
        FactVal::Null => LimitFact::Absent,
        FactVal::Param(_) => LimitFact::Unknown("the LIMIT is a parameter, bound at execution"),
        _ => LimitFact::Unknown("the LIMIT is not a literal"),
    }
}

/// Function names, from libpg_query's own scanner: every identifier or
/// non-reserved keyword written right before `(` (a superset: type
/// modifiers are dropped, `row(` and the like are kept). Qualified names are
/// listed both as written (`pg_catalog.pg_sleep`) and by their last part.
fn functions(text: &str) -> Result<Vec<String>, &'static str> {
    use protobuf::{KeywordKind, Token};
    let scan = pg_query::scan(text).map_err(|_| "the statement text did not scan")?;
    let toks = &scan.tokens;
    let tok_text = |i: usize| -> Option<&str> {
        let t = toks.get(i)?;
        text.get(usize::try_from(t.start).ok()?..usize::try_from(t.end).ok()?)
    };
    let mut out = Vec::new();
    for i in 0..toks.len() {
        let t = &toks[i];
        let is_name = t.token == Token::Ident as i32
            || (t.keyword_kind != KeywordKind::NoKeyword as i32
                && t.keyword_kind != KeywordKind::ReservedKeyword as i32);
        if !is_name || toks.get(i + 1).map(|n| n.token) != Some(Token::Ascii40 as i32) {
            continue;
        }
        let Some(raw) = tok_text(i) else { continue };
        let name = unquote(raw);
        if super::is_type_modifier(&name) || NOT_CALLS.contains(&name.as_str()) {
            continue;
        }
        // A name before `(` that is not a call: a table with its column list
        // (`INSERT INTO t (…)`, `REFERENCES t (…)`, `ON t (…)`), an alias
        // with column names (`AS x(a, b)`), a type (`AS varchar(10)`), a
        // CTE (`WITH x(a) AS`). Skipping one of these can only drop a name
        // that is not a function.
        let mut prev = i;
        // Step over a qualification: `schema . name`.
        if prev >= 2 && toks[prev - 1].token == Token::Ascii46 as i32 {
            prev -= 2;
        }
        let before = prev
            .checked_sub(1)
            .and_then(tok_text)
            .map(str::to_ascii_lowercase);
        if before
            .as_deref()
            .is_some_and(|b| NOT_CALL_AFTER.contains(&b))
        {
            continue;
        }
        // `schema.fn(`
        if i >= 2 && toks[i - 1].token == Token::Ascii46 as i32 {
            if let Some(schema) = tok_text(i - 2) {
                out.push(format!("{}.{name}", unquote(schema)));
            }
        }
        out.push(name);
    }
    Ok(out)
}

/// Keywords and names written before `(` that are syntax, not calls.
const NOT_CALLS: &[&str] = &[
    "values",
    "conflict",
    "row",
    "exists",
    "in",
    "any",
    "all",
    "some",
    "array",
    "over",
    "filter",
    "within",
    "using",
    "key",
    "references",
    "check",
    "unique",
    "primary",
    "on",
    "as",
    "and",
    "or",
    "not",
    "into",
    "from",
    "where",
    "select",
    "with",
    "partition",
];

/// Tokens after which a name followed by `(` is not a call.
/// Only tokens after which no call can follow (`JOIN f(…)` and `ON f(…)`
/// can be calls, so they are not here).
const NOT_CALL_AFTER: &[&str] = &[
    "into",
    "table",
    "references",
    "as",
    "view",
    "index",
    "with",
    "conflict",
];

fn unquote(raw: &str) -> String {
    match raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => inner.replace("\"\"", "\""),
        None => raw.to_ascii_lowercase(),
    }
}
