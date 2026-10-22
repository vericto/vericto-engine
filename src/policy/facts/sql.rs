// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The sqlparser front end of the policy facts (MySQL, SQL Server, Oracle,
//! Snowflake, SQLite): one [`Shape`] per top-level statement.

use std::ops::ControlFlow;

use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, Expr, FromTable, LimitClause, ObjectName, ObjectType,
    OnConflictAction, OnInsert, Query, SetExpr, Statement, TableFactor, TableObject,
    TableWithJoins, TopQuantity, UnaryOperator, UpdateTableFromKind, Value, ValueWithSpan, Visit,
    Visitor,
};

use super::{Assign, ColRef, FactVal, LimitFact, Name, Pred, ScopeItem, Shape};
use crate::parser::{Dialect, WherePresence};
use crate::sensitive::{Ref, name_parts};

type Refs = Option<Result<Vec<Ref>, String>>;

pub(crate) fn shapes(
    statements: &[Statement],
    dialect: Dialect,
    want: super::Want,
) -> Vec<(Shape, Refs)> {
    statements
        .iter()
        .map(|s| statement(s, dialect, want))
        .collect()
}

fn walk(s: &Statement, dialect: Dialect) -> Refs {
    Some(crate::access::refs_sql(s, dialect))
}

fn statement(s: &Statement, dialect: Dialect, want: super::Want) -> (Shape, Refs) {
    if let Statement::Explain {
        statement: inner, ..
    } = s
    {
        return statement(inner, dialect, want);
    }
    let mut shape = shape_of(s, dialect);
    shape.functions = if want.functions {
        Ok(functions(s))
    } else {
        Err("not extracted")
    };
    let refs = if !want.refs {
        None
    } else if shape.refs_from_walk {
        match s {
            Statement::CreateTable(ct) => ct
                .query
                .as_ref()
                .and_then(|q| walk(&Statement::Query(q.clone()), dialect)),
            Statement::CreateView(cv) => walk(&Statement::Query(cv.query.clone()), dialect),
            Statement::Query(q) if select_into(q) => {
                let mut q = q.clone();
                if let SetExpr::Select(sel) = q.body.as_mut() {
                    sel.into = None;
                }
                walk(&Statement::Query(q), dialect)
            }
            other => walk(other, dialect),
        }
    } else {
        None
    };
    (shape, refs)
}

fn name(n: &ObjectName) -> Name {
    Name::new(name_parts(n).into_iter().map(str::to_string).collect())
}

fn select_into(q: &Query) -> bool {
    matches!(q.body.as_ref(), SetExpr::Select(s) if s.into.is_some())
}

fn nested_writes(q: Option<&sqlparser::ast::With>) -> bool {
    q.is_some_and(|w| {
        w.cte_tables.iter().any(|c| {
            matches!(
                c.query.body.as_ref(),
                SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Delete(_) | SetExpr::Merge(_)
            )
        })
    })
}

fn walked(op: &'static str, kind: &str) -> Shape {
    let mut sh = Shape::new(op, kind);
    sh.refs_from_walk = true;
    sh
}

fn shape_of(s: &Statement, dialect: Dialect) -> Shape {
    let sqlite = dialect == Dialect::Sqlite;
    match s {
        Statement::Query(q) if select_into(q) => {
            let mut sh = Shape::new("ddl", "SelectStmt");
            if let SetExpr::Select(sel) = q.body.as_ref() {
                // `SELECT … INTO new_table` (a table name) is DDL; INTO a
                // variable or anything else: the targets are not known.
                sh.ddl_targets = sel.into.as_ref().and_then(|i| {
                    i.targets
                        .iter()
                        .map(|t| match t {
                            Expr::Identifier(id) if !id.value.starts_with('@') => {
                                Some(Name::new(vec![id.value.clone()]))
                            }
                            Expr::CompoundIdentifier(parts) => {
                                Some(Name::new(parts.iter().map(|p| p.value.clone()).collect()))
                            }
                            _ => None,
                        })
                        .collect::<Option<Vec<_>>>()
                });
            }
            sh.refs_from_walk = sh.ddl_targets.is_some();
            sh
        }
        Statement::Query(q) => {
            let mut sh = walked("select", "SelectStmt");
            sh.nested_writes = nested_writes(q.with.as_ref());
            sh.limit = query_limit(q);
            if let SetExpr::Select(sel) = q.body.as_ref() {
                for t in &sel.from {
                    scope_twj(t, &mut sh.scope);
                }
                set_where(&mut sh, sel.selection.as_ref(), sqlite);
            }
            sh
        }
        Statement::Insert(ins) => {
            let mut sh = walked("insert", "InsertStmt");
            if let TableObject::TableName(n) = &ins.table {
                sh.target = Some(name(n));
            }
            sh.has_returning =
                ins.returning.as_ref().is_some_and(|r| !r.is_empty()) || ins.output.is_some();
            let columns: Vec<String> = ins
                .columns
                .iter()
                .filter_map(|c| name_parts(c).last().map(|s| s.to_string()))
                .collect();
            sh.assign = if !ins.assignments.is_empty() {
                // MySQL `INSERT INTO t SET a = 1`.
                assignments(&ins.assignments)
            } else {
                match ins.source.as_deref() {
                    Some(q) => {
                        sh.nested_writes = nested_writes(q.with.as_ref());
                        match q.body.as_ref() {
                            SetExpr::Values(v) => {
                                sh.insert_rows = Some(v.rows.len() as i64);
                                Assign::Rows {
                                    columns: (!columns.is_empty()).then_some(columns),
                                    rows: v
                                        .rows
                                        .iter()
                                        .map(|r| r.iter().map(fact_val).collect())
                                        .collect(),
                                }
                            }
                            _ => Assign::Unknown("INSERT … SELECT: the values come from a query"),
                        }
                    }
                    None => Assign::Unknown(
                        "INSERT … DEFAULT VALUES: the values are the column defaults",
                    ),
                }
            };
            match &ins.on {
                Some(OnInsert::DuplicateKeyUpdate(a)) => upsert(&mut sh, a, "values"),
                Some(OnInsert::OnConflict(oc)) => {
                    if let OnConflictAction::DoUpdate(du) = &oc.action {
                        upsert(&mut sh, &du.assignments, "excluded");
                    }
                }
                _ => {}
            }
            sh
        }
        Statement::Update(u) => {
            let mut sh = walked("update", "UpdateStmt");
            sh.has_returning =
                u.returning.as_ref().is_some_and(|r| !r.is_empty()) || u.output.is_some();
            if let TableFactor::Table { name: n, .. } = &u.table.relation {
                sh.target = Some(name(n));
            }
            scope_twj(&u.table, &mut sh.scope);
            match &u.from {
                Some(UpdateTableFromKind::BeforeSet(t) | UpdateTableFromKind::AfterSet(t)) => {
                    for x in t {
                        scope_twj(x, &mut sh.scope);
                    }
                }
                None => {}
            }
            sh.assign = assignments(&u.assignments);
            set_where(&mut sh, u.selection.as_ref(), sqlite);
            sh
        }
        Statement::Delete(d) => {
            let mut sh = walked("delete", "DeleteStmt");
            sh.has_returning =
                d.returning.as_ref().is_some_and(|r| !r.is_empty()) || d.output.is_some();
            let from = match &d.from {
                FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
            };
            sh.target = d.tables.first().map(name).or_else(|| {
                from.first().and_then(|t| match &t.relation {
                    TableFactor::Table { name: n, .. } => Some(name(n)),
                    _ => None,
                })
            });
            for t in from {
                scope_twj(t, &mut sh.scope);
            }
            for t in d.using.iter().flatten() {
                scope_twj(t, &mut sh.scope);
            }
            set_where(&mut sh, d.selection.as_ref(), sqlite);
            sh
        }
        Statement::Merge(m) => {
            let mut sh = walked("merge", "MergeStmt");
            if let TableFactor::Table { name: n, .. } = &m.table {
                sh.target = Some(name(n));
            }
            sh.assign = Assign::Unknown("MERGE: the values depend on the matched rows");
            sh
        }
        Statement::Copy { .. } => {
            let mut sh = walked("copy", "CopyStmt");
            sh.assign = Assign::Unknown("COPY: the rows come from outside the statement");
            sh
        }
        Statement::Call(_) => walked("call", "CallStmt"),
        Statement::Set(_) | Statement::Use(_) => walked("set", "VariableSetStmt"),
        Statement::ShowVariable { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowStatus { .. } => walked("set", "VariableShowStmt"),
        Statement::StartTransaction { statements, .. } if statements.is_empty() => {
            walked("other", "TransactionStmt")
        }
        Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. } => walked("other", "TransactionStmt"),
        Statement::Declare { .. } => walked("select", "DeclareCursorStmt"),
        Statement::Drop {
            object_type, names, ..
        } => {
            let mut sh = Shape::new("ddl", "DropStmt");
            if matches!(
                object_type,
                ObjectType::Table | ObjectType::View | ObjectType::MaterializedView
            ) {
                sh.ddl_targets = Some(names.iter().map(name).collect());
            }
            sh
        }
        Statement::Truncate(t) => {
            let mut sh = Shape::new("ddl", "TruncateStmt");
            sh.ddl_targets = Some(t.table_names.iter().map(|x| name(&x.name)).collect());
            sh
        }
        Statement::AlterTable(a) => {
            let mut sh = Shape::new("ddl", "AlterTableStmt");
            sh.ddl_targets = Some(vec![name(&a.name)]);
            sh
        }
        Statement::CreateIndex(ci) => {
            let mut sh = Shape::new("ddl", "IndexStmt");
            sh.ddl_targets = Some(vec![name(&ci.table_name)]);
            sh
        }
        Statement::CreateTable(ct) => {
            let mut sh = Shape::new("ddl", "CreateStmt");
            sh.ddl_targets = Some(vec![name(&ct.name)]);
            sh.refs_from_walk = ct.query.is_some();
            if ct.query.is_none() {
                // No query to walk: the target is the only table.
                sh.refs_from_walk = false;
            }
            sh
        }
        Statement::CreateView(cv) => {
            let mut sh = Shape::new("ddl", "ViewStmt");
            sh.ddl_targets = Some(vec![name(&cv.name)]);
            sh.refs_from_walk = true;
            sh
        }
        other => Shape::new("ddl", statement_kind(other)),
    }
}

fn statement_kind(s: &Statement) -> String {
    let debug = format!("{s:?}");
    debug
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or("Statement")
        .to_string()
}

fn assignments(a: &[sqlparser::ast::Assignment]) -> Assign {
    let mut pairs = Vec::new();
    for x in a {
        match &x.target {
            AssignmentTarget::ColumnName(n) => {
                if let Some(c) = name_parts(n).last() {
                    pairs.push((c.to_string(), fact_val(&x.value)));
                }
            }
            AssignmentTarget::Tuple(_) => {
                return Assign::Unknown("a tuple assignment `SET (a, b) = …`");
            }
        }
    }
    Assign::Set(pairs)
}

/// Upsert assignments; `col = VALUES(col)` (MySQL) and `col = EXCLUDED.col`
/// are the inserted value and are left out.
fn upsert(sh: &mut Shape, a: &[sqlparser::ast::Assignment], same_kw: &str) {
    for x in a {
        let AssignmentTarget::ColumnName(n) = &x.target else {
            sh.upsert.push(("*".into(), FactVal::Expr));
            continue;
        };
        let Some(col) = name_parts(n).last().map(|s| s.to_string()) else {
            continue;
        };
        let same = match unwrap(&x.value) {
            Expr::CompoundIdentifier(parts) if same_kw == "excluded" => {
                parts.len() == 2
                    && parts[0].value.eq_ignore_ascii_case("excluded")
                    && parts[1].value.eq_ignore_ascii_case(&col)
            }
            Expr::Function(f) if same_kw == "values" => {
                name_parts(&f.name)
                    .last()
                    .is_some_and(|n| n.eq_ignore_ascii_case("values"))
                    && f.args
                        .to_string()
                        .trim_matches(|c| c == '(' || c == ')')
                        .trim()
                        .trim_matches('`')
                        .eq_ignore_ascii_case(&col)
            }
            _ => false,
        };
        if !same {
            sh.upsert.push((col, fact_val(&x.value)));
        }
    }
}

fn scope_twj(t: &TableWithJoins, out: &mut Vec<ScopeItem>) {
    scope_tf(&t.relation, out);
    for j in &t.joins {
        scope_tf(&j.relation, out);
    }
}

fn scope_tf(tf: &TableFactor, out: &mut Vec<ScopeItem>) {
    match tf {
        TableFactor::Table {
            name: n,
            alias,
            args: None,
            ..
        } => out.push(ScopeItem {
            alias: alias.as_ref().map(|a| a.name.value.clone()),
            table: Some(name(n)),
        }),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => scope_twj(table_with_joins, out),
        other => out.push(ScopeItem {
            alias: table_factor_alias(other),
            table: None,
        }),
    }
}

fn table_factor_alias(tf: &TableFactor) -> Option<String> {
    match tf {
        TableFactor::Table { alias, .. }
        | TableFactor::Derived { alias, .. }
        | TableFactor::TableFunction { alias, .. }
        | TableFactor::Function { alias, .. }
        | TableFactor::UNNEST { alias, .. } => alias.as_ref().map(|a| a.name.value.clone()),
        _ => None,
    }
}

fn set_where(sh: &mut Shape, w: Option<&Expr>, sqlite: bool) {
    let Some(w) = w else { return };
    sh.where_always_true =
        crate::parser::walk::where_presence(Some(w), sqlite) == WherePresence::AlwaysTrue;
    sh.where_pred = Some(pred(w, 0));
}

const MAX_PRED_DEPTH: usize = 64;

fn unwrap(e: &Expr) -> &Expr {
    match e {
        Expr::Nested(inner) => unwrap(inner),
        other => other,
    }
}

fn pred(e: &Expr, depth: usize) -> Pred {
    if depth > MAX_PRED_DEPTH {
        return Pred::Other;
    }
    match unwrap(e) {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            let mut items = Vec::new();
            for side in [left, right] {
                match pred(side, depth + 1) {
                    Pred::And(v) => items.extend(v),
                    p => items.push(p),
                }
            }
            Pred::And(items)
        }
        Expr::BinaryOp { left, op, right } => {
            let (col, val, col_left) = match (column(left), column(right)) {
                (Some(c), None) => match value(right) {
                    Some(v) => (c, v, true),
                    None => return Pred::Other,
                },
                (None, Some(c)) => match value(left) {
                    Some(v) => (c, v, false),
                    None => return Pred::Other,
                },
                _ => return Pred::Other,
            };
            match op {
                BinaryOperator::Eq => Pred::Eq(col, val),
                BinaryOperator::Gt | BinaryOperator::GtEq => Pred::Bound {
                    col,
                    lower: col_left,
                    val,
                },
                BinaryOperator::Lt | BinaryOperator::LtEq => Pred::Bound {
                    col,
                    lower: !col_left,
                    val,
                },
                _ => Pred::Other,
            }
        }
        Expr::InList {
            expr,
            list,
            negated: false,
        } => {
            let Some(col) = column(expr) else {
                return Pred::Other;
            };
            let mut vals = Vec::new();
            for item in list {
                match value(item) {
                    Some(v) => vals.push(v),
                    None => return Pred::Other,
                }
            }
            Pred::In(col, vals)
        }
        Expr::Between {
            expr,
            negated: false,
            low,
            high,
        } => match (column(expr), value(low), value(high)) {
            (Some(c), Some(lo), Some(hi)) => Pred::Between(c, lo, hi),
            _ => Pred::Other,
        },
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match (column(left), value(right)) {
            (Some(c), Some(_)) => Pred::In(c, vec![FactVal::Expr]),
            _ => Pred::Other,
        },
        _ => Pred::Other,
    }
}

fn column(e: &Expr) -> Option<ColRef> {
    match unwrap(e) {
        Expr::Identifier(i) => Some(ColRef {
            qualifier: Vec::new(),
            column: i.value.clone(),
        }),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            let mut p: Vec<String> = parts.iter().map(|i| i.value.clone()).collect();
            let column = p.pop()?;
            Some(ColRef {
                qualifier: p,
                column,
            })
        }
        Expr::Cast { expr, .. } => column(expr),
        _ => None,
    }
}

/// The value side of a pin (see the Postgres front end).
fn value(e: &Expr) -> Option<FactVal> {
    if !row_free(e, 0) {
        return None;
    }
    Some(fact_val(e))
}

fn row_free(e: &Expr, depth: usize) -> bool {
    if depth > MAX_PRED_DEPTH {
        return false;
    }
    match unwrap(e) {
        Expr::Value(_) | Expr::TypedString(_) => true,
        Expr::UnaryOp { expr, .. } => row_free(expr, depth + 1),
        Expr::Cast { expr, .. } => row_free(expr, depth + 1),
        Expr::BinaryOp { left, right, .. } => {
            row_free(left, depth + 1) && row_free(right, depth + 1)
        }
        Expr::Function(f) => {
            if f.over.is_some() || f.filter.is_some() {
                return false;
            }
            // Arguments: only plain expressions, all row-free.
            let mut ok = true;
            let _ = sqlparser::ast::visit_expressions(&f.args, |x: &Expr| {
                if matches!(
                    x,
                    Expr::Identifier(_)
                        | Expr::CompoundIdentifier(_)
                        | Expr::Subquery(_)
                        | Expr::Exists { .. }
                        | Expr::InSubquery { .. }
                ) {
                    ok = false;
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });
            ok
        }
        _ => false,
    }
}

/// The value an expression stands for.
pub(crate) fn fact_val(e: &Expr) -> FactVal {
    match unwrap(e) {
        Expr::Value(ValueWithSpan { value, .. }) => match value {
            Value::Number(n, _) => super::pg::number(n),
            Value::SingleQuotedString(s) | Value::NationalStringLiteral(s) => {
                FactVal::Str(s.clone())
            }
            Value::Boolean(b) => FactVal::Bool(*b),
            Value::Null => FactVal::Null,
            Value::Placeholder(p) => FactVal::Param(placeholder_index(p)),
            // `"x"` (MySQL: a string, or a column under ANSI_QUOTES) and the
            // other literal forms: not known for certain.
            _ => FactVal::Expr,
        },
        Expr::UnaryOp {
            op: UnaryOperator::Minus,
            expr,
        } => match fact_val(expr) {
            FactVal::Int(i) => i.checked_neg().map_or(FactVal::Expr, FactVal::Int),
            FactVal::Double(d) => FactVal::Double(-d),
            _ => FactVal::Expr,
        },
        Expr::Cast {
            expr, data_type, ..
        } => match fact_val(expr) {
            p @ FactVal::Param(_) => p,
            s @ FactVal::Str(_) if is_date_type(data_type) => s,
            _ => FactVal::Expr,
        },
        Expr::TypedString(ts) if is_date_type(&ts.data_type) => match &ts.value.value {
            Value::SingleQuotedString(s) => FactVal::Str(s.clone()),
            _ => FactVal::Expr,
        },
        _ => FactVal::Expr,
    }
}

fn is_date_type(t: &sqlparser::ast::DataType) -> bool {
    use sqlparser::ast::DataType as D;
    matches!(
        t,
        D::Date | D::Timestamp(..) | D::Datetime(..) | D::Time(..) | D::Datetime64(..)
    )
}

/// `$2` → 2, `?` → 0 (positional, counted by the host), `:name`/`@p` → 0.
fn placeholder_index(p: &str) -> u32 {
    p.strip_prefix('$')
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn literal_limit(e: &Expr) -> LimitFact {
    match fact_val(e) {
        FactVal::Int(i) => LimitFact::Int(i),
        FactVal::Null => LimitFact::Absent,
        FactVal::Param(_) => LimitFact::Unknown("the LIMIT is a parameter, bound at execution"),
        _ => LimitFact::Unknown("the LIMIT is not a literal"),
    }
}

fn query_limit(q: &Query) -> LimitFact {
    match &q.limit_clause {
        Some(LimitClause::LimitOffset { limit: Some(l), .. }) => return literal_limit(l),
        Some(LimitClause::OffsetCommaLimit { limit, .. }) => return literal_limit(limit),
        _ => {}
    }
    if let Some(f) = &q.fetch {
        if f.percent {
            return LimitFact::Unknown("FETCH … PERCENT is not a row count");
        }
        return match &f.quantity {
            Some(e) => literal_limit(e),
            None => LimitFact::Int(1),
        };
    }
    if let SetExpr::Select(sel) = q.body.as_ref() {
        if let Some(top) = &sel.top {
            if top.percent {
                return LimitFact::Unknown("TOP … PERCENT is not a row count");
            }
            return match &top.quantity {
                Some(TopQuantity::Constant(n)) => {
                    i64::try_from(*n).map_or(LimitFact::Unknown("TOP out of range"), LimitFact::Int)
                }
                Some(TopQuantity::Expr(e)) => literal_limit(e),
                None => LimitFact::Unknown("TOP without a quantity"),
            };
        }
    }
    LimitFact::Absent
}

/// Every function called anywhere in the statement (the visitor walks every
/// expression), table functions and `CALL` included. Qualified names are
/// listed as written and by their last part.
fn functions(s: &Statement) -> Vec<String> {
    struct F(Vec<String>);
    impl F {
        fn push(&mut self, n: &ObjectName) {
            let parts = name_parts(n);
            if let Some(last) = parts.last() {
                if parts.len() > 1 {
                    self.0.push(parts.join("."));
                }
                self.0.push(last.to_string());
            }
        }
    }
    impl Visitor for F {
        type Break = ();
        fn pre_visit_expr(&mut self, e: &Expr) -> ControlFlow<()> {
            if let Expr::Function(f) = e {
                self.push(&f.name);
            }
            ControlFlow::Continue(())
        }
        fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<()> {
            match tf {
                TableFactor::Table {
                    name,
                    args: Some(_),
                    ..
                } => self.push(name),
                TableFactor::Function { name, .. } => self.push(name),
                _ => {}
            }
            ControlFlow::Continue(())
        }
        fn pre_visit_statement(&mut self, s: &Statement) -> ControlFlow<()> {
            if let Statement::Call(f) = s {
                self.push(&f.name);
            }
            ControlFlow::Continue(())
        }
    }
    let mut f = F(Vec::new());
    let _ = s.visit(&mut f);
    f.0
}
