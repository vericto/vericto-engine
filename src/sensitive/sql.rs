//! Sensitive-column derivation over the `sqlparser-rs` AST (MySQL, Oracle,
//! MS SQL). Same model as [`super::pg`] — same scopes, same sinks, same
//! conservative rules — with no rewrite: `mask` is not applied on these
//! dialects in this phase, and the verdict turns it into a block.

use sqlparser::ast::{
    Assignment, AssignmentTarget, Cte, Expr, FromTable, FunctionArg, FunctionArgExpr,
    FunctionArguments, Ident, MergeAction, MergeInsertKind, ObjectName, Query, SelectItem, SetExpr,
    Statement, TableAlias, TableFactor, TableWithJoins,
};

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::sensitive::{
    Item, Lineage, OutCol, Scopes, Sink, Tags, Touches, ieq, indirect, merge, outcol_all,
    outcols_all, starred,
};

pub(crate) fn analyze(
    statements: &[Statement],
    tags: &Tags,
) -> Result<(Touches, super::pg::Rewrite)> {
    let mut w = Walker {
        tags,
        scopes: Scopes::default(),
        ctes: Vec::new(),
        touches: Touches::default(),
    };
    for s in statements {
        w.stmt(s, 0)?;
    }
    Ok((w.touches, None))
}

/// Never rewritten on these dialects.
const VISIBLE: Sink = Sink::Projected { rewrite: false };

struct Walker<'a, 't> {
    tags: &'a Tags<'t>,
    scopes: Scopes,
    ctes: Vec<Vec<(String, Vec<OutCol>)>>,
    touches: Touches,
}

fn too_deep(depth: usize) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        Err(ProxyError::AstTooDeep)
    } else {
        Ok(())
    }
}

/// `[db.]schema.table` → (schema, table).
fn split_name(name: &ObjectName) -> (Option<String>, String) {
    let parts = &name.0;
    let table = parts.last().map(|i| i.value.clone()).unwrap_or_default();
    let schema = if parts.len() >= 2 {
        Some(parts[parts.len() - 2].value.clone())
    } else {
        None
    };
    (schema, table)
}

fn rename(mut cols: Vec<OutCol>, alias: Option<&TableAlias>) -> Vec<OutCol> {
    let Some(a) = alias else { return cols };
    if a.columns.is_empty() || cols.iter().any(|c| !matches!(c, OutCol::Named { .. })) {
        return cols;
    }
    for (c, n) in cols.iter_mut().zip(&a.columns) {
        if let OutCol::Named { name, .. } = c {
            *name = n.value.clone();
        }
    }
    cols
}

impl Walker<'_, '_> {
    fn stmt(&mut self, s: &Statement, depth: usize) -> Result<()> {
        too_deep(depth)?;
        let d = depth + 1;
        match s {
            Statement::Query(q) => {
                self.query(q, Some(VISIBLE), d)?;
            }
            Statement::Insert(ins) => {
                let (schema, table) = split_name(&ins.table_name);
                let target = Item::Base {
                    refname: ins
                        .table_alias
                        .as_ref()
                        .map(|a| a.value.clone())
                        .unwrap_or_else(|| table.clone()),
                    schema,
                    table,
                };
                if let Some(src) = &ins.source {
                    let outs = self.query(src, None, d)?;
                    for (j, c) in outs.iter().enumerate() {
                        let mut lin = outcol_all(self.tags, c);
                        if let Some(dest) = ins.columns.get(j) {
                            for k in target.column(self.tags, &dest.value).keys() {
                                lin.remove(k);
                            }
                        }
                        self.touches.record(&lin, Sink::Copy);
                    }
                }
                if let Some(ret) = &ins.returning {
                    self.scopes.push();
                    self.scopes.add(target);
                    let r = self.projection(ret, Some(VISIBLE), d);
                    self.scopes.pop();
                    r?;
                }
            }
            Statement::Update {
                table,
                assignments,
                from,
                returning,
                ..
            } => {
                self.scopes.push();
                let r = (|| -> Result<()> {
                    let targets = self.table_with_joins(table, d)?;
                    let target = targets.first().cloned();
                    for it in targets {
                        self.scopes.add(it);
                    }
                    if let Some(f) = from {
                        for it in self.table_with_joins(f, d)? {
                            self.scopes.add(it);
                        }
                    }
                    self.assignments(assignments, target.as_ref(), d)?;
                    if let Some(ret) = returning {
                        self.projection(ret, Some(VISIBLE), d)?;
                    }
                    Ok(())
                })();
                self.scopes.pop();
                r?;
            }
            Statement::Delete(del) => {
                if let Some(ret) = &del.returning {
                    self.scopes.push();
                    let r = (|| -> Result<()> {
                        let from = match &del.from {
                            FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
                        };
                        for twj in from.iter().chain(del.using.iter().flatten()) {
                            for it in self.table_with_joins(twj, d)? {
                                self.scopes.add(it);
                            }
                        }
                        self.projection(ret, Some(VISIBLE), d)?;
                        Ok(())
                    })();
                    self.scopes.pop();
                    r?;
                }
            }
            Statement::CreateTable(ct) => {
                if let Some(q) = &ct.query {
                    self.query(q, Some(Sink::Copy), d)?;
                }
            }
            Statement::CreateView { query, .. } => {
                self.query(query, Some(Sink::Copy), d)?;
            }
            Statement::Directory { source, .. } => {
                self.query(source, Some(Sink::Copy), d)?;
            }
            Statement::Copy { source, to, .. } if *to => match source {
                sqlparser::ast::CopySource::Query(q) => {
                    self.query(q, Some(VISIBLE), d)?;
                }
                sqlparser::ast::CopySource::Table {
                    table_name,
                    columns,
                } => {
                    let (schema, table) = split_name(table_name);
                    let lin = if columns.is_empty() {
                        starred(self.tags.of_table(schema.as_deref(), &table))
                    } else {
                        let mut l = Lineage::new();
                        for c in columns {
                            merge(
                                &mut l,
                                self.tags.of_column(schema.as_deref(), &table, &c.value),
                            );
                        }
                        l
                    };
                    self.touches.record_fixed(&lin);
                }
            },
            Statement::Declare { stmts } => {
                for decl in stmts {
                    if let Some(q) = &decl.for_query {
                        self.query(q, Some(VISIBLE), d)?;
                    }
                }
            }
            Statement::Prepare { statement, .. } => self.stmt(statement, d)?,
            Statement::Explain { statement, .. } => {
                // A plan, not rows. Data copies inside still count.
                if let Statement::Query(q) = statement.as_ref() {
                    self.query(q, None, d)?;
                } else {
                    self.stmt(statement, d)?;
                }
            }
            Statement::Merge {
                table,
                source,
                clauses,
                ..
            } => {
                self.scopes.push();
                let r = (|| -> Result<()> {
                    let target = self.table_factor(table, d)?.into_iter().next();
                    if let Some(t) = target.clone() {
                        self.scopes.add(t);
                    }
                    for it in self.table_factor(source, d)? {
                        self.scopes.add(it);
                    }
                    for c in clauses {
                        match &c.action {
                            MergeAction::Update { assignments } => {
                                self.assignments(assignments, target.as_ref(), d)?
                            }
                            MergeAction::Insert(ins) => {
                                if let MergeInsertKind::Values(v) = &ins.kind {
                                    for row in &v.rows {
                                        for (j, e) in row.iter().enumerate() {
                                            let mut lin = self.expr(e, d)?;
                                            if let (Some(dest), Some(t)) =
                                                (ins.columns.get(j), target.as_ref())
                                            {
                                                for k in t.column(self.tags, &dest.value).keys() {
                                                    lin.remove(k);
                                                }
                                            }
                                            self.touches.record(&lin, Sink::Copy);
                                        }
                                    }
                                }
                            }
                            MergeAction::Delete => {}
                        }
                    }
                    Ok(())
                })();
                self.scopes.pop();
                r?;
            }
            _ => {}
        }
        Ok(())
    }

    fn assignments(
        &mut self,
        list: &[Assignment],
        target: Option<&Item>,
        depth: usize,
    ) -> Result<()> {
        for a in list {
            let mut lin = self.expr(&a.value, depth + 1)?;
            if let (AssignmentTarget::ColumnName(n), Some(t)) = (&a.target, target) {
                if let Some(col) = n.0.last() {
                    for k in t.column(self.tags, &col.value).keys() {
                        lin.remove(k);
                    }
                }
            }
            self.touches.record(&lin, Sink::Copy);
        }
        Ok(())
    }

    // ── queries ─────────────────────────────────────────────────────────────

    fn query(&mut self, q: &Query, sink: Option<Sink>, depth: usize) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let pushed = if let Some(with) = &q.with {
            self.ctes.push(Vec::new());
            for cte in &with.cte_tables {
                let cols = if with.recursive {
                    self.recursive_cte(cte, depth + 1)?
                } else {
                    self.cte_cols(cte, depth + 1)?
                };
                if let Some(level) = self.ctes.last_mut() {
                    level.push((cte.alias.name.value.clone(), cols));
                }
            }
            true
        } else {
            false
        };
        let out = self.set_expr(&q.body, sink, depth + 1);
        if pushed {
            self.ctes.pop();
        }
        out
    }

    fn cte_cols(&mut self, cte: &Cte, depth: usize) -> Result<Vec<OutCol>> {
        let cols = self.query(&cte.query, None, depth + 1)?;
        Ok(rename(cols, Some(&cte.alias)))
    }

    fn recursive_cte(&mut self, cte: &Cte, depth: usize) -> Result<Vec<OutCol>> {
        let name = cte.alias.name.value.clone();
        let mut cols: Vec<OutCol> = Vec::new();
        let mut last = Lineage::new();
        for _ in 0..8 {
            if let Some(level) = self.ctes.last_mut() {
                level.retain(|(n, _)| n != &name);
                level.push((name.clone(), cols.clone()));
            }
            cols = self.cte_cols(cte, depth)?;
            let now = outcols_all(self.tags, &cols);
            if now == last {
                break;
            }
            last = now;
        }
        if let Some(level) = self.ctes.last_mut() {
            level.retain(|(n, _)| n != &name);
        }
        Ok(cols)
    }

    /// CTE lookup. These dialects fold (or not) identifier case by server
    /// configuration, which the engine cannot see: an exact match is the CTE;
    /// a case-insensitive one may be the CTE OR the table, so both are kept.
    fn find_cte(&self, name: &str) -> Option<(bool, Vec<OutCol>)> {
        for level in self.ctes.iter().rev() {
            if let Some((_, cols)) = level.iter().rev().find(|(n, _)| n == name) {
                return Some((true, cols.clone()));
            }
            if let Some((_, cols)) = level.iter().rev().find(|(n, _)| ieq(n, name)) {
                return Some((false, cols.clone()));
            }
        }
        None
    }

    fn set_expr(
        &mut self,
        body: &SetExpr,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let d = depth + 1;
        match body {
            SetExpr::Select(sel) => {
                // `SELECT … INTO t` / `INTO OUTFILE`: a copy, not a read.
                let sink = if sel.into.is_some() {
                    Some(Sink::Copy)
                } else {
                    sink
                };
                self.scopes.push();
                let r = (|| -> Result<Vec<OutCol>> {
                    for twj in &sel.from {
                        for it in self.table_with_joins(twj, d)? {
                            self.scopes.add(it);
                        }
                    }
                    self.projection(&sel.projection, sink, d)
                })();
                self.scopes.pop();
                r
            }
            SetExpr::Query(q) => self.query(q, sink, d),
            SetExpr::SetOperation { left, right, .. } => {
                let l = self.set_expr(left, sink, d)?;
                let r = self.set_expr(right, sink, d)?;
                Ok(self.combine(l, r))
            }
            SetExpr::Values(v) => {
                let mut cols: Vec<Lineage> = Vec::new();
                for row in &v.rows {
                    for (j, e) in row.iter().enumerate() {
                        let lin = self.expr(e, d)?;
                        if let Some(sink) = sink {
                            self.touches.record(&lin, sink);
                        }
                        if cols.len() <= j {
                            cols.resize_with(j + 1, Lineage::new);
                        }
                        merge(&mut cols[j], lin);
                    }
                }
                Ok(cols
                    .into_iter()
                    .enumerate()
                    .map(|(j, lin)| OutCol::Named {
                        name: format!("column{}", j + 1),
                        lin,
                    })
                    .collect())
            }
            SetExpr::Insert(s) | SetExpr::Update(s) => {
                self.stmt(s, d)?;
                Ok(Vec::new())
            }
            SetExpr::Table(t) => {
                // `TABLE t` is `SELECT * FROM t`.
                let table = t.table_name.clone().unwrap_or_default();
                let lin = starred(self.tags.of_table(t.schema_name.as_deref(), &table));
                if let Some(sink) = sink {
                    self.touches.record(&lin, sink);
                }
                Ok(vec![OutCol::BaseStar {
                    schema: t.schema_name.clone(),
                    table,
                }])
            }
        }
    }

    fn combine(&self, l: Vec<OutCol>, r: Vec<OutCol>) -> Vec<OutCol> {
        let all_named = |v: &[OutCol]| v.iter().all(|c| matches!(c, OutCol::Named { .. }));
        if l.len() == r.len() && all_named(&l) && all_named(&r) {
            l.into_iter()
                .zip(r)
                .map(|(a, b)| match (a, b) {
                    (OutCol::Named { name, mut lin }, OutCol::Named { lin: rl, .. }) => {
                        merge(&mut lin, rl);
                        OutCol::Named { name, lin }
                    }
                    (a, _) => a,
                })
                .collect()
        } else {
            let mut lin = outcols_all(self.tags, &l);
            merge(&mut lin, outcols_all(self.tags, &r));
            vec![OutCol::OpaqueStar { lin }]
        }
    }

    fn projection(
        &mut self,
        items: &[SelectItem],
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        let mut outs = Vec::new();
        for item in items {
            let (lin, cols) = match item {
                SelectItem::Wildcard(_) => self.scopes.star(self.tags, &[]),
                SelectItem::QualifiedWildcard(name, _) => {
                    let q: Vec<&str> = name.0.iter().map(|i| i.value.as_str()).collect();
                    self.scopes.star(self.tags, &q)
                }
                SelectItem::UnnamedExpr(e) => {
                    let lin = self.expr(e, depth + 1)?;
                    let name = figure(e);
                    (lin.clone(), vec![OutCol::Named { name, lin }])
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    let lin = self.expr(expr, depth + 1)?;
                    (
                        lin.clone(),
                        vec![OutCol::Named {
                            name: alias.value.clone(),
                            lin,
                        }],
                    )
                }
            };
            if let Some(sink) = sink {
                self.touches.record(&lin, sink);
            }
            outs.extend(cols);
        }
        Ok(outs)
    }

    // ── FROM ────────────────────────────────────────────────────────────────

    fn table_with_joins(&mut self, twj: &TableWithJoins, depth: usize) -> Result<Vec<Item>> {
        too_deep(depth)?;
        let mut items = self.table_factor(&twj.relation, depth + 1)?;
        for j in &twj.joins {
            // LATERAL on the right side may reference the left.
            let mark = self.scopes.levels.last().map_or(0, Vec::len);
            for it in &items {
                self.scopes.add(it.clone());
            }
            let right = self.table_factor(&j.relation, depth + 1);
            if let Some(level) = self.scopes.levels.last_mut() {
                level.truncate(mark);
            }
            items.extend(right?);
        }
        Ok(items)
    }

    fn table_factor(&mut self, tf: &TableFactor, depth: usize) -> Result<Vec<Item>> {
        too_deep(depth)?;
        let d = depth + 1;
        let alias_name = |a: &Option<TableAlias>| a.as_ref().map(|a| a.name.value.clone());
        Ok(match tf {
            TableFactor::Table {
                name, alias, args, ..
            } => {
                let (schema, table) = split_name(name);
                let refname = alias_name(alias).unwrap_or_else(|| table.clone());
                if let Some(args) = args {
                    // A table-valued function call.
                    let mut lin = Lineage::new();
                    for a in &args.args {
                        merge(&mut lin, self.function_arg(a, d)?);
                    }
                    return Ok(vec![Item::Opaque {
                        refname: Some(refname),
                        lin: indirect(lin),
                    }]);
                }
                let base = Item::Base {
                    refname: refname.clone(),
                    schema: schema.clone(),
                    table: table.clone(),
                };
                if schema.is_none() {
                    if let Some((exact, cols)) = self.find_cte(&table) {
                        let cte = Item::Derived {
                            refname: Some(refname.clone()),
                            cols: rename(cols, alias.as_ref()),
                        };
                        return Ok(vec![if exact {
                            cte
                        } else {
                            Item::Join {
                                refname: Some(refname),
                                items: vec![cte, base],
                            }
                        }]);
                    }
                }
                if alias.as_ref().is_some_and(|a| !a.columns.is_empty()) {
                    return Ok(vec![Item::Opaque {
                        refname: Some(refname),
                        lin: indirect(self.tags.of_table(schema.as_deref(), &table)),
                    }]);
                }
                vec![base]
            }
            TableFactor::Derived {
                subquery, alias, ..
            } => {
                let cols = self.query(subquery, None, d)?;
                vec![Item::Derived {
                    refname: alias_name(alias),
                    cols: rename(cols, alias.as_ref()),
                }]
            }
            TableFactor::TableFunction { expr, alias } => vec![Item::Opaque {
                refname: alias_name(alias),
                lin: indirect(self.expr(expr, d)?),
            }],
            TableFactor::Function { args, alias, .. } => {
                let mut lin = Lineage::new();
                for a in args {
                    merge(&mut lin, self.function_arg(a, d)?);
                }
                vec![Item::Opaque {
                    refname: alias_name(alias),
                    lin: indirect(lin),
                }]
            }
            TableFactor::UNNEST {
                alias, array_exprs, ..
            } => {
                let mut lin = Lineage::new();
                for e in array_exprs {
                    merge(&mut lin, self.expr(e, d)?);
                }
                vec![Item::Opaque {
                    refname: alias_name(alias),
                    lin: indirect(lin),
                }]
            }
            TableFactor::JsonTable {
                json_expr, alias, ..
            } => vec![Item::Opaque {
                refname: alias_name(alias),
                lin: indirect(self.expr(json_expr, d)?),
            }],
            TableFactor::NestedJoin {
                table_with_joins,
                alias,
            } => vec![Item::Join {
                refname: alias_name(alias),
                items: self.table_with_joins(table_with_joins, d)?,
            }],
            TableFactor::Pivot { table, alias, .. }
            | TableFactor::Unpivot { table, alias, .. }
            | TableFactor::MatchRecognize { table, alias, .. } => {
                // Reshapes its input: every output may derive from any input.
                let inner = self.table_factor(table, d)?;
                let mut lin = Lineage::new();
                for it in &inner {
                    merge(&mut lin, it.star_all(self.tags));
                }
                vec![Item::Opaque {
                    refname: alias_name(alias),
                    lin: indirect(lin),
                }]
            }
        })
    }

    // ── expressions ─────────────────────────────────────────────────────────

    fn function_arg(&mut self, a: &FunctionArg, depth: usize) -> Result<Lineage> {
        let arg = match a {
            FunctionArg::Named { arg, .. } | FunctionArg::Unnamed(arg) => arg,
        };
        Ok(match arg {
            FunctionArgExpr::Expr(e) => self.expr(e, depth)?,
            FunctionArgExpr::Wildcard => {
                // `COUNT(*)` counts rows; `JSON_OBJECT(*)`-style uses do not
                // exist in these dialects, but be conservative for any other
                // function: a bare `*` argument reads the whole row.
                Lineage::new()
            }
            FunctionArgExpr::QualifiedWildcard(name) => {
                let q: Vec<&str> = name.0.iter().map(|i| i.value.as_str()).collect();
                self.scopes.star(self.tags, &q).0
            }
        })
    }

    fn exprs(&mut self, list: &[Expr], depth: usize) -> Result<Lineage> {
        let mut out = Lineage::new();
        for e in list {
            merge(&mut out, self.expr(e, depth)?);
        }
        Ok(out)
    }

    fn query_value(&mut self, q: &Query, depth: usize) -> Result<Lineage> {
        let cols = self.query(q, None, depth)?;
        Ok(outcols_all(self.tags, &cols))
    }

    fn expr(&mut self, e: &Expr, depth: usize) -> Result<Lineage> {
        too_deep(depth)?;
        let d = depth + 1;
        let lin = match e {
            Expr::Identifier(id) => {
                let mut l = self.scopes.column(self.tags, &[], &id.value);
                merge(&mut l, self.scopes.whole_row(self.tags, &id.value));
                return Ok(l);
            }
            Expr::CompoundIdentifier(ids) => return Ok(self.compound(ids)),
            Expr::Value(_) | Expr::TypedString { .. } | Expr::IntroducedString { .. } => {
                Lineage::new()
            }
            Expr::Nested(x) => return self.expr(x, d),
            // Only the arguments are values; FILTER / OVER / WITHIN GROUP decide
            // which rows and in what order, like WHERE.
            Expr::Function(f) => match &f.args {
                FunctionArguments::None => Lineage::new(),
                FunctionArguments::Subquery(q) => self.query_value(q, d)?,
                FunctionArguments::List(list) => {
                    let mut l = Lineage::new();
                    for a in &list.args {
                        merge(&mut l, self.function_arg(a, d)?);
                    }
                    l
                }
            },
            Expr::Subquery(q) => {
                // `(SELECT email …)` IS the value: keep directness.
                let cols = self.query(q, None, d)?;
                return Ok(cols
                    .first()
                    .map(|c| outcol_all(self.tags, c))
                    .unwrap_or_default());
            }
            Expr::Exists { .. } => Lineage::new(),
            Expr::InSubquery { expr, subquery, .. } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.query_value(subquery, d)?);
                l
            }
            Expr::BinaryOp { left, right, .. }
            | Expr::IsDistinctFrom(left, right)
            | Expr::IsNotDistinctFrom(left, right)
            | Expr::AnyOp { left, right, .. }
            | Expr::AllOp { left, right, .. } => {
                let mut l = self.expr(left, d)?;
                merge(&mut l, self.expr(right, d)?);
                l
            }
            Expr::UnaryOp { expr, .. }
            | Expr::IsFalse(expr)
            | Expr::IsNotFalse(expr)
            | Expr::IsTrue(expr)
            | Expr::IsNotTrue(expr)
            | Expr::IsNull(expr)
            | Expr::IsNotNull(expr)
            | Expr::IsUnknown(expr)
            | Expr::IsNotUnknown(expr)
            | Expr::Cast { expr, .. }
            | Expr::Collate { expr, .. }
            | Expr::Extract { expr, .. }
            | Expr::Ceil { expr, .. }
            | Expr::Floor { expr, .. }
            | Expr::Named { expr, .. }
            | Expr::OuterJoin(expr)
            | Expr::Prior(expr)
            | Expr::CompositeAccess { expr, .. } => self.expr(expr, d)?,
            Expr::JsonAccess { value, .. } => self.expr(value, d)?,
            Expr::Convert { expr, styles, .. } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.exprs(styles, d)?);
                l
            }
            Expr::AtTimeZone {
                timestamp,
                time_zone,
            } => {
                let mut l = self.expr(timestamp, d)?;
                merge(&mut l, self.expr(time_zone, d)?);
                l
            }
            Expr::Position { expr, r#in } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.expr(r#in, d)?);
                l
            }
            Expr::Substring {
                expr,
                substring_from,
                substring_for,
                ..
            } => {
                let mut l = self.expr(expr, d)?;
                for x in [substring_from, substring_for].into_iter().flatten() {
                    merge(&mut l, self.expr(x, d)?);
                }
                l
            }
            Expr::Trim {
                expr,
                trim_what,
                trim_characters,
                ..
            } => {
                let mut l = self.expr(expr, d)?;
                if let Some(w) = trim_what {
                    merge(&mut l, self.expr(w, d)?);
                }
                if let Some(c) = trim_characters {
                    merge(&mut l, self.exprs(c, d)?);
                }
                l
            }
            Expr::Overlay {
                expr,
                overlay_what,
                overlay_from,
                overlay_for,
            } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.expr(overlay_what, d)?);
                merge(&mut l, self.expr(overlay_from, d)?);
                if let Some(f) = overlay_for {
                    merge(&mut l, self.expr(f, d)?);
                }
                l
            }
            Expr::InList { expr, list, .. } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.exprs(list, d)?);
                l
            }
            Expr::InUnnest {
                expr, array_expr, ..
            } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.expr(array_expr, d)?);
                l
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.expr(low, d)?);
                merge(&mut l, self.expr(high, d)?);
                l
            }
            Expr::Like { expr, pattern, .. }
            | Expr::ILike { expr, pattern, .. }
            | Expr::SimilarTo { expr, pattern, .. }
            | Expr::RLike { expr, pattern, .. } => {
                let mut l = self.expr(expr, d)?;
                merge(&mut l, self.expr(pattern, d)?);
                l
            }
            Expr::Case {
                operand,
                conditions,
                results,
                else_result,
            } => {
                let mut l = Lineage::new();
                if let Some(o) = operand {
                    merge(&mut l, self.expr(o, d)?);
                }
                merge(&mut l, self.exprs(conditions, d)?);
                merge(&mut l, self.exprs(results, d)?);
                if let Some(x) = else_result {
                    merge(&mut l, self.expr(x, d)?);
                }
                l
            }
            Expr::Tuple(list) => self.exprs(list, d)?,
            Expr::Array(a) => self.exprs(&a.elem, d)?,
            Expr::Interval(i) => self.expr(&i.value, d)?,
            Expr::GroupingSets(sets) | Expr::Cube(sets) | Expr::Rollup(sets) => {
                let mut l = Lineage::new();
                for s in sets {
                    merge(&mut l, self.exprs(s, d)?);
                }
                l
            }
            Expr::MapAccess { column, keys } => {
                let mut l = self.expr(column, d)?;
                for k in keys {
                    merge(&mut l, self.expr(&k.key, d)?);
                }
                l
            }
            Expr::Subscript { expr, .. } => self.expr(expr, d)?,
            Expr::MatchAgainst { columns, .. } => {
                let mut l = Lineage::new();
                for c in columns {
                    merge(&mut l, self.scopes.column(self.tags, &[], &c.value));
                }
                l
            }
            Expr::Wildcard => self.scopes.star(self.tags, &[]).0,
            Expr::QualifiedWildcard(name) => {
                let q: Vec<&str> = name.0.iter().map(|i| i.value.as_str()).collect();
                self.scopes.star(self.tags, &q).0
            }
            // Struct / Dictionary / Map / Lambda: not produced by these dialects'
            // queries in practice. Assume the worst: every tag in scope.
            _ => self.everything_in_scope(),
        };
        Ok(indirect(lin))
    }

    fn compound(&self, ids: &[Ident]) -> Lineage {
        let names: Vec<&str> = ids.iter().map(|i| i.value.as_str()).collect();
        match names.as_slice() {
            [] => Lineage::new(),
            [one] => {
                let mut l = self.scopes.column(self.tags, &[], one);
                merge(&mut l, self.scopes.whole_row(self.tags, one));
                l
            }
            [q @ .., col] => self.scopes.column(self.tags, q, col),
        }
    }

    fn everything_in_scope(&self) -> Lineage {
        let mut out = Lineage::new();
        for level in &self.scopes.levels {
            for item in level {
                merge(&mut out, item.star_all(self.tags));
            }
        }
        indirect(out)
    }
}

/// MySQL's output name for an unaliased expression is its text; only the
/// bare-column case matters for resolution through derived tables.
fn figure(e: &Expr) -> String {
    match e {
        Expr::Identifier(i) => i.value.clone(),
        Expr::CompoundIdentifier(ids) => ids.last().map(|i| i.value.clone()).unwrap_or_default(),
        Expr::Nested(x) => figure(x),
        other => other.to_string(),
    }
}

impl Item {
    /// Everything this item derives from, as a non-star lineage.
    pub(crate) fn star_all(&self, tags: &Tags) -> Lineage {
        let mut out = Lineage::new();
        match self {
            Item::Base { schema, table, .. } => {
                merge(&mut out, tags.of_table(schema.as_deref(), table))
            }
            Item::Derived { cols, .. } => merge(&mut out, outcols_all(tags, cols)),
            Item::Opaque { lin, .. } => merge(&mut out, lin.clone()),
            Item::Join { items, .. } => {
                for i in items {
                    merge(&mut out, i.star_all(tags));
                }
            }
        }
        out
    }
}
