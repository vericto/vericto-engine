//! Sensitive-column derivation over the `sqlparser-rs` AST (MySQL, Oracle,
//! MS SQL). Same model as [`super::pg`] — same scopes, same sinks, same
//! conservative rules. On MySQL the walk also applies the mask rewrite to the
//! client-visible projections (Oracle and MS SQL still block a mask); the
//! text it walks and the text it emits go through [`super::mysql`], which
//! reads and prints them the way MySQL does.

use sqlparser::ast::{
    Assignment, AssignmentTarget, Cte, Expr, FromTable, FunctionArg, FunctionArgExpr,
    FunctionArguments, GroupByExpr, Ident, MergeAction, MergeInsertKind, ObjectName,
    OnConflictAction, OnInsert, OrderBy, Query, Select, SelectItem, SetExpr, Statement, TableAlias,
    TableFactor, TableWithJoins, Value,
};

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::sensitive::mysql::{self, Prepared};
use crate::sensitive::{
    Item, Lineage, OutCol, Scopes, Sink, Tags, Touches, ieq, indirect, mask_style_for, merge,
    outcol_all, outcols_all, starred,
};

/// Why the MySQL analysis could not run.
pub(crate) enum Failure {
    /// Nesting past [`MAX_AST_DEPTH`].
    TooDeep(ProxyError),
    /// The text cannot be read the way MySQL reads it (see [`mysql`]).
    Unreadable(String),
}

/// Oracle / MS SQL: derivation only.
pub(crate) fn analyze(statements: &[Statement], tags: &Tags) -> Result<Touches> {
    let mut statements = statements.to_vec();
    let mut w = Walker::new(tags, false, None);
    for s in statements.iter_mut() {
        w.stmt(s, 0)?;
    }
    Ok(w.touches)
}

/// MySQL: derivation over the text as MySQL reads it, and the mask rewrite
/// when `any_mask`.
pub(crate) fn analyze_mysql(
    sql: &str,
    tags: &Tags,
    any_mask: bool,
) -> std::result::Result<(Touches, super::pg::Rewrite), Failure> {
    let mut prepared = mysql::prepare(sql).map_err(|e| Failure::Unreadable(e.0))?;
    let mut statements = std::mem::take(&mut prepared.statements);
    // The unmodified tree, for the fidelity check; only needed if a rewrite
    // can happen.
    let original = any_mask.then(|| statements.clone());
    let mut w = Walker::new(tags, any_mask, Some(&prepared));
    for s in statements.iter_mut() {
        w.stmt(s, 0).map_err(Failure::TooDeep)?;
    }
    let (touches, rewrote, refused) = (w.touches, w.rewrote, w.refused);
    if !rewrote {
        return Ok((touches, None));
    }
    #[cfg(test)]
    if FORCE_RENDER_FAILURE.with(|f| f.get()) {
        return Ok((touches, Some(Err("forced by test".to_string()))));
    }
    let faithful = |why: String| {
        format!(
            "the MySQL text cannot be reproduced faithfully ({why}); tag the column block or flag, or simplify the query"
        )
    };
    let rewrite = match refused {
        Some(why) => Err(why),
        None => prepared
            .check_original(original.as_deref().unwrap_or_default())
            .and_then(|()| prepared.render(&statements))
            .map_err(faithful),
    };
    Ok((touches, Some(rewrite)))
}

#[cfg(test)]
thread_local! {
    /// Lets a test prove that a render failure blocks.
    pub(crate) static FORCE_RENDER_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A masked projection: (position, output name, original expression).
type Rewritten = (usize, String, Expr);

struct Walker<'a, 't, 'p, 's> {
    tags: &'a Tags<'t>,
    scopes: Scopes,
    ctes: Vec<Vec<(String, Vec<OutCol>)>>,
    touches: Touches,
    /// Client-visible projections may be rewritten (MySQL, some tag a mask).
    rewrite: bool,
    rewrote: bool,
    /// Set when a rewrite would change what the query means (e.g. `HAVING`
    /// over a masked alias): the verdict blocks with this reason.
    refused: Option<String>,
    /// MySQL only: the client's text (output names, `"…"` handling).
    mysql: Option<&'p Prepared<'s>>,
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

/// The bare column an expression is, through parentheses (`(email)`).
fn bare_column(e: &Expr) -> Option<&Expr> {
    match e {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => Some(e),
        Expr::Nested(x) => bare_column(x),
        _ => None,
    }
}

fn column_name(e: &Expr) -> Option<&str> {
    match bare_column(e)? {
        Expr::Identifier(i) => Some(&i.value),
        Expr::CompoundIdentifier(ids) => ids.last().map(|i| i.value.as_str()),
        _ => None,
    }
}

/// A 1-based position (`ORDER BY 2`, `GROUP BY 1`) → 0-based index.
fn position(e: &Expr) -> Option<usize> {
    match e {
        Expr::Value(Value::Number(n, _)) => n.parse::<usize>().ok()?.checked_sub(1),
        _ => None,
    }
}

impl<'a, 't, 'p, 's> Walker<'a, 't, 'p, 's> {
    fn new(tags: &'a Tags<'t>, rewrite: bool, mysql: Option<&'p Prepared<'s>>) -> Self {
        Walker {
            tags,
            scopes: Scopes::default(),
            ctes: Vec::new(),
            touches: Touches::default(),
            rewrite,
            rewrote: false,
            refused: None,
            mysql,
        }
    }

    fn visible(&self) -> Sink {
        Sink::Projected {
            rewrite: self.rewrite,
        }
    }

    fn refuse(&mut self, why: String) {
        if self.refused.is_none() {
            self.refused = Some(why);
        }
    }

    fn stmt(&mut self, s: &mut Statement, depth: usize) -> Result<()> {
        too_deep(depth)?;
        let d = depth + 1;
        let visible = self.visible();
        match s {
            Statement::Query(q) => {
                self.query(q, Some(visible), d)?;
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
                if let Some(src) = ins.source.as_deref_mut() {
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
                // `ON DUPLICATE KEY UPDATE x = <expr>` / `ON CONFLICT DO
                // UPDATE SET x = <expr>` store a value like `UPDATE … SET`.
                let upsert = match ins.on.as_mut() {
                    Some(OnInsert::DuplicateKeyUpdate(a)) => Some(a),
                    Some(OnInsert::OnConflict(oc)) => match &mut oc.action {
                        OnConflictAction::DoUpdate(u) => Some(&mut u.assignments),
                        OnConflictAction::DoNothing => None,
                    },
                    _ => None,
                };
                if let Some(assignments) = upsert {
                    self.scopes.push();
                    self.scopes.add(target.clone());
                    let r = self.assignments(assignments, Some(&target), d);
                    self.scopes.pop();
                    r?;
                }
                if let Some(ret) = ins.returning.as_mut() {
                    self.scopes.push();
                    self.scopes.add(target);
                    let r = self.projection(ret, Some(visible), d);
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
                        self.projection(ret, Some(visible), d)?;
                    }
                    Ok(())
                })();
                self.scopes.pop();
                r?;
            }
            Statement::Delete(del) => {
                if del.returning.is_some() {
                    self.scopes.push();
                    let r = (|| -> Result<()> {
                        let from = match &mut del.from {
                            FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
                        };
                        for twj in from.iter_mut().chain(del.using.iter_mut().flatten()) {
                            for it in self.table_with_joins(twj, d)? {
                                self.scopes.add(it);
                            }
                        }
                        if let Some(ret) = del.returning.as_mut() {
                            self.projection(ret, Some(visible), d)?;
                        }
                        Ok(())
                    })();
                    self.scopes.pop();
                    r?;
                }
            }
            Statement::CreateTable(ct) => {
                if let Some(q) = ct.query.as_deref_mut() {
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
                    self.query(q, Some(visible), d)?;
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
                    if let Some(q) = decl.for_query.as_deref_mut() {
                        self.query(q, Some(visible), d)?;
                    }
                }
            }
            Statement::Prepare { statement, .. } => self.stmt(statement, d)?,
            Statement::Explain { statement, .. } => {
                // A plan, not rows. Data copies inside still count.
                if let Statement::Query(q) = statement.as_mut() {
                    self.query(q, None, d)?;
                } else {
                    self.stmt(statement, d)?;
                }
            }
            // `SET @v = (SELECT email …)`: the value moves into a session
            // variable the next statement reads freely — a copy.
            Statement::SetVariable { value, .. } => {
                for e in value.iter_mut() {
                    let lin = self.expr(e, d)?;
                    self.touches.record(&lin, Sink::Copy);
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
                    for c in clauses.iter_mut() {
                        match &mut c.action {
                            MergeAction::Update { assignments } => {
                                self.assignments(assignments, target.as_ref(), d)?
                            }
                            MergeAction::Insert(ins) => {
                                if let MergeInsertKind::Values(v) = &mut ins.kind {
                                    for row in v.rows.iter_mut() {
                                        for (j, e) in row.iter_mut().enumerate() {
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
        list: &mut [Assignment],
        target: Option<&Item>,
        depth: usize,
    ) -> Result<()> {
        for a in list.iter_mut() {
            let mut lin = self.expr(&mut a.value, depth + 1)?;
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

    fn query(&mut self, q: &mut Query, sink: Option<Sink>, depth: usize) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let pushed = if let Some(with) = q.with.as_mut() {
            self.ctes.push(Vec::new());
            let recursive = with.recursive;
            for cte in with.cte_tables.iter_mut() {
                let cols = if recursive {
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
        let out = if let SetExpr::Select(sel) = q.body.as_mut() {
            // A simple SELECT: its ORDER BY lives on the query.
            self.select(sel, sink, depth + 1)
                .map(|(outs, rw, star, distinct)| {
                    if !rw.is_empty() && !distinct {
                        if let Some(ob) = q.order_by.as_mut() {
                            if let Err(why) = fix_order_by(ob, &rw, star) {
                                self.refuse(why);
                            }
                        }
                    }
                    outs
                })
        } else {
            self.set_expr(&mut q.body, sink, depth + 1)
        };
        if pushed {
            self.ctes.pop();
        }
        out
    }

    fn cte_cols(&mut self, cte: &mut Cte, depth: usize) -> Result<Vec<OutCol>> {
        let cols = self.query(&mut cte.query, None, depth + 1)?;
        Ok(rename(cols, Some(&cte.alias)))
    }

    fn recursive_cte(&mut self, cte: &mut Cte, depth: usize) -> Result<Vec<OutCol>> {
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
        body: &mut SetExpr,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let d = depth + 1;
        match body {
            SetExpr::Select(sel) => Ok(self.select(sel, sink, d)?.0),
            SetExpr::Query(q) => self.query(q, sink, d),
            SetExpr::SetOperation { left, right, .. } => {
                let l = self.set_expr(left, sink, d)?;
                let r = self.set_expr(right, sink, d)?;
                Ok(self.combine(l, r))
            }
            SetExpr::Values(v) => {
                let mut cols: Vec<Lineage> = Vec::new();
                for row in v.rows.iter_mut() {
                    for (j, e) in row.iter_mut().enumerate() {
                        let lin = self.expr(e, d)?;
                        if let Some(sink) = sink {
                            self.touches.record(&lin, sink);
                            if let Sink::Projected { rewrite: true } = sink {
                                if let Some(style) = mask_style_for(self.tags, &lin) {
                                    *e = mysql::mask_expr(style, e);
                                    self.rewrote = true;
                                }
                            }
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

    /// One `SELECT`: (output columns, masked projections, whether the list
    /// has a star, whether it is DISTINCT).
    #[allow(clippy::type_complexity)]
    fn select(
        &mut self,
        sel: &mut Select,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<(Vec<OutCol>, Vec<Rewritten>, bool, bool)> {
        // `SELECT … INTO t` / `INTO OUTFILE` / `INTO @v`: a copy, not a read.
        let sink = if sel.into.is_some() {
            Some(Sink::Copy)
        } else {
            sink
        };
        self.scopes.push();
        let r = (|| -> Result<(Vec<OutCol>, Vec<Rewritten>, bool)> {
            for twj in sel.from.iter_mut() {
                for it in self.table_with_joins(twj, depth)? {
                    self.scopes.add(it);
                }
            }
            self.projection(&mut sel.projection, sink, depth)
        })();
        self.scopes.pop();
        let (outs, rw, star) = r?;
        if !rw.is_empty() {
            self.fix_group_and_having(sel, &rw, star);
        }
        Ok((outs, rw, star, sel.distinct.is_some()))
    }

    /// After masking, `GROUP BY` / `HAVING` items naming a masked output could
    /// now see the MASKED value. MySQL resolves a `GROUP BY` name against the
    /// FROM columns first and the select aliases second, so whether `x` is the
    /// column or the alias depends on a schema the engine does not have:
    /// - `GROUP BY 2` (a position) always meant the select item: it is pointed
    ///   at the original expression;
    /// - `GROUP BY email` over a masked `email` column groups by that column
    ///   either way: unchanged;
    /// - any other masked output name in `GROUP BY`, and any masked output
    ///   name in `HAVING` (which prefers the alias), cannot be resolved safely:
    ///   the rewrite is refused, i.e. the query is blocked.
    fn fix_group_and_having(&mut self, sel: &mut Select, rw: &[Rewritten], star: bool) {
        // A masked bare column keeps its own name (`email` over `email`): in
        // GROUP BY that name is the FROM column either way, which is unchanged.
        let captured: Vec<&str> = rw
            .iter()
            .filter(|(_, n, orig)| !column_name(orig).is_some_and(|c| ieq(c, n)))
            .map(|(_, n, _)| n.as_str())
            .collect();
        if let GroupByExpr::Expressions(exprs, _) = &mut sel.group_by {
            for e in exprs.iter_mut() {
                if let Some(p) = position(e).filter(|_| !star) {
                    if let Some((_, _, orig)) = rw.iter().find(|(i, _, _)| *i == p) {
                        *e = orig.clone();
                    }
                    continue;
                }
                // A qualified name is a column, never an alias.
                if matches!(e, Expr::CompoundIdentifier(_) | Expr::Value(_)) {
                    continue;
                }
                if !captured.is_empty() && mysql::mentions(e, &captured) {
                    self.refuse(format!(
                        "GROUP BY uses the masked output name(s) {}; group by the expression itself",
                        captured.join(", ")
                    ));
                }
            }
        }
        // HAVING resolves a name to the select alias even when a FROM column
        // has it (measured): every masked name counts.
        let names: Vec<&str> = rw.iter().map(|(_, n, _)| n.as_str()).collect();
        if let Some(h) = &sel.having {
            if mysql::mentions(h, &names) {
                self.refuse(format!(
                    "HAVING uses the masked output name(s) {}; MySQL would compare the masked value",
                    names.join(", ")
                ));
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

    /// MySQL's name for an unaliased select item: a column's name as written,
    /// otherwise the expression's own text as the client wrote it.
    fn output_name(&self, e: &Expr) -> String {
        if let Some(c) = column_name(e) {
            return c.to_string();
        }
        if let Expr::Value(Value::SingleQuotedString(s) | Value::DoubleQuotedString(s)) = e {
            return s.clone();
        }
        let text = match self.mysql {
            Some(p) => p
                .verbatim(e)
                .unwrap_or_else(|| mysql::plain_placeholders(&e.to_string())),
            None => e.to_string(),
        };
        // MySQL truncates a generated name to 255 characters.
        text.chars().take(255).collect()
    }

    fn projection(
        &mut self,
        items: &mut [SelectItem],
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<(Vec<OutCol>, Vec<Rewritten>, bool)> {
        let mut outs = Vec::new();
        let mut rewritten = Vec::new();
        let mut has_star = false;
        for (idx, item) in items.iter_mut().enumerate() {
            let (lin, name) = match item {
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => {
                    has_star = true;
                    let (lin, cols) = match item {
                        SelectItem::QualifiedWildcard(name, _) => {
                            let q: Vec<&str> = name.0.iter().map(|i| i.value.as_str()).collect();
                            self.scopes.star(self.tags, &q)
                        }
                        _ => self.scopes.star(self.tags, &[]),
                    };
                    if let Some(sink) = sink {
                        self.touches.record(&lin, sink);
                    }
                    outs.extend(cols);
                    continue;
                }
                SelectItem::UnnamedExpr(e) => {
                    let lin = self.expr(e, depth + 1)?;
                    // Only a bare column's name matters for resolution through
                    // derived tables; the exact MySQL name of an expression is
                    // looked up only when the item is rewritten (below).
                    let name = column_name(e).map_or_else(|| e.to_string(), str::to_string);
                    (lin, name)
                }
                SelectItem::ExprWithAlias { expr, alias } => {
                    let lin = self.expr(expr, depth + 1)?;
                    (lin, alias.value.clone())
                }
            };
            if let Some(sink) = sink {
                self.touches.record(&lin, sink);
                if let Sink::Projected { rewrite: true } = sink {
                    if let Some(style) = mask_style_for(self.tags, &lin) {
                        let (orig, name) = match item {
                            SelectItem::UnnamedExpr(e) => (e.clone(), self.output_name(e)),
                            SelectItem::ExprWithAlias { expr, .. } => (expr.clone(), name.clone()),
                            _ => unreachable!("stars are handled above"),
                        };
                        *item = SelectItem::ExprWithAlias {
                            expr: mysql::mask_expr(style, &orig),
                            // Keep the client-visible column name.
                            alias: Ident::with_quote('`', name.clone()),
                        };
                        rewritten.push((idx, name.clone(), orig));
                        self.rewrote = true;
                    }
                }
            }
            outs.push(OutCol::Named { name, lin });
        }
        Ok((outs, rewritten, has_star))
    }

    // ── FROM ────────────────────────────────────────────────────────────────

    fn table_with_joins(&mut self, twj: &mut TableWithJoins, depth: usize) -> Result<Vec<Item>> {
        too_deep(depth)?;
        let mut items = self.table_factor(&mut twj.relation, depth + 1)?;
        for j in twj.joins.iter_mut() {
            // LATERAL on the right side may reference the left.
            let mark = self.scopes.levels.last().map_or(0, Vec::len);
            for it in &items {
                self.scopes.add(it.clone());
            }
            let right = self.table_factor(&mut j.relation, depth + 1);
            if let Some(level) = self.scopes.levels.last_mut() {
                level.truncate(mark);
            }
            items.extend(right?);
        }
        Ok(items)
    }

    fn table_factor(&mut self, tf: &mut TableFactor, depth: usize) -> Result<Vec<Item>> {
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
                    for a in args.args.iter_mut() {
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
                for a in args.iter_mut() {
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
                for e in array_exprs.iter_mut() {
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

    fn function_arg(&mut self, a: &mut FunctionArg, depth: usize) -> Result<Lineage> {
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

    fn exprs(&mut self, list: &mut [Expr], depth: usize) -> Result<Lineage> {
        let mut out = Lineage::new();
        for e in list.iter_mut() {
            merge(&mut out, self.expr(e, depth)?);
        }
        Ok(out)
    }

    fn query_value(&mut self, q: &mut Query, depth: usize) -> Result<Lineage> {
        let cols = self.query(q, None, depth)?;
        Ok(outcols_all(self.tags, &cols))
    }

    fn expr(&mut self, e: &mut Expr, depth: usize) -> Result<Lineage> {
        too_deep(depth)?;
        let d = depth + 1;
        let lin = match e {
            Expr::Identifier(id) => {
                let mut l = self.scopes.column(self.tags, &[], &id.value);
                merge(&mut l, self.scopes.whole_row(self.tags, &id.value));
                return Ok(l);
            }
            Expr::CompoundIdentifier(ids) => return Ok(self.compound(ids)),
            // With `ANSI_QUOTES` (server-wide, or per statement through a
            // `SET_VAR` hint) MySQL reads `"email"` as the column. The engine
            // cannot see the SQL mode: treat it as a possible column.
            Expr::Value(Value::DoubleQuotedString(s)) if self.mysql.is_some() => {
                self.scopes.column(self.tags, &[], s)
            }
            Expr::Value(_) | Expr::TypedString { .. } | Expr::IntroducedString { .. } => {
                Lineage::new()
            }
            Expr::Nested(x) => return self.expr(x, d),
            // Only the arguments are values; FILTER / OVER / WITHIN GROUP decide
            // which rows and in what order, like WHERE.
            Expr::Function(f) => match &mut f.args {
                FunctionArguments::None => Lineage::new(),
                FunctionArguments::Subquery(q) => self.query_value(q, d)?,
                FunctionArguments::List(list) => {
                    let mut l = Lineage::new();
                    for a in list.args.iter_mut() {
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
            Expr::Array(a) => self.exprs(&mut a.elem, d)?,
            Expr::Interval(i) => self.expr(&mut i.value, d)?,
            Expr::GroupingSets(sets) | Expr::Cube(sets) | Expr::Rollup(sets) => {
                let mut l = Lineage::new();
                for s in sets.iter_mut() {
                    merge(&mut l, self.exprs(s, d)?);
                }
                l
            }
            Expr::MapAccess { column, keys } => {
                let mut l = self.expr(column, d)?;
                for k in keys.iter_mut() {
                    merge(&mut l, self.expr(&mut k.key, d)?);
                }
                l
            }
            Expr::Subscript { expr, .. } => self.expr(expr, d)?,
            Expr::MatchAgainst { columns, .. } => {
                let mut l = Lineage::new();
                for c in columns.iter() {
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

/// After masking, an `ORDER BY` item that refers to a masked output — by
/// name, or by position when no `*` precedes it — would sort by the MASKED
/// value: MySQL resolves an `ORDER BY` name against the select aliases first.
/// Point it back at the original expression. A bare column is wrapped in
/// `COALESCE()`: inside an expression MySQL resolves the name to the column
/// first (measured on 5.7 and 8.0), so the alias can no longer capture it.
/// An expression over the name of a masked alias that is not itself a column
/// (`ORDER BY LENGTH(le)`) would sort by the masked value: refused.
fn fix_order_by(ob: &mut OrderBy, rw: &[Rewritten], star: bool) -> std::result::Result<(), String> {
    let captured: Vec<&str> = rw
        .iter()
        .filter(|(_, n, orig)| !column_name(orig).is_some_and(|c| ieq(c, n)))
        .map(|(_, n, _)| n.as_str())
        .collect();
    for item in ob.exprs.iter_mut() {
        let hit = match &item.expr {
            Expr::Identifier(id) => rw.iter().find(|(_, n, _)| ieq(n, &id.value)),
            e => position(e)
                .filter(|_| !star)
                .and_then(|p| rw.iter().find(|(i, _, _)| *i == p)),
        };
        let Some((_, _, orig)) = hit else {
            let plain = matches!(
                item.expr,
                Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
            );
            if !plain && !captured.is_empty() && mysql::mentions(&item.expr, &captured) {
                return Err(format!(
                    "ORDER BY uses the masked output name(s) {} inside an expression; order by the expression itself",
                    captured.join(", ")
                ));
            }
            continue;
        };
        item.expr = match bare_column(orig) {
            Some(c @ Expr::Identifier(_)) => mysql::coalesce(c),
            Some(c) => c.clone(),
            None => orig.clone(),
        };
    }
    Ok(())
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
