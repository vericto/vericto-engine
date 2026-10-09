//! Sensitive-column derivation and mask rewrite over the `pg_query` AST.
//!
//! The walk runs on a **clone** of the parse tree, because the same pass that
//! derives each projected expression's source columns also replaces the masked
//! ones. The clone is only deparsed when something was rewritten, and it is
//! discarded whenever the verdict is not a mask (block, flag, or a mask that
//! cannot be applied). Nothing here runs unless tags are configured.

use std::sync::OnceLock;

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{
    self, Alias, CoalesceExpr, ColumnRef, CommonTableExpr, InsertStmt, Node, RangeVar, SelectStmt,
    SetOperation, SubLinkType, WithClause,
};

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::sensitive::{
    Item, Lineage, MaskStyle, OutCol, Scopes, Sink, Tags, Touches, indirect, mask_style_for, merge,
    outcol_all, outcols_all, starred,
};

/// Rewrite outcome: `Some(Ok(sql))` when at least one projection was masked,
/// `Some(Err(reason))` when the rewrite cannot be forwarded (the reason is
/// shown after `mask unsupported: `), `None` when nothing was rewritten.
pub(crate) type Rewrite = Option<std::result::Result<String, String>>;

/// Derives every tagged column the statements read and, when any tag is a
/// mask, rewrites the masked projections. Errors only on nesting past
/// [`MAX_AST_DEPTH`]; the caller fails closed on that.
pub(crate) fn analyze(
    tree: &protobuf::ParseResult,
    tags: &Tags,
    any_mask: bool,
) -> Result<(Touches, Rewrite)> {
    let mut tree = tree.clone();
    let mut w = Walker {
        tags,
        scopes: Scopes::default(),
        ctes: Vec::new(),
        touches: Touches::default(),
        rewrite: any_mask,
        rewrote: false,
        all: false,
    };
    for raw in tree.stmts.iter_mut() {
        if let Some(node) = raw.stmt.as_deref_mut().and_then(|n| n.node.as_mut()) {
            w.stmt(node, 0)?;
        }
    }
    let rewrite = if w.rewrote {
        #[cfg(test)]
        if FORCE_DEPARSE_FAILURE.with(|f| f.get()) {
            return Ok((
                w.touches,
                Some(Err("rewrite failed (forced by test)".to_string())),
            ));
        }
        Some(pg_query::deparse(&tree).map_err(|e| format!("rewrite failed ({e})")))
    } else {
        None
    };
    Ok((w.touches, rewrite))
}

/// The access analysis (VERICTO-087) of one statement: the same walk, with
/// `tags` collecting every resolution and every clause visited (see
/// [`crate::access`]). The statement is the caller's clone; nothing is
/// rewritten.
pub(crate) fn access_walk(node: &mut NodeEnum, tags: &Tags) -> Result<()> {
    let mut w = Walker {
        tags,
        scopes: Scopes::default(),
        ctes: Vec::new(),
        touches: Touches::default(),
        rewrite: false,
        rewrote: false,
        all: true,
    };
    w.stmt(node, 0)
}

#[cfg(test)]
thread_local! {
    /// Lets a test prove that a deparse failure blocks (deparse of a tree
    /// Postgres itself produced practically never fails, so it cannot be
    /// triggered from SQL).
    pub(crate) static FORCE_DEPARSE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct Walker<'a, 't> {
    tags: &'a Tags<'t>,
    scopes: Scopes,
    /// CTEs in scope, one level per `WITH`, innermost last.
    ctes: Vec<Vec<(String, Vec<OutCol>)>>,
    touches: Touches,
    /// Whether client-visible projections may be rewritten (some tag is a mask).
    rewrite: bool,
    rewrote: bool,
    /// The access analysis: every clause counts (WHERE, JOIN, GROUP BY, …),
    /// not only what is projected, and tables and write targets are recorded.
    all: bool,
}

fn too_deep(depth: usize) -> Result<()> {
    if depth > MAX_AST_DEPTH {
        Err(ProxyError::AstTooDeep)
    } else {
        Ok(())
    }
}

fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

fn str_of(n: &Node) -> Option<&str> {
    match n.node.as_ref() {
        Some(NodeEnum::String(s)) => Some(&s.sval),
        _ => None,
    }
}

/// Renames output columns positionally (`AS x(a, b)`, `WITH x(a, b) AS`).
fn rename(mut cols: Vec<OutCol>, names: &[Node]) -> Vec<OutCol> {
    if names.is_empty() {
        return cols;
    }
    // Positional renaming over a star expansion of unknown width cannot be
    // aligned: keep every source reachable under every new name.
    if cols.iter().any(|c| !matches!(c, OutCol::Named { .. })) {
        return cols;
    }
    for (c, n) in cols.iter_mut().zip(names) {
        if let (OutCol::Named { name, .. }, Some(new)) = (c, str_of(n)) {
            *name = new.to_string();
        }
    }
    cols
}

fn alias_name(a: Option<&Alias>) -> Option<String> {
    a.and_then(|a| non_empty(&a.aliasname)).map(str::to_string)
}

impl Walker<'_, '_> {
    fn visible(&self) -> Sink {
        Sink::Projected {
            rewrite: self.rewrite,
        }
    }

    // ── statements ──────────────────────────────────────────────────────────

    fn stmt(&mut self, node: &mut NodeEnum, depth: usize) -> Result<()> {
        too_deep(depth)?;
        let visible = self.visible();
        match node {
            NodeEnum::SelectStmt(s) => {
                // `SELECT … INTO t` creates a table: a copy, not a read.
                let sink = if s.into_clause.is_some() {
                    Sink::Copy
                } else {
                    visible
                };
                self.select(s, Some(sink), depth + 1)?;
            }
            NodeEnum::InsertStmt(s) => {
                self.insert(s, Some(visible), depth + 1)?;
            }
            NodeEnum::UpdateStmt(_) | NodeEnum::DeleteStmt(_) | NodeEnum::MergeStmt(_) => {
                self.dml(node, Some(visible), depth + 1)?;
            }
            NodeEnum::CopyStmt(c) if c.is_from => {
                // Only reached by the access analysis (085 reads nothing here):
                // `COPY t [(cols)] FROM` writes those columns, or every one.
                if let Some(rel) = c.relation.as_ref() {
                    let schema = non_empty(&rel.schemaname);
                    self.tags.write(schema, &rel.relname, None);
                    if c.attlist.is_empty() {
                        self.tags.write(schema, &rel.relname, Some("*"));
                    }
                    for a in &c.attlist {
                        if let Some(col) = str_of(a) {
                            self.tags.write(schema, &rel.relname, Some(col));
                        }
                    }
                    if self.all {
                        if let Some(w) = c.where_clause.as_deref_mut() {
                            self.scopes.push();
                            self.scopes.add(base_item(rel));
                            let r = self.expr(w, depth + 1);
                            self.scopes.pop();
                            r?;
                        }
                    }
                }
            }
            NodeEnum::CopyStmt(c) if !c.is_from => {
                if let Some(rel) = c.relation.as_ref() {
                    self.tags.relation(non_empty(&rel.schemaname), &rel.relname);
                }
                if let Some(q) = c.query.as_deref_mut() {
                    self.query(q, Some(visible), depth + 1)?;
                } else if let Some(rel) = c.relation.as_ref() {
                    // `COPY t TO` is `SELECT *`; `COPY t (cols) TO` names the
                    // columns but has no projection to rewrite either way.
                    let schema = non_empty(&rel.schemaname);
                    let lin = if c.attlist.is_empty() {
                        starred(self.tags.of_table(schema, &rel.relname))
                    } else {
                        let mut lin = Lineage::new();
                        for a in &c.attlist {
                            if let Some(col) = str_of(a) {
                                merge(&mut lin, self.tags.of_column(schema, &rel.relname, col));
                            }
                        }
                        lin
                    };
                    self.touches.record_fixed(&lin);
                }
            }
            NodeEnum::CreateTableAsStmt(c) => {
                if let Some(q) = c.query.as_deref_mut() {
                    self.query(q, Some(Sink::Copy), depth + 1)?;
                }
            }
            NodeEnum::ViewStmt(v) => {
                if let Some(q) = v.query.as_deref_mut() {
                    self.query(q, Some(Sink::Copy), depth + 1)?;
                }
            }
            NodeEnum::DeclareCursorStmt(d) => {
                if let Some(q) = d.query.as_deref_mut() {
                    self.query(q, Some(visible), depth + 1)?;
                }
            }
            NodeEnum::PrepareStmt(p) => {
                if let Some(q) = p.query.as_deref_mut() {
                    self.query(q, Some(visible), depth + 1)?;
                }
            }
            NodeEnum::ExplainStmt(e) => {
                // A plan, not rows: only data copies inside count.
                if let Some(q) = e.query.as_deref_mut() {
                    self.query(q, None, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// A statement used as a query (subquery, CTE body, COPY/CTAS/VIEW query).
    /// Returns its output columns.
    fn query(&mut self, node: &mut Node, sink: Option<Sink>, depth: usize) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        match node.node.as_mut() {
            Some(NodeEnum::SelectStmt(s)) => self.select(s, sink, depth + 1),
            Some(NodeEnum::InsertStmt(s)) => self.insert(s, sink, depth + 1),
            Some(
                n @ (NodeEnum::UpdateStmt(_) | NodeEnum::DeleteStmt(_) | NodeEnum::MergeStmt(_)),
            ) => self.dml(n, sink, depth + 1),
            _ => Ok(Vec::new()),
        }
    }

    // ── CTEs ────────────────────────────────────────────────────────────────

    fn push_ctes(&mut self, with: Option<&mut WithClause>, depth: usize) -> Result<bool> {
        let Some(with) = with else {
            return Ok(false);
        };
        self.ctes.push(Vec::new());
        for node in with.ctes.iter_mut() {
            let Some(NodeEnum::CommonTableExpr(cte)) = node.node.as_mut() else {
                continue;
            };
            let cols = if with.recursive {
                self.recursive_cte(cte, depth + 1)?
            } else {
                self.cte_cols(cte, depth + 1)?
            };
            if let Some(level) = self.ctes.last_mut() {
                level.push((cte.ctename.clone(), cols));
            }
        }
        Ok(true)
    }

    fn cte_cols(&mut self, cte: &mut CommonTableExpr, depth: usize) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let cols = match cte.ctequery.as_deref_mut() {
            Some(q) => self.query(q, None, depth + 1)?,
            None => Vec::new(),
        };
        Ok(rename(cols, &cte.aliascolnames))
    }

    /// A recursive CTE refers to itself: iterate to a fixed point (lineage only
    /// grows and is bounded by the tag count, so this ends; capped anyway).
    fn recursive_cte(&mut self, cte: &mut CommonTableExpr, depth: usize) -> Result<Vec<OutCol>> {
        let name = cte.ctename.clone();
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

    /// A CTE named exactly `name` (identifiers are already case-folded by the
    /// parser, so exact comparison is Postgres's own rule: a quoted `"Customers"`
    /// CTE does NOT shadow the table `customers`).
    fn find_cte(&self, name: &str) -> Option<Vec<OutCol>> {
        for level in self.ctes.iter().rev() {
            if let Some((_, cols)) = level.iter().rev().find(|(n, _)| n == name) {
                return Some(cols.clone());
            }
        }
        None
    }

    // ── SELECT ──────────────────────────────────────────────────────────────

    fn select(
        &mut self,
        s: &mut SelectStmt,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let pushed = self.push_ctes(s.with_clause.as_mut(), depth + 1)?;
        let op = s.op;
        let is_setop = op != SetOperation::SetopNone as i32 && op != SetOperation::Undefined as i32;
        let out = if is_setop {
            let l = match s.larg.as_deref_mut() {
                Some(l) => self.select(l, sink, depth + 1)?,
                None => Vec::new(),
            };
            let r = match s.rarg.as_deref_mut() {
                Some(r) => self.select(r, sink, depth + 1)?,
                None => Vec::new(),
            };
            let out = self.combine(l, r);
            if self.all {
                // ORDER BY / LIMIT of the whole set operation: output names
                // or positions, or expressions over the enclosing scopes.
                self.order_and_limit(s, &out, depth + 1)?;
            }
            out
        } else {
            self.scopes.push();
            let res = self.simple_select(s, sink, depth + 1);
            self.scopes.pop();
            res?
        };
        if pushed {
            self.ctes.pop();
        }
        Ok(out)
    }

    /// Set operation: output column i derives from column i of every arm.
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
            // A star arm has unknown width: positions cannot be aligned.
            let mut lin = outcols_all(self.tags, &l);
            merge(&mut lin, outcols_all(self.tags, &r));
            vec![OutCol::OpaqueStar { lin }]
        }
    }

    fn simple_select(
        &mut self,
        s: &mut SelectStmt,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        for item in s.from_clause.iter_mut() {
            for it in self.range_item(item, depth + 1)? {
                self.scopes.add(it);
            }
        }

        if !s.values_lists.is_empty() {
            let outs = self.values(&mut s.values_lists, sink, depth + 1)?;
            if self.all {
                // `VALUES … ORDER BY (SELECT …) LIMIT …`
                self.order_and_limit(s, &outs, depth + 1)?;
            }
            return Ok(outs);
        }

        let (outs, rewritten, has_star) = self.targets(&mut s.target_list, sink, depth + 1)?;
        if !rewritten.is_empty() && s.distinct_clause.is_empty() {
            fix_order_and_group(s, &rewritten, has_star);
        }
        if self.all {
            self.select_clauses(s, &outs, depth + 1)?;
        }
        Ok(outs)
    }

    /// Access analysis: every clause of a simple `SELECT` besides its target
    /// list and `FROM`. A predicate lets the caller probe a value it cannot
    /// read, so it counts as much as a projection.
    fn select_clauses(&mut self, s: &mut SelectStmt, outs: &[OutCol], depth: usize) -> Result<()> {
        self.opt(s.where_clause.as_deref_mut(), depth)?;
        // GROUP BY prefers the input column over an output alias of the same
        // name: resolved as an input column (conservative).
        self.exprs(&mut s.group_clause, depth)?;
        self.opt(s.having_clause.as_deref_mut(), depth)?;
        self.exprs(&mut s.window_clause, depth)?;
        self.exprs(&mut s.distinct_clause, depth)?;
        self.order_and_limit(s, outs, depth)
    }

    /// Access analysis: `ORDER BY` (a bare name equal to an output column IS
    /// that output, already counted), `LIMIT`, `OFFSET`.
    fn order_and_limit(&mut self, s: &mut SelectStmt, outs: &[OutCol], depth: usize) -> Result<()> {
        for item in s.sort_clause.iter_mut() {
            let Some(NodeEnum::SortBy(sb)) = item.node.as_mut() else {
                self.expr(item, depth)?;
                continue;
            };
            let output = match sb.node.as_deref().and_then(|n| n.node.as_ref()) {
                Some(NodeEnum::ColumnRef(c)) if c.fields.len() == 1 => str_of(&c.fields[0])
                    .is_some_and(|name| {
                        outs.iter()
                            .any(|o| matches!(o, OutCol::Named { name: n, .. } if n == name))
                    }),
                _ => false,
            };
            if !output {
                self.opt(sb.node.as_deref_mut(), depth)?;
            }
        }
        self.opt(s.limit_count.as_deref_mut(), depth)?;
        self.opt(s.limit_offset.as_deref_mut(), depth)?;
        Ok(())
    }

    /// `VALUES (…), (…)`: column j derives from item j of every row.
    fn values(
        &mut self,
        rows: &mut [Node],
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        let mut cols: Vec<Lineage> = Vec::new();
        for row in rows.iter_mut() {
            let Some(NodeEnum::List(list)) = row.node.as_mut() else {
                continue;
            };
            for (j, item) in list.items.iter_mut().enumerate() {
                let lin = self.expr(item, depth + 1)?;
                if let Some(sink) = sink {
                    self.touches.record(&lin, sink);
                    if let Sink::Projected { rewrite: true } = sink {
                        if let Some(style) = mask_style_for(self.tags, &lin) {
                            let orig = std::mem::take(item);
                            *item = mask_node(style, orig);
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

    /// A target list (`SELECT` list or `RETURNING`). Returns the output
    /// columns, the rewritten targets `(position, output name, original
    /// expression)`, and whether the list contains a star.
    #[allow(clippy::type_complexity)]
    fn targets(
        &mut self,
        list: &mut [Node],
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<(Vec<OutCol>, Vec<(usize, String, Node)>, bool)> {
        let mut outs = Vec::new();
        let mut rewritten = Vec::new();
        let mut has_star = false;
        for (idx, t) in list.iter_mut().enumerate() {
            let Some(NodeEnum::ResTarget(rt)) = t.node.as_mut() else {
                continue;
            };
            if let Some(q) = rt.val.as_deref().and_then(star_qualifier) {
                has_star = true;
                let q: Vec<&str> = q.iter().map(String::as_str).collect();
                let (lin, cols) = self.scopes.star(self.tags, &q);
                if let Some(sink) = sink {
                    self.touches.record(&lin, sink);
                }
                outs.extend(cols);
                continue;
            }
            let lin = match rt.val.as_deref_mut() {
                Some(v) => self.expr(v, depth + 1)?,
                None => Lineage::new(),
            };
            let name = if rt.name.is_empty() {
                figure_colname(rt.val.as_deref())
            } else {
                rt.name.clone()
            };
            if let Some(sink) = sink {
                self.touches.record(&lin, sink);
                if let Sink::Projected { rewrite: true } = sink {
                    // Check the style BEFORE taking the value: `take()` empties it.
                    if let Some(style) = mask_style_for(self.tags, &lin)
                        && let Some(orig) = rt.val.take()
                    {
                        let orig = *orig;
                        rt.val = Some(Box::new(mask_node(style, orig.clone())));
                        // Keep the client-visible column name.
                        rt.name = name.clone();
                        rewritten.push((idx, name.clone(), orig));
                        self.rewrote = true;
                    }
                }
            }
            outs.push(OutCol::Named { name, lin });
        }
        Ok((outs, rewritten, has_star))
    }

    // ── INSERT / UPDATE / DELETE / MERGE ────────────────────────────────────

    fn insert(
        &mut self,
        s: &mut InsertStmt,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let pushed = self.push_ctes(s.with_clause.as_mut(), depth + 1)?;
        let target = s.relation.as_ref().map(base_item);
        if let Some(rv) = s.relation.as_ref() {
            // Access analysis: the target and each column written (no column
            // list = every column). No-op for tags.
            let schema = non_empty(&rv.schemaname);
            self.tags.write(schema, &rv.relname, None);
            if s.cols.is_empty() {
                self.tags.write(schema, &rv.relname, Some("*"));
            }
            for c in &s.cols {
                if let Some(NodeEnum::ResTarget(r)) = c.node.as_ref() {
                    self.tags.write(schema, &rv.relname, Some(&r.name));
                }
            }
        }
        let all = self.all;
        let res = (|| -> Result<Vec<OutCol>> {
            if let Some(src) = s.select_stmt.as_deref_mut() {
                let outs = self.query(src, None, depth + 1)?;
                for (j, c) in outs.iter().enumerate() {
                    let mut lin = outcol_all(self.tags, c);
                    // Writing a tagged column into itself is not a copy out.
                    // (The access analysis records the write itself instead.)
                    if let (false, Some(dest), Some(t)) = (
                        all,
                        s.cols.get(j).and_then(|n| match n.node.as_ref() {
                            Some(NodeEnum::ResTarget(r)) => Some(r.name.as_str()),
                            _ => None,
                        }),
                        target.as_ref(),
                    ) {
                        for k in t.column(self.tags, dest).keys() {
                            lin.remove(k);
                        }
                    }
                    self.touches.record(&lin, Sink::Copy);
                }
            }
            self.scopes.push();
            if let Some(t) = target.clone() {
                self.scopes.add(t);
            }
            let r = (|| -> Result<Vec<OutCol>> {
                if let Some(oc) = s.on_conflict_clause.as_deref_mut() {
                    if all {
                        // `EXCLUDED` is the row proposed for insertion: the
                        // target's columns.
                        if let Some(Item::Base { schema, table, .. }) = target.clone() {
                            self.scopes.add(Item::Base {
                                refname: "excluded".to_string(),
                                schema,
                                table,
                            });
                        }
                        if let Some(inf) = oc.infer.as_deref_mut() {
                            for e in inf.index_elems.iter_mut() {
                                if let Some(NodeEnum::IndexElem(ie)) = e.node.as_mut() {
                                    if !ie.name.is_empty() {
                                        self.scopes.column(self.tags, &[], &ie.name);
                                    }
                                    self.opt(ie.expr.as_deref_mut(), depth + 1)?;
                                }
                            }
                            self.opt(inf.where_clause.as_deref_mut(), depth + 1)?;
                        }
                        self.opt(oc.where_clause.as_deref_mut(), depth + 1)?;
                    }
                    self.set_list(&mut oc.target_list, target.as_ref(), depth + 1)?;
                }
                let (outs, _, _) = self.targets(&mut s.returning_list, sink, depth + 1)?;
                Ok(outs)
            })();
            self.scopes.pop();
            r
        })();
        if pushed {
            self.ctes.pop();
        }
        res
    }

    fn dml(
        &mut self,
        node: &mut NodeEnum,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        too_deep(depth)?;
        let with = match node {
            NodeEnum::UpdateStmt(s) => s.with_clause.as_mut(),
            NodeEnum::DeleteStmt(s) => s.with_clause.as_mut(),
            NodeEnum::MergeStmt(s) => s.with_clause.as_mut(),
            _ => return Ok(Vec::new()),
        };
        let pushed = self.push_ctes(with, depth + 1)?;
        self.scopes.push();
        let res = self.dml_body(node, sink, depth + 1);
        self.scopes.pop();
        if pushed {
            self.ctes.pop();
        }
        res
    }

    fn dml_body(
        &mut self,
        node: &mut NodeEnum,
        sink: Option<Sink>,
        depth: usize,
    ) -> Result<Vec<OutCol>> {
        match node {
            NodeEnum::UpdateStmt(s) => {
                let target = s.relation.as_ref().map(base_item);
                if let Some(rv) = s.relation.as_ref() {
                    self.tags
                        .write(non_empty(&rv.schemaname), &rv.relname, None);
                }
                if let Some(t) = target.clone() {
                    self.scopes.add(t);
                }
                for f in s.from_clause.iter_mut() {
                    for it in self.range_item(f, depth + 1)? {
                        self.scopes.add(it);
                    }
                }
                self.set_list(&mut s.target_list, target.as_ref(), depth + 1)?;
                if self.all {
                    self.opt(s.where_clause.as_deref_mut(), depth + 1)?;
                }
                Ok(self.targets(&mut s.returning_list, sink, depth + 1)?.0)
            }
            NodeEnum::DeleteStmt(s) => {
                if let Some(rv) = s.relation.as_ref() {
                    // Removing a row removes every column's value.
                    let schema = non_empty(&rv.schemaname);
                    self.tags.write(schema, &rv.relname, None);
                    self.tags.write(schema, &rv.relname, Some("*"));
                }
                if let Some(t) = s.relation.as_ref().map(base_item) {
                    self.scopes.add(t);
                }
                for f in s.using_clause.iter_mut() {
                    for it in self.range_item(f, depth + 1)? {
                        self.scopes.add(it);
                    }
                }
                if self.all {
                    self.opt(s.where_clause.as_deref_mut(), depth + 1)?;
                }
                Ok(self.targets(&mut s.returning_list, sink, depth + 1)?.0)
            }
            NodeEnum::MergeStmt(s) => {
                let target = s.relation.as_ref().map(base_item);
                let tgt = s.relation.as_ref().map(|rv| {
                    (
                        non_empty(&rv.schemaname).map(str::to_string),
                        rv.relname.clone(),
                    )
                });
                if let Some((schema, table)) = &tgt {
                    self.tags.write(schema.as_deref(), table, None);
                }
                if let Some(t) = target.clone() {
                    self.scopes.add(t);
                }
                if let Some(src) = s.source_relation.as_deref_mut() {
                    for it in self.range_item(src, depth + 1)? {
                        self.scopes.add(it);
                    }
                }
                if self.all {
                    self.opt(s.join_condition.as_deref_mut(), depth + 1)?;
                }
                for clause in s.merge_when_clauses.iter_mut() {
                    let Some(NodeEnum::MergeWhenClause(c)) = clause.node.as_mut() else {
                        continue;
                    };
                    if self.all {
                        self.opt(c.condition.as_deref_mut(), depth + 1)?;
                        if let Some((schema, table)) = &tgt {
                            let schema = schema.as_deref();
                            let insert = c.command_type == protobuf::CmdType::CmdInsert as i32;
                            let delete = c.command_type == protobuf::CmdType::CmdDelete as i32;
                            // DELETE removes whole rows; INSERT without a
                            // column list writes every column.
                            if delete || (insert && c.target_list.is_empty()) {
                                self.tags.write(schema, table, Some("*"));
                            } else if insert {
                                for n in &c.target_list {
                                    if let Some(NodeEnum::ResTarget(r)) = n.node.as_ref() {
                                        self.tags.write(schema, table, Some(&r.name));
                                    }
                                }
                            }
                        }
                    }
                    if c.values.is_empty() {
                        // WHEN MATCHED THEN UPDATE SET …
                        self.set_list(&mut c.target_list, target.as_ref(), depth + 1)?;
                    } else {
                        // WHEN NOT MATCHED THEN INSERT (cols) VALUES (…)
                        let dests: Vec<String> = c
                            .target_list
                            .iter()
                            .filter_map(|n| match n.node.as_ref() {
                                Some(NodeEnum::ResTarget(r)) => Some(r.name.clone()),
                                _ => None,
                            })
                            .collect();
                        for (j, v) in c.values.iter_mut().enumerate() {
                            let mut lin = self.expr(v, depth + 1)?;
                            if let (false, Some(dest), Some(t)) =
                                (self.all, dests.get(j), target.as_ref())
                            {
                                for k in t.column(self.tags, dest).keys() {
                                    lin.remove(k);
                                }
                            }
                            self.touches.record(&lin, Sink::Copy);
                        }
                    }
                }
                Ok(self.targets(&mut s.returning_list, sink, depth + 1)?.0)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// `SET col = expr, …`: each value is copied into `col`. Writing a tagged
    /// column into itself (`SET email = lower(email)`) is not a copy out.
    fn set_list(&mut self, list: &mut [Node], target: Option<&Item>, depth: usize) -> Result<()> {
        for n in list.iter_mut() {
            let Some(NodeEnum::ResTarget(rt)) = n.node.as_mut() else {
                continue;
            };
            let mut lin = match rt.val.as_deref_mut() {
                Some(v) => self.expr(v, depth + 1)?,
                None => Lineage::new(),
            };
            if self.all {
                // Access analysis: the column written.
                if let Some(Item::Base { schema, table, .. }) = target {
                    self.tags.write(schema.as_deref(), table, Some(&rt.name));
                }
                for ind in rt.indirection.iter_mut() {
                    if let Some(NodeEnum::AIndices(ix)) = ind.node.as_mut() {
                        self.opt(ix.lidx.as_deref_mut(), depth + 1)?;
                        self.opt(ix.uidx.as_deref_mut(), depth + 1)?;
                    }
                }
            } else if let Some(t) = target {
                for k in t.column(self.tags, &rt.name).keys() {
                    lin.remove(k);
                }
            }
            self.touches.record(&lin, Sink::Copy);
        }
        Ok(())
    }

    // ── FROM ────────────────────────────────────────────────────────────────

    fn range_item(&mut self, node: &mut Node, depth: usize) -> Result<Vec<Item>> {
        too_deep(depth)?;
        let Some(n) = node.node.as_mut() else {
            return Ok(Vec::new());
        };
        Ok(match n {
            NodeEnum::RangeVar(rv) => vec![self.range_var(rv)],
            NodeEnum::RangeSubselect(rs) => {
                let cols = match rs.subquery.as_deref_mut() {
                    Some(q) => self.query(q, None, depth + 1)?,
                    None => Vec::new(),
                };
                let names = rs
                    .alias
                    .as_ref()
                    .map(|a| a.colnames.as_slice())
                    .unwrap_or(&[]);
                vec![Item::Derived {
                    refname: alias_name(rs.alias.as_ref()),
                    cols: rename(cols, names),
                }]
            }
            NodeEnum::RangeFunction(rf) => {
                let mut lin = Lineage::new();
                for f in rf.functions.iter_mut() {
                    // Each entry is a List [function call, column definitions].
                    match f.node.as_mut() {
                        Some(NodeEnum::List(l)) => {
                            if let Some(call) = l.items.first_mut() {
                                merge(&mut lin, self.expr(call, depth + 1)?);
                            }
                        }
                        _ => merge(&mut lin, self.expr(f, depth + 1)?),
                    }
                }
                vec![Item::Opaque {
                    refname: alias_name(rf.alias.as_ref()),
                    lin: indirect(lin),
                }]
            }
            NodeEnum::JoinExpr(j) => {
                let mut items = Vec::new();
                if let Some(l) = j.larg.as_deref_mut() {
                    items.extend(self.range_item(l, depth + 1)?);
                }
                // A LATERAL item on the right may reference the left side:
                // make it visible while walking the right side.
                let mark = self.scopes.levels.last().map_or(0, Vec::len);
                for it in &items {
                    self.scopes.add(it.clone());
                }
                let right = match j.rarg.as_deref_mut() {
                    Some(r) => self.range_item(r, depth + 1),
                    None => Ok(Vec::new()),
                };
                if let Some(level) = self.scopes.levels.last_mut() {
                    level.truncate(mark);
                }
                items.extend(right?);
                if self.all {
                    // Access analysis: `ON`, `USING` and `NATURAL` read the
                    // join columns of both sides.
                    for it in &items {
                        self.scopes.add(it.clone());
                    }
                    let r = (|| -> Result<()> {
                        self.opt(j.quals.as_deref_mut(), depth + 1)?;
                        for u in &j.using_clause {
                            if let Some(name) = str_of(u) {
                                for it in &items {
                                    it.column(self.tags, name);
                                }
                            }
                        }
                        if j.is_natural {
                            // The common columns are unknown: every column.
                            for it in &items {
                                it.star_all(self.tags);
                            }
                        }
                        Ok(())
                    })();
                    if let Some(level) = self.scopes.levels.last_mut() {
                        level.truncate(mark);
                    }
                    r?;
                }
                vec![Item::Join {
                    refname: alias_name(j.alias.as_ref()),
                    items,
                }]
            }
            NodeEnum::RangeTableSample(t) => match t.relation.as_deref_mut() {
                Some(r) => self.range_item(r, depth + 1)?,
                None => Vec::new(),
            },
            other => {
                // XMLTABLE, JSON_TABLE, … : columns unknown, conservatively
                // derived from everything mentioned inside.
                let refname = serde_json::to_value(&*other).ok().and_then(|v| {
                    v.as_object()?
                        .values()
                        .next()?
                        .get("alias")?
                        .get("aliasname")?
                        .as_str()
                        .and_then(non_empty)
                        .map(str::to_string)
                });
                vec![Item::Opaque {
                    refname,
                    lin: self.fallback(other, depth + 1)?,
                }]
            }
        })
    }

    fn range_var(&self, rv: &RangeVar) -> Item {
        let refname = alias_name(rv.alias.as_ref()).unwrap_or_else(|| rv.relname.clone());
        if rv.schemaname.is_empty() {
            if let Some(cols) = self.find_cte(&rv.relname) {
                let names = rv
                    .alias
                    .as_ref()
                    .map(|a| a.colnames.as_slice())
                    .unwrap_or(&[]);
                return Item::Derived {
                    refname: Some(refname),
                    cols: rename(cols, names),
                };
            }
        }
        let schema = non_empty(&rv.schemaname).map(str::to_string);
        // Access analysis: a relation read. No-op for tags.
        self.tags.relation(schema.as_deref(), &rv.relname);
        if rv.alias.as_ref().is_some_and(|a| !a.colnames.is_empty()) {
            // `customers AS c(a, b)` renames columns by position, which the
            // engine cannot map without the schema: every column may be any tag.
            return Item::Opaque {
                refname: Some(refname),
                lin: indirect(self.tags.of_table(schema.as_deref(), &rv.relname)),
            };
        }
        Item::Base {
            refname,
            schema,
            table: rv.relname.clone(),
        }
    }

    // ── expressions ─────────────────────────────────────────────────────────

    fn exprs(&mut self, nodes: &mut [Node], depth: usize) -> Result<Lineage> {
        let mut out = Lineage::new();
        for n in nodes.iter_mut() {
            merge(&mut out, self.expr(n, depth)?);
        }
        Ok(out)
    }

    fn opt(&mut self, node: Option<&mut Node>, depth: usize) -> Result<Lineage> {
        match node {
            Some(n) => self.expr(n, depth),
            None => Ok(Lineage::new()),
        }
    }

    /// The tagged columns an expression derives from.
    fn expr(&mut self, node: &mut Node, depth: usize) -> Result<Lineage> {
        too_deep(depth)?;
        let d = depth + 1;
        let Some(n) = node.node.as_mut() else {
            return Ok(Lineage::new());
        };
        let lin = match n {
            NodeEnum::ColumnRef(c) => return Ok(self.column_ref(c)),
            NodeEnum::AConst(_) | NodeEnum::ParamRef(_) | NodeEnum::SqlvalueFunction(_) => {
                Lineage::new()
            }
            // Only the arguments are values. FILTER, ORDER BY and OVER decide
            // which rows or in what order — like WHERE, not projected.
            NodeEnum::FuncCall(f) => {
                if self.all {
                    if let Some(what) = set_config_target(f) {
                        // `set_config('search_path', …)` is `SET search_path`.
                        self.tags.statement(&what);
                    }
                    // Access analysis: these choose rows and order, which
                    // still reads the columns.
                    self.opt(f.agg_filter.as_deref_mut(), d)?;
                    self.exprs(&mut f.agg_order, d)?;
                    if let Some(w) = f.over.as_deref_mut() {
                        self.exprs(&mut w.partition_clause, d)?;
                        self.exprs(&mut w.order_clause, d)?;
                        self.opt(w.start_offset.as_deref_mut(), d)?;
                        self.opt(w.end_offset.as_deref_mut(), d)?;
                    }
                }
                self.exprs(&mut f.args, d)?
            }
            NodeEnum::SortBy(sb) if self.all => self.opt(sb.node.as_deref_mut(), d)?,
            NodeEnum::WindowDef(w) if self.all => {
                let mut l = self.exprs(&mut w.partition_clause, d)?;
                merge(&mut l, self.exprs(&mut w.order_clause, d)?);
                merge(&mut l, self.opt(w.start_offset.as_deref_mut(), d)?);
                merge(&mut l, self.opt(w.end_offset.as_deref_mut(), d)?);
                l
            }
            NodeEnum::GroupingSet(g) if self.all => self.exprs(&mut g.content, d)?,
            NodeEnum::AExpr(a) => {
                let mut l = self.opt(a.lexpr.as_deref_mut(), d)?;
                merge(&mut l, self.opt(a.rexpr.as_deref_mut(), d)?);
                l
            }
            NodeEnum::BoolExpr(b) => self.exprs(&mut b.args, d)?,
            NodeEnum::TypeCast(t) => self.opt(t.arg.as_deref_mut(), d)?,
            NodeEnum::CollateClause(c) => self.opt(c.arg.as_deref_mut(), d)?,
            NodeEnum::NullTest(t) => self.opt(t.arg.as_deref_mut(), d)?,
            NodeEnum::BooleanTest(t) => self.opt(t.arg.as_deref_mut(), d)?,
            NodeEnum::CaseExpr(c) => {
                let mut l = self.opt(c.arg.as_deref_mut(), d)?;
                merge(&mut l, self.exprs(&mut c.args, d)?);
                merge(&mut l, self.opt(c.defresult.as_deref_mut(), d)?);
                l
            }
            NodeEnum::CaseWhen(w) => {
                let mut l = self.opt(w.expr.as_deref_mut(), d)?;
                merge(&mut l, self.opt(w.result.as_deref_mut(), d)?);
                l
            }
            NodeEnum::CoalesceExpr(c) => self.exprs(&mut c.args, d)?,
            NodeEnum::MinMaxExpr(m) => self.exprs(&mut m.args, d)?,
            NodeEnum::AArrayExpr(a) => self.exprs(&mut a.elements, d)?,
            NodeEnum::RowExpr(r) => self.exprs(&mut r.args, d)?,
            NodeEnum::AIndirection(i) => {
                let mut l = self.opt(i.arg.as_deref_mut(), d)?;
                for ind in i.indirection.iter_mut() {
                    if let Some(NodeEnum::AIndices(ix)) = ind.node.as_mut() {
                        merge(&mut l, self.opt(ix.lidx.as_deref_mut(), d)?);
                        merge(&mut l, self.opt(ix.uidx.as_deref_mut(), d)?);
                    }
                }
                l
            }
            NodeEnum::NamedArgExpr(a) => self.opt(a.arg.as_deref_mut(), d)?,
            NodeEnum::GroupingFunc(g) => self.exprs(&mut g.args, d)?,
            NodeEnum::List(l) => self.exprs(&mut l.items, d)?,
            NodeEnum::ResTarget(r) => self.opt(r.val.as_deref_mut(), d)?,
            NodeEnum::MultiAssignRef(m) => self.opt(m.source.as_deref_mut(), d)?,
            NodeEnum::SubLink(sl) => {
                let kind = sl.sub_link_type;
                if kind == SubLinkType::ExistsSublink as i32 {
                    // EXISTS projects a boolean about rows, not their values.
                    // The access analysis still reads what is inside.
                    if self.all {
                        if let Some(q) = sl.subselect.as_deref_mut() {
                            self.query(q, None, d)?;
                        }
                    }
                    return Ok(Lineage::new());
                }
                let cols = match sl.subselect.as_deref_mut() {
                    Some(q) => self.query(q, None, d)?,
                    None => Vec::new(),
                };
                if kind == SubLinkType::ExprSublink as i32 {
                    // `(SELECT email FROM …)` IS the value: keep directness.
                    return Ok(cols
                        .first()
                        .map(|c| outcol_all(self.tags, c))
                        .unwrap_or_default());
                }
                let mut l = self.opt(sl.testexpr.as_deref_mut(), d)?;
                merge(&mut l, outcols_all(self.tags, &cols));
                l
            }
            other => self.fallback(other, d)?,
        };
        Ok(indirect(lin))
    }

    fn column_ref(&self, c: &ColumnRef) -> Lineage {
        let star = matches!(
            c.fields.last().and_then(|f| f.node.as_ref()),
            Some(NodeEnum::AStar(_))
        );
        let names: Vec<&str> = c.fields.iter().filter_map(str_of).collect();
        if star {
            return self.scopes.star(self.tags, &names).0;
        }
        match names.as_slice() {
            [] => Lineage::new(),
            [one] => {
                // A bare name is a column — or a whole-row reference to a
                // relation of that name. Both, conservatively.
                let mut l = self.scopes.column(self.tags, &[], one);
                merge(&mut l, self.scopes.whole_row(self.tags, one));
                l
            }
            [q @ .., col] => self.scopes.column(self.tags, q, col),
        }
    }

    /// Conservative derivation for a node the walker does not model: every
    /// column reference anywhere inside it, resolved in scope AND by name
    /// against every tag; every star or whole-row reference over every tagged
    /// table mentioned inside.
    fn fallback(&self, node: &NodeEnum, depth: usize) -> Result<Lineage> {
        let json = serde_json::to_value(node).unwrap_or(serde_json::Value::Null);
        let mut refs: Vec<(Vec<String>, bool)> = Vec::new();
        let mut rels: Vec<(Option<String>, String)> = Vec::new();
        collect_json(&json, depth, &mut refs, &mut rels)?;
        // Access analysis: every relation mentioned inside is read.
        for (s, t) in &rels {
            if s.is_some() || self.find_cte(t).is_none() {
                self.tags.relation(s.as_deref(), t);
            }
        }
        let mut out = Lineage::new();
        for (names, star) in &refs {
            let v: Vec<&str> = names.iter().map(String::as_str).collect();
            if *star {
                merge(&mut out, self.scopes.star(self.tags, &v).0);
                for (s, t) in &rels {
                    merge(&mut out, starred(self.tags.of_table(s.as_deref(), t)));
                }
                continue;
            }
            match v.as_slice() {
                [] => {}
                [one] => {
                    merge(&mut out, self.scopes.column(self.tags, &[], one));
                    merge(&mut out, self.scopes.whole_row(self.tags, one));
                    merge(&mut out, self.tags.any_with_column(one));
                    if self.all {
                        // Access analysis: the name may belong to a relation
                        // read inside the unmodelled node (a subquery passed
                        // to XMLTABLE, …), whose scope is not modelled.
                        for (s, t) in &rels {
                            merge(&mut out, self.tags.of_column(s.as_deref(), t, one));
                        }
                    }
                    for (s, t) in &rels {
                        if crate::sensitive::ieq(t, one) {
                            merge(&mut out, starred(self.tags.of_table(s.as_deref(), t)));
                        }
                    }
                }
                [q @ .., col] => {
                    merge(&mut out, self.scopes.column(self.tags, q, col));
                    merge(&mut out, self.tags.any_with_column(col));
                }
            }
        }
        Ok(indirect(out))
    }
}

/// Access analysis: `set_config(name, …)` changes a setting like `SET` does.
/// The settings an allowlist depends on (who the session is, where
/// unqualified names resolve) are denied as their `SET` form; a name that is
/// not a literal could be any of them.
fn set_config_target(f: &protobuf::FuncCall) -> Option<String> {
    let name = f.funcname.iter().rev().find_map(str_of)?;
    if !name.eq_ignore_ascii_case("set_config") {
        return None;
    }
    let setting = f.args.first().and_then(|a| match a.node.as_ref() {
        Some(NodeEnum::AConst(c)) => match c.val.as_ref() {
            Some(protobuf::a_const::Val::Sval(s)) => Some(s.sval.to_ascii_lowercase()),
            _ => None,
        },
        _ => None,
    });
    match setting.as_deref() {
        Some("search_path") => Some("SET search_path".to_string()),
        Some("role") => Some("SET ROLE".to_string()),
        Some("session_authorization") => Some("SET SESSION AUTHORIZATION".to_string()),
        Some(_) => None,
        None => Some("set_config".to_string()),
    }
}

/// JSON walk for [`Walker::fallback`]. The protobuf serializes as
/// `{"ColumnRef": {"fields": [{"node": {"String": {"sval": …}}}, …]}}`.
fn collect_json(
    v: &serde_json::Value,
    depth: usize,
    refs: &mut Vec<(Vec<String>, bool)>,
    rels: &mut Vec<(Option<String>, String)>,
) -> Result<()> {
    use serde_json::Value;
    // JSON nests ~3 levels per AST level.
    if depth > MAX_AST_DEPTH * 4 {
        return Err(ProxyError::AstTooDeep);
    }
    match v {
        Value::Object(map) => {
            if let Some(Value::Object(cr)) = map.get("ColumnRef") {
                let mut names = Vec::new();
                let mut star = false;
                if let Some(Value::Array(fields)) = cr.get("fields") {
                    for f in fields {
                        let node = f.get("node");
                        if let Some(s) = node
                            .and_then(|n| n.get("String"))
                            .and_then(|s| s.get("sval"))
                            .and_then(Value::as_str)
                        {
                            names.push(s.to_string());
                        } else if node.and_then(|n| n.get("AStar")).is_some() {
                            star = true;
                        }
                    }
                }
                refs.push((names, star));
            }
            if let Some(Value::Object(rv)) = map.get("RangeVar") {
                let rel = rv.get("relname").and_then(Value::as_str).unwrap_or("");
                let sch = rv.get("schemaname").and_then(Value::as_str).unwrap_or("");
                if !rel.is_empty() {
                    rels.push((non_empty(sch).map(str::to_string), rel.to_string()));
                }
            }
            for child in map.values() {
                collect_json(child, depth + 1, refs, rels)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_json(child, depth + 1, refs, rels)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The base-table item for a DML target (never a CTE).
fn base_item(rv: &RangeVar) -> Item {
    Item::Base {
        refname: alias_name(rv.alias.as_ref()).unwrap_or_else(|| rv.relname.clone()),
        schema: non_empty(&rv.schemaname).map(str::to_string),
        table: rv.relname.clone(),
    }
}

/// `*` → `Some([])`, `t.*` → `Some(["t"])`; `None` when not a star.
fn star_qualifier(val: &Node) -> Option<Vec<String>> {
    let Some(NodeEnum::ColumnRef(c)) = val.node.as_ref() else {
        return None;
    };
    if !matches!(
        c.fields.last().and_then(|f| f.node.as_ref()),
        Some(NodeEnum::AStar(_))
    ) {
        return None;
    }
    Some(
        c.fields
            .iter()
            .filter_map(str_of)
            .map(str::to_string)
            .collect(),
    )
}

/// Postgres's own output-name rule (`FigureColname`), for the cases that
/// matter here: a masked target keeps the name the client expected.
fn figure_colname(val: Option<&Node>) -> String {
    figure(val).unwrap_or_else(|| "?column?".to_string())
}

fn figure(val: Option<&Node>) -> Option<String> {
    let n = val?.node.as_ref()?;
    match n {
        NodeEnum::ColumnRef(c) => c.fields.iter().rev().find_map(str_of).map(str::to_string),
        NodeEnum::AIndirection(i) => i
            .indirection
            .iter()
            .rev()
            .find_map(str_of)
            .map(str::to_string)
            .or_else(|| figure(i.arg.as_deref())),
        NodeEnum::FuncCall(f) => f.funcname.iter().rev().find_map(str_of).map(str::to_string),
        NodeEnum::AExpr(a) if a.kind == protobuf::AExprKind::AexprNullif as i32 => {
            Some("nullif".to_string())
        }
        NodeEnum::TypeCast(t) => figure(t.arg.as_deref()).or_else(|| {
            t.type_name
                .as_ref()
                .and_then(|tn| tn.names.iter().rev().find_map(str_of))
                .map(str::to_string)
        }),
        NodeEnum::CollateClause(c) => figure(c.arg.as_deref()),
        NodeEnum::CaseExpr(_) => Some("case".to_string()),
        NodeEnum::AArrayExpr(_) => Some("array".to_string()),
        NodeEnum::RowExpr(_) => Some("row".to_string()),
        NodeEnum::CoalesceExpr(_) => Some("coalesce".to_string()),
        NodeEnum::MinMaxExpr(m) => Some(
            if m.op == protobuf::MinMaxOp::IsGreatest as i32 {
                "greatest"
            } else {
                "least"
            }
            .to_string(),
        ),
        NodeEnum::SubLink(sl) => match SubLinkType::try_from(sl.sub_link_type) {
            Ok(SubLinkType::ExistsSublink) => Some("exists".to_string()),
            Ok(SubLinkType::ArraySublink) => Some("array".to_string()),
            Ok(SubLinkType::ExprSublink) => {
                match sl.subselect.as_deref().and_then(|s| s.node.as_ref()) {
                    Some(NodeEnum::SelectStmt(s)) => first_target_name(s),
                    _ => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn first_target_name(s: &SelectStmt) -> Option<String> {
    if let Some(l) = s.larg.as_deref() {
        return first_target_name(l);
    }
    match s.target_list.first().and_then(|t| t.node.as_ref()) {
        Some(NodeEnum::ResTarget(rt)) if !rt.name.is_empty() => Some(rt.name.clone()),
        Some(NodeEnum::ResTarget(rt)) => figure(rt.val.as_deref()),
        _ => None,
    }
}

/// After masking, an `ORDER BY` / `GROUP BY` item that referred to a rewritten
/// output (by its name, or by position) would now sort or group by the MASKED
/// value — `ORDER BY email` resolves to the output column first. Point it back
/// at the original expression so rows come back in the same order and groups.
/// A bare column is wrapped as `COALESCE(col)`: still the input column, but no
/// longer a bare name the output alias can capture. Positions are only fixed
/// when no `*` precedes them (a star has unknown width).
fn fix_order_and_group(s: &mut SelectStmt, rewritten: &[(usize, String, Node)], has_star: bool) {
    let lookup = |n: &Node| -> Option<&Node> {
        match n.node.as_ref()? {
            NodeEnum::ColumnRef(c) if c.fields.len() == 1 => {
                let name = str_of(&c.fields[0])?;
                rewritten
                    .iter()
                    .find(|(_, out, _)| out == name)
                    .map(|(_, _, o)| o)
            }
            NodeEnum::AConst(a) if !has_star => match a.val.as_ref()? {
                protobuf::a_const::Val::Ival(i) => {
                    let pos = usize::try_from(i.ival).ok()?.checked_sub(1)?;
                    rewritten
                        .iter()
                        .find(|(p, _, _)| *p == pos)
                        .map(|(_, _, o)| o)
                }
                _ => None,
            },
            _ => None,
        }
    };
    for item in s.sort_clause.iter_mut() {
        let Some(NodeEnum::SortBy(sb)) = item.node.as_mut() else {
            continue;
        };
        let Some(key) = sb.node.as_deref() else {
            continue;
        };
        if let Some(orig) = lookup(key) {
            let replacement = if matches!(orig.node, Some(NodeEnum::ColumnRef(_))) {
                Node {
                    node: Some(NodeEnum::CoalesceExpr(Box::new(CoalesceExpr {
                        args: vec![orig.clone()],
                        location: -1,
                        ..Default::default()
                    }))),
                }
            } else {
                orig.clone()
            };
            sb.node = Some(Box::new(replacement));
        }
    }
    for item in s.group_clause.iter_mut() {
        if let Some(orig) = lookup(item) {
            *item = orig.clone();
        }
    }
}

// ── mask expressions ───────────────────────────────────────────────────────

const MASK_ARG: &str = "vericto_mask_arg";

/// Design §5.4, built from SQL templates parsed once by Postgres's own parser,
/// with the original expression spliced in for the placeholder. Two deliberate
/// departures from the design text, both fail-safe:
/// - `email` uses `^(.)[^@]*(@.*)?$`, so a value with no `@` is still masked
///   (`'^(.).*(@.*)$'` would not match it and return it in clear);
/// - `hash` hashes `convert_to(x::text, 'UTF8')` instead of `x::text::bytea`,
///   which fails on any text containing a backslash.
static TEMPLATES: OnceLock<[Node; 5]> = OnceLock::new();

fn template(style: MaskStyle) -> &'static Node {
    let all = TEMPLATES.get_or_init(|| {
        let parse = |sql: &str| -> Node {
            let tree = pg_query::parse(sql).expect("mask template parses");
            let stmt = tree.protobuf.stmts[0]
                .stmt
                .as_ref()
                .and_then(|s| s.node.as_ref())
                .cloned();
            match stmt {
                Some(NodeEnum::SelectStmt(s)) => match s.target_list[0].node.as_ref() {
                    Some(NodeEnum::ResTarget(rt)) => *rt.val.clone().expect("template value"),
                    _ => unreachable!("template is a SELECT of one expression"),
                },
                _ => unreachable!("template is a SELECT"),
            }
        };
        [
            parse("SELECT '[redacted]'::text"),
            parse("SELECT '****' || right(vericto_mask_arg::text, 4)"),
            parse(r"SELECT regexp_replace(vericto_mask_arg::text, '^(.)[^@]*(@.*)?$', '\1***\2')"),
            parse("SELECT encode(sha256(convert_to(vericto_mask_arg::text, 'UTF8')), 'hex')"),
            parse("SELECT concat('[redacted]'::text, left(vericto_mask_arg::text, 0))"),
        ]
    });
    match style {
        MaskStyle::Full => &all[0],
        MaskStyle::Last4 => &all[1],
        MaskStyle::Email => &all[2],
        MaskStyle::Hash => &all[3],
    }
}

/// `full` for an expression that contains bind parameters:
/// `concat('[redacted]'::text, left((expr)::text, 0))`.
///
/// Plain `'[redacted]'` would drop every `$n` inside the replaced expression,
/// and a client that binds them then fails the extended protocol on a
/// parameter-count mismatch. This keeps the original expression, so every
/// parameter stays present AND keeps the type Postgres infers for it from the
/// same context (`substring(card, $1, 4)` still types `$1` as integer). A
/// `CASE WHEN $1 IS NULL …` wrapper would keep the count but leave an
/// untyped `$1` ("could not determine data type of parameter"), and CASE /
/// COALESCE reject set-returning functions. `left(x, 0)` is `''` for any
/// non-NULL x and NULL for NULL, and `concat` ignores NULL, so the result is
/// always exactly `'[redacted]'`: neither the value nor its NULL-ness leaks.
fn full_keeping_params() -> &'static Node {
    // `template` initialises every entry, including this one.
    let _ = template(MaskStyle::Full);
    &TEMPLATES.get().expect("templates initialised")[4]
}

/// Whether a node contains a bind parameter anywhere inside it.
fn has_param(node: &Node) -> bool {
    fn walk(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::Object(m) => m.contains_key("ParamRef") || m.values().any(walk),
            serde_json::Value::Array(a) => a.iter().any(walk),
            _ => false,
        }
    }
    // Serialization of the protobuf cannot fail; if it ever did, keep the
    // expression (the parameter-preserving form is correct either way).
    serde_json::to_value(node).map_or(true, |v| walk(&v))
}

/// A bare column or a scalar subquery: replacing it with a constant changes
/// nothing but the value. Any other expression may be an aggregate
/// (`string_agg(email, ',')`) or a set-returning function, and replacing it
/// with a constant would change how many rows come back.
fn plain_value(node: &Node) -> bool {
    match node.node.as_ref() {
        Some(NodeEnum::ColumnRef(_)) => true,
        Some(NodeEnum::SubLink(sl)) => sl.sub_link_type == SubLinkType::ExprSublink as i32,
        _ => false,
    }
}

/// The mask expression for `style` applied to `orig`. `full` over a bare
/// column discards `orig` entirely, so nothing of the value (not even its
/// NULL-ness) reaches the client. Over a computed expression it keeps the
/// expression and discards its value at run time ([`full_keeping_params`]):
/// bind parameters must stay in the statement, and an aggregate or a
/// set-returning function must still decide how many rows come back
/// (`'[redacted]'` in place of `string_agg(email, ',')` returns one row per
/// input row instead of one).
pub(crate) fn mask_node(style: MaskStyle, orig: Node) -> Node {
    let base = if style == MaskStyle::Full && (has_param(&orig) || !plain_value(&orig)) {
        full_keeping_params()
    } else {
        template(style)
    };
    let mut out = base.clone();
    let mut orig = Some(orig);
    splice(&mut out, &mut orig);
    out
}

fn splice(node: &mut Node, orig: &mut Option<Node>) {
    let is_placeholder = matches!(
        node.node.as_ref(),
        Some(NodeEnum::ColumnRef(c)) if c.fields.len() == 1 && str_of(&c.fields[0]) == Some(MASK_ARG)
    );
    if is_placeholder {
        if let Some(o) = orig.take() {
            *node = o;
        }
        return;
    }
    match node.node.as_mut() {
        Some(NodeEnum::FuncCall(f)) => f.args.iter_mut().for_each(|a| splice(a, orig)),
        Some(NodeEnum::AExpr(a)) => {
            if let Some(l) = a.lexpr.as_deref_mut() {
                splice(l, orig);
            }
            if let Some(r) = a.rexpr.as_deref_mut() {
                splice(r, orig);
            }
        }
        Some(NodeEnum::TypeCast(t)) => {
            if let Some(a) = t.arg.as_deref_mut() {
                splice(a, orig);
            }
        }
        _ => {}
    }
}
