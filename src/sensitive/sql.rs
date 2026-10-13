//! Sensitive-column derivation over the `sqlparser-rs` AST (MySQL, Oracle,
//! MS SQL). Same model as [`super::pg`] — same scopes, same sinks, same
//! conservative rules. On MySQL the walk also applies the mask rewrite to the
//! client-visible projections (Oracle and MS SQL still block a mask); the
//! text it walks and the text it emits go through [`super::mysql`], which
//! reads and prints them the way MySQL does.

use sqlparser::ast::{
    AccessExpr, Assignment, AssignmentTarget, Cte, Expr, FromTable, FunctionArg, FunctionArgExpr,
    FunctionArguments, GroupByExpr, Ident, LimitClause, MergeAction, MergeInsertKind,
    MergeUpdateKind, ObjectName, OnConflictAction, OnInsert, OrderBy, OrderByKind, OutputClause,
    Query, Select, SelectItem, SelectItemQualifiedWildcardKind, SetExpr, Statement, Subscript,
    TableAlias, TableFactor, TableObject, TableWithJoins, UpdateTableFromKind, Value,
    ValueWithSpan,
};

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::sensitive::mysql::{self, Prepared};
use crate::sensitive::{
    Item, Lineage, OutCol, Scopes, Sink, Tags, Touches, ieq, indirect, mask_style_for, merge,
    name_part, name_parts, outcol_all, outcols_all, starred,
};

/// Why the MySQL analysis could not run.
pub(crate) enum Failure {
    /// Nesting past [`MAX_AST_DEPTH`].
    TooDeep(ProxyError),
    /// The text cannot be read the way MySQL reads it (see [`mysql`]).
    Unreadable(String),
}

/// Snowflake: derivation, and the mask rewrite when `any_mask`, rendered
/// and checked by [`super::snowflake::render`] against the client's text.
pub(crate) fn analyze_snowflake(
    statements: &[Statement],
    sql: &str,
    tags: &Tags,
    any_mask: bool,
) -> Result<(Touches, super::pg::Rewrite)> {
    let mut statements = statements.to_vec();
    let original = any_mask.then(|| statements.clone());
    let mut w = Walker::new(tags, any_mask, None);
    w.snowflake = true;
    for s in statements.iter_mut() {
        w.stmt(s, 0)?;
    }
    let (touches, rewrote, refused) = (w.touches, w.rewrote, w.refused);
    if !rewrote {
        return Ok((touches, None));
    }
    let rewrite = match refused {
        Some(why) => Err(why),
        None => super::snowflake::render(sql, original.as_deref().unwrap_or_default(), &statements),
    };
    Ok((touches, Some(rewrite)))
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

/// The access analysis (VERICTO-087) of one statement: the same walk, with
/// `tags` collecting every resolution and every clause visited (see
/// [`crate::access`]). `mysql`: `"x"` may be a column (`ANSI_QUOTES`). The
/// statement is the caller's clone; nothing is rewritten.
pub(crate) fn access_walk(
    stmt: &mut Statement,
    tags: &Tags,
    dialect: crate::parser::Dialect,
) -> Result<()> {
    let mut w = Walker::new(tags, false, None);
    w.all = true;
    w.ansi_quotes = dialect == crate::parser::Dialect::Mysql;
    w.oracle = dialect == crate::parser::Dialect::Oracle;
    w.snowflake = dialect == crate::parser::Dialect::Snowflake;
    w.stmt(stmt, 0)
}

/// Oracle pseudo-columns: values the server supplies, not table columns.
fn is_oracle_pseudo_column(name: &str) -> bool {
    [
        "rownum",
        "rowid",
        "level",
        "sysdate",
        "systimestamp",
        "user",
        "uid",
        "ora_rowscn",
        "connect_by_isleaf",
        "connect_by_iscycle",
    ]
    .iter()
    .any(|p| p.eq_ignore_ascii_case(name))
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
    /// `"x"` may be the column `x` (MySQL, whose `ANSI_QUOTES` the engine
    /// cannot see).
    ansi_quotes: bool,
    /// Oracle: `ROWNUM`, `LEVEL`, … are pseudo-columns (access analysis).
    oracle: bool,
    /// Snowflake: three-part names and stages (access analysis), dynamic
    /// table functions denied (access analysis), and the Snowflake mask
    /// rewrite (see [`super::snowflake`]).
    snowflake: bool,
    /// The access analysis: every clause counts (WHERE, JOIN, GROUP BY, …),
    /// not only what is projected, and tables and write targets are recorded.
    all: bool,
    /// Access analysis: the locking clauses (`FOR UPDATE/SHARE`) of the query
    /// whose simple `SELECT` is walked next — `(no OF, the OF names)`. Taken by
    /// that `SELECT`, so nested queries never inherit it.
    lock: Option<(bool, Vec<ObjectName>)>,
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
    let parts = name_parts(name);
    let table = parts.last().map(|p| p.to_string()).unwrap_or_default();
    // SQL Server's `db..t` (which sqlparser 0.52 rejected) leaves the schema
    // empty: it is the default schema, i.e. unqualified, not a schema named
    // "" that no tag would match.
    let schema = if parts.len() >= 2 {
        Some(parts[parts.len() - 2])
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    } else {
        None
    };
    (schema, table)
}

/// Snowflake's `db.schema.table` → (`DB\u{1f}SCHEMA`, table) for the access
/// analysis, which must tell databases apart (see `access::DB_SEP`); two-
/// and one-part names as [`split_name`]. A stage reference (`@stage/path`,
/// `@db.schema.stage`, `@~`, `@%t`) is the stage, as a relation: reading
/// staged files needs an entry naming it.
pub(crate) fn split_name_snowflake(name: &ObjectName) -> (Option<String>, String) {
    let parts = name_parts(name);
    if parts.first().is_some_and(|p| p.starts_with('@')) {
        let full = parts.join(".");
        let stage = full.split('/').next().unwrap_or(&full);
        return (None, stage.to_string());
    }
    match parts.as_slice() {
        [.., db, schema, table] => (
            Some(format!("{db}{}{schema}", crate::access::DB_SEP)),
            table.to_string(),
        ),
        _ => split_name(name),
    }
}

/// The column a column list names. Since sqlparser 0.62 an `INSERT`/`MERGE`
/// column list holds names, not identifiers; a qualified one (`t.col`) is
/// still the column `col` of the target.
fn column_of(name: &ObjectName) -> String {
    name.0.last().map(name_part).unwrap_or_default().to_string()
}

fn rename(mut cols: Vec<OutCol>, alias: Option<&TableAlias>) -> Vec<OutCol> {
    let Some(a) = alias else { return cols };
    if a.columns.is_empty() || cols.iter().any(|c| !matches!(c, OutCol::Named { .. })) {
        return cols;
    }
    for (c, n) in cols.iter_mut().zip(&a.columns) {
        if let OutCol::Named { name, .. } = c {
            *name = n.name.value.clone();
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

/// The dotted name a field-access chain spells, when every part is a name:
/// an identifier, or (`ansi_quotes`) a double-quoted string MySQL may read as
/// one. `None` for a subscript or any other part.
fn dotted_name(root: &Expr, chain: &[AccessExpr], ansi_quotes: bool) -> Option<Vec<Ident>> {
    let name = |e: &Expr| match e {
        Expr::Identifier(i) => Some(i.clone()),
        Expr::Value(ValueWithSpan {
            value: Value::DoubleQuotedString(s),
            ..
        }) if ansi_quotes => Some(Ident::with_quote('"', s.clone())),
        _ => None,
    };
    let mut out = vec![name(root)?];
    for a in chain {
        match a {
            AccessExpr::Dot(e) => out.push(name(e)?),
            AccessExpr::Subscript(_) => return None,
        }
    }
    Some(out)
}

/// A 1-based position (`ORDER BY 2`, `GROUP BY 1`) → 0-based index.
fn position(e: &Expr) -> Option<usize> {
    match e {
        Expr::Value(ValueWithSpan {
            value: Value::Number(n, _),
            ..
        }) => n.parse::<usize>().ok()?.checked_sub(1),
        _ => None,
    }
}

impl<'a, 't, 'p, 's> Walker<'a, 't, 'p, 's> {
    /// `[db.]schema.table` → (schema, table); on Snowflake's access analysis
    /// the database is kept (see [`split_name_snowflake`]).
    fn split(&self, name: &ObjectName) -> (Option<String>, String) {
        if self.snowflake && self.all {
            split_name_snowflake(name)
        } else {
            split_name(name)
        }
    }

    /// Snowflake's access analysis: a table function whose rows are computed
    /// from its arguments only (`FLATTEN`, `SPLIT_TO_TABLE`, `GENERATOR`, …)
    /// reads nothing else. Any other one may read anything (`RESULT_SCAN` of
    /// another query, `INFORMATION_SCHEMA.QUERY_HISTORY()`, a UDTF, `TABLE($t)`
    /// naming a table at run time): denied outright.
    fn snowflake_table_function(&self, name: Option<&ObjectName>) {
        const PURE: &[&str] = &[
            "FLATTEN",
            "SPLIT_TO_TABLE",
            "STRTOK_SPLIT_TO_TABLE",
            "GENERATOR",
        ];
        if !(self.snowflake && self.all) {
            return;
        }
        let pure =
            name.is_some_and(|n| n.0.len() == 1 && PURE.iter().any(|p| ieq(p, name_part(&n.0[0]))));
        if !pure {
            let what = name.map_or_else(|| "TABLE(…)".to_string(), |n| format!("TABLE({n}(…))"));
            self.tags.statement(&what);
        }
    }

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
            ansi_quotes: mysql.is_some(),
            oracle: false,
            snowflake: false,
            all: false,
            lock: None,
        }
    }

    /// Access analysis: the tables an assignment target `[q.]col` writes to.
    /// Qualified: what the qualifier names in scope (or the qualifier itself
    /// as a table); unqualified: the statement's target.
    fn write_targets(
        &self,
        n: &ObjectName,
        target: Option<&Item>,
    ) -> Vec<(Option<String>, String)> {
        let parts = name_parts(n);
        match parts.as_slice() {
            [] => Vec::new(),
            [_] => match target {
                Some(Item::Base { schema, table, .. }) => vec![(schema.clone(), table.clone())],
                _ => Vec::new(),
            },
            [q @ .., _] => {
                let found = self.scopes.base_tables(q);
                if found.is_empty() {
                    let q = &q[q.len().saturating_sub(2)..];
                    match q {
                        [t] => vec![(None, t.to_string())],
                        [s, t] => vec![(Some(s.to_string()), t.to_string())],
                        _ => Vec::new(),
                    }
                } else {
                    found
                }
            }
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
                let (schema, table) = match &ins.table {
                    TableObject::TableName(name) => self.split(name),
                    // `INSERT INTO TABLE FUNCTION f(…)` / `INSERT INTO (SELECT …)`
                    // (ClickHouse, Oracle): no table name the engine can
                    // resolve. Recorded under the statement's own text, which
                    // matches no tag and no allowlist entry: denied under an
                    // allowlist.
                    other => (None, other.to_string()),
                };
                // Access analysis: the target and each column written (no
                // column list, or REPLACE, which deletes rows: every column).
                // MySQL's `INSERT … SET a = …` (parsed since sqlparser 0.54)
                // names its columns in the assignments, walked below.
                self.tags.write(schema.as_deref(), &table, None);
                if (ins.columns.is_empty() && ins.assignments.is_empty()) || ins.replace_into {
                    self.tags.write(schema.as_deref(), &table, Some("*"));
                }
                for c in &ins.columns {
                    self.tags
                        .write(schema.as_deref(), &table, Some(&column_of(c)));
                }
                let target = Item::Base {
                    refname: ins
                        .table_alias
                        .as_ref()
                        .map(|a| a.alias.value.clone())
                        .unwrap_or_else(|| table.clone()),
                    schema,
                    table,
                };
                if let Some(src) = ins.source.as_deref_mut() {
                    let outs = self.query(src, None, d)?;
                    for (j, c) in outs.iter().enumerate() {
                        let mut lin = outcol_all(self.tags, c);
                        if let (false, Some(dest)) = (self.all, ins.columns.get(j)) {
                            for k in target.column(self.tags, &column_of(dest)).keys() {
                                lin.remove(k);
                            }
                        }
                        self.touches.record(&lin, Sink::Copy);
                    }
                }
                // MySQL's `INSERT INTO t SET a = <expr>, …` stores each value
                // like `UPDATE … SET`.
                if !ins.assignments.is_empty() {
                    self.scopes.push();
                    let r = self.assignments(&mut ins.assignments, Some(&target), d);
                    self.scopes.pop();
                    r?;
                }
                // `ON DUPLICATE KEY UPDATE x = <expr>` / `ON CONFLICT DO
                // UPDATE SET x = <expr>` store a value like `UPDATE … SET`.
                let mut conflict_cols: Vec<String> = Vec::new();
                let mut upsert_where: Option<&mut Expr> = None;
                let upsert = match ins.on.as_mut() {
                    Some(OnInsert::DuplicateKeyUpdate(a)) => Some(a),
                    Some(OnInsert::OnConflict(oc)) => {
                        if let Some(sqlparser::ast::ConflictTarget::Columns(cols)) =
                            &oc.conflict_target
                        {
                            conflict_cols = cols.iter().map(|c| c.value.clone()).collect();
                        }
                        match &mut oc.action {
                            OnConflictAction::DoUpdate(u) => {
                                upsert_where = u.selection.as_mut();
                                Some(&mut u.assignments)
                            }
                            OnConflictAction::DoNothing => None,
                        }
                    }
                    _ => None,
                };
                if self.all && !conflict_cols.is_empty() {
                    for c in &conflict_cols {
                        target.column(self.tags, c);
                    }
                }
                if let Some(assignments) = upsert {
                    self.scopes.push();
                    self.scopes.add(target.clone());
                    if self.all {
                        // `EXCLUDED` is the proposed row: the target's columns.
                        if let Item::Base { schema, table, .. } = &target {
                            self.scopes.add(Item::Base {
                                refname: "excluded".to_string(),
                                schema: schema.clone(),
                                table: table.clone(),
                            });
                        }
                    }
                    let r = self
                        .assignments(assignments, Some(&target), d)
                        .and_then(|()| match (self.all, upsert_where) {
                            (true, Some(w)) => self.expr(w, d).map(|_| ()),
                            _ => Ok(()),
                        });
                    self.scopes.pop();
                    r?;
                }
                if let Some(ret) = ins.returning.as_mut() {
                    self.scopes.push();
                    self.scopes.add(target.clone());
                    let r = self.projection(ret, Some(visible), d);
                    self.scopes.pop();
                    r?;
                }
                if let Some(out) = ins.output.as_mut() {
                    self.output(out, std::slice::from_ref(&target), visible, d)?;
                }
            }
            Statement::Update(sqlparser::ast::Update {
                table,
                assignments,
                from,
                selection,
                returning,
                output,
                order_by,
                limit,
                ..
            }) => {
                self.scopes.push();
                let r = (|| -> Result<()> {
                    let targets = self.table_with_joins(table, d)?;
                    let target = targets.first().cloned();
                    for it in targets.iter().cloned() {
                        self.scopes.add(it);
                    }
                    // `UPDATE … FROM t1, t2` (the Snowflake form puts it
                    // before SET).
                    if let Some(
                        UpdateTableFromKind::BeforeSet(f) | UpdateTableFromKind::AfterSet(f),
                    ) = from
                    {
                        for twj in f.iter_mut() {
                            for it in self.table_with_joins(twj, d)? {
                                self.scopes.add(it);
                            }
                        }
                    }
                    self.assignments(assignments, target.as_ref(), d)?;
                    if self.all {
                        if let Some(w) = selection {
                            self.expr(w, d)?;
                        }
                        // MySQL's `UPDATE … ORDER BY … LIMIT n` (which
                        // sqlparser 0.52 rejected), read like DELETE's.
                        for o in order_by.iter_mut() {
                            self.expr(&mut o.expr, d)?;
                        }
                        if let Some(l) = limit.as_mut() {
                            self.expr(l, d)?;
                        }
                    }
                    if let Some(ret) = returning {
                        self.projection(ret, Some(visible), d)?;
                    }
                    if let Some(out) = output {
                        self.output(out, &targets, visible, d)?;
                    }
                    Ok(())
                })();
                self.scopes.pop();
                r?;
            }
            Statement::Delete(del) => {
                if del.returning.is_some() || del.output.is_some() || self.all {
                    self.scopes.push();
                    let r = (|| -> Result<()> {
                        let from = match &mut del.from {
                            FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
                        };
                        // Access analysis: the targets lose whole rows. With
                        // a table list (`DELETE t FROM t JOIN …`) those are
                        // the targets; otherwise each FROM relation.
                        let mut targets: Vec<(Option<String>, String)> = Vec::new();
                        if self.all && del.tables.is_empty() {
                            for twj in from.iter() {
                                if let TableFactor::Table { name, .. } = &twj.relation {
                                    targets.push(self.split(name));
                                }
                            }
                        }
                        for twj in from.iter_mut().chain(del.using.iter_mut().flatten()) {
                            for it in self.table_with_joins(twj, d)? {
                                self.scopes.add(it);
                            }
                        }
                        if self.all {
                            for n in &del.tables {
                                let parts = name_parts(n);
                                let found = self.scopes.base_tables(&parts);
                                if found.is_empty() {
                                    targets.push(self.split(n));
                                } else {
                                    targets.extend(found);
                                }
                            }
                            // Removing a row is a write to the table, whatever
                            // its columns: a `read_write` entry, any column list.
                            for (schema, table) in &targets {
                                self.tags.write(schema.as_deref(), table, None);
                            }
                            if let Some(w) = del.selection.as_mut() {
                                self.expr(w, d)?;
                            }
                            for o in del.order_by.iter_mut() {
                                self.expr(&mut o.expr, d)?;
                            }
                            if let Some(l) = del.limit.as_mut() {
                                self.expr(l, d)?;
                            }
                        }
                        if let Some(ret) = del.returning.as_mut() {
                            self.projection(ret, Some(visible), d)?;
                        }
                        if let Some(out) = del.output.as_mut() {
                            // SQL Server's `deleted.*` is the removed rows of
                            // the target: the first relation (or the table list).
                            let mut bases: Vec<Item> = Vec::new();
                            for twj in from.iter() {
                                if let TableFactor::Table { name, .. } = &twj.relation {
                                    let (schema, table) = self.split(name);
                                    bases.push(Item::Base {
                                        refname: table.clone(),
                                        schema,
                                        table,
                                    });
                                }
                            }
                            self.output(out, &bases, visible, d)?;
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
            Statement::CreateView(sqlparser::ast::CreateView { query, .. }) => {
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
                    let (schema, table) = self.split(table_name);
                    self.tags.relation(schema.as_deref(), &table);
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
            Statement::Copy {
                source:
                    sqlparser::ast::CopySource::Table {
                        table_name,
                        columns,
                    },
                to: false,
                ..
            } => {
                // Access analysis: `COPY t [(cols)] FROM` writes them.
                let (schema, table) = self.split(table_name);
                self.tags.write(schema.as_deref(), &table, None);
                if columns.is_empty() {
                    self.tags.write(schema.as_deref(), &table, Some("*"));
                }
                for c in columns.iter() {
                    self.tags.write(schema.as_deref(), &table, Some(&c.value));
                }
            }
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
            Statement::Set(set) => {
                use sqlparser::ast::Set;
                let values: Vec<&mut Expr> = match set {
                    Set::SingleAssignment { values, .. }
                    | Set::ParenthesizedAssignments { values, .. } => values.iter_mut().collect(),
                    Set::MultipleAssignments { assignments } => {
                        assignments.iter_mut().map(|a| &mut a.value).collect()
                    }
                    // Roles, time zone, names, transactions, session
                    // parameters: no value read from a table, as before
                    // (they were their own statements before sqlparser 0.56).
                    _ => Vec::new(),
                };
                for e in values {
                    let lin = self.expr(e, d)?;
                    self.touches.record(&lin, Sink::Copy);
                }
            }
            Statement::Merge(sqlparser::ast::Merge {
                table,
                source,
                on,
                clauses,
                output,
                ..
            }) => {
                self.scopes.push();
                let r = (|| -> Result<()> {
                    let target = self.table_factor(table, d)?.into_iter().next();
                    let tgt = match &target {
                        Some(Item::Base { schema, table, .. }) => {
                            Some((schema.clone(), table.clone()))
                        }
                        _ => None,
                    };
                    if let Some((schema, table)) = &tgt {
                        self.tags.write(schema.as_deref(), table, None);
                    }
                    if let Some(t) = target.clone() {
                        self.scopes.add(t);
                    }
                    for it in self.table_factor(source, d)? {
                        self.scopes.add(it);
                    }
                    if self.all {
                        self.expr(on, d)?;
                    }
                    for c in clauses.iter_mut() {
                        if self.all {
                            if let Some(p) = c.predicate.as_mut() {
                                self.expr(p, d)?;
                            }
                            if let Some((schema, table)) = &tgt {
                                let schema = schema.as_deref();
                                match &c.action {
                                    // A table-level write: the target's
                                    // `None` write above. `DO NOTHING`
                                    // (PostgreSQL 17) writes nothing more.
                                    MergeAction::Delete { .. } | MergeAction::DoNothing { .. } => {}
                                    MergeAction::Insert(ins) if ins.columns.is_empty() => {
                                        self.tags.write(schema, table, Some("*"))
                                    }
                                    MergeAction::Insert(ins) => {
                                        for col in &ins.columns {
                                            self.tags.write(schema, table, Some(&column_of(col)));
                                        }
                                    }
                                    MergeAction::Update(_) => {}
                                }
                            }
                        }
                        match &mut c.action {
                            MergeAction::Update(u) => {
                                match &mut u.kind {
                                    MergeUpdateKind::Set(assignments) => {
                                        self.assignments(assignments, target.as_ref(), d)?
                                    }
                                    // `UPDATE *` copies every source column
                                    // into the same-named target column.
                                    MergeUpdateKind::Wildcard => {
                                        if let (true, Some((schema, table))) = (self.all, &tgt) {
                                            self.tags.write(schema.as_deref(), table, Some("*"));
                                        }
                                        let lin = self.everything_in_scope();
                                        self.touches.record(&lin, Sink::Copy);
                                    }
                                }
                                // Oracle's `UPDATE … WHERE … DELETE WHERE …`.
                                if self.all {
                                    for p in [&mut u.update_predicate, &mut u.delete_predicate]
                                        .into_iter()
                                        .flatten()
                                    {
                                        self.expr(p, d)?;
                                    }
                                }
                            }
                            MergeAction::Insert(ins) => {
                                if let (true, Some(p)) = (self.all, ins.insert_predicate.as_mut()) {
                                    self.expr(p, d)?;
                                }
                                if let MergeInsertKind::Values(v) = &mut ins.kind {
                                    for row in v.rows.iter_mut() {
                                        for (j, e) in row.iter_mut().enumerate() {
                                            let mut lin = self.expr(e, d)?;
                                            if let (false, Some(dest), Some(t)) =
                                                (self.all, ins.columns.get(j), target.as_ref())
                                            {
                                                for k in
                                                    t.column(self.tags, &column_of(dest)).keys()
                                                {
                                                    lin.remove(k);
                                                }
                                            }
                                            self.touches.record(&lin, Sink::Copy);
                                        }
                                    }
                                }
                            }
                            MergeAction::Delete { .. } | MergeAction::DoNothing { .. } => {}
                        }
                    }
                    if let Some(out) = output {
                        let targets: Vec<Item> = target.iter().cloned().collect();
                        self.output(out, &targets, visible, d)?;
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

    /// The `OUTPUT` clause of SQL Server (and `RETURNING` on `MERGE`), which
    /// sqlparser now reads on every dialect: what it projects goes to
    /// the client like `RETURNING`, or into a table with `OUTPUT … INTO`, a
    /// copy. `inserted.*` / `deleted.*` are the target's rows.
    fn output(
        &mut self,
        out: &mut OutputClause,
        targets: &[Item],
        visible: Sink,
        depth: usize,
    ) -> Result<()> {
        let (items, into) = match out {
            OutputClause::Output {
                select_items,
                into_table,
                ..
            } => (select_items, into_table.is_some()),
            OutputClause::Returning { select_items, .. } => (select_items, false),
        };
        if self.all && into {
            // Writes a table the clause names: denied under an allowlist.
            self.tags.statement("OUTPUT INTO");
        }
        let sink = if into { Sink::Copy } else { visible };
        self.scopes.push();
        for t in targets {
            if let Item::Base { schema, table, .. } = t {
                for refname in ["inserted", "deleted"] {
                    self.scopes.add(Item::Base {
                        refname: refname.to_string(),
                        schema: schema.clone(),
                        table: table.clone(),
                    });
                }
            }
            self.scopes.add(t.clone());
        }
        let r = self.projection(items, Some(sink), depth + 1);
        self.scopes.pop();
        r.map(|_| ())
    }

    fn assignments(
        &mut self,
        list: &mut [Assignment],
        target: Option<&Item>,
        depth: usize,
    ) -> Result<()> {
        for a in list.iter_mut() {
            let mut lin = self.expr(&mut a.value, depth + 1)?;
            if self.all {
                // Access analysis: the column (and its table) written.
                let names: Vec<&ObjectName> = match &a.target {
                    AssignmentTarget::ColumnName(n) => vec![n],
                    AssignmentTarget::Tuple(ns) => ns.iter().collect(),
                };
                for n in names {
                    let col = column_of(n);
                    for (schema, table) in self.write_targets(n, target) {
                        self.tags.write(schema.as_deref(), &table, None);
                        self.tags.write(schema.as_deref(), &table, Some(&col));
                    }
                }
                self.touches.record(&lin, Sink::Copy);
                continue;
            }
            if let (AssignmentTarget::ColumnName(n), Some(t)) = (&a.target, target) {
                if let Some(col) = n.0.last() {
                    for k in t.column(self.tags, name_part(col)).keys() {
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
        // Pipe syntax (`|> SELECT …`, Generic dialect only) projects and
        // filters in ways this walker does not model: not analysed (a block
        // under a protective tag or an enforced allowlist).
        if !q.pipe_operators.is_empty() {
            return Err(ProxyError::ParseError(
                "pipe syntax (`|>`) is not analysed".to_string(),
            ));
        }
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
        let all = self.all;
        // Access analysis: `FOR UPDATE/SHARE` locks rows, a write (see
        // `select`).
        let lock = (all && !q.locks.is_empty()).then(|| {
            (
                q.locks.iter().any(|l| l.of.is_none()),
                q.locks
                    .iter()
                    .filter_map(|l| l.of.clone())
                    .collect::<Vec<_>>(),
            )
        });
        let out = if let SetExpr::Select(sel) = q.body.as_mut() {
            self.lock = lock;
            // A simple SELECT: its ORDER BY lives on the query. The access
            // analysis walks it inside the SELECT's scope (it may name FROM
            // columns that are not projected).
            let order = if all { q.order_by.as_mut() } else { None };
            self.select(sel, sink, order, depth + 1)
                .map(|(outs, rw, star, distinct)| {
                    if !rw.is_empty() && self.snowflake {
                        // Snowflake resolves ORDER BY names to the select
                        // aliases first: ordering by a masked output would
                        // order by the masked value. Refused, as is a
                        // position naming one.
                        if let Some(ob) = q.order_by.as_ref() {
                            if let Some(why) = snowflake_order_refusal(ob, &rw) {
                                self.refuse(why);
                            }
                        }
                    } else if !rw.is_empty() && !distinct {
                        if let Some(ob) = q.order_by.as_mut() {
                            if let Err(why) = fix_order_by(ob, &rw, star) {
                                self.refuse(why);
                            }
                        }
                    }
                    outs
                })
        } else {
            // A locking set operation: every relation inside is taken as
            // locked (conservative).
            let tags = self.tags;
            let out = tags.locking(lock.is_some(), || {
                self.set_expr(&mut q.body, sink, depth + 1)
            });
            if let (true, Ok(outs), Some(ob)) = (all, out.as_ref(), q.order_by.as_mut()) {
                // ORDER BY of a set operation: output names, positions, or
                // expressions over the enclosing scopes.
                let outs = outs.clone();
                if let Err(e) = self.order_by(ob, &outs, depth + 1) {
                    if pushed {
                        self.ctes.pop();
                    }
                    return Err(e);
                }
            }
            out
        };
        let out = match (all, out) {
            (true, Ok(o)) => {
                let r = (|| -> Result<()> {
                    match q.limit_clause.as_mut() {
                        Some(LimitClause::LimitOffset {
                            limit,
                            offset,
                            limit_by,
                        }) => {
                            if let Some(l) = limit.as_mut() {
                                self.expr(l, depth + 1)?;
                            }
                            self.exprs(limit_by, depth + 1)?;
                            if let Some(o) = offset.as_mut() {
                                self.expr(&mut o.value, depth + 1)?;
                            }
                        }
                        Some(LimitClause::OffsetCommaLimit { offset, limit }) => {
                            self.expr(offset, depth + 1)?;
                            self.expr(limit, depth + 1)?;
                        }
                        None => {}
                    }
                    if let Some(f) = q.fetch.as_mut().and_then(|f| f.quantity.as_mut()) {
                        self.expr(f, depth + 1)?;
                    }
                    Ok(())
                })();
                r.map(|()| o)
            }
            (_, other) => other,
        };
        if pushed {
            self.ctes.pop();
        }
        out
    }

    /// Access analysis: `ORDER BY` items. A bare name equal to an output
    /// column IS that output (MySQL and the others resolve ORDER BY names to
    /// the select list first), already counted.
    fn order_by(&mut self, ob: &mut OrderBy, outs: &[OutCol], depth: usize) -> Result<()> {
        // `ORDER BY ALL` orders by the outputs, already counted.
        let OrderByKind::Expressions(items) = &mut ob.kind else {
            return Ok(());
        };
        for item in items.iter_mut() {
            let output = match &item.expr {
                Expr::Identifier(id) => outs
                    .iter()
                    .any(|o| matches!(o, OutCol::Named { name, .. } if ieq(name, &id.value))),
                _ => false,
            };
            if !output {
                self.expr(&mut item.expr, depth)?;
            }
        }
        Ok(())
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
            SetExpr::Select(sel) => Ok(self.select(sel, sink, None, d)?.0),
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
                                    *e = if self.snowflake {
                                        super::snowflake::mask_expr(style, e)
                                    } else {
                                        mysql::mask_expr(style, e)
                                    };
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
            SetExpr::Insert(s) | SetExpr::Update(s) | SetExpr::Delete(s) | SetExpr::Merge(s) => {
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
        order: Option<&mut OrderBy>,
        depth: usize,
    ) -> Result<(Vec<OutCol>, Vec<Rewritten>, bool, bool)> {
        if self.all {
            // `SELECT … INTO t` creates a table (SQL Server, Postgres via
            // sqlparser); `INTO @v` (MySQL) only sets a session variable.
            if let Some(into) = &sel.into {
                // The targets are expressions since sqlparser 0.63 (MySQL's
                // `INTO @a, @b`): only user variables are not a table.
                let variable = |e: &Expr| matches!(e, Expr::Identifier(i) if i.quote_style.is_none() && i.value.starts_with('@'));
                if into.targets.is_empty() || !into.targets.iter().all(variable) {
                    self.tags.statement("SELECT INTO");
                }
            }
        }
        // `SELECT … INTO t` / `INTO OUTFILE` / `INTO @v`: a copy, not a read.
        let sink = if sel.into.is_some() {
            Some(Sink::Copy)
        } else {
            sink
        };
        let (lock_all, lock_of) = self.lock.take().unwrap_or_default();
        let tags = self.tags;
        self.scopes.push();
        let r = (|| -> Result<(Vec<OutCol>, Vec<Rewritten>, bool)> {
            // A row lock needs write on the locked tables: every relation of
            // the `FROM` (derived tables included) without `OF`, else the
            // ones `OF` names.
            tags.locking(lock_all, || -> Result<()> {
                for twj in sel.from.iter_mut() {
                    for it in self.table_with_joins(twj, depth)? {
                        self.scopes.add(it);
                    }
                }
                Ok(())
            })?;
            for n in &lock_of {
                let parts = name_parts(n);
                let bases = self.scopes.base_tables(&parts);
                if bases.is_empty() {
                    // Not a base table in scope: taken as a table name,
                    // denied unless granted for writing (conservative).
                    let (schema, table) = self.split(n);
                    tags.write(schema.as_deref(), &table, None);
                }
                for (schema, table) in &bases {
                    tags.write(schema.as_deref(), table, None);
                }
            }
            let p = self.projection(&mut sel.projection, sink, depth)?;
            if self.all {
                self.select_clauses(sel, &p.0, order, depth)?;
            }
            Ok(p)
        })();
        self.scopes.pop();
        let (outs, rw, star) = r?;
        if !rw.is_empty() && self.snowflake {
            self.snowflake_clause_refusals(sel, &rw);
        } else if !rw.is_empty() {
            self.fix_group_and_having(sel, &rw, star);
        }
        Ok((outs, rw, star, sel.distinct.is_some()))
    }

    /// Access analysis: every clause of a `SELECT` besides its projection and
    /// `FROM`. A predicate lets the caller probe a value it cannot read, so it
    /// counts as much as a projection.
    fn select_clauses(
        &mut self,
        sel: &mut Select,
        outs: &[OutCol],
        order: Option<&mut OrderBy>,
        depth: usize,
    ) -> Result<()> {
        let d = depth + 1;
        for e in [
            &mut sel.prewhere,
            &mut sel.selection,
            &mut sel.having,
            &mut sel.qualify,
        ]
        .into_iter()
        .flatten()
        {
            self.expr(e, d)?;
        }
        // GROUP BY prefers the input column over an alias of the same name:
        // resolved as an input column (conservative).
        if let GroupByExpr::Expressions(exprs, _) = &mut sel.group_by {
            self.exprs(exprs, d)?;
        }
        self.exprs(&mut sel.cluster_by, d)?;
        self.exprs(&mut sel.distribute_by, d)?;
        for o in sel.sort_by.iter_mut() {
            self.expr(&mut o.expr, d)?;
        }
        if let Some(sqlparser::ast::Distinct::On(exprs)) = &mut sel.distinct {
            self.exprs(exprs, d)?;
        }
        for w in sel.named_window.iter_mut() {
            if let sqlparser::ast::NamedWindowExpr::WindowSpec(spec) = &mut w.1 {
                self.window_spec(spec, d)?;
            }
        }
        for lv in sel.lateral_views.iter_mut() {
            self.expr(&mut lv.lateral_view, d)?;
        }
        for cb in sel.connect_by.iter_mut() {
            match cb {
                sqlparser::ast::ConnectByKind::ConnectBy { relationships, .. } => {
                    self.exprs(relationships, d)?;
                }
                sqlparser::ast::ConnectByKind::StartWith { condition, .. } => {
                    self.expr(condition, d)?;
                }
            }
        }
        if let Some(sqlparser::ast::TopQuantity::Expr(e)) =
            sel.top.as_mut().and_then(|t| t.quantity.as_mut())
        {
            self.expr(e, d)?;
        }
        if let Some(ob) = order {
            self.order_by(ob, outs, d)?;
        }
        Ok(())
    }

    fn window_spec(&mut self, spec: &mut sqlparser::ast::WindowSpec, depth: usize) -> Result<()> {
        self.exprs(&mut spec.partition_by, depth)?;
        for o in spec.order_by.iter_mut() {
            self.expr(&mut o.expr, depth)?;
        }
        Ok(())
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

    /// Snowflake: after masking, `GROUP BY`, `HAVING` and `QUALIFY` naming a
    /// masked output (or `GROUP BY` a position of one) may see the masked
    /// value, depending on name resolution the engine cannot check without
    /// a schema: the rewrite is refused (the query blocks).
    fn snowflake_clause_refusals(&mut self, sel: &Select, rw: &[Rewritten]) {
        let names: Vec<&str> = rw.iter().map(|(_, n, _)| n.as_str()).collect();
        if let GroupByExpr::Expressions(exprs, _) = &sel.group_by {
            for e in exprs {
                let masked_position =
                    position(e).is_some_and(|p| rw.iter().any(|(i, _, _)| *i == p));
                if masked_position || super::snowflake::mentions(e, &names) {
                    self.refuse(format!(
                        "GROUP BY uses the masked output(s) {}; group by the expression itself, unaliased",
                        names.join(", ")
                    ));
                }
            }
        }
        for (clause, e) in [("HAVING", &sel.having), ("QUALIFY", &sel.qualify)] {
            if e.as_ref()
                .is_some_and(|e| super::snowflake::mentions(e, &names))
            {
                self.refuse(format!(
                    "{clause} uses the masked output name(s) {}; Snowflake would compare the masked value",
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
        if let Expr::Value(ValueWithSpan {
            value: Value::SingleQuotedString(s) | Value::DoubleQuotedString(s),
            ..
        }) = e
        {
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
                        SelectItem::QualifiedWildcard(
                            SelectItemQualifiedWildcardKind::ObjectName(name),
                            _,
                        ) => {
                            let q = name_parts(name);
                            self.scopes.star(self.tags, &q)
                        }
                        // `<expr>.*` (BigQuery): every field of the value.
                        SelectItem::QualifiedWildcard(
                            SelectItemQualifiedWildcardKind::Expr(e),
                            _,
                        ) => {
                            let lin = self.expr(e, depth + 1)?;
                            (lin.clone(), vec![OutCol::OpaqueStar { lin }])
                        }
                        _ => self.scopes.star(self.tags, &[]),
                    };
                    if let Some(sink) = sink {
                        self.touches.record(&lin, sink);
                    }
                    outs.extend(cols);
                    continue;
                }
                // `expr AS (a, b)` (Spark/Databricks only): every output may
                // carry the value. Not rewritten: a mask refuses the query.
                SelectItem::ExprWithAliases { expr, aliases } => {
                    let lin = self.expr(expr, depth + 1)?;
                    if let Some(sink) = sink {
                        self.touches.record(&lin, sink);
                        if let (Sink::Projected { rewrite: true }, Some(_)) =
                            (sink, mask_style_for(self.tags, &lin))
                        {
                            self.refuse("a multi-alias select item cannot be masked".to_string());
                        }
                    }
                    for a in aliases.iter() {
                        outs.push(OutCol::Named {
                            name: a.value.clone(),
                            lin: lin.clone(),
                        });
                    }
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
                if let (Sink::Projected { rewrite: true }, true) = (sink, self.snowflake) {
                    if let Some(style) = mask_style_for(self.tags, &lin) {
                        // Snowflake names an unaliased column after the column
                        // (folded unless quoted): the alias is the column's
                        // own identifier, quote style included. Any other
                        // unaliased expression gets a name Snowflake derives
                        // from its text, which the rewrite cannot reproduce.
                        let alias = match item {
                            SelectItem::ExprWithAlias { alias, .. } => Some(alias.clone()),
                            SelectItem::UnnamedExpr(Expr::Identifier(i)) => Some(i.clone()),
                            SelectItem::UnnamedExpr(Expr::CompoundIdentifier(ids)) => {
                                ids.last().cloned()
                            }
                            _ => None,
                        };
                        match (alias, &*item) {
                            (
                                Some(alias),
                                SelectItem::UnnamedExpr(e)
                                | SelectItem::ExprWithAlias { expr: e, .. },
                            ) => {
                                let orig = e.clone();
                                *item = SelectItem::ExprWithAlias {
                                    expr: super::snowflake::mask_expr(style, &orig),
                                    alias,
                                };
                                rewritten.push((idx, name.clone(), orig));
                                self.rewrote = true;
                            }
                            _ => {
                                self.rewrote = true;
                                self.refuse(
                                    "an unaliased expression over a masked column has a name Snowflake derives from its text; alias it (`AS name`)"
                                        .to_string(),
                                );
                            }
                        }
                    }
                } else if let Sink::Projected { rewrite: true } = sink {
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
        if self.all && !twj.joins.is_empty() {
            // Access analysis: `ON`, `USING` and `NATURAL` read the join
            // columns, with every relation of the join visible.
            let mark = self.scopes.levels.last().map_or(0, Vec::len);
            for it in &items {
                self.scopes.add(it.clone());
            }
            let r = (|| -> Result<()> {
                for j in twj.joins.iter_mut() {
                    use sqlparser::ast::{JoinConstraint, JoinOperator as J};
                    let (constraint, matching) = match &mut j.join_operator {
                        J::Join(c)
                        | J::Inner(c)
                        | J::Left(c)
                        | J::LeftOuter(c)
                        | J::Right(c)
                        | J::Semi(c)
                        | J::Anti(c)
                        | J::StraightJoin(c)
                        | J::RightOuter(c)
                        | J::FullOuter(c)
                        | J::LeftSemi(c)
                        | J::RightSemi(c)
                        | J::LeftAnti(c)
                        | J::RightAnti(c) => (Some(c), None),
                        J::AsOf {
                            match_condition,
                            constraint,
                        } => (Some(constraint), Some(match_condition)),
                        J::CrossJoin(c) => (Some(c), None),
                        J::CrossApply
                        | J::OuterApply
                        | J::ArrayJoin
                        | J::LeftArrayJoin
                        | J::InnerArrayJoin => (None, None),
                    };
                    if let Some(m) = matching {
                        self.expr(m, depth + 1)?;
                    }
                    match constraint {
                        Some(JoinConstraint::On(e)) => {
                            self.expr(e, depth + 1)?;
                        }
                        Some(JoinConstraint::Using(cols)) => {
                            for c in cols.iter() {
                                let c = column_of(c);
                                for it in &items {
                                    it.column(self.tags, &c);
                                }
                            }
                        }
                        Some(JoinConstraint::Natural) => {
                            // The common columns are unknown: every column.
                            for it in &items {
                                it.star_all(self.tags);
                            }
                        }
                        Some(JoinConstraint::None) | None => {}
                    }
                }
                Ok(())
            })();
            if let Some(level) = self.scopes.levels.last_mut() {
                level.truncate(mark);
            }
            r?;
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
                let (schema, table) = self.split(name);
                let refname = alias_name(alias).unwrap_or_else(|| table.clone());
                if let Some(args) = args {
                    // A table-valued function call.
                    self.snowflake_table_function(Some(name));
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
                        if !exact {
                            // Maybe the table: the access analysis reads it.
                            self.tags.relation(None, &table);
                        }
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
                // Access analysis: a relation read. No-op for tags.
                self.tags.relation(schema.as_deref(), &table);
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
            TableFactor::TableFunction { expr, alias } => {
                self.snowflake_table_function(match &*expr {
                    Expr::Function(f) => Some(&f.name),
                    _ => None,
                });
                vec![Item::Opaque {
                    refname: alias_name(alias),
                    lin: indirect(self.expr(expr, d)?),
                }]
            }
            TableFactor::Function {
                name, args, alias, ..
            } => {
                self.snowflake_table_function(Some(name));
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
            // SQL Server's `OPENJSON(…)`: rows computed from a value, like
            // JSON_TABLE.
            TableFactor::OpenJsonTable {
                json_expr, alias, ..
            } => vec![Item::Opaque {
                refname: alias_name(alias),
                lin: indirect(self.expr(json_expr, d)?),
            }],
            // `XMLTABLE(… PASSING x …)`: rows computed from the values passed.
            TableFactor::XmlTable {
                row_expression,
                passing,
                alias,
                ..
            } => {
                let mut lin = self.expr(row_expression, d)?;
                for a in passing.arguments.iter_mut() {
                    merge(&mut lin, self.expr(&mut a.expr, d)?);
                }
                vec![Item::Opaque {
                    refname: alias_name(alias),
                    lin: indirect(lin),
                }]
            }
            // Redshift's `UNPIVOT expr AS v`: values of the expression.
            TableFactor::UnpivotExpr {
                expression,
                value_alias,
                ..
            } => vec![Item::Opaque {
                refname: Some(value_alias.value.clone()),
                lin: indirect(self.expr(expression, d)?),
            }],
            // Snowflake's `SEMANTIC_VIEW(v …)`: reads the view, whole.
            TableFactor::SemanticView { name, alias, .. } => {
                let (schema, table) = self.split(name);
                self.tags.relation(schema.as_deref(), &table);
                vec![Item::Opaque {
                    refname: alias_name(alias),
                    lin: indirect(self.tags.of_table(schema.as_deref(), &table)),
                }]
            }
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
            FunctionArg::Named { arg, .. }
            | FunctionArg::ExprNamed { arg, .. }
            | FunctionArg::Unnamed(arg) => arg,
        };
        Ok(match arg {
            FunctionArgExpr::Expr(e) => self.expr(e, depth)?,
            FunctionArgExpr::Wildcard | FunctionArgExpr::WildcardWithOptions(_) => {
                // `COUNT(*)` counts rows; `JSON_OBJECT(*)`-style uses do not
                // exist in these dialects, but be conservative for any other
                // function: a bare `*` argument reads the whole row.
                Lineage::new()
            }
            FunctionArgExpr::QualifiedWildcard(name) => {
                let q = name_parts(name);
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
            // Access analysis: `@v` / `@@version` are variables, and Oracle's
            // pseudo-columns are not columns of any table.
            Expr::Identifier(id)
                if self.all
                    && id.quote_style.is_none()
                    && (id.value.starts_with('@')
                        || (self.oracle && is_oracle_pseudo_column(&id.value))) =>
            {
                Lineage::new()
            }
            Expr::Identifier(id) => {
                let mut l = self.scopes.column(self.tags, &[], &id.value);
                merge(&mut l, self.scopes.whole_row(self.tags, &id.value));
                return Ok(l);
            }
            // Access analysis: `@@SESSION.sql_mode` is a system variable.
            Expr::CompoundIdentifier(ids)
                if self.all
                    && ids
                        .first()
                        .is_some_and(|i| i.quote_style.is_none() && i.value.starts_with('@')) =>
            {
                Lineage::new()
            }
            Expr::CompoundIdentifier(ids) => return Ok(self.compound(ids)),
            // With `ANSI_QUOTES` (server-wide, or per statement through a
            // `SET_VAR` hint) MySQL reads `"email"` as the column. The engine
            // cannot see the SQL mode: treat it as a possible column.
            Expr::Value(ValueWithSpan {
                value: Value::DoubleQuotedString(s),
                ..
            }) if self.ansi_quotes => self.scopes.column(self.tags, &[], s),
            Expr::Value(_) | Expr::TypedString { .. } => Lineage::new(),
            // `_utf8mb4'x'` (an introducer, `IntroducedString` before
            // sqlparser 0.56): the value is a literal.
            Expr::Prefixed { value, .. } => self.expr(value, d)?,
            Expr::Nested(x) => return self.expr(x, d),
            // Only the arguments are values; FILTER / OVER / WITHIN GROUP decide
            // which rows and in what order, like WHERE.
            Expr::Function(f) => {
                if self.all {
                    // Access analysis: these choose rows and order, which
                    // still reads the columns.
                    if let Some(x) = f.filter.as_deref_mut() {
                        self.expr(x, d)?;
                    }
                    if let Some(sqlparser::ast::WindowType::WindowSpec(spec)) = f.over.as_mut() {
                        self.window_spec(spec, d)?;
                    }
                    for o in f.within_group.iter_mut() {
                        self.expr(&mut o.expr, d)?;
                    }
                    if let FunctionArguments::List(list) = &mut f.args {
                        for c in list.clauses.iter_mut() {
                            match c {
                                sqlparser::ast::FunctionArgumentClause::OrderBy(obs) => {
                                    for o in obs.iter_mut() {
                                        self.expr(&mut o.expr, d)?;
                                    }
                                }
                                sqlparser::ast::FunctionArgumentClause::Limit(e) => {
                                    self.expr(e, d)?;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                match &mut f.args {
                    FunctionArguments::None => Lineage::new(),
                    FunctionArguments::Subquery(q) => self.query_value(q, d)?,
                    FunctionArguments::List(list) => {
                        let mut l = Lineage::new();
                        for a in list.args.iter_mut() {
                            merge(&mut l, self.function_arg(a, d)?);
                        }
                        l
                    }
                }
            }
            Expr::Subquery(q) => {
                // `(SELECT email …)` IS the value: keep directness.
                let cols = self.query(q, None, d)?;
                return Ok(cols
                    .first()
                    .map(|c| outcol_all(self.tags, c))
                    .unwrap_or_default());
            }
            Expr::Exists { subquery, .. } => {
                // A boolean about rows, not their values; the access analysis
                // still reads what is inside.
                if self.all {
                    self.query(subquery, None, d)?;
                }
                Lineage::new()
            }
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
            | Expr::IsNormalized { expr, .. }
            | Expr::IsJson { expr, .. } => self.expr(expr, d)?,
            // MySQL's `v MEMBER OF (json_array)`.
            Expr::MemberOf(m) => {
                let mut l = self.expr(&mut m.value, d)?;
                merge(&mut l, self.expr(&mut m.array, d)?);
                l
            }
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
                else_result,
                ..
            } => {
                let mut l = Lineage::new();
                if let Some(o) = operand {
                    merge(&mut l, self.expr(o, d)?);
                }
                for w in conditions.iter_mut() {
                    merge(&mut l, self.expr(&mut w.condition, d)?);
                    merge(&mut l, self.expr(&mut w.result, d)?);
                }
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
            // `a[1]`, `m['k']`, `(x).f` (MapAccess / Subscript /
            // CompositeAccess before sqlparser 0.54/0.55): the value comes from the
            // root; a computed subscript (`a[(SELECT …)]`) is read as well.
            // `"public"."User"."email"` on MySQL: with `ANSI_QUOTES` a column
            // name, which sqlparser 0.63 reads as field access on the string
            // `"public"` (0.52 rejected it). Read as the dotted name it is.
            Expr::CompoundFieldAccess { root, access_chain }
                if dotted_name(root, access_chain, self.ansi_quotes).is_some() =>
            {
                let ids = dotted_name(root, access_chain, self.ansi_quotes).unwrap_or_default();
                return Ok(self.compound(&ids));
            }
            Expr::CompoundFieldAccess { root, access_chain } => {
                let mut l = self.expr(root, d)?;
                for a in access_chain.iter_mut() {
                    match a {
                        AccessExpr::Subscript(Subscript::Index { index }) => {
                            merge(&mut l, self.expr(index, d)?);
                        }
                        AccessExpr::Subscript(Subscript::Slice {
                            lower_bound,
                            upper_bound,
                            stride,
                        }) => {
                            for x in [lower_bound, upper_bound, stride].into_iter().flatten() {
                                merge(&mut l, self.expr(x, d)?);
                            }
                        }
                        // A field name, not a value.
                        AccessExpr::Dot(_) => {}
                    }
                }
                l
            }
            Expr::MatchAgainst { columns, .. } => {
                let mut l = Lineage::new();
                for c in columns.iter() {
                    let parts = name_parts(c);
                    if let [q @ .., col] = parts.as_slice() {
                        merge(&mut l, self.scopes.column(self.tags, q, col));
                    }
                }
                l
            }
            Expr::Wildcard(_) => self.scopes.star(self.tags, &[]).0,
            Expr::QualifiedWildcard(name, _) => {
                let q = name_parts(name);
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
/// Snowflake: why an `ORDER BY` cannot stay as it is over masked outputs
/// (see the caller), or `None`.
fn snowflake_order_refusal(ob: &OrderBy, rw: &[Rewritten]) -> Option<String> {
    let names: Vec<&str> = rw.iter().map(|(_, n, _)| n.as_str()).collect();
    let OrderByKind::Expressions(items) = &ob.kind else {
        // `ORDER BY ALL` orders by every output, the masked ones included.
        return Some("ORDER BY ALL orders by the masked output".to_string());
    };
    items
        .iter()
        .any(|o| {
            position(&o.expr).is_some_and(|p| rw.iter().any(|(i, _, _)| *i == p))
                || super::snowflake::mentions(&o.expr, &names)
        })
        .then(|| {
            format!(
                "ORDER BY uses the masked output(s) {}; Snowflake would order by the masked value",
                names.join(", ")
            )
        })
}

fn fix_order_by(ob: &mut OrderBy, rw: &[Rewritten], star: bool) -> std::result::Result<(), String> {
    let captured: Vec<&str> = rw
        .iter()
        .filter(|(_, n, orig)| !column_name(orig).is_some_and(|c| ieq(c, n)))
        .map(|(_, n, _)| n.as_str())
        .collect();
    let items = match &mut ob.kind {
        OrderByKind::Expressions(items) => items,
        // `ORDER BY ALL` would sort by the masked values.
        OrderByKind::All(_) => {
            return Err(
                "ORDER BY ALL sorts by the masked output(s); order by the expressions themselves"
                    .to_string(),
            );
        }
    };
    for item in items.iter_mut() {
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
