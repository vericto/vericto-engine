// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Statement facts for policies (`stmt.*`, design §4.2): what a top-level
//! statement reads and writes, the values it assigns, and the values its
//! `WHERE` pins columns to.
//!
//! Two sources, one meaning on every dialect:
//!
//! - **References** (tables, columns read and written) come from the
//!   VERICTO-087 collector walk, so they follow its scope and alias rules
//!   and its conservative fallbacks.
//! - **Shape** (operation, assignments, top-level filters, `LIMIT`) is read
//!   by a small front end per parser ([`pg`] for `pg_query`, [`sql`] for
//!   sqlparser) into the [`Shape`] below, and every rule about what it means
//!   is in this module, once. That is what keeps Postgres, MySQL, Oracle and
//!   SQL Server answering alike (the parity tests check the front ends).
//!
//! Conservative by construction: when a fact cannot be known it is UNKNOWN
//! (the policy's `on_unknown` decides), never a guess that could hide a
//! violation. An assignment that is not a literal, a column the walk cannot
//! resolve to one table, a list longer than [`MAX_FACTS`], a statement kind
//! whose tables are not extracted: all UNKNOWN.

pub(crate) mod pg;
pub(crate) mod sql;

use crate::parser::Dialect;
use crate::sensitive::Ref;

/// Which of the costlier facts to extract: the reference walk and the
/// function scan run only when a selected policy reads them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Want {
    pub(crate) refs: bool,
    pub(crate) functions: bool,
}

/// Facts of every top-level statement of `parsed`.
pub(crate) fn extract(
    parsed: &crate::parser::ParsedQuery,
    sql: Option<&str>,
    host_default_schema: Option<&str>,
    want: Want,
) -> Vec<Facts> {
    use crate::parser::SourceAst;
    let Some(dialect) = parsed.dialect() else {
        return Vec::new();
    };
    let namer = Namer::new(dialect, host_default_schema);
    let shapes = match &parsed.ast {
        SourceAst::Pg(tree) => pg::shapes(tree, sql, want),
        SourceAst::Sql { statements, .. } => sql::shapes(statements, dialect, want),
        SourceAst::Classified { what, .. } => return vec![Facts::opaque(what, namer)],
        SourceAst::None => return Vec::new(),
    };
    shapes
        .into_iter()
        .map(|(shape, refs)| {
            // Without the walk (not wanted), the reference lists stay
            // unknown; nothing reads them then.
            Facts::build(shape, refs, namer.clone())
        })
        .collect()
}

/// Longest fact list kept (design §4.7). A longer one is truncated:
/// `stmt.truncated` is true and reading the list is UNKNOWN.
pub(crate) const MAX_FACTS: usize = 1024;

/// A literal or parameter as SQL wrote it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FactVal {
    Int(i64),
    Double(f64),
    Str(String),
    Bool(bool),
    Null,
    /// A bind parameter (`$2`, `?`): 1-based position when known, 0 when not.
    Param(u32),
    /// Anything else: an expression, a column, a function call, `DEFAULT`, a
    /// cast. Its value is not known before execution.
    Expr,
}

/// A column as written: its qualifier parts (alias, table, or schema.table)
/// and its name.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ColRef {
    pub(crate) qualifier: Vec<String>,
    pub(crate) column: String,
}

/// The top-level `WHERE`, as far as policies read it: its conjunction.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Pred {
    And(Vec<Pred>),
    /// `col = v` (either side).
    Eq(ColRef, FactVal),
    /// `col IN (v, …)`.
    In(ColRef, Vec<FactVal>),
    /// `col > v`, `col >= v`, `v < col`, …: `lower` when it bounds from below.
    Bound {
        col: ColRef,
        lower: bool,
        val: FactVal,
    },
    /// `col BETWEEN lo AND hi`.
    Between(ColRef, FactVal, FactVal),
    /// Anything else (`OR`, `NOT`, functions, subqueries): pins nothing.
    Other,
}

/// A relation name as written (unquoted; folded by the front end the way the
/// parser hands it over).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Name {
    pub(crate) parts: Vec<String>,
}

impl Name {
    pub(crate) fn new(parts: Vec<String>) -> Self {
        Name { parts }
    }

    fn table(&self) -> &str {
        self.parts.last().map_or("", String::as_str)
    }
}

/// One entry of the top-level `FROM` (with `UPDATE`/`DELETE` targets): an
/// alias and, for a base table, its name; `None` for a derived table, a
/// function or anything else whose columns are not a table's.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeItem {
    pub(crate) alias: Option<String>,
    pub(crate) table: Option<Name>,
}

/// What an `INSERT`/`UPDATE` assigns to its target.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Assign {
    /// No assignment (not a write, or a `DELETE`).
    None,
    /// `INSERT … VALUES`: the column list (`None` when omitted) and rows.
    Rows {
        columns: Option<Vec<String>>,
        rows: Vec<Vec<FactVal>>,
    },
    /// `UPDATE … SET`, MySQL `INSERT … SET`.
    Set(Vec<(String, FactVal)>),
    /// The values are not visible: `INSERT … SELECT`, `MERGE`, `COPY FROM`,
    /// a tuple assignment from a subquery, …
    Unknown(&'static str),
}

/// The `LIMIT`/`FETCH`/`TOP` of the outer query.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LimitFact {
    Absent,
    Int(i64),
    Unknown(&'static str),
}

/// What a front end reads from one top-level statement.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Shape {
    /// `select`, `insert`, `update`, `delete`, `merge`, `ddl`, `copy`,
    /// `call`, `set`, `other`.
    pub(crate) op: &'static str,
    /// The node name custom rules use (`DeleteStmt`, `AlterTableStmt`, …).
    pub(crate) kind: String,
    /// The write target of `INSERT`/`UPDATE`/`DELETE`/`MERGE`.
    pub(crate) target: Option<Name>,
    pub(crate) assign: Assign,
    /// Upsert assignments (`ON CONFLICT DO UPDATE SET`, `ON DUPLICATE KEY
    /// UPDATE`): a `SET col = EXCLUDED.col` / `VALUES(col)` is the inserted
    /// value, already in `assign`, and is left out by the front end.
    pub(crate) upsert: Vec<(String, FactVal)>,
    pub(crate) scope: Vec<ScopeItem>,
    /// `None`: no `WHERE`.
    pub(crate) where_pred: Option<Pred>,
    pub(crate) where_always_true: bool,
    pub(crate) insert_rows: Option<i64>,
    pub(crate) limit: LimitFact,
    pub(crate) has_returning: bool,
    /// For statements the reference walk does not cover (DDL): their
    /// targets. `None` with `refs_from_walk == false`: the tables are not
    /// known.
    pub(crate) ddl_targets: Option<Vec<Name>>,
    /// Whether the reference walk describes this statement.
    pub(crate) refs_from_walk: bool,
    /// The statement writes through a nested statement (a data-modifying
    /// CTE): its values are not visible.
    pub(crate) nested_writes: bool,
    pub(crate) functions: Result<Vec<String>, &'static str>,
}

impl Shape {
    pub(crate) fn new(op: &'static str, kind: impl Into<String>) -> Self {
        Shape {
            op,
            kind: kind.into(),
            target: None,
            assign: Assign::None,
            upsert: Vec::new(),
            scope: Vec::new(),
            where_pred: None,
            where_always_true: false,
            insert_rows: None,
            limit: LimitFact::Absent,
            has_returning: false,
            ddl_targets: None,
            refs_from_walk: false,
            nested_writes: false,
            functions: Ok(Vec::new()),
        }
    }
}

/// A fact list, or why it is not known.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FactList {
    Known(Vec<String>),
    Unknown(String),
}

impl FactList {
    fn capped(mut v: Vec<String>, truncated: &mut bool) -> FactList {
        v.sort();
        v.dedup();
        if v.len() > MAX_FACTS {
            *truncated = true;
            return FactList::Unknown(format!("more than {MAX_FACTS} entries (truncated)"));
        }
        FactList::Known(v)
    }
}

/// How the dialect folds identifiers for comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fold {
    /// Postgres: names come out of the parser folded (unquoted → lower case,
    /// quoted as written): compare exactly.
    Exact,
    /// Every other dialect: ASCII lower case.
    Lower,
}

impl Fold {
    pub(crate) fn of(dialect: Dialect) -> Fold {
        match dialect {
            Dialect::Postgres => Fold::Exact,
            _ => Fold::Lower,
        }
    }

    pub(crate) fn apply(self, s: &str) -> String {
        match self {
            Fold::Exact => s.to_string(),
            Fold::Lower => s.to_ascii_lowercase(),
        }
    }

    pub(crate) fn eq(self, a: &str, b: &str) -> bool {
        match self {
            Fold::Exact => a == b,
            Fold::Lower => a.eq_ignore_ascii_case(b),
        }
    }
}

/// The schema an unqualified name lands in (as VERICTO-087 reads it).
fn default_schema(dialect: Dialect, host: Option<&str>) -> Option<String> {
    let host = host.filter(|s| !s.is_empty()).map(str::to_string);
    match dialect {
        Dialect::Postgres => host.or(Some("public".into())),
        Dialect::MsSql => host.or(Some("dbo".into())),
        Dialect::Sqlite => host.or(Some("main".into())),
        Dialect::Mysql | Dialect::Snowflake | Dialect::Oracle => host,
    }
}

/// Builds normalized names: `schema.table[.column]`, default schema
/// applied, folded as the dialect folds.
#[derive(Debug, Clone)]
pub(crate) struct Namer {
    pub(crate) fold: Fold,
    default: Option<String>,
}

impl Namer {
    pub(crate) fn new(dialect: Dialect, host_default: Option<&str>) -> Self {
        let fold = Fold::of(dialect);
        Namer {
            fold,
            default: default_schema(dialect, host_default).map(|s| fold.apply(&s)),
        }
    }

    /// `schema.table` from a reference's schema (if any) and table.
    pub(crate) fn table(&self, schema: Option<&str>, table: &str) -> String {
        let table = self.fold.apply(table);
        match schema.filter(|s| !s.is_empty()) {
            // Snowflake's three-part names come from the access walk with
            // the database and schema joined by DB_SEP.
            Some(s) => format!(
                "{}.{table}",
                self.fold.apply(&s.replace(crate::access::DB_SEP, "."))
            ),
            None => match &self.default {
                Some(d) => format!("{d}.{table}"),
                None => table,
            },
        }
    }

    pub(crate) fn name(&self, n: &Name) -> String {
        match n.parts.len() {
            0 => String::new(),
            1 => self.table(None, &n.parts[0]),
            k => self.table(Some(&n.parts[..k - 1].join(".")), &n.parts[k - 1]),
        }
    }
}

/// A resolved pin from the top-level conjunction.
#[derive(Debug, Clone, PartialEq)]
enum PinKind {
    Values(Vec<FactVal>),
    Lower(FactVal),
    Upper(FactVal),
}

/// What a target's columns are assigned (column → values), or why that is
/// not visible.
type Assigned = Result<Vec<(String, Vec<FactVal>)>, &'static str>;

/// Resolved pins (table, column, kind) and ambiguous unqualified columns
/// (column, candidate tables).
type Pins = (Vec<(String, String, PinKind)>, Vec<(String, Vec<String>)>);

/// Per-statement facts, read by the CEL helpers.
#[derive(Debug, Clone)]
pub(crate) struct Facts {
    pub(crate) op: &'static str,
    pub(crate) kind: String,
    pub(crate) tables: FactList,
    pub(crate) tables_written: FactList,
    pub(crate) columns_read: FactList,
    pub(crate) columns_written: FactList,
    pub(crate) functions: FactList,
    pub(crate) has_where: bool,
    pub(crate) where_always_true: bool,
    pub(crate) limit: LimitFact,
    pub(crate) has_returning: bool,
    pub(crate) insert_rows: Option<i64>,
    pub(crate) truncated: bool,
    namer: Namer,
    /// Known targets and what they are assigned (column → values).
    targets: Vec<(String, Assigned)>,
    /// Pins: (table, column, kind).
    pins: Vec<(String, String, PinKind)>,
    /// Unqualified WHERE columns that could belong to more than one table
    /// of the scope, or to a derived table: (column, candidate base tables).
    ambiguous: Vec<(String, Vec<String>)>,
}

/// The answer of a value helper: values, or why they are not known.
pub(crate) type Vals = Result<Vec<FactVal>, String>;

impl Facts {
    /// Facts of one statement from its shape and the reference walk of it
    /// (`Err`: the walk failed, e.g. nesting past the limits).
    pub(crate) fn build(
        shape: Shape,
        refs: Option<Result<Vec<Ref>, String>>,
        namer: Namer,
    ) -> Facts {
        let mut truncated = false;
        let mut tables = Vec::new();
        let mut written = Vec::new();
        let mut cols_read = Vec::new();
        let mut cols_written = Vec::new();
        let mut refs_unknown: Option<String> = None;
        let refs_seen = refs.is_some();

        match refs {
            Some(Ok(refs)) => {
                for r in refs {
                    match r {
                        Ref::Relation { schema, table } => {
                            tables.push(namer.table(schema.as_deref(), &table));
                        }
                        Ref::Column {
                            schema,
                            table,
                            column,
                        } => {
                            let t = namer.table(schema.as_deref(), &table);
                            cols_read.push(format!("{t}.{}", namer.fold.apply(&column)));
                            tables.push(t);
                        }
                        Ref::AllColumns { schema, table } => {
                            let t = namer.table(schema.as_deref(), &table);
                            cols_read.push(format!("{t}.*"));
                            tables.push(t);
                        }
                        Ref::Write {
                            schema,
                            table,
                            column,
                        } => {
                            let t = namer.table(schema.as_deref(), &table);
                            if let Some(c) = column {
                                let c = if c == "*" { c } else { namer.fold.apply(&c) };
                                cols_written.push(format!("{t}.{c}"));
                            }
                            written.push(t.clone());
                            tables.push(t);
                        }
                        // A statement kind the walk denies outright: its
                        // tables are the DDL targets below, or unknown.
                        Ref::Statement(_) => {}
                    }
                }
            }
            Some(Err(e)) => refs_unknown = Some(e),
            None => {}
        }
        if let Some(targets) = &shape.ddl_targets {
            for t in targets {
                let n = namer.name(t);
                written.push(n.clone());
                tables.push(n);
            }
        }
        let walked = !shape.refs_from_walk || refs_seen;
        let tables_known = refs_unknown.is_none()
            && walked
            && (shape.refs_from_walk || shape.ddl_targets.is_some());
        let unknown = |why: &str| FactList::Unknown(why.to_string());
        let not_extracted = || {
            refs_unknown.clone().unwrap_or_else(|| {
                format!("the tables of a {} statement are not extracted", shape.kind)
            })
        };
        let (tables, tables_written, columns_read, columns_written) = if tables_known {
            (
                FactList::capped(tables, &mut truncated),
                FactList::capped(written, &mut truncated),
                FactList::capped(cols_read, &mut truncated),
                FactList::capped(cols_written, &mut truncated),
            )
        } else {
            let why = not_extracted();
            (unknown(&why), unknown(&why), unknown(&why), unknown(&why))
        };
        let functions = match &shape.functions {
            Ok(f) => FactList::capped(
                f.iter().map(|s| s.to_ascii_lowercase()).collect(),
                &mut truncated,
            ),
            Err(why) => unknown(why),
        };

        // Assignments, keyed by the normalized target.
        let mut targets = Vec::new();
        if let Some(t) = &shape.target {
            let name = namer.name(t);
            let assigned = assignments(&shape, &namer);
            targets.push((name, assigned));
        }

        let (pins, ambiguous) = match &shape.where_pred {
            Some(p) => resolve_pins(p, &shape.scope, &namer),
            None => (Vec::new(), Vec::new()),
        };

        Facts {
            op: shape.op,
            kind: shape.kind.clone(),
            tables,
            tables_written,
            columns_read,
            columns_written,
            functions,
            has_where: shape.where_pred.is_some(),
            where_always_true: shape.where_always_true,
            limit: shape.limit.clone(),
            has_returning: shape.has_returning,
            insert_rows: shape.insert_rows,
            truncated,
            namer,
            targets: if shape.nested_writes {
                // A nested write can assign anything to any table it writes.
                Vec::new()
            } else {
                targets
            },
            pins,
            ambiguous,
        }
    }

    /// Facts for a statement nothing could be read from (a Snowflake
    /// statement only the pre-classifier recognised).
    pub(crate) fn opaque(kind: &str, namer: Namer) -> Facts {
        let mut shape = Shape::new("other", kind);
        shape.functions = Err("the statement was not parsed");
        Facts::build(shape, None, namer)
    }

    /// Normalizes a `schema.table.column` (or `table.column`) argument.
    fn split_col(&self, col: &str) -> Option<(String, String)> {
        let (t, c) = col.rsplit_once('.')?;
        Some((self.namer.fold.apply(t), self.namer.fold.apply(c)))
    }

    /// Whether a normalized fact table is the table an argument names: the
    /// same name, or the same table segment when either side has no schema
    /// (an unknown default schema, or `table.column` in the policy): the
    /// over-matching side, which is the conservative one.
    pub(crate) fn same_table(&self, fact: &str, arg: &str) -> bool {
        if fact == arg {
            return true;
        }
        let seg = |s: &str| {
            s.rsplit_once('.')
                .map_or(s.to_string(), |(_, t)| t.to_string())
        };
        let unqualified = |s: &str| !s.contains('.');
        (unqualified(fact) || unqualified(arg)) && self.namer.fold.eq(&seg(fact), &seg(arg))
    }

    fn written_tables(&self) -> &[String] {
        match &self.tables_written {
            FactList::Known(v) => v,
            FactList::Unknown(_) => &[],
        }
    }

    /// `stmt.values(col)`: the values assigned to `col`.
    pub(crate) fn values(&self, col: &str) -> Vals {
        let Some((table, column)) = self.split_col(col) else {
            return Err(format!("`{col}` is not a schema.table.column name"));
        };
        let mut out = Vec::new();
        let mut matched_target = false;
        for (t, assigned) in &self.targets {
            if !self.same_table(t, &table) {
                continue;
            }
            matched_target = true;
            match assigned {
                Ok(cols) => {
                    for (c, vals) in cols {
                        if c == &column || c == "*" {
                            out.extend(vals.iter().cloned());
                        }
                    }
                }
                Err(why) => return Err(format!("values assigned to {t}: {why}")),
            }
        }
        if let FactList::Unknown(why) = &self.tables_written {
            return Err(format!(
                "the tables this statement writes are not known ({why})"
            ));
        }
        // Written, but not as the visible target (a nested write, MERGE,
        // INSERT … SELECT): the values are not visible.
        if !matched_target
            && self
                .written_tables()
                .iter()
                .any(|w| self.same_table(w, &table))
        {
            return Err(format!("the values written to {table} are not visible"));
        }
        // Parameters and expressions are returned as they are: the CEL
        // layer turns them into UNKNOWN only when the policy reads them.
        Ok(out)
    }

    fn ambiguous_for(&self, table: &str, column: &str) -> bool {
        self.ambiguous.iter().any(|(c, cands)| {
            self.namer.fold.eq(c, column) && cands.iter().any(|t| self.same_table(t, table))
        })
    }

    fn pins_for(&self, col: &str) -> Result<Vec<&PinKind>, String> {
        let Some((table, column)) = self.split_col(col) else {
            return Err(format!("`{col}` is not a schema.table.column name"));
        };
        if self.ambiguous_for(&table, &column) {
            return Err(format!(
                "`{column}` is unqualified in the WHERE and may belong to more than one table"
            ));
        }
        Ok(self
            .pins
            .iter()
            .filter(|(t, c, _)| c == &column && self.same_table(t, &table))
            .map(|(_, _, k)| k)
            .collect())
    }

    /// `stmt.has_filter(col)`: a top-level conjunctive `=`/`IN` on `col`.
    pub(crate) fn has_filter(&self, col: &str) -> Result<bool, String> {
        Ok(self
            .pins_for(col)?
            .iter()
            .any(|k| matches!(k, PinKind::Values(_))))
    }

    /// `stmt.filter_values(col)`: the values `col` is pinned to (empty when
    /// unconstrained). Several pins on the same column: their union (each
    /// value is a value the statement may select).
    pub(crate) fn filter_values(&self, col: &str) -> Vals {
        let mut out: Vec<FactVal> = Vec::new();
        for k in self.pins_for(col)? {
            if let PinKind::Values(v) = k {
                for x in v {
                    if !out.contains(x) {
                        out.push(x.clone());
                    }
                }
            }
        }
        Ok(out)
    }

    /// The bounds of `col` from the top-level conjunction: every lower (or
    /// upper) bound written, equality and `IN` included (`col = v` bounds
    /// both ways). The CEL layer takes the tightest known one.
    pub(crate) fn bounds(&self, col: &str, lower: bool) -> Vals {
        let mut out = Vec::new();
        for k in self.pins_for(col)? {
            match k {
                PinKind::Values(v) => out.extend(v.iter().cloned()),
                PinKind::Lower(v) if lower => out.push(v.clone()),
                PinKind::Upper(v) if !lower => out.push(v.clone()),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Normalizes a table glob argument the way fact names are folded.
    pub(crate) fn fold_arg(&self, s: &str) -> String {
        self.namer.fold.apply(s)
    }
}

/// What the target's columns are assigned, by normalized column name (`*`:
/// every column, for `INSERT` without a column list).
fn assignments(shape: &Shape, namer: &Namer) -> Assigned {
    let fold = |c: &str| namer.fold.apply(c);
    let mut out: Vec<(String, Vec<FactVal>)> = Vec::new();
    let mut push = |c: String, v: FactVal| match out.iter_mut().find(|(k, _)| *k == c) {
        Some((_, vals)) => vals.push(v),
        None => out.push((c, vec![v])),
    };
    match &shape.assign {
        Assign::None => {}
        Assign::Unknown(why) => return Err(why),
        Assign::Rows { columns: None, .. } => {
            return Err(
                "INSERT without a column list: which value goes to which column is not known",
            );
        }
        Assign::Rows {
            columns: Some(cols),
            rows,
        } => {
            for row in rows {
                if row.len() != cols.len() {
                    return Err("a VALUES row does not match the column list");
                }
                for (c, v) in cols.iter().zip(row) {
                    push(fold(c), v.clone());
                }
            }
        }
        Assign::Set(pairs) => {
            for (c, v) in pairs {
                push(fold(c), v.clone());
            }
        }
    }
    for (c, v) in &shape.upsert {
        push(fold(c), v.clone());
    }
    Ok(out)
}

/// The conjuncts of the top-level WHERE resolved to tables of the scope.
fn resolve_pins(pred: &Pred, scope: &[ScopeItem], namer: &Namer) -> Pins {
    let mut conj = Vec::new();
    flatten(pred, &mut conj);
    let base: Vec<String> = scope
        .iter()
        .filter_map(|s| s.table.as_ref().map(|t| namer.name(t)))
        .collect();
    let mut pins = Vec::new();
    let mut ambiguous = Vec::new();
    for p in conj {
        let (col, kind) = match p {
            Pred::Eq(c, v) => (c, PinKind::Values(vec![v.clone()])),
            Pred::In(c, vs) => (c, PinKind::Values(vs.clone())),
            Pred::Bound { col, lower, val } => (
                col,
                if *lower {
                    PinKind::Lower(val.clone())
                } else {
                    PinKind::Upper(val.clone())
                },
            ),
            Pred::Between(c, lo, hi) => {
                if let Some(t) = resolve(c, scope, namer, &base, &mut ambiguous) {
                    let column = namer.fold.apply(&c.column);
                    pins.push((t.clone(), column.clone(), PinKind::Lower(lo.clone())));
                    pins.push((t, column, PinKind::Upper(hi.clone())));
                }
                continue;
            }
            Pred::And(_) | Pred::Other => continue,
        };
        if let Some(t) = resolve(col, scope, namer, &base, &mut ambiguous) {
            pins.push((t, namer.fold.apply(&col.column), kind));
        }
    }
    (pins, ambiguous)
}

fn flatten<'p>(p: &'p Pred, out: &mut Vec<&'p Pred>) {
    match p {
        Pred::And(items) => items.iter().for_each(|i| flatten(i, out)),
        other => out.push(other),
    }
}

/// The base table a WHERE column belongs to, or `None` (recording it as
/// ambiguous when it may belong to a base table).
fn resolve(
    c: &ColRef,
    scope: &[ScopeItem],
    namer: &Namer,
    base: &[String],
    ambiguous: &mut Vec<(String, Vec<String>)>,
) -> Option<String> {
    let fold = namer.fold;
    if c.qualifier.is_empty() {
        return match scope {
            [ScopeItem { table: Some(t), .. }] => Some(namer.name(t)),
            _ => {
                if !base.is_empty() {
                    ambiguous.push((c.column.clone(), base.to_vec()));
                }
                None
            }
        };
    }
    let q = &c.qualifier;
    // An alias (one part) of a scope item.
    if q.len() == 1 {
        if let Some(item) = scope
            .iter()
            .find(|s| s.alias.as_deref().is_some_and(|a| fold.eq(a, &q[0])))
        {
            return item.table.as_ref().map(|t| namer.name(t));
        }
    }
    // A table named by itself (`orders.id`, `public.orders.id`), not hidden
    // by an alias.
    scope.iter().find_map(|s| {
        let t = s.table.as_ref()?;
        if s.alias.is_some() {
            return None;
        }
        let matches = if q.len() == 1 {
            fold.eq(t.table(), &q[0])
        } else {
            namer.name(&Name::new(q.clone())) == namer.name(t)
        };
        matches.then(|| namer.name(t))
    })
}

/// The names sqlparser and pg_query front ends treat as type modifiers, not
/// functions, when they are read from tokens (`varchar(10)`).
pub(crate) fn is_type_modifier(name: &str) -> bool {
    matches!(
        name,
        "varchar"
            | "char"
            | "character"
            | "nchar"
            | "nvarchar"
            | "varbinary"
            | "binary"
            | "numeric"
            | "decimal"
            | "dec"
            | "timestamp"
            | "timestamptz"
            | "time"
            | "timetz"
            | "interval"
            | "bit"
            | "varbit"
            | "float"
            | "varying"
    )
}

#[cfg(test)]
mod tests;

/// The facts of one statement, as policies read them: for the policy
/// editor ("what does Vericto see in this SQL?") and for tests. Values a
/// statement assigns or pins are rendered as SQL-ish text (`950`, `'x'`,
/// `$2`, `<expr>`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[non_exhaustive]
pub struct StatementFacts {
    pub op: String,
    pub kind: String,
    /// `Err`: why the list is not known.
    pub tables: Result<Vec<String>, String>,
    pub tables_written: Result<Vec<String>, String>,
    pub columns_read: Result<Vec<String>, String>,
    pub columns_written: Result<Vec<String>, String>,
    pub functions: Result<Vec<String>, String>,
    pub has_where: bool,
    pub where_always_true: bool,
    /// `None`: no LIMIT; `Some(Err)`: not a literal.
    pub limit: Option<Result<i64, String>>,
    pub has_returning: bool,
    pub insert_rows: Option<i64>,
    pub truncated: bool,
    /// Target column → assigned values (`Err`: not visible).
    pub assignments: Vec<(String, Result<Vec<String>, String>)>,
    /// `table.column` → pin kind and values, from the top-level WHERE.
    pub pins: Vec<(String, String, Vec<String>)>,
    /// Unqualified WHERE columns that could not be resolved to one table.
    pub ambiguous: Vec<String>,
}

fn show(v: &FactVal) -> String {
    match v {
        FactVal::Int(i) => i.to_string(),
        FactVal::Double(d) => d.to_string(),
        FactVal::Str(s) => format!("'{s}'"),
        FactVal::Bool(b) => b.to_string(),
        FactVal::Null => "NULL".into(),
        FactVal::Param(0) => "?".into(),
        FactVal::Param(n) => format!("${n}"),
        FactVal::Expr => "<expr>".into(),
    }
}

fn list_res(l: &FactList) -> Result<Vec<String>, String> {
    match l {
        FactList::Known(v) => Ok(v.clone()),
        FactList::Unknown(w) => Err(w.clone()),
    }
}

impl Facts {
    pub(crate) fn public(&self) -> StatementFacts {
        StatementFacts {
            op: self.op.to_string(),
            kind: self.kind.clone(),
            tables: list_res(&self.tables),
            tables_written: list_res(&self.tables_written),
            columns_read: list_res(&self.columns_read),
            columns_written: list_res(&self.columns_written),
            functions: list_res(&self.functions),
            has_where: self.has_where,
            where_always_true: self.where_always_true,
            limit: match &self.limit {
                LimitFact::Absent => None,
                LimitFact::Int(i) => Some(Ok(*i)),
                LimitFact::Unknown(w) => Some(Err(w.to_string())),
            },
            has_returning: self.has_returning,
            insert_rows: self.insert_rows,
            truncated: self.truncated,
            assignments: self
                .targets
                .iter()
                .flat_map(|(t, a)| match a {
                    Ok(cols) => cols
                        .iter()
                        .map(|(c, v)| (format!("{t}.{c}"), Ok(v.iter().map(show).collect())))
                        .collect::<Vec<_>>(),
                    Err(w) => vec![(t.clone(), Err(w.to_string()))],
                })
                .collect(),
            pins: self
                .pins
                .iter()
                .map(|(t, c, k)| {
                    let (kind, vals) = match k {
                        PinKind::Values(v) => ("=", v.iter().map(show).collect()),
                        PinKind::Lower(v) => (">=", vec![show(v)]),
                        PinKind::Upper(v) => ("<=", vec![show(v)]),
                    };
                    (format!("{t}.{c}"), kind.to_string(), vals)
                })
                .collect(),
            ambiguous: self.ambiguous.iter().map(|(c, _)| c.clone()).collect(),
        }
    }
}

/// The facts policies read from each top-level statement of `sql`
/// (every fact, including the function scan). `default_schema` is the
/// host's, as in [`crate::policy::EvalContext::default_schema`].
pub fn statement_facts(
    sql: &str,
    dialect: Dialect,
    default_schema: Option<&str>,
) -> Result<Vec<StatementFacts>, String> {
    let parsed = crate::parser::parser_for(dialect)
        .parse(sql)
        .map_err(|e| e.to_string())?;
    if parsed
        .mysql
        .as_deref()
        .is_some_and(|m| matches!(m, crate::parser::MysqlReadings::Ambiguous(_)))
    {
        return Err("MySQL may read this text differently (VERICTO-086)".into());
    }
    Ok(extract(
        &parsed,
        Some(sql),
        default_schema,
        Want {
            refs: true,
            functions: true,
        },
    )
    .iter()
    .map(Facts::public)
    .collect())
}
