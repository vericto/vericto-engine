//! Sensitive Column Protection (VERICTO-085).
//!
//! The host tags columns as sensitive ([`SensitiveColumn`], carried in
//! [`EnforcementPolicy::sensitive_columns`](crate::EnforcementPolicy)) and gives
//! each one a policy: `block`, `flag` or `mask`. This module decides whether a
//! query **reads** one of them — whether a tagged column reaches the client, or
//! is copied somewhere an agent could read it next — and resolves the policy.
//!
//! ## What "reads" means
//!
//! A column is read when it is among the *source columns* of a projected
//! expression: the target list of the statement the client receives rows from
//! (every arm of a set operation), `RETURNING`, `COPY … TO`, a cursor or a
//! prepared statement. Derivation is followed through aliases, expressions,
//! functions, aggregates, casts, scalar subqueries, derived tables and CTEs.
//! A column used only to filter, join, group or order (`WHERE`, `JOIN ON`,
//! `GROUP BY`, `HAVING`, `ORDER BY`, aggregate `FILTER`, `EXISTS`) is not read:
//! nothing of it is projected. Inference by probing is out of scope.
//!
//! **Data copies count as reads** — `INSERT … SELECT`, `CREATE TABLE … AS`,
//! `SELECT … INTO`, `CREATE VIEW`, `UPDATE … SET x = <tagged>`, `MERGE` — because
//! they move the value into an untagged place the next query reads freely.
//!
//! ## Conservative by construction
//!
//! The engine has no schema. Every place where it cannot know, it assumes the
//! column is sensitive (design §5.3): a false positive is a blocked query with a
//! clear message, a false negative is a leak.
//!
//! - `*`, `t.*` and whole-row references (`to_jsonb(c)`) touch **every** tagged
//!   column of the table, and cannot be masked (there is nothing to name).
//! - An unqualified table matches a tag of any schema; an unqualified column
//!   resolves against every relation in scope, at every nesting level.
//! - Identifiers compare ASCII case-insensitively.
//! - An expression the walker does not model is assumed to read every tagged
//!   column it mentions anywhere inside it.
//!
//! ## Zero cost when unused
//!
//! Nothing here runs when `sensitive_columns` is empty: the engine checks the
//! vector before calling in, so a host that sends no tags pays one `is_empty()`.

pub(crate) mod mysql;
pub(crate) mod pg;
pub(crate) mod sql;

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::parser::{Dialect, ParsedQuery, SourceAst};

/// Rule code reported for every sensitive-column outcome.
pub const SENSITIVE_RULE_CODE: &str = "VERICTO-085";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// What to do when a query reads a tagged column.
///
/// Strictness, used when one query reads several tagged columns:
/// `Block > Mask > Flag`. Deserializes case-insensitively, and **an unknown value
/// deserializes as `Block`**, so a policy name this engine does not know yet can
/// never silently disable the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SensitivePolicy {
    /// Allow the query, record and alert.
    Flag,
    /// Rewrite the projection so the column's value is masked (Postgres and
    /// MySQL; Oracle and SQL Server block).
    Mask,
    /// Reject the query.
    Block,
}

impl SensitivePolicy {
    /// Strictness rank: `Flag < Mask < Block`.
    fn rank(self) -> u8 {
        match self {
            SensitivePolicy::Flag => 0,
            SensitivePolicy::Mask => 1,
            SensitivePolicy::Block => 2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SensitivePolicy::Flag => "flag",
            SensitivePolicy::Mask => "mask",
            SensitivePolicy::Block => "block",
        }
    }
}

impl<'de> Deserialize<'de> for SensitivePolicy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "flag" => SensitivePolicy::Flag,
            "mask" => SensitivePolicy::Mask,
            "block" => SensitivePolicy::Block,
            other => {
                tracing::warn!(
                    policy = other,
                    "unknown sensitive-column policy, treating as block"
                );
                SensitivePolicy::Block
            }
        })
    }
}

/// How a masked column is rendered (design §5.4). Deserializes
/// case-insensitively; an unknown value deserializes as `Full`, the style that
/// reveals nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MaskStyle {
    /// `'[redacted]'`
    #[default]
    Full,
    /// `'****' || right(col::text, 4)`
    Last4,
    /// First character and the domain kept: `j***@example.com`.
    Email,
    /// SHA-256 hex of the text value.
    Hash,
}

impl<'de> Deserialize<'de> for MaskStyle {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "full" => MaskStyle::Full,
            "last4" => MaskStyle::Last4,
            "email" => MaskStyle::Email,
            "hash" => MaskStyle::Hash,
            other => {
                tracing::warn!(style = other, "unknown mask style, treating as full");
                MaskStyle::Full
            }
        })
    }
}

/// A column the host marked as sensitive, with its policy.
///
/// JSON: `{"schema":"public","table":"customers","column":"email","policy":"mask","mask_style":"email"}`.
/// `schema` may be null or absent (any schema); `mask_style` may be absent
/// (`full`). The database column names `schema_name` / `table_name` /
/// `column_name` are accepted as aliases.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SensitiveColumn {
    #[serde(default, alias = "schema_name")]
    pub schema: Option<String>,
    #[serde(alias = "table_name")]
    pub table: String,
    #[serde(alias = "column_name")]
    pub column: String,
    pub policy: SensitivePolicy,
    #[serde(default)]
    pub mask_style: MaskStyle,
}

/// A tagged column a query reads, reported for the audit trail. The identity is
/// the **tag's**, not the query's spelling of it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TouchedColumn {
    pub schema: Option<String>,
    pub table: String,
    pub column: String,
    pub policy: SensitivePolicy,
}

impl PartialOrd for SensitivePolicy {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SensitivePolicy {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// ---------------------------------------------------------------------------
// Tag index
// ---------------------------------------------------------------------------

pub(crate) fn ieq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The configured tags, with the matching rules of design §5.3.
pub(crate) struct Tags<'a> {
    pub(crate) cols: &'a [SensitiveColumn],
}

impl<'a> Tags<'a> {
    pub(crate) fn new(cols: &'a [SensitiveColumn]) -> Self {
        Self { cols }
    }

    /// Whether tag `i` can be the relation `schema.table` as written in the
    /// query. Unqualified in the query: any schema (the `search_path` could
    /// resolve it there). Unqualified tag: any schema. Both qualified: equal.
    fn table_matches(&self, i: usize, schema: Option<&str>, table: &str) -> bool {
        let tag = &self.cols[i];
        if !ieq(&tag.table, table) {
            return false;
        }
        match (tag.schema.as_deref(), schema) {
            (Some(ts), Some(qs)) => ieq(ts, qs),
            _ => true,
        }
    }

    /// Tags on `schema.table`.
    pub(crate) fn of_table(&self, schema: Option<&str>, table: &str) -> Lineage {
        let mut out = Lineage::new();
        for i in 0..self.cols.len() {
            if self.table_matches(i, schema, table) {
                out.insert(i, Flow::DIRECT);
            }
        }
        out
    }

    /// Tags on `schema.table.column`.
    pub(crate) fn of_column(&self, schema: Option<&str>, table: &str, column: &str) -> Lineage {
        let mut out = Lineage::new();
        for i in 0..self.cols.len() {
            if self.table_matches(i, schema, table) && ieq(&self.cols[i].column, column) {
                out.insert(i, Flow::DIRECT);
            }
        }
        out
    }

    /// Every tag on a column named `column`, whatever its table. Used by the
    /// conservative fallback for expressions the walkers do not model.
    pub(crate) fn any_with_column(&self, column: &str) -> Lineage {
        let mut out = Lineage::new();
        for (i, tag) in self.cols.iter().enumerate() {
            if ieq(&tag.column, column) {
                out.insert(i, Flow::INDIRECT);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Lineage: which tagged columns a value derives from, and how
// ---------------------------------------------------------------------------

/// How a value derives from one tagged column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flow {
    /// The value IS the column: reached through bare column references only
    /// (aliases, CTE/subquery pass-through, scalar subquery). Only a direct
    /// value may be masked with its tag's style; anything computed is masked
    /// `full`, because applying `last4`/`hash` to a caller-chosen expression
    /// leaks (four `substring` calls rebuild a card number).
    pub(crate) direct: bool,
    /// Reached through `*`, `t.*` or a whole-row reference: cannot be masked.
    pub(crate) star: bool,
}

impl Flow {
    pub(crate) const DIRECT: Flow = Flow {
        direct: true,
        star: false,
    };
    pub(crate) const INDIRECT: Flow = Flow {
        direct: false,
        star: false,
    };

    fn join(self, other: Flow) -> Flow {
        Flow {
            direct: self.direct && other.direct,
            star: self.star || other.star,
        }
    }
}

/// Tag index → how the value derives from it. A `BTreeMap` so iteration (and
/// therefore every message and the touched list) is deterministic.
pub(crate) type Lineage = BTreeMap<usize, Flow>;

pub(crate) fn merge(into: &mut Lineage, from: Lineage) {
    for (k, f) in from {
        into.entry(k).and_modify(|e| *e = e.join(f)).or_insert(f);
    }
}

/// The value is computed from these sources, not equal to them.
pub(crate) fn indirect(mut l: Lineage) -> Lineage {
    for f in l.values_mut() {
        f.direct = false;
    }
    l
}

/// The sources were reached through a star or a whole-row reference.
pub(crate) fn starred(mut l: Lineage) -> Lineage {
    for f in l.values_mut() {
        f.direct = false;
        f.star = true;
    }
    l
}

// ---------------------------------------------------------------------------
// Scopes: what a column reference can resolve to
// ---------------------------------------------------------------------------

/// One output column of a derived relation (subquery, CTE, `RETURNING`).
#[derive(Debug, Clone)]
pub(crate) enum OutCol {
    Named {
        name: String,
        lin: Lineage,
    },
    /// `*` over a base table: the column names are unknown, but a reference by
    /// name resolves exactly to that table's column.
    BaseStar {
        schema: Option<String>,
        table: String,
    },
    /// `*` over something whose columns are unknown and not a base table
    /// (a function): any name resolves to everything it derives from.
    OpaqueStar {
        lin: Lineage,
    },
}

/// A relation visible in a `FROM` scope.
#[derive(Debug, Clone)]
pub(crate) enum Item {
    Base {
        refname: String,
        schema: Option<String>,
        table: String,
    },
    Derived {
        refname: Option<String>,
        cols: Vec<OutCol>,
    },
    /// Columns unknown; every column derives from `lin`.
    Opaque {
        refname: Option<String>,
        lin: Lineage,
    },
    /// An aliased join, `(a JOIN b) AS j`: `j.x` may be either side.
    Join {
        refname: Option<String>,
        items: Vec<Item>,
    },
}

impl Item {
    fn refname(&self) -> Option<&str> {
        match self {
            Item::Base { refname, .. } => Some(refname),
            Item::Derived { refname, .. }
            | Item::Opaque { refname, .. }
            | Item::Join { refname, .. } => refname.as_deref(),
        }
    }

    /// Whether `qualifier` (`t` or `s.t`) names this item.
    fn named_by(&self, qualifier: &[&str]) -> bool {
        match (self, qualifier) {
            (_, [t]) => self.refname().is_some_and(|r| ieq(r, t)),
            (
                Item::Base {
                    refname,
                    schema,
                    table,
                },
                [s, t],
            ) => {
                // `s.t.col` only names an unaliased base table (an alias hides
                // the qualified name), but be generous: refname or table.
                (ieq(refname, t) || ieq(table, t)) && schema.as_deref().is_none_or(|sc| ieq(sc, s))
            }
            _ => false,
        }
    }

    fn column(&self, tags: &Tags, col: &str) -> Lineage {
        match self {
            Item::Base { schema, table, .. } => tags.of_column(schema.as_deref(), table, col),
            Item::Derived { cols, .. } => {
                let mut out = Lineage::new();
                for c in cols {
                    match c {
                        OutCol::Named { name, lin } if ieq(name, col) => {
                            merge(&mut out, lin.clone())
                        }
                        OutCol::Named { .. } => {}
                        OutCol::BaseStar { schema, table } => {
                            merge(&mut out, tags.of_column(schema.as_deref(), table, col))
                        }
                        OutCol::OpaqueStar { lin } => merge(&mut out, indirect(lin.clone())),
                    }
                }
                out
            }
            Item::Opaque { lin, .. } => indirect(lin.clone()),
            Item::Join { items, .. } => {
                let mut out = Lineage::new();
                for it in items {
                    merge(&mut out, it.column(tags, col));
                }
                out
            }
        }
    }

    /// Everything a `*` / whole-row reference over this item reads.
    fn star(&self, tags: &Tags) -> Lineage {
        let mut out = Lineage::new();
        for c in self.star_cols() {
            merge(&mut out, outcol_all(tags, &c));
        }
        starred(out)
    }

    /// The output columns `*` over this item expands to.
    fn star_cols(&self) -> Vec<OutCol> {
        match self {
            Item::Base { schema, table, .. } => vec![OutCol::BaseStar {
                schema: schema.clone(),
                table: table.clone(),
            }],
            Item::Derived { cols, .. } => cols.clone(),
            Item::Opaque { lin, .. } => vec![OutCol::OpaqueStar { lin: lin.clone() }],
            Item::Join { items, .. } => items.iter().flat_map(|i| i.star_cols()).collect(),
        }
    }
}

/// Everything an output column derives from.
pub(crate) fn outcol_all(tags: &Tags, c: &OutCol) -> Lineage {
    match c {
        OutCol::Named { lin, .. } => lin.clone(),
        OutCol::BaseStar { schema, table } => starred(tags.of_table(schema.as_deref(), table)),
        OutCol::OpaqueStar { lin } => starred(lin.clone()),
    }
}

/// Union of everything a list of output columns derives from.
pub(crate) fn outcols_all(tags: &Tags, cols: &[OutCol]) -> Lineage {
    let mut out = Lineage::new();
    for c in cols {
        merge(&mut out, outcol_all(tags, c));
    }
    out
}

/// The `FROM` scopes of the query being walked, outermost first.
#[derive(Default)]
pub(crate) struct Scopes {
    pub(crate) levels: Vec<Vec<Item>>,
}

impl Scopes {
    pub(crate) fn push(&mut self) {
        self.levels.push(Vec::new());
    }

    pub(crate) fn pop(&mut self) -> Vec<Item> {
        self.levels.pop().unwrap_or_default()
    }

    pub(crate) fn add(&mut self, item: Item) {
        if let Some(level) = self.levels.last_mut() {
            level.push(item);
        }
    }

    /// Items named by `qualifier`, at the innermost level that has one (a
    /// relation name is known for certain, so the first match shadows outer
    /// ones, as in SQL).
    fn named(&self, qualifier: &[&str]) -> Vec<&Item> {
        for level in self.levels.iter().rev() {
            let hits: Vec<&Item> = level
                .iter()
                .flat_map(flatten_unaliased)
                .filter(|i| i.named_by(qualifier))
                .collect();
            if !hits.is_empty() {
                return hits;
            }
        }
        Vec::new()
    }

    /// Resolves a column reference `qualifier.col` (qualifier may be empty).
    ///
    /// Unqualified: the union over **every** item at **every** level. The
    /// engine cannot tell which relation has the column (it has no schema), so
    /// it does not stop at the innermost one: a correlated subquery over a
    /// table without that column would otherwise hide the outer tagged one.
    pub(crate) fn column(&self, tags: &Tags, qualifier: &[&str], col: &str) -> Lineage {
        let mut out = Lineage::new();
        if qualifier.is_empty() {
            for level in &self.levels {
                for item in level {
                    merge(&mut out, item.column(tags, col));
                }
            }
            return out;
        }
        let q = &qualifier[qualifier.len().saturating_sub(2)..];
        let hits = self.named(q);
        if hits.is_empty() {
            // Not a relation in scope (or a spelling the walker does not model):
            // match the tags by name.
            let (schema, table) = match q {
                [t] => (None, *t),
                [s, t] => (Some(*s), *t),
                _ => return out,
            };
            return tags.of_column(schema, table, col);
        }
        for item in hits {
            merge(&mut out, item.column(tags, col));
        }
        out
    }

    /// `qualifier.*`, or `*` over the innermost level when `qualifier` is empty.
    pub(crate) fn star(&self, tags: &Tags, qualifier: &[&str]) -> (Lineage, Vec<OutCol>) {
        let mut lin = Lineage::new();
        let mut cols = Vec::new();
        let items: Vec<&Item> = if qualifier.is_empty() {
            self.levels
                .last()
                .map(|l| l.iter().collect())
                .unwrap_or_default()
        } else {
            let q = &qualifier[qualifier.len().saturating_sub(2)..];
            let hits = self.named(q);
            if hits.is_empty() {
                let (schema, table) = match q {
                    [t] => (None, *t),
                    [s, t] => (Some(*s), *t),
                    _ => return (lin, cols),
                };
                return (
                    starred(tags.of_table(schema, table)),
                    vec![OutCol::BaseStar {
                        schema: schema.map(str::to_string),
                        table: table.to_string(),
                    }],
                );
            }
            hits
        };
        for item in items {
            merge(&mut lin, item.star(tags));
            cols.extend(item.star_cols());
        }
        (lin, cols)
    }

    /// A single-name reference that may be a whole-row reference
    /// (`to_jsonb(c)`, `SELECT c FROM customers c`).
    pub(crate) fn whole_row(&self, tags: &Tags, name: &str) -> Lineage {
        let mut out = Lineage::new();
        for item in self.named(&[name]) {
            merge(&mut out, item.star(tags));
        }
        out
    }
}

/// An unaliased join's sides are visible by their own names.
fn flatten_unaliased(item: &Item) -> Vec<&Item> {
    match item {
        Item::Join {
            refname: None,
            items,
        } => items.iter().flat_map(flatten_unaliased).collect(),
        other => vec![other],
    }
}

// ---------------------------------------------------------------------------
// Touches: what the walk found at the sinks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TouchFlags {
    /// Read through `*` / whole-row / `COPY table TO`.
    pub(crate) star: bool,
    /// Copied into another relation (INSERT … SELECT, CTAS, VIEW, UPDATE SET).
    pub(crate) copy: bool,
    /// Read somewhere a rewrite cannot reach (star, copy, `COPY table (cols)`).
    pub(crate) fixed: bool,
}

/// Where a lineage ends up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sink {
    /// Sent to the client. `rewrite` = this target list may be rewritten.
    Projected { rewrite: bool },
    /// Copied into another relation.
    Copy,
}

#[derive(Debug, Default)]
pub(crate) struct Touches {
    pub(crate) map: BTreeMap<usize, TouchFlags>,
}

impl Touches {
    pub(crate) fn record(&mut self, lin: &Lineage, sink: Sink) {
        for (&i, f) in lin {
            let e = self.map.entry(i).or_default();
            match sink {
                Sink::Projected { .. } => {
                    e.star |= f.star;
                    e.fixed |= f.star;
                }
                Sink::Copy => {
                    e.copy = true;
                    e.fixed = true;
                }
            }
        }
    }

    /// A projected read that no rewrite can reach (`COPY t (col) TO`).
    pub(crate) fn record_fixed(&mut self, lin: &Lineage) {
        for (&i, f) in lin {
            let e = self.map.entry(i).or_default();
            e.star |= f.star;
            e.fixed = true;
        }
    }
}

/// Which mask style a projected value gets: the tag's own style only when the
/// value is exactly one masked column, or several with the same style, all
/// direct. Anything computed or mixed gets `full`. `None` when the value reads
/// no masked tag (or reads one through a star, which cannot be rewritten).
pub(crate) fn mask_style_for(tags: &Tags, lin: &Lineage) -> Option<MaskStyle> {
    let mut style: Option<MaskStyle> = None;
    let mut all_direct = true;
    let mut any = false;
    for (&i, f) in lin {
        let tag = &tags.cols[i];
        if tag.policy != SensitivePolicy::Mask {
            continue;
        }
        if f.star {
            return None;
        }
        any = true;
        all_direct &= f.direct;
        style = match style {
            None => Some(tag.mask_style),
            Some(s) if s == tag.mask_style => Some(s),
            Some(_) => Some(MaskStyle::Full),
        };
    }
    if !any {
        return None;
    }
    if all_direct {
        style
    } else {
        Some(MaskStyle::Full)
    }
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// The sensitive-column verdict for one query, before it is combined with the
/// rule engine's verdict.
#[derive(Debug, Clone)]
pub(crate) struct SensitiveVerdict {
    /// The strictest policy that resolved: `Block` (block, or a mask that could
    /// not be applied), `Mask` (rewritten), or `Flag`.
    pub(crate) outcome: SensitivePolicy,
    pub(crate) ast_node_path: String,
    pub(crate) suggested_safe_query: Option<String>,
    /// The masked SQL, for a successful rewrite.
    pub(crate) rewritten_query: Option<String>,
    pub(crate) touched: Vec<TouchedColumn>,
}

fn display(tag: &SensitiveColumn) -> String {
    match &tag.schema {
        Some(s) => format!("{s}.{}.{}", tag.table, tag.column),
        None => format!("{}.{}", tag.table, tag.column),
    }
}

fn display_table(tag: &SensitiveColumn) -> String {
    match &tag.schema {
        Some(s) => format!("{s}.{}", tag.table),
        None => tag.table.clone(),
    }
}

#[cfg(test)]
thread_local! {
    /// How many times the analysis ran on this thread: lets a test prove the
    /// no-tags path never enters it.
    pub(crate) static ANALYSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Runs the analysis for `parsed` against `cols`. `None` when the query reads
/// no tagged column. Callers guarantee `cols` is non-empty.
pub(crate) fn evaluate(parsed: &ParsedQuery, cols: &[SensitiveColumn]) -> Option<SensitiveVerdict> {
    #[cfg(test)]
    ANALYSES.with(|n| n.set(n.get() + 1));
    let tags = Tags::new(cols);
    let any_mask = cols.iter().any(|c| c.policy == SensitivePolicy::Mask);

    let dialect = match &parsed.ast {
        SourceAst::Pg(_) => Dialect::Postgres,
        SourceAst::Sql { dialect, .. } => *dialect,
        SourceAst::None => return None,
    };
    let analysis = match &parsed.ast {
        SourceAst::Pg(tree) => pg::analyze(tree, &tags, any_mask),
        SourceAst::Sql {
            sql: Some(sql),
            dialect: Dialect::Mysql,
            ..
        } => match sql::analyze_mysql(sql, &tags, any_mask) {
            Ok(found) => Ok(found),
            Err(sql::Failure::TooDeep(e)) => Err(e),
            Err(sql::Failure::Unreadable(why)) => {
                // sqlparser and MySQL would read this text differently: it
                // cannot be shown not to read a tagged column. Resolved like a
                // parse error: blocked when any tag is `block` or `mask`,
                // flagged when every tag is `flag`.
                let protective = cols.iter().any(|c| c.policy != SensitivePolicy::Flag);
                return Some(SensitiveVerdict {
                    outcome: if protective {
                        SensitivePolicy::Block
                    } else {
                        SensitivePolicy::Flag
                    },
                    ast_node_path: format!(
                        "SensitiveColumn > query could not be analysed for sensitive columns ({why})"
                    ),
                    suggested_safe_query: None,
                    rewritten_query: None,
                    touched: Vec::new(),
                });
            }
        },
        SourceAst::Sql { statements, .. } => sql::analyze(statements, &tags).map(|t| (t, None)),
        SourceAst::None => return None,
    };

    let (touches, rewrite) = match analysis {
        Ok(found) => found,
        Err(e) => {
            // The walk itself failed (nesting past MAX_AST_DEPTH). The query
            // may read anything, so fail closed: this only happens when tags
            // are configured, which is exactly when a guess is a leak.
            return Some(SensitiveVerdict {
                outcome: SensitivePolicy::Block,
                ast_node_path: format!(
                    "SensitiveColumn > query could not be analysed for sensitive columns ({e})"
                ),
                suggested_safe_query: None,
                rewritten_query: None,
                touched: Vec::new(),
            });
        }
    };
    if touches.map.is_empty() {
        return None;
    }

    let mut touched: Vec<TouchedColumn> = touches
        .map
        .keys()
        .map(|&i| {
            let t = &cols[i];
            TouchedColumn {
                schema: t.schema.clone(),
                table: t.table.clone(),
                column: t.column.clone(),
                policy: t.policy,
            }
        })
        .collect();
    touched.sort();
    touched.dedup();

    let strictest = touches
        .map
        .keys()
        .map(|&i| cols[i].policy)
        .max()
        .unwrap_or(SensitivePolicy::Flag);

    // Columns at the strictest policy: the ones the message names.
    // Sorted by the tag's identity, not its position in the host's slice, so
    // the message is the same whatever order the tags arrive in.
    let mut culprits: Vec<usize> = touches
        .map
        .keys()
        .copied()
        .filter(|&i| cols[i].policy == strictest)
        .collect();
    culprits.sort_by(|&a, &b| {
        let key = |i: usize| (&cols[i].schema, &cols[i].table, &cols[i].column);
        key(a).cmp(&key(b))
    });
    let star_tables = |ids: &[usize]| -> Vec<String> {
        let mut t: Vec<String> = ids
            .iter()
            .filter(|i| touches.map[i].star)
            .map(|&i| display_table(&cols[i]))
            .collect();
        t.sort();
        t.dedup();
        t
    };
    let names = |ids: &[usize]| -> String {
        ids.iter()
            .map(|&i| display(&cols[i]))
            .collect::<Vec<_>>()
            .join(", ")
    };

    const LIST_COLUMNS: &str = "List the columns explicitly: `*`, `t.*`, whole-row references and `COPY table TO` read every tagged column";

    let verdict = match strictest {
        SensitivePolicy::Block | SensitivePolicy::Flag => {
            let stars = star_tables(&culprits);
            let path = if stars.is_empty() {
                format!(
                    "SensitiveColumn > {} ({})",
                    names(&culprits),
                    strictest.as_str()
                )
            } else {
                format!(
                    "SensitiveColumn > * over {} ({}): list the columns explicitly",
                    stars.join(", "),
                    strictest.as_str()
                )
            };
            SensitiveVerdict {
                outcome: strictest,
                ast_node_path: path,
                suggested_safe_query: if stars.is_empty() {
                    None
                } else {
                    Some(LIST_COLUMNS.to_string())
                },
                rewritten_query: None,
                touched,
            }
        }
        SensitivePolicy::Mask => {
            let fixed: Vec<usize> = culprits
                .iter()
                .copied()
                .filter(|i| touches.map[i].fixed)
                .collect();
            let blocked = |reason: String, hint: Option<String>| SensitiveVerdict {
                outcome: SensitivePolicy::Block,
                ast_node_path: format!(
                    "SensitiveColumn > {} (mask): mask unsupported: {reason}",
                    names(if fixed.is_empty() { &culprits } else { &fixed })
                ),
                suggested_safe_query: hint,
                rewritten_query: None,
                touched: touched.clone(),
            };
            if !matches!(dialect, Dialect::Postgres | Dialect::Mysql) {
                // Oracle and SQL Server have no rewrite. Forwarding the
                // unmasked value (flag) would silently downgrade "never in
                // clear" to "tell me afterwards"; block is the fail-safe
                // direction.
                blocked(
                    format!(
                        "no rewrite for {} yet; tag the column block or flag, or leave it out of the projection",
                        dialect_name(dialect)
                    ),
                    None,
                )
            } else if !fixed.is_empty() {
                let star = fixed.iter().any(|i| touches.map[i].star);
                let copy = fixed.iter().any(|i| touches.map[i].copy);
                if star {
                    blocked(
                        "`*`, whole-row reference or `COPY … TO` cannot be masked; list the columns explicitly".to_string(),
                        Some(LIST_COLUMNS.to_string()),
                    )
                } else if copy {
                    blocked(
                        "the value is copied into another relation (INSERT … SELECT, CREATE TABLE AS, SELECT INTO, VIEW, UPDATE … SET, MERGE); masking it would change stored data".to_string(),
                        None,
                    )
                } else {
                    blocked(
                        "COPY with a column list cannot be rewritten; use COPY (SELECT …) TO"
                            .to_string(),
                        None,
                    )
                }
            } else {
                match rewrite {
                    Some(Ok(sql)) => SensitiveVerdict {
                        outcome: SensitivePolicy::Mask,
                        ast_node_path: format!("SensitiveColumn > {} (mask)", names(&culprits)),
                        suggested_safe_query: Some(sql.clone()),
                        rewritten_query: Some(sql),
                        touched,
                    },
                    // Never send the unmasked query: any failure blocks.
                    Some(Err(reason)) => blocked(reason, None),
                    None => blocked("rewrite produced no query".to_string(), None),
                }
            }
        }
    };
    Some(verdict)
}

fn dialect_name(d: Dialect) -> &'static str {
    match d {
        Dialect::Postgres => "postgres",
        Dialect::Mysql => "mysql",
        Dialect::Oracle => "oracle",
        Dialect::MsSql => "mssql",
    }
}

#[cfg(test)]
mod tests;
