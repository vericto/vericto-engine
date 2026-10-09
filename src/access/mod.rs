//! Agent access allowlists (VERICTO-087).
//!
//! The host gives the identity making the call (an API key, or the database
//! user of a proxy session) an [`AccessPolicy`], carried in
//! [`EnforcementPolicy::access_policy`](crate::EnforcementPolicy): the tables
//! and columns it may read, the ones it may also write, and nothing else.
//! Deny by default. This module decides whether a statement stays inside it.
//!
//! ## What counts as access
//!
//! Stricter than VERICTO-085, which counts what is projected: here **every
//! reference counts**, because a predicate lets an agent probe a value it may
//! not read (`WHERE salary > 100000`). Columns in the select list, `WHERE`,
//! `JOIN`, `GROUP BY`, `HAVING`, `ORDER BY`, windows, aggregate clauses,
//! subqueries, CTEs, every arm of a set operation, `RETURNING`, upserts and
//! `MERGE`; every table in `FROM` even when no column of it is named; every
//! write target. `*` and whole-row references need every column of the table.
//! DDL and the statements that change identity or name resolution are always
//! denied; a statement kind not known to be harmless is denied too.
//!
//! The derivation is VERICTO-085's: the same two walkers (`pg_query` for
//! Postgres, `sqlparser` for MySQL, Oracle and SQL Server) and the same scope
//! rules, run with a [`Tags::collecting`] index that records every resolution
//! instead of matching tags, and walking the clauses 085 skips.
//!
//! ## Conservative by construction
//!
//! The engine has no schema. An unqualified column resolves against every
//! relation in scope and must be allowed in all of them; a qualifier that
//! names nothing in scope is taken as a table; an expression the walker does
//! not model reads every column it mentions. A false positive is a refused
//! query whose message says what to grant or how to qualify; a false
//! negative is an agent outside its allowlist.
//!
//! ## Zero cost when unused
//!
//! Nothing here runs when `access_policy` is `None`: the engine checks the
//! option before calling in.

pub(crate) mod pg;
pub(crate) mod session;
pub(crate) mod sql;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::parser::{Dialect, ParsedQuery, SourceAst};
use crate::sensitive::{Collector, Ref, Tags, ieq};

/// Rule code reported for every agent-access outcome.
pub const ACCESS_RULE_CODE: &str = "VERICTO-087";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Whether a policy blocks or only reports.
///
/// Deserializes case-insensitively; **an absent or unknown value is
/// `Enforce`**, so a value this engine does not know can never silently turn
/// enforcement off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Report what would be denied (flag), never block.
    Observe,
    /// Block what is denied.
    #[default]
    Enforce,
}

impl<'de> Deserialize<'de> for AccessMode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "observe" => AccessMode::Observe,
            "enforce" => AccessMode::Enforce,
            other => {
                tracing::warn!(
                    mode = other,
                    "unknown access-policy mode, treating as enforce"
                );
                AccessMode::Enforce
            }
        })
    }
}

/// What a policy does with DDL. Only `Deny` exists in this phase; any value
/// deserializes as `Deny`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DdlPolicy {
    #[default]
    Deny,
}

impl<'de> Deserialize<'de> for DdlPolicy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if !raw.eq_ignore_ascii_case("deny") {
            tracing::warn!(ddl = %raw, "unknown access-policy ddl value, treating as deny");
        }
        Ok(DdlPolicy::Deny)
    }
}

/// What an entry grants on its columns.
///
/// Deserializes case-insensitively (`read`, `read_write`; also `readwrite`,
/// `read-write`, `rw`, `write`); **an absent or unknown value is `Read`**, so
/// a value this engine does not know never grants a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    #[default]
    Read,
    ReadWrite,
}

impl<'de> Deserialize<'de> for AccessLevel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(match raw.to_ascii_lowercase().as_str() {
            "read" => AccessLevel::Read,
            "read_write" | "readwrite" | "read-write" | "rw" | "write" => AccessLevel::ReadWrite,
            other => {
                tracing::warn!(access = other, "unknown access level, treating as read");
                AccessLevel::Read
            }
        })
    }
}

/// The columns an entry covers. JSON: `"*"` or `["id", "name"]`; any other
/// string `"x"` is read as `["x"]` (never widened to every column).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccessColumns {
    AllColumns,
    List(Vec<String>),
}

impl Default for AccessColumns {
    fn default() -> Self {
        AccessColumns::List(Vec::new())
    }
}

impl Serialize for AccessColumns {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            AccessColumns::AllColumns => s.serialize_str("*"),
            AccessColumns::List(cols) => cols.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for AccessColumns {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::One(s) if s.trim() == "*" => AccessColumns::AllColumns,
            Raw::One(s) => AccessColumns::List(vec![s]),
            Raw::Many(v) => AccessColumns::List(v),
        })
    }
}

impl AccessColumns {
    fn covers(&self, column: &str) -> bool {
        match self {
            AccessColumns::AllColumns => true,
            AccessColumns::List(cols) => cols.iter().any(|c| ieq(c, column)),
        }
    }
}

/// One grant: a table (in a schema, or in any schema), some or all of its
/// columns, read or read/write.
///
/// JSON: `{"schema":"public","table":"orders","columns":"*","access":"read"}`.
/// `schema` may be null or absent (any schema; never a catalogue schema);
/// `schema_name` / `table_name` are accepted as aliases.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessEntry {
    #[serde(default, alias = "schema_name")]
    pub schema: Option<String>,
    #[serde(alias = "table_name")]
    pub table: String,
    #[serde(default)]
    pub columns: AccessColumns,
    #[serde(default)]
    pub access: AccessLevel,
}

/// The allowlist of one identity. Deny by default: an empty `entries` lets
/// the identity touch no table.
///
/// JSON: `{"mode":"enforce","ddl":"deny","entries":[…]}`; every field is
/// optional (`enforce`, `deny`, `[]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct AccessPolicy {
    #[serde(default)]
    pub mode: AccessMode,
    #[serde(default)]
    pub entries: Vec<AccessEntry>,
    #[serde(default)]
    pub ddl: DdlPolicy,
}

/// The policies of a database, keyed by database user, as the TCP proxy
/// receives them (`agent_access` in the rules sync). `"*"` is an optional
/// default for users not listed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessPolicyMap(pub BTreeMap<String, AccessPolicy>);

impl AccessPolicyMap {
    /// The policy for a session of `db_user`: the exact (case-sensitive) key,
    /// else `"*"`, else none — no allowlist, today's behaviour.
    pub fn for_user(&self, db_user: &str) -> Option<&AccessPolicy> {
        self.0.get(db_user).or_else(|| self.0.get("*"))
    }
}

/// What a denied reference needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Needed {
    Read,
    Write,
    /// A statement denied outright (DDL, `SET ROLE`, `USE`, …).
    Ddl,
}

impl Needed {
    pub fn as_str(&self) -> &'static str {
        match self {
            Needed::Read => "read",
            Needed::Write => "write",
            Needed::Ddl => "ddl",
        }
    }
}

/// A reference the allowlist denied, for the audit trail. Names are the
/// query's spelling (`schema` is `pg_catalog` for an unqualified `pg_*`
/// relation on Postgres).
///
/// JSON: `{"schema":"public","table":"customers","column":"email","needed":"read"}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeniedRef {
    pub schema: Option<String>,
    /// The table; for a denied statement, its keyword (`CREATE TABLE`).
    pub table: String,
    /// `None` = the table itself; `Some("*")` = every column.
    pub column: Option<String>,
    pub needed: Needed,
}

// ---------------------------------------------------------------------------
// Name matching
// ---------------------------------------------------------------------------

/// Schemas that hold the catalogue or the server's own state. Only an entry
/// that names one of them explicitly can allow a reference into it.
const SYSTEM_SCHEMAS: &[&str] = &[
    "information_schema",
    "pg_catalog",
    "pg_toast",
    "mysql",
    "performance_schema",
    "sys",
];

fn is_system(schema: &str) -> bool {
    SYSTEM_SCHEMAS.iter().any(|s| ieq(s, schema))
}

/// The schema a reference resolves to for matching. On Postgres `pg_catalog`
/// is searched before any other schema, so an unqualified `pg_*` relation is
/// the catalogue's.
fn effective_schema(dialect: Dialect, schema: Option<&str>, table: &str) -> Option<String> {
    match schema {
        Some(s) => Some(s.to_string()),
        None if dialect == Dialect::Postgres
            && table.len() > 3
            && table
                .get(..3)
                .is_some_and(|p| p.eq_ignore_ascii_case("pg_")) =>
        {
            Some("pg_catalog".to_string())
        }
        None => None,
    }
}

/// The schema an unqualified name lands in without a `search_path` change
/// (which is denied under a policy). MySQL and Oracle default to the
/// connection's database / user, which the engine cannot see.
fn default_schema(dialect: Dialect) -> Option<&'static str> {
    match dialect {
        Dialect::Postgres => Some("public"),
        Dialect::MsSql => Some("dbo"),
        Dialect::Mysql | Dialect::Oracle => None,
    }
}

fn entry_matches(e: &AccessEntry, dialect: Dialect, schema: Option<&str>, table: &str) -> bool {
    if !ieq(&e.table, table) {
        return false;
    }
    match (e.schema.as_deref(), schema) {
        // A catalogue reference needs an entry naming that schema.
        (None, Some(qs)) => !is_system(qs),
        (None, None) => true,
        (Some(es), Some(qs)) => ieq(es, qs),
        (Some(es), None) => default_schema(dialect).is_some_and(|d| ieq(es, d)),
    }
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// The access verdict for one reading, before it is combined with the rules'
/// and VERICTO-085's.
#[derive(Debug, Clone)]
pub(crate) struct AccessVerdict {
    pub(crate) mode: AccessMode,
    pub(crate) ast_node_path: String,
    pub(crate) suggested_safe_query: Option<String>,
    pub(crate) denied: Vec<DeniedRef>,
}

#[cfg(test)]
thread_local! {
    /// How many times the analysis ran on this thread: lets a test prove the
    /// no-policy path never enters it.
    pub(crate) static ANALYSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

const LIST_COLUMNS: &str = "List the columns explicitly: `*`, `t.*` and whole-row references need every column of the table granted";

/// Runs the analysis for `parsed` against `policy`. `None` when everything the
/// statement references is allowed.
pub(crate) fn evaluate(parsed: &ParsedQuery, policy: &AccessPolicy) -> Option<AccessVerdict> {
    #[cfg(test)]
    ANALYSES.with(|n| n.set(n.get() + 1));
    let collector = Collector::default();
    let tags = Tags::collecting(&collector);
    let (dialect, walked) = match &parsed.ast {
        SourceAst::Pg(tree) => (Dialect::Postgres, pg::collect(tree, &tags)),
        SourceAst::Sql {
            statements,
            dialect,
            ..
        } => (*dialect, sql::collect(statements, &tags, *dialect)),
        // MySQL text that cannot be read with certainty: VERICTO-086 blocks it
        // before this runs.
        SourceAst::None => return None,
    };
    if let Err(e) = walked {
        // Nesting past MAX_AST_DEPTH: the statement may reference anything.
        return Some(AccessVerdict {
            mode: policy.mode,
            ast_node_path: format!("AccessPolicy > query could not be analysed for access ({e})"),
            suggested_safe_query: None,
            denied: Vec::new(),
        });
    }
    let (refs, ambiguous) = collector.finish();
    let denied = check(&refs, policy, dialect);
    if denied.is_empty() {
        return None;
    }
    let first = &denied[0];
    let object = display(first);
    let hint = match (first.needed, first.column.as_deref()) {
        (Needed::Ddl, _) => Some("denied for this identity".to_string()),
        (_, Some("*")) => Some("list the columns explicitly".to_string()),
        (Needed::Read, Some(c)) if ambiguous.contains(&c.to_ascii_lowercase()) => Some(format!(
            "`{c}` is unqualified and may belong to several tables; qualify the column"
        )),
        _ => None,
    };
    let mut path = format!("AccessPolicy > {object} ({})", first.needed.as_str());
    if let Some(h) = hint {
        path.push_str(": ");
        path.push_str(&h);
    }
    if denied.len() > 1 {
        path.push_str(&format!(" (+{} more)", denied.len() - 1));
    }
    let star = denied.iter().any(|d| d.column.as_deref() == Some("*"));
    Some(AccessVerdict {
        mode: policy.mode,
        ast_node_path: path,
        suggested_safe_query: star.then(|| LIST_COLUMNS.to_string()),
        denied,
    })
}

fn display(d: &DeniedRef) -> String {
    let mut s = String::new();
    if let Some(schema) = &d.schema {
        s.push_str(schema);
        s.push('.');
    }
    s.push_str(&d.table);
    if let Some(c) = &d.column {
        s.push('.');
        s.push_str(c);
    }
    s
}

/// Every reference the policy does not allow, deduplicated and sorted.
fn check(refs: &[Ref], policy: &AccessPolicy, dialect: Dialect) -> Vec<DeniedRef> {
    let mut denied: BTreeSet<DeniedRef> = BTreeSet::new();
    let deny =
        |schema: Option<String>, table: &str, column: Option<&str>, needed: Needed| DeniedRef {
            schema,
            table: table.to_string(),
            column: column.map(str::to_string),
            needed,
        };
    for r in refs {
        match r {
            Ref::Statement(what) => {
                denied.insert(deny(None, what, None, Needed::Ddl));
            }
            Ref::Relation { schema, table }
            | Ref::Column { schema, table, .. }
            | Ref::AllColumns { schema, table }
            | Ref::Write { schema, table, .. } => {
                let schema = effective_schema(dialect, schema.as_deref(), table);
                let entries: Vec<&AccessEntry> = policy
                    .entries
                    .iter()
                    .filter(|e| entry_matches(e, dialect, schema.as_deref(), table))
                    .collect();
                let (needed, column) = match r {
                    Ref::Write { column, .. } => (Needed::Write, column.as_deref()),
                    Ref::Column { column, .. } => (Needed::Read, Some(column.as_str())),
                    Ref::AllColumns { .. } => (Needed::Read, Some("*")),
                    _ => (Needed::Read, None),
                };
                let candidates: Vec<&AccessEntry> = match needed {
                    Needed::Write => entries
                        .iter()
                        .copied()
                        .filter(|e| e.access == AccessLevel::ReadWrite)
                        .collect(),
                    _ => entries.clone(),
                };
                if candidates.is_empty() {
                    // Not granted at all (or not for writing): the table is
                    // what is denied, whatever column was named.
                    denied.insert(deny(schema, table, None, needed));
                    continue;
                }
                let ok = match column {
                    None => true,
                    Some("*") => candidates
                        .iter()
                        .any(|e| e.columns == AccessColumns::AllColumns),
                    Some(c) => candidates.iter().any(|e| e.columns.covers(c)),
                };
                if !ok {
                    denied.insert(deny(schema, table, column, needed));
                }
            }
        }
    }
    denied.into_iter().collect()
}

#[cfg(test)]
mod tests;
