// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

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
    fn covers(&self, names: Names, column: &str) -> bool {
        let case = column_case(names.dialect);
        match self {
            AccessColumns::AllColumns => true,
            AccessColumns::List(cols) => {
                cols.iter().any(|c| case.eq(&entry_ident(names, c), column))
            }
        }
    }
}

/// One grant: a table (in a schema, or in the default schema), some or all of
/// its columns, read or read/write.
///
/// JSON: `{"schema":"public","table":"orders","columns":"*","access":"read"}`.
/// `schema` may be null, empty or absent: the **default schema** only
/// (`public` on Postgres, `dbo` on SQL Server, the unqualified name on MySQL
/// and Oracle; never a catalogue schema). Names are written unquoted and
/// compared the way the dialect compares them; on Postgres they fold to lower
/// case unless written in double quotes (`"Customers"`). `schema_name` /
/// `table_name` are accepted as aliases.
///
/// Snowflake names are three-part: `database` (alias `database_name`) is the
/// database the table is in; null, empty or absent is the host's
/// [`AccessPolicy::default_database`]. Ignored on every other dialect.
///
/// `#[non_exhaustive]` since 4.0.0: build one with [`AccessEntry::new`] (and
/// [`in_schema`](AccessEntry::in_schema) / [`in_database`](AccessEntry::in_database)),
/// or from JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccessEntry {
    #[serde(
        default,
        alias = "database_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub database: Option<String>,
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
///
/// `#[non_exhaustive]` since 4.0.0: build one with [`AccessPolicy::new`] or
/// `AccessPolicy::default()` and set the fields, or from JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccessPolicy {
    #[serde(default)]
    pub mode: AccessMode,
    #[serde(default)]
    pub entries: Vec<AccessEntry>,
    #[serde(default)]
    pub ddl: DdlPolicy,
    /// The schema unqualified names resolve to, **set by the host** (never by
    /// the customer): on MySQL the connection's current database (the
    /// handshake's), on Postgres the first schema of a known `search_path`, on
    /// SQL Server the user's default schema. As stored, unquoted. A name
    /// qualified with it is the default schema's too, so it matches entries
    /// without a schema (Prisma's `` `db`.`User` ``). `None` (or empty): `public`
    /// on Postgres, `dbo` on SQL Server, unknown on MySQL (unqualified names
    /// only). Ignored on Oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_schema: Option<String>,
    /// Snowflake only: the database unqualified and two-part names resolve
    /// to, **set by the host** from the connection (its current database).
    /// As stored, unquoted. `None` (or empty): unknown, so a schema-less or
    /// database-less entry only matches names that are not qualified with a
    /// database. Ignored on every other dialect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_database: Option<String>,
    /// Snowflake only: the account or session value of
    /// `QUOTED_IDENTIFIERS_IGNORE_CASE`, **set by the host**. `Some(true)`:
    /// quoted names fold to upper case like unquoted ones; `Some(false)`:
    /// quoted names are case-sensitive (Snowflake's default). `None`: unknown,
    /// so both readings are checked and a reference either denies is denied.
    /// Ignored on every other dialect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_identifiers_ignore_case: Option<bool>,
}

impl AccessEntry {
    /// An entry for `table` in the default schema (and, on Snowflake, the
    /// default database).
    pub fn new(table: impl Into<String>, columns: AccessColumns, access: AccessLevel) -> Self {
        Self {
            database: None,
            schema: None,
            table: table.into(),
            columns,
            access,
        }
    }

    /// The same entry in `schema`.
    pub fn in_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// The same entry in `database` (Snowflake).
    pub fn in_database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }
}

impl AccessPolicy {
    /// A policy with `mode` and `entries`; every other field at its default
    /// (DDL denied, no host defaults).
    pub fn new(mode: AccessMode, entries: Vec<AccessEntry>) -> Self {
        Self {
            mode,
            entries,
            ..Self::default()
        }
    }
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
/// (which is denied under a policy): the host's
/// [`AccessPolicy::default_schema`] when it sets one, else `public` on
/// Postgres, `dbo` on SQL Server and `main` on SQLite. MySQL's is the
/// session's current database, unknown unless the host names it; Oracle's is
/// the user's schema, never known. (On SQLite an unqualified name resolves to
/// `temp` first when a temporary table of that name exists; creating one is
/// DDL, denied under a policy.)
fn default_schema(dialect: Dialect, host: Option<&str>) -> Option<&str> {
    let host = host.filter(|s| !s.is_empty());
    match dialect {
        Dialect::Postgres => host.or(Some("public")),
        Dialect::MsSql => host.or(Some("dbo")),
        Dialect::Sqlite => host.or(Some("main")),
        // Snowflake's is the connection's current schema, like MySQL's
        // current database: unknown unless the host names it.
        Dialect::Mysql | Dialect::Snowflake => host,
        Dialect::Oracle => None,
    }
}

/// How names are read: the dialect, and on Snowflake whether quoted names
/// fold too (`QUOTED_IDENTIFIERS_IGNORE_CASE`, one reading of it).
#[derive(Clone, Copy)]
struct Names {
    dialect: Dialect,
    fold_quoted: bool,
}

/// The separator the Snowflake access walk puts between the database and
/// the schema of a three-part name (`db.schema.table` → schema
/// `DB\u{1f}SCHEMA`). A control character no identifier the engine folds
/// can hold, so a two-part name can never be mistaken for a three-part one.
pub(crate) const DB_SEP: char = '\u{1f}';

/// `(database, schema)` of a Snowflake reference's schema as the access walk
/// records it (see [`DB_SEP`]).
fn split_db(schema: &str) -> (Option<&str>, &str) {
    match schema.split_once(DB_SEP) {
        Some((db, s)) => (Some(db), s),
        None => (None, schema),
    }
}

/// How the dialect compares an identifier of some kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    /// Byte for byte (after the entry is folded the way the dialect folds it).
    Exact,
    /// ASCII case-insensitively.
    Insensitive,
}

impl Case {
    fn eq(self, a: &str, b: &str) -> bool {
        match self {
            Case::Exact => a == b,
            Case::Insensitive => ieq(a, b),
        }
    }
}

/// Schema and table names.
/// - Postgres: exact. The query's names come out of the parser already
///   folded (unquoted → lower case, quoted → as written), and the entry's are
///   folded the same way by [`entry_ident`].
/// - MySQL: exact, the conservative reading of `lower_case_table_names=0`
///   (tables and databases are files, so `Orders` and `orders` can be two
///   tables). `information_schema` is the exception MySQL makes itself: its
///   names compare case-insensitively under every setting.
/// - SQL Server and Oracle: ASCII case-insensitive, as in 3.8.0 (SQL
///   Server's default collations are case-insensitive; Oracle folds unquoted
///   names to upper case, so only a quoted mixed-case name is compared more
///   loosely than Oracle does).
/// - Snowflake: exact. Both sides are folded the way Snowflake stores them
///   (unquoted → upper case; quoted as written, or upper case too under
///   `QUOTED_IDENTIFIERS_IGNORE_CASE`).
/// - SQLite: ASCII case-insensitive, quoted or not, as SQLite compares every
///   identifier.
fn relation_case(dialect: Dialect, schema: Option<&str>) -> Case {
    match dialect {
        Dialect::Postgres | Dialect::Snowflake => Case::Exact,
        Dialect::Mysql if schema.is_some_and(|s| ieq(s, "information_schema")) => Case::Insensitive,
        Dialect::Mysql => Case::Exact,
        Dialect::MsSql | Dialect::Oracle | Dialect::Sqlite => Case::Insensitive,
    }
}

/// Column names: exact on Postgres and Snowflake (folded as above);
/// case-insensitive on MySQL (as MySQL compares them), SQL Server, Oracle and
/// SQLite.
fn column_case(dialect: Dialect) -> Case {
    match dialect {
        Dialect::Postgres | Dialect::Snowflake => Case::Exact,
        Dialect::Mysql | Dialect::MsSql | Dialect::Oracle | Dialect::Sqlite => Case::Insensitive,
    }
}

/// An entry's identifier (schema, table or column) the way the dialect
/// stores it. Entries are written unquoted, so on Postgres they fold to lower
/// case, exactly as the same name unquoted in a query would; an entry written
/// in double quotes (`"Customers"`, with `""` for an embedded quote) is taken
/// as written. That is how a case-sensitive Postgres name is granted. MySQL
/// also accepts backticks, SQLite backticks and `[name]`; elsewhere quotes are
/// stripped and the name compares as the dialect compares names. On Snowflake, the mirror image of Postgres:
/// unquoted entries fold to upper case, quoted ones are taken as written
/// (upper-cased too under `QUOTED_IDENTIFIERS_IGNORE_CASE`).
fn entry_ident(names: Names, raw: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let dialect = names.dialect;
    let unquote = |q: char| -> Option<String> {
        let inner = raw.strip_prefix(q)?.strip_suffix(q)?;
        let doubled: String = [q, q].iter().collect();
        Some(inner.replace(&doubled, &q.to_string()))
    };
    if raw.len() >= 2 {
        if let Some(s) = unquote('"') {
            if dialect == Dialect::Snowflake && names.fold_quoted {
                return Cow::Owned(s.to_ascii_uppercase());
            }
            return Cow::Owned(s);
        }
        if matches!(dialect, Dialect::Mysql | Dialect::Sqlite) {
            if let Some(s) = unquote('`') {
                return Cow::Owned(s);
            }
        }
        // SQLite also accepts `[name]` (no escape inside).
        if dialect == Dialect::Sqlite {
            if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
                return Cow::Owned(inner.to_string());
            }
        }
    }
    match dialect {
        // PostgreSQL folds ASCII letters only (`downcase_identifier`).
        Dialect::Postgres if raw.bytes().any(|b| b.is_ascii_uppercase()) => {
            Cow::Owned(raw.to_ascii_lowercase())
        }
        // Snowflake folds unquoted names to upper case (ASCII: an unquoted
        // Snowflake identifier is ASCII).
        Dialect::Snowflake if raw.bytes().any(|b| b.is_ascii_lowercase()) => {
            Cow::Owned(raw.to_ascii_uppercase())
        }
        _ => Cow::Borrowed(raw),
    }
}

/// Whether entry `e` is the relation `schema.table` of the query (`schema`
/// already through [`effective_schema`]).
///
/// An entry without a schema is the table **in the default schema** only
/// ([`default_schema`]), qualified with it or not in the query; where the
/// default is unknown (MySQL without a host value, Oracle), only the
/// unqualified name. A table of the same name in any other schema needs
/// an entry naming that schema. An entry naming a schema matches that schema,
/// and the unqualified name where the default schema is known to be it.
fn entry_matches(
    e: &AccessEntry,
    names: Names,
    policy: &AccessPolicy,
    schema: Option<&str>,
    table: &str,
) -> bool {
    let dialect = names.dialect;
    let host_default = policy.default_schema.as_deref();
    let case = relation_case(dialect, schema);
    if !case.eq(&entry_ident(names, &e.table), table) {
        return false;
    }
    // Snowflake: the database first. The reference's is the one its name
    // spells (three-part) or the host's current database; the entry's is the
    // one it names or, again, the host's. Either unknown: only both unknown
    // match. The shared `SNOWFLAKE` database (ACCOUNT_USAGE, …) is the
    // account's catalogue: only an entry naming it reaches it.
    let schema = if dialect == Dialect::Snowflake {
        let fold = |s: &str| entry_ident(names, s).into_owned();
        // The host's value is as stored (`CURRENT_DATABASE()`): not folded.
        let host_db = policy
            .default_database
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let (ref_db, ref_schema) = match schema.map(split_db) {
            Some((db, s)) => (db.map(str::to_string).or_else(|| host_db.clone()), Some(s)),
            None => (host_db.clone(), None),
        };
        let named_db = e.database.as_deref().filter(|s| !s.is_empty()).map(fold);
        if ref_db.as_deref() == Some("SNOWFLAKE") && named_db.is_none() {
            return false;
        }
        match (named_db.or(host_db), ref_db) {
            (Some(a), Some(b)) if a == b => {}
            (None, None) => {}
            _ => return false,
        }
        // `db..t`: the schema is PUBLIC.
        ref_schema.map(|s| if s.is_empty() { "PUBLIC" } else { s })
    } else {
        schema
    };
    // An empty schema is no schema (a blank field in the dashboard).
    let entry_schema = e
        .schema
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| entry_ident(names, s));
    let default = default_schema(dialect, host_default);
    match (entry_schema.as_deref().or(default), schema.or(default)) {
        (Some(es), Some(qs)) => {
            // A catalogue reference needs an entry naming that schema, even
            // when the host's default schema is a catalogue one.
            (entry_schema.is_some() || !is_system(qs)) && case.eq(es, qs)
        }
        (None, None) => true,
        // Default unknown: a schema-less entry is not a qualified name, nor a
        // qualified entry an unqualified name.
        _ => false,
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
    let unanalysable = |e: &dyn std::fmt::Display| AccessVerdict {
        mode: policy.mode,
        ast_node_path: format!("AccessPolicy > query could not be analysed for access ({e})"),
        suggested_safe_query: None,
        denied: Vec::new(),
    };
    let one = |dialect: Dialect, walk: &dyn Fn(&Tags) -> crate::error::Result<()>, fold_quoted| {
        let collector = Collector::default();
        let tags = Tags::collecting(&collector);
        walk(&tags).map(|()| {
            let (refs, ambiguous) = collector.finish();
            let names = Names {
                dialect,
                fold_quoted,
            };
            (check(&refs, policy, names), ambiguous)
        })
    };
    let result = match &parsed.ast {
        SourceAst::Pg(tree) => one(Dialect::Postgres, &|t| pg::collect(tree, t), false),
        // Snowflake: identifiers fold to upper case unless quoted, so the
        // query is read again with its names folded, once per reading of
        // `QUOTED_IDENTIFIERS_IGNORE_CASE` the host leaves open; a reference
        // either reading denies is denied.
        SourceAst::Sql {
            dialect: Dialect::Snowflake,
            sql,
            ..
        } => {
            let readings: &[bool] = match policy.quoted_identifiers_ignore_case {
                Some(true) => &[true],
                Some(false) => &[false],
                None => &[false, true],
            };
            let mut denied: BTreeSet<DeniedRef> = BTreeSet::new();
            let mut ambiguous = BTreeSet::new();
            for &fold_quoted in readings {
                let Some(folded) = sql
                    .as_deref()
                    .and_then(|t| sql::fold_snowflake(t, fold_quoted))
                else {
                    return Some(unanalysable(&"the folded Snowflake text does not parse"));
                };
                match one(
                    Dialect::Snowflake,
                    &|t| sql::collect(&folded, t, Dialect::Snowflake),
                    fold_quoted,
                ) {
                    Ok((d, a)) => {
                        denied.extend(d);
                        ambiguous.extend(a);
                    }
                    Err(e) => return Some(unanalysable(&e)),
                }
            }
            Ok((denied.into_iter().collect(), ambiguous))
        }
        SourceAst::Sql {
            statements,
            dialect,
            ..
        } => one(*dialect, &|t| sql::collect(statements, t, *dialect), false),
        // Snowflake text only the pre-classifier recognised: a statement kind
        // denied outright (DDL, transfers, role switches).
        SourceAst::Classified { what, .. } => Ok((
            vec![DeniedRef {
                schema: None,
                table: what.clone(),
                column: None,
                needed: Needed::Ddl,
            }],
            BTreeSet::new(),
        )),
        // MySQL text that cannot be read with certainty: VERICTO-086 blocks it
        // before this runs.
        SourceAst::None => return None,
    };
    let (denied, ambiguous) = match result {
        Ok(found) => found,
        // Nesting past MAX_AST_DEPTH: the statement may reference anything.
        Err(e) => return Some(unanalysable(&e)),
    };
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

/// Every reference one top-level Postgres statement makes, as the access
/// analysis records them (for the policy facts, `crate::policy::facts`).
pub(crate) fn refs_pg(
    node: &pg_query::protobuf::node::Node,
) -> std::result::Result<Vec<Ref>, String> {
    let collector = Collector::default();
    let tags = Tags::collecting(&collector);
    let mut node = node.clone();
    pg::collect_statement(&mut node, &tags).map_err(|e| e.to_string())?;
    Ok(collector.finish().0)
}

/// [`refs_pg`] for one statement of a sqlparser dialect.
pub(crate) fn refs_sql(
    stmt: &sqlparser::ast::Statement,
    dialect: Dialect,
) -> std::result::Result<Vec<Ref>, String> {
    let collector = Collector::default();
    let tags = Tags::collecting(&collector);
    sql::collect_statement(stmt, &tags, dialect).map_err(|e| e.to_string())?;
    Ok(collector.finish().0)
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
fn check(refs: &[Ref], policy: &AccessPolicy, names: Names) -> Vec<DeniedRef> {
    let dialect = names.dialect;
    let mut denied: BTreeSet<DeniedRef> = BTreeSet::new();
    // A Snowflake three-part name reports its schema as `database.schema`.
    let deny =
        |schema: Option<String>, table: &str, column: Option<&str>, needed: Needed| DeniedRef {
            schema: schema.map(|s| s.replace(DB_SEP, ".")),
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
                    .filter(|e| entry_matches(e, names, policy, schema.as_deref(), table))
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
                    Some(c) => candidates.iter().any(|e| e.columns.covers(names, c)),
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
