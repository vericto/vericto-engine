// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Snowflake AST parser.
//!
//! Uses `sqlparser-rs` with `SnowflakeDialect`, walked by the shared
//! sqlparser walker (`parser::walk`), which records the Snowflake-only
//! statement kinds (`COPY INTO`, stages, `PUT`, `USE ROLE`, scripting blocks,
//! warehouses, shares, …) for the Snowflake rules.
//!
//! sqlparser does not parse every Snowflake statement. Those it rejects are
//! parse errors, resolved as on every dialect (see
//! [`crate::EnforcementPolicy::effective_parse_error_for`]: flagged by
//! default, blocked under `parse_error: block`, a `block`/`mask` tag or an
//! enforced allowlist), except two kinds the keyword pre-classifier below
//! recognises, only when the parse fails and only on a single statement:
//!
//! - the known-dangerous ones (`UNDROP`, `CREATE TASK`, `ALTER WAREHOUSE … SET
//!   WAREHOUSE_SIZE`, `GET`, …) become findings of the rule that names them.
//!   Such a statement is still unread code, so the rule engine keeps the
//!   stricter of the finding and the parse-error outcome: recognising it never
//!   makes the outcome more permissive;
//! - a short [`allowlisted`] set of legitimate statements (`COMMENT ON … IS
//!   $$…$$`, `ALTER VIEW … SET SECURE`, …) is analysed with no finding, as the
//!   same statements are where the parser reads them.

use crate::error::{ProxyError, Result};
use crate::parser::walk::parse_with_dialect;
use crate::parser::{
    AlterTableKind, Dialect, ParsedQuery, SnowflakeRisk, SourceAst, SqlParser, StatementInfo,
    StatementKind,
};

use sqlparser::dialect::SnowflakeDialect;

pub struct SnowflakeParser {
    dialect: SnowflakeDialect,
}

impl SnowflakeParser {
    pub fn new() -> Self {
        Self {
            dialect: SnowflakeDialect {},
        }
    }
}

impl Default for SnowflakeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for SnowflakeParser {
    /// Parses with sqlparser; on a parse error (and only then), tries the
    /// pre-classifier. Nesting past the limits is never pre-classified.
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        match parse_with_dialect(&self.dialect, Dialect::Snowflake, sql) {
            Err(ProxyError::ParseError(_)) if allowlisted(sql).is_some() => {
                let what = allowlisted(sql).unwrap_or_default();
                Ok(ParsedQuery {
                    statements: vec![StatementInfo {
                        kind: if what.starts_with("COPY") {
                            StatementKind::Copy
                        } else {
                            StatementKind::Other
                        },
                        ast_node_path: format!("Allowlisted > {what}"),
                        ..Default::default()
                    }],
                    ast: SourceAst::Classified {
                        what: what.to_string(),
                        dialect: Dialect::Snowflake,
                    },
                    mysql: None,
                    // Read, not unread: analysed with no finding.
                    unread: None,
                })
            }
            Err(ProxyError::ParseError(e)) => match preclassify(sql) {
                Some((what, statements)) => Ok(ParsedQuery {
                    statements,
                    ast: SourceAst::Classified {
                        what: what.to_string(),
                        dialect: Dialect::Snowflake,
                    },
                    mysql: None,
                    unread: Some(format!(
                        "{what}: recognised by its keywords, not parsed ({e})"
                    )),
                }),
                None => Err(ProxyError::ParseError(e)),
            },
            other => other,
        }
    }

    fn dialect_name(&self) -> &'static str {
        "snowflake"
    }
}

// ---------------------------------------------------------------------------
// Pre-classifier
// ---------------------------------------------------------------------------

/// A lexical token of the text, as far as the pre-classifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An unquoted word (keyword, name, number, `$var`), upper-cased.
    Word(String),
    /// A `'…'` string literal.
    Str,
    /// A `"…"` quoted identifier.
    Ident,
    /// A `$$…$$` string (a literal, or the body of a procedure or a block).
    Dollar,
    Eq,
    Semi,
    /// Any other character (`.`, `(`, `)`, `,`, `@`, …).
    Punct(char),
}

/// The tokens of one statement, comments removed. `None` when the text holds
/// more than one statement, an unterminated quote or comment, or nothing. A
/// Snowflake scripting block (`DECLARE …` / `BEGIN …`) is one statement
/// whatever `;` it holds.
fn tokens(sql: &str) -> Option<Vec<Tok>> {
    let toks = scan(sql)?;
    let block = matches!(toks.first(), Some(Tok::Word(w)) if w == "DECLARE" || w == "BEGIN");
    let last = toks.iter().rposition(|t| *t != Tok::Semi)?;
    if !block && toks[..last].contains(&Tok::Semi) {
        return None;
    }
    Some(toks.into_iter().filter(|t| *t != Tok::Semi).collect())
}

/// Every token of the text, comments removed, `;` included. `None` for an
/// unterminated quote or comment, or no token at all.
fn scan(sql: &str) -> Option<Vec<Tok>> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // `--` and `//` line comments, `/* … */` block comments.
        if (c == b'-' && b.get(i + 1) == Some(&b'-')) || (c == b'/' && b.get(i + 1) == Some(&b'/'))
        {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let end = sql[i + 2..].find("*/")?;
            i += 2 + end + 2;
            continue;
        }
        match c {
            b';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            b'\'' | b'"' => {
                // `''` / `""` doubles the quote; `\` escapes inside strings.
                i += 1;
                loop {
                    match b.get(i) {
                        None => return None,
                        Some(&q) if q == c => {
                            if b.get(i + 1) == Some(&c) {
                                i += 2;
                            } else {
                                i += 1;
                                break;
                            }
                        }
                        Some(b'\\') if c == b'\'' => i += 2,
                        Some(_) => i += 1,
                    }
                }
                out.push(if c == b'\'' { Tok::Str } else { Tok::Ident });
            }
            b'$' if b.get(i + 1) == Some(&b'$') => {
                let end = sql[i + 2..].find("$$")?;
                i += 2 + end + 2;
                out.push(Tok::Dollar);
            }
            b'=' => {
                out.push(Tok::Eq);
                i += 1;
            }
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$')
                {
                    i += 1;
                }
                out.push(Tok::Word(sql[start..i].to_ascii_uppercase()));
            }
            _ => {
                // Punctuation, or a non-ASCII character (never part of a
                // keyword): one token for the whole character.
                let ch = sql[i..].chars().next().unwrap_or('\u{fffd}');
                out.push(Tok::Punct(ch));
                i += ch.len_utf8();
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

fn word(t: Option<&Tok>) -> &str {
    match t {
        Some(Tok::Word(w)) => w,
        _ => "",
    }
}

/// Whether `KEY = <value>` appears with `value` one of `values` (`None`: any
/// value).
fn assigns(toks: &[Tok], key: &str, values: Option<&[&str]>) -> bool {
    toks.windows(3).any(|w| {
        word(Some(&w[0])) == key
            && w[1] == Tok::Eq
            && values.is_none_or(|vs| vs.contains(&word(Some(&w[2]))))
    })
}

/// Whether the words `seq` appear consecutively.
fn has_words(toks: &[Tok], seq: &[&str]) -> bool {
    toks.windows(seq.len())
        .any(|w| w.iter().zip(seq).all(|(t, s)| word(Some(t)) == *s))
}

/// The options that make a warehouse cost more (see `walk::warehouse_cost`).
const WAREHOUSE_COST_OPTIONS: &[&str] = &[
    "WAREHOUSE_SIZE",
    "MAX_CLUSTER_COUNT",
    "MIN_CLUSTER_COUNT",
    "SCALING_POLICY",
    "WAREHOUSE_TYPE",
    "RESOURCE_CONSTRAINT",
    "QUERY_ACCELERATION_MAX_SCALE_FACTOR",
    "ENABLE_QUERY_ACCELERATION",
];

/// The statement `sql` is, when sqlparser rejected it but its keywords name
/// a statement a Snowflake rule covers: a name for it and the entries the
/// rules read. `None` for anything else, which stays a parse error.
pub(crate) fn preclassify(sql: &str) -> Option<(&'static str, Vec<StatementInfo>)> {
    let toks = tokens(sql)?;
    let w = |k: usize| word(toks.get(k));
    let mut out: Vec<StatementInfo> = Vec::new();
    let entry = |risk: Option<SnowflakeRisk>, path: String| StatementInfo {
        ast_node_path: path,
        snowflake: risk,
        ..Default::default()
    };
    let retention_zero = assigns(&toks, "DATA_RETENTION_TIME_IN_DAYS", Some(&["0"]));

    let what: &'static str = match w(0) {
        "UNDROP" => {
            out.push(entry(
                Some(SnowflakeRisk::RecoveryReduced),
                "UndropStmt (restores a dropped object; it can shadow a newer one)".to_string(),
            ));
            "UNDROP"
        }
        "PUT" | "GET" => {
            let what = if w(0) == "PUT" { "PUT" } else { "GET" };
            out.push(entry(
                Some(SnowflakeRisk::StageTransfer),
                format!(
                    "{}Stmt > file transfer {} a stage",
                    if what == "PUT" { "Put" } else { "Get" },
                    if what == "PUT" { "to" } else { "from" }
                ),
            ));
            what
        }
        "DECLARE" | "BEGIN" => {
            out.push(StatementInfo {
                kind: StatementKind::DoBlock,
                ast_node_path: "ScriptingBlock (DECLARE / BEGIN … END)".to_string(),
                ..Default::default()
            });
            "Snowflake scripting block"
        }
        "EXECUTE" if w(1) == "IMMEDIATE" => {
            out.push(StatementInfo {
                kind: StatementKind::DoBlock,
                ast_node_path: "ExecuteImmediateStmt".to_string(),
                ..Default::default()
            });
            "EXECUTE IMMEDIATE"
        }
        // A GRANT or REVOKE sqlparser does not read (`GRANT CREATE TABLE ON
        // SCHEMA …`, `… ON FUTURE TABLES …`): still VERICTO-082, and a share
        // grant VERICTO-093.
        "GRANT" | "REVOKE" => {
            out.push(StatementInfo {
                kind: StatementKind::Grant,
                ast_node_path: "GrantStmt".to_string(),
                ..Default::default()
            });
            if w(0) == "GRANT" && has_words(&toks, &["TO", "SHARE"]) {
                out.push(entry(
                    Some(SnowflakeRisk::Share),
                    "GrantStmt > TO SHARE".to_string(),
                ));
            }
            if w(0) == "GRANT" { "GRANT" } else { "REVOKE" }
        }
        "EXECUTE" if w(1) == "TASK" => {
            out.push(entry(
                Some(SnowflakeRisk::Persistence),
                "ExecuteTaskStmt (runs a task's stored statement now)".to_string(),
            ));
            "EXECUTE TASK"
        }
        "CREATE" => {
            let mut k = 1;
            let mut or_replace = false;
            // `OR ALTER` updates the object in place: no drop.
            if w(k) == "OR" && matches!(w(k + 1), "REPLACE" | "ALTER") {
                or_replace = w(k + 1) == "REPLACE";
                k += 2;
            }
            while matches!(
                w(k),
                "TEMPORARY" | "TEMP" | "TRANSIENT" | "SECURE" | "VOLATILE" | "LOCAL" | "GLOBAL"
            ) {
                k += 1;
            }
            let what = match (w(k), w(k + 1), w(k + 2)) {
                ("TASK", ..) => Some(("CREATE TASK", Some(SnowflakeRisk::Persistence))),
                ("STREAM", ..) => Some(("CREATE STREAM", Some(SnowflakeRisk::Persistence))),
                ("PIPE", ..) => Some(("CREATE PIPE", Some(SnowflakeRisk::Persistence))),
                ("PROCEDURE", ..) => Some(("CREATE PROCEDURE", Some(SnowflakeRisk::Persistence))),
                ("FUNCTION", ..) | ("AGGREGATE", "FUNCTION", _) => {
                    Some(("CREATE FUNCTION", Some(SnowflakeRisk::Persistence)))
                }
                ("ALERT", ..) => Some(("CREATE ALERT", Some(SnowflakeRisk::Persistence))),
                ("EXTERNAL", "FUNCTION", _) => {
                    // Code that runs later, and calls out of the account.
                    out.push(entry(
                        Some(SnowflakeRisk::ExternalAccess),
                        "CreateExternalFunctionStmt > calls an external API".to_string(),
                    ));
                    Some(("CREATE EXTERNAL FUNCTION", Some(SnowflakeRisk::Persistence)))
                }
                ("SHARE", ..) => Some(("CREATE SHARE", Some(SnowflakeRisk::Share))),
                ("LISTING", ..) | ("ORGANIZATION", "LISTING", _) => {
                    Some(("CREATE LISTING", Some(SnowflakeRisk::Share)))
                }
                ("STORAGE", "INTEGRATION", _) => Some((
                    "CREATE STORAGE INTEGRATION",
                    Some(SnowflakeRisk::ExternalAccess),
                )),
                ("EXTERNAL", "ACCESS", "INTEGRATION") => Some((
                    "CREATE EXTERNAL ACCESS INTEGRATION",
                    Some(SnowflakeRisk::ExternalAccess),
                )),
                ("API", "INTEGRATION", _) => Some((
                    "CREATE API INTEGRATION",
                    Some(SnowflakeRisk::ExternalAccess),
                )),
                ("NETWORK", "RULE", _) => Some((
                    "CREATE NETWORK RULE",
                    assigns(&toks, "MODE", Some(&["EGRESS"]))
                        .then_some(SnowflakeRisk::ExternalAccess),
                )),
                ("STAGE", ..) => Some((
                    "CREATE STAGE",
                    (assigns(&toks, "URL", None) || assigns(&toks, "CREDENTIALS", None))
                        .then_some(SnowflakeRisk::ExternalAccess),
                )),
                ("WAREHOUSE", ..) => Some((
                    "CREATE WAREHOUSE",
                    (WAREHOUSE_COST_OPTIONS
                        .iter()
                        .any(|o| assigns(&toks, o, None))
                        || assigns(&toks, "AUTO_SUSPEND", Some(&["0", "NULL"])))
                    .then_some(SnowflakeRisk::WarehouseCost),
                )),
                ("TABLE", ..) | ("DYNAMIC", "TABLE", _) | ("ICEBERG", "TABLE", _) => {
                    Some(("CREATE TABLE", None))
                }
                ("SCHEMA", ..) => Some(("CREATE SCHEMA", None)),
                ("DATABASE", ..) => Some(("CREATE DATABASE", None)),
                _ => None,
            };
            let (what, risk) = what?;
            if let Some(risk) = risk {
                out.push(entry(Some(risk), format!("Classified > {what}")));
            }
            // `CLONE` copies the source's data (VERICTO-084), whatever else
            // the statement holds (`AT (…)`, `IGNORE TABLES …`).
            if matches!(what, "CREATE TABLE" | "CREATE SCHEMA" | "CREATE DATABASE")
                && toks.iter().any(|t| word(Some(t)) == "CLONE")
            {
                out.push(StatementInfo {
                    kind: StatementKind::CreateTableAs,
                    ast_node_path: format!("Classified > {what} > CLONE"),
                    ..Default::default()
                });
            }
            if or_replace && matches!(what, "CREATE TABLE" | "CREATE SCHEMA" | "CREATE DATABASE") {
                out.push(entry(
                    Some(SnowflakeRisk::RecoveryReduced),
                    format!(
                        "Classified > {what} OR REPLACE (drops an existing object of that name)"
                    ),
                ));
            }
            what
        }
        // A table drop sqlparser does not read (VERICTO-010).
        "DROP"
            if matches!(w(1), "DYNAMIC" | "ICEBERG" | "EXTERNAL" | "HYBRID") && w(2) == "TABLE" =>
        {
            out.push(StatementInfo {
                kind: StatementKind::Drop,
                drop_object: Some(crate::parser::DropObjectKind::Table),
                drop_index_if_exists: w(3) == "IF",
                ast_node_path: "DropStmt".to_string(),
                ..Default::default()
            });
            "DROP TABLE"
        }
        "ALTER" => match (w(1), w(2)) {
            ("WAREHOUSE", _) => {
                if WAREHOUSE_COST_OPTIONS
                    .iter()
                    .any(|o| assigns(&toks, o, None))
                    || assigns(&toks, "AUTO_SUSPEND", Some(&["0", "NULL"]))
                {
                    out.push(entry(
                        Some(SnowflakeRisk::WarehouseCost),
                        "Classified > ALTER WAREHOUSE (size, clusters or suspension)".to_string(),
                    ));
                }
                "ALTER WAREHOUSE"
            }
            ("RESOURCE", "MONITOR") => {
                out.push(entry(
                    Some(SnowflakeRisk::WarehouseCost),
                    "Classified > ALTER RESOURCE MONITOR (credit quota or triggers)".to_string(),
                ));
                "ALTER RESOURCE MONITOR"
            }
            ("ACCOUNT", _) => {
                out.push(entry(
                    Some(SnowflakeRisk::RecoveryReduced),
                    "Classified > ALTER ACCOUNT (account-wide parameters)".to_string(),
                ));
                "ALTER ACCOUNT"
            }
            ("SHARE", _) => {
                if has_words(&toks, &["ADD", "ACCOUNTS"]) || has_words(&toks, &["SET", "ACCOUNTS"])
                {
                    out.push(entry(
                        Some(SnowflakeRisk::Share),
                        "Classified > ALTER SHARE > ADD / SET ACCOUNTS".to_string(),
                    ));
                }
                "ALTER SHARE"
            }
            ("STAGE", _) => {
                if assigns(&toks, "URL", None) || assigns(&toks, "CREDENTIALS", None) {
                    out.push(entry(
                        Some(SnowflakeRisk::ExternalAccess),
                        "Classified > ALTER STAGE > SET URL / CREDENTIALS".to_string(),
                    ));
                }
                "ALTER STAGE"
            }
            ("TASK", _) => {
                if toks.iter().any(|t| word(Some(t)) == "RESUME")
                    || has_words(&toks, &["MODIFY", "AS"])
                {
                    out.push(entry(
                        Some(SnowflakeRisk::Persistence),
                        "Classified > ALTER TASK > RESUME / MODIFY AS".to_string(),
                    ));
                }
                "ALTER TASK"
            }
            ("TABLE", _) => {
                // VERICTO-019's Snowflake equivalents: the row access
                // policy or the masking policy that protects the data.
                if has_words(&toks, &["DROP", "ROW", "ACCESS", "POLICY"])
                    || has_words(&toks, &["DROP", "ALL", "ROW", "ACCESS", "POLICIES"])
                    || has_words(&toks, &["UNSET", "MASKING", "POLICY"])
                {
                    out.push(StatementInfo {
                        kind: StatementKind::AlterTable,
                        alter_table_kind: Some(AlterTableKind::DisableTrigger),
                        ast_node_path: "AlterTableStmt > DropPolicy (row access / masking)"
                            .to_string(),
                        ..Default::default()
                    });
                }
                "ALTER TABLE"
            }
            ("SCHEMA", _) => "ALTER SCHEMA",
            ("DATABASE", _) => "ALTER DATABASE",
            _ => return None,
        },
        _ => return None,
    };
    if retention_zero {
        out.push(entry(
            Some(SnowflakeRisk::RecoveryReduced),
            format!("Classified > {what} > DATA_RETENTION_TIME_IN_DAYS = 0"),
        ));
    }
    (!out.is_empty()).then_some((what, out))
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// A cursor over the statement's tokens, for the allowlist patterns: each
/// step consumes exactly what it names or fails, and a pattern only matches
/// when it consumes every token.
struct Cur<'t> {
    toks: &'t [Tok],
    at: usize,
}

impl Cur<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    /// The next token is the word `w`.
    fn word(&mut self, w: &str) -> bool {
        let ok = word(self.peek()) == w;
        self.at += ok as usize;
        ok
    }

    /// The words `ws`, in order.
    fn words(&mut self, ws: &[&str]) -> bool {
        let start = self.at;
        if ws.iter().all(|w| self.word(w)) {
            true
        } else {
            self.at = start;
            false
        }
    }

    /// Optionally the words `ws`.
    fn opt(&mut self, ws: &[&str]) {
        self.words(ws);
    }

    /// One of `ws`; returns it.
    fn one_of(&mut self, ws: &[&'static str]) -> Option<&'static str> {
        let w = ws.iter().find(|w| word(self.peek()) == **w)?;
        self.at += 1;
        Some(w)
    }

    fn tok(&mut self, t: &Tok) -> bool {
        let ok = self.peek() == Some(t);
        self.at += ok as usize;
        ok
    }

    /// An object name: up to `max` parts (`db.schema.table`), each an unquoted
    /// word or a quoted identifier. A word that is not a name (a keyword the
    /// pattern expects next) is not consumed: names come before them.
    fn name(&mut self, max: usize) -> bool {
        let part = |t: Option<&Tok>| matches!(t, Some(Tok::Word(_) | Tok::Ident));
        if !part(self.peek()) {
            return false;
        }
        self.at += 1;
        let mut parts = 1;
        while parts < max
            && self.peek() == Some(&Tok::Punct('.'))
            && part(self.toks.get(self.at + 1))
        {
            self.at += 2;
            parts += 1;
        }
        true
    }

    /// A string literal (`'…'`, or `$$…$$` when `dollar`).
    fn string(&mut self, dollar: bool) -> bool {
        let ok = matches!(self.peek(), Some(Tok::Str))
            || (dollar && matches!(self.peek(), Some(Tok::Dollar)));
        self.at += ok as usize;
        ok
    }

    /// A parenthesised list of names: `(a, b, c)`.
    fn name_list(&mut self) -> bool {
        let start = self.at;
        if !self.tok(&Tok::Punct('(')) {
            return false;
        }
        loop {
            if !self.name(1) {
                self.at = start;
                return false;
            }
            if self.tok(&Tok::Punct(')')) {
                return true;
            }
            if !self.tok(&Tok::Punct(',')) {
                self.at = start;
                return false;
            }
        }
    }

    fn done(&self) -> bool {
        self.at == self.toks.len()
    }
}

/// The object kinds `COMMENT ON` and `DESCRIBE` name, as words.
const COMMENT_OBJECTS: &[&[&str]] = &[
    &["TABLE"],
    &["VIEW"],
    &["MATERIALIZED", "VIEW"],
    &["DYNAMIC", "TABLE"],
    &["EXTERNAL", "TABLE"],
    &["ICEBERG", "TABLE"],
    &["COLUMN"],
    &["SCHEMA"],
    &["DATABASE"],
    &["STAGE"],
    &["SEQUENCE"],
    &["FILE", "FORMAT"],
    &["PIPE"],
    &["STREAM"],
    &["TASK"],
    &["WAREHOUSE"],
];

/// `DESCRIBE` kinds whose output is structure only: not `USER`, `SHARE`,
/// `INTEGRATION`, `SECRET`, `NETWORK POLICY` (identities and credentials).
const DESCRIBE_OBJECTS: &[&[&str]] = &[
    &["VIEW"],
    &["MATERIALIZED", "VIEW"],
    &["DYNAMIC", "TABLE"],
    &["EXTERNAL", "TABLE"],
    &["ICEBERG", "TABLE"],
    &["SEMANTIC", "VIEW"],
    &["STAGE"],
    &["SEQUENCE"],
    &["FILE", "FORMAT"],
    &["PIPE"],
    &["STREAM"],
    &["TASK"],
    &["WAREHOUSE"],
    &["SCHEMA"],
    &["DATABASE"],
];

fn object_kind(c: &mut Cur, kinds: &[&[&str]]) -> bool {
    kinds.iter().any(|k| c.words(k))
}

/// **The allowlist**: legitimate Snowflake statements sqlparser 0.63 rejects,
/// which change no data, run no code and widen no access. Each entry is an
/// anchored pattern over the whole statement (its head keywords, its names,
/// its literal values, nothing else), so a statement with anything more, or
/// a body that could hold another statement (a `$$` procedure or block body,
/// a subquery), is not on it. An allowlisted statement is analysed with no
/// finding, as the same statement is on the dialects whose parser reads it
/// (`COMMENT ON`, `ALTER VIEW`, `DESCRIBE` match no rule on PostgreSQL);
/// under an agent allowlist it is still denied as DDL.
///
/// | Entry | Example | Why it is safe |
/// |---|---|---|
/// | `COMMENT ON <object> <name> IS <literal>` | `COMMENT ON TABLE orders IS $$One row per order$$` | sets a comment; a `$$…$$` here is a string, never executed (dbt `persist_docs`) |
/// | `ALTER VIEW <name> SET\|UNSET SECURE`, `SET COMMENT = '…'`, `UNSET COMMENT` | `ALTER VIEW v SET SECURE` | hides the view definition from non-owners; no data or grant changes |
/// | `ALTER DYNAMIC TABLE <name> SET TARGET_LAG\|WAREHOUSE\|COMMENT = <value>…`, `REFRESH`, `SUSPEND`, `RESUME` | `ALTER DYNAMIC TABLE dt SET TARGET_LAG = '2 hours' WAREHOUSE = wh_s` | refresh scheduling of an existing dynamic table; its query is unchanged |
/// | `ALTER TABLE <name> ALTER\|MODIFY [COLUMN] <col> COMMENT <literal>` / `UNSET COMMENT` | `ALTER TABLE orders ALTER "STATUS" COMMENT $$Order status$$` | column comment (dbt `persist_docs`) |
/// | `ALTER TABLE <name> ADD ROW ACCESS POLICY <p> ON (<cols>)` | `ALTER TABLE t ADD ROW ACCESS POLICY rap ON (region)` | adds a protection (removing one is VERICTO-019) |
/// | `ALTER TABLE <name> ALTER\|MODIFY [COLUMN] <col> SET MASKING POLICY <p> [USING (<cols>)]` | `ALTER TABLE t MODIFY COLUMN email SET MASKING POLICY m` | adds a protection; `FORCE` (replacing an existing policy) is not on the list |
/// | `ALTER TABLE <name> ADD [COLUMN] IF NOT EXISTS <col> <type>` | `ALTER TABLE t ADD COLUMN IF NOT EXISTS a2 NUMBER(38, 2)` | additive column; a type only (no expression, no default) |
/// | `ALTER WAREHOUSE <name> SUSPEND \| RESUME [IF SUSPENDED] \| ABORT ALL QUERIES` | `ALTER WAREHOUSE wh RESUME IF SUSPENDED` | routine warehouse state; sizing stays VERICTO-095 |
/// | `ALTER TASK <name> SUSPEND` | `ALTER TASK t SUSPEND` | stops a task; resuming or changing it stays VERICTO-096 |
/// | `ALTER STAGE <name> REFRESH [SUBPATH = '…']` | `ALTER STAGE s REFRESH` | refreshes a directory table; URL or credentials stay VERICTO-092 |
/// | `DESC\|DESCRIBE <object> <name>` | `DESC EXTERNAL TABLE ext` | structure only; not users, shares, integrations or secrets |
/// | `SHOW …` made of words, names and `'…'` only | `SHOW TERSE TABLES IN ACCOUNT LIKE 'ORD%'` | metadata listing; no parenthesis, `=` or `$$` can follow |
/// | `ALTER TABLE <name> SET COMMENT = '…' \| CHANGE_TRACKING = TRUE\|FALSE \| DEFAULT_DDL_COLLATION = '…'`, `UNSET COMMENT` | `ALTER TABLE t SET CHANGE_TRACKING = TRUE` | metadata; retention changes are not on the list (0 is VERICTO-094) |
/// | `CREATE [TRANSIENT\|TEMPORARY] TABLE <name> (<columns>)` | `CREATE TABLE x (y INT AUTOINCREMENT START 10)` | a new, empty table: names, types, `AUTOINCREMENT`, `NOT NULL` only; no `OR REPLACE`, `AS`, `CLONE`, `LIKE`, default, policy or tag |
/// | `CREATE SEQUENCE <name> [WITH] START/INCREMENT [=] <n> …` | `CREATE SEQUENCE seq1 WITH START=1 INCREMENT=1 ORDER` | a new sequence; no `OR REPLACE` |
/// | `CREATE TAG <name> [ALLOWED_VALUES '…', …] [COMMENT = '…']` | `CREATE TAG cost_center ALLOWED_VALUES 'a', 'b'` | defines a tag; setting or unsetting tags on objects is not on the list (tag-based masking) |
/// | `CREATE STAGE <name> FILE_FORMAT\|COPY_OPTIONS\|COMMENT\|DIRECTORY = …` | `CREATE STAGE stage1 FILE_FORMAT = schema1.format1` | an internal stage; `URL`, credentials, integration or encryption are not on the list (VERICTO-092) |
/// | `DESCRIBE TABLE <name> TYPE = STAGE\|COLUMNS` | `DESCRIBE TABLE t TYPE = STAGE` | structure only |
/// | `UNSET <var>` / `UNSET (<var>, …)` | `UNSET my_var` | drops a session variable |
/// | `COPY INTO <table> [<option> = <value>]…` | `COPY INTO orders FILE_FORMAT = (TYPE = CSV) PURGE = TRUE` | a load from the table's own stage, like `COPY INTO t FROM @stage`; no `FROM`, no query, not a location |
pub(crate) fn allowlisted(sql: &str) -> Option<&'static str> {
    let toks = tokens(sql)?;
    // A scripting block is one "statement" to `tokens`: never allowlisted.
    if toks.contains(&Tok::Semi) {
        return None;
    }
    // A `$$` string is only accepted as a comment value (`COMMENT … IS
    // $$…$$`, `… COLUMN c COMMENT $$…$$`); no other entry takes one.
    let c = &mut Cur { toks: &toks, at: 0 };
    let what = allowlist_entry(c)?;
    c.done().then_some(what)
}

fn allowlist_entry(c: &mut Cur) -> Option<&'static str> {
    match word(c.peek()) {
        "COMMENT" => {
            c.word("COMMENT");
            c.opt(&["IF", "EXISTS"]);
            (c.word("ON") && object_kind(c, COMMENT_OBJECTS) && c.name(4) && c.word("IS"))
                .then_some(())?;
            c.string(true).then_some("COMMENT ON")
        }
        "DESC" | "DESCRIBE" => {
            c.at += 1;
            if c.word("TABLE") {
                // `DESCRIBE TABLE t TYPE = STAGE | COLUMNS`, which sqlparser
                // does not read (plain `DESCRIBE TABLE t` it does).
                return (c.name(3)
                    && c.word("TYPE")
                    && c.tok(&Tok::Eq)
                    && c.one_of(&["STAGE", "COLUMNS"]).is_some())
                .then_some("DESCRIBE TABLE … TYPE");
            }
            (object_kind(c, DESCRIBE_OBJECTS) && c.name(3)).then_some("DESCRIBE")
        }
        "CREATE" => {
            c.at += 1;
            // No `OR REPLACE` / `OR ALTER`: those replace an existing object.
            c.opt(&["TRANSIENT"]);
            c.opt(&["TEMPORARY"]);
            match c.one_of(&["TABLE", "SEQUENCE", "TAG", "STAGE"])? {
                "TABLE" => {
                    c.opt(&["IF", "NOT", "EXISTS"]);
                    (c.name(3) && c.tok(&Tok::Punct('('))).then_some(())?;
                    // Column definitions: names, types and the AUTOINCREMENT
                    // / NOT NULL words only; nothing after the list.
                    let mut depth = 1;
                    while depth > 0 {
                        match c.peek()? {
                            Tok::Punct('(') => depth += 1,
                            Tok::Punct(')') => depth -= 1,
                            Tok::Punct(',') | Tok::Ident => {}
                            Tok::Word(w) if !COLUMN_DEF_BANNED.contains(&w.as_str()) => {}
                            _ => return None,
                        }
                        c.at += 1;
                    }
                    Some("CREATE TABLE (columns only)")
                }
                "SEQUENCE" => {
                    c.opt(&["IF", "NOT", "EXISTS"]);
                    c.name(3).then_some(())?;
                    c.opt(&["WITH"]);
                    while c.peek().is_some() {
                        c.tok(&Tok::Punct(','));
                        match c.one_of(&["START", "INCREMENT", "ORDER", "NOORDER", "COMMENT"])? {
                            "START" | "INCREMENT" => {
                                c.opt(&["WITH"]);
                                c.opt(&["BY"]);
                                c.tok(&Tok::Eq);
                                matches!(c.peek(), Some(Tok::Word(w)) if w.bytes().all(|b| b.is_ascii_digit()))
                                    .then(|| c.at += 1)?;
                            }
                            "COMMENT" => (c.tok(&Tok::Eq) && c.string(false)).then_some(())?,
                            _ => {}
                        }
                    }
                    Some("CREATE SEQUENCE")
                }
                "TAG" => {
                    c.opt(&["IF", "NOT", "EXISTS"]);
                    c.name(3).then_some(())?;
                    if c.word("ALLOWED_VALUES") {
                        c.string(false).then_some(())?;
                        while c.tok(&Tok::Punct(',')) {
                            c.string(false).then_some(())?;
                        }
                    }
                    if c.word("COMMENT") {
                        (c.tok(&Tok::Eq) && c.string(false)).then_some(())?;
                    }
                    Some("CREATE TAG")
                }
                _ => {
                    // An internal stage: format and copy options only; no
                    // URL, credentials, integration or encryption.
                    c.opt(&["IF", "NOT", "EXISTS"]);
                    c.name(3).then_some(())?;
                    while c.peek().is_some() {
                        c.one_of(&["FILE_FORMAT", "COPY_OPTIONS", "COMMENT", "DIRECTORY"])?;
                        (c.tok(&Tok::Eq) && (stage_name_value(c) || copy_value(c))).then_some(())?;
                    }
                    Some("CREATE STAGE (internal)")
                }
            }
        }
        "SHOW" => {
            c.at += 1;
            // Words, names and string literals only.
            while let Some(t) = c.peek() {
                match t {
                    Tok::Word(_) | Tok::Ident | Tok::Str | Tok::Punct('.') => c.at += 1,
                    _ => return None,
                }
            }
            Some("SHOW")
        }
        "UNSET" => {
            c.at += 1;
            (c.name_list() || c.name(1)).then_some("UNSET")
        }
        "COPY" => {
            c.at += 1;
            if !(c.word("INTO") && c.name(3)) {
                return None;
            }
            // `<option> = <value>` pairs only; a value is a word, a literal,
            // or a parenthesised list of `<option> = <value>` / literals.
            while c.peek().is_some() {
                if !(c.name(1) && c.tok(&Tok::Eq) && copy_value(c)) {
                    return None;
                }
            }
            // Not a stage or a location, and no FROM (handled by the parser).
            Some("COPY INTO (table stage)")
        }
        "ALTER" => {
            c.at += 1;
            match word(c.peek()) {
                "VIEW" | "MATERIALIZED" => {
                    c.opt(&["MATERIALIZED"]);
                    c.word("VIEW").then_some(())?;
                    c.opt(&["IF", "EXISTS"]);
                    c.name(3).then_some(())?;
                    let ok = c.words(&["SET", "SECURE"])
                        || c.words(&["UNSET", "SECURE"])
                        || c.words(&["UNSET", "COMMENT"])
                        || (c.words(&["SET", "COMMENT"]) && c.tok(&Tok::Eq) && c.string(false));
                    ok.then_some("ALTER VIEW (SECURE / COMMENT)")
                }
                "DYNAMIC" => {
                    c.words(&["DYNAMIC", "TABLE"]).then_some(())?;
                    c.opt(&["IF", "EXISTS"]);
                    c.name(3).then_some(())?;
                    if c.one_of(&["REFRESH", "SUSPEND", "RESUME"]).is_some() {
                        return Some("ALTER DYNAMIC TABLE (REFRESH / SUSPEND / RESUME)");
                    }
                    c.word("SET").then_some(())?;
                    let mut any = false;
                    while c.peek().is_some() {
                        c.tok(&Tok::Punct(','));
                        let key = c.one_of(&["TARGET_LAG", "WAREHOUSE", "COMMENT"])?;
                        c.tok(&Tok::Eq).then_some(())?;
                        let value = match key {
                            "TARGET_LAG" => c.string(false) || c.word("DOWNSTREAM"),
                            "WAREHOUSE" => c.name(1),
                            _ => c.string(false),
                        };
                        value.then_some(())?;
                        any = true;
                    }
                    any.then_some("ALTER DYNAMIC TABLE SET (lag / warehouse / comment)")
                }
                "TABLE" => {
                    c.word("TABLE");
                    c.opt(&["IF", "EXISTS"]);
                    c.name(3).then_some(())?;
                    if c.words(&["ADD", "ROW", "ACCESS", "POLICY"]) {
                        return (c.name(3) && c.word("ON") && c.name_list())
                            .then_some("ALTER TABLE ADD ROW ACCESS POLICY");
                    }
                    if c.word("ADD") {
                        c.opt(&["COLUMN"]);
                        // `ADD [IF NOT EXISTS] <col> <type> [, …]`: names and
                        // types only (no expression, default, tag or policy).
                        c.opt(&["IF", "NOT", "EXISTS"]);
                        c.name(1).then_some(())?;
                        let mut typed = false;
                        while let Some(t) = c.peek() {
                            match t {
                                Tok::Word(w) if !COLUMN_DEF_BANNED.contains(&w.as_str()) => {
                                    typed = true;
                                    c.at += 1;
                                }
                                Tok::Punct('(' | ')' | ',') => c.at += 1,
                                _ => return None,
                            }
                        }
                        return typed.then_some("ALTER TABLE ADD COLUMN");
                    }
                    // Table-level settings that change no data or access.
                    if c.word("SET") {
                        let key =
                            c.one_of(&["COMMENT", "CHANGE_TRACKING", "DEFAULT_DDL_COLLATION"])?;
                        c.tok(&Tok::Eq).then_some(())?;
                        let ok = match key {
                            "CHANGE_TRACKING" => c.one_of(&["TRUE", "FALSE"]).is_some(),
                            _ => c.string(false),
                        };
                        return ok
                            .then_some("ALTER TABLE SET (comment / change tracking / collation)");
                    }
                    if c.words(&["UNSET", "COMMENT"]) {
                        return Some("ALTER TABLE UNSET COMMENT");
                    }
                    c.one_of(&["ALTER", "MODIFY"])?;
                    c.opt(&["COLUMN"]);
                    c.name(1).then_some(())?;
                    if c.word("COMMENT") {
                        return c.string(true).then_some("ALTER TABLE … COLUMN COMMENT");
                    }
                    if c.words(&["UNSET", "COMMENT"]) {
                        return Some("ALTER TABLE … COLUMN UNSET COMMENT");
                    }
                    if c.words(&["SET", "MASKING", "POLICY"]) && c.name(3) {
                        if c.word("USING") && !c.name_list() {
                            return None;
                        }
                        return Some("ALTER TABLE … SET MASKING POLICY");
                    }
                    None
                }
                "WAREHOUSE" => {
                    c.word("WAREHOUSE");
                    c.opt(&["IF", "EXISTS"]);
                    c.name(1).then_some(())?;
                    let ok = c.word("SUSPEND")
                        || (c.word("RESUME") && {
                            c.opt(&["IF", "SUSPENDED"]);
                            true
                        })
                        || c.words(&["ABORT", "ALL", "QUERIES"]);
                    ok.then_some("ALTER WAREHOUSE (SUSPEND / RESUME / ABORT)")
                }
                "TASK" => {
                    c.word("TASK");
                    c.opt(&["IF", "EXISTS"]);
                    (c.name(3) && c.word("SUSPEND")).then_some("ALTER TASK SUSPEND")
                }
                "STAGE" => {
                    c.word("STAGE");
                    c.opt(&["IF", "EXISTS"]);
                    (c.name(3) && c.word("REFRESH")).then_some(())?;
                    if c.word("SUBPATH") && !(c.tok(&Tok::Eq) && c.string(false)) {
                        return None;
                    }
                    Some("ALTER STAGE REFRESH")
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Words a column definition the allowlist accepts never holds: an
/// expression (`AS`), a default, a subquery, a policy or a tag, a copy
/// (`CLONE`, `LIKE`, `COPY`), a `USING`.
const COLUMN_DEF_BANNED: &[&str] = &[
    "AS",
    "DEFAULT",
    "SELECT",
    "WITH",
    "POLICY",
    "TAG",
    "MASKING",
    "CLONE",
    "LIKE",
    "COPY",
    "USING",
    "PROJECTION",
];

/// `FILE_FORMAT = <format name>` (a name, not an option list).
fn stage_name_value(c: &mut Cur) -> bool {
    let start = c.at;
    if c.name(3) && !matches!(c.peek(), Some(Tok::Eq)) {
        return true;
    }
    c.at = start;
    false
}

/// A `COPY INTO <table>` option value: a word or a literal (not `$$`), or
/// a parenthesised list of `<option> = <value>` pairs and literals.
fn copy_value(c: &mut Cur) -> bool {
    if c.string(false) {
        return true;
    }
    if matches!(c.peek(), Some(Tok::Word(w)) if w != "FROM" && w != "SELECT") {
        c.at += 1;
        return true;
    }
    if !c.tok(&Tok::Punct('(')) {
        return false;
    }
    loop {
        if c.tok(&Tok::Punct(')')) {
            return true;
        }
        c.tok(&Tok::Punct(','));
        if c.string(false) {
            continue;
        }
        if !(c.name(1) && c.tok(&Tok::Eq)) {
            return false;
        }
        if c.string(false) {
            continue;
        }
        match c.peek() {
            Some(Tok::Word(w)) if w != "FROM" && w != "SELECT" => {
                c.name(3);
            }
            _ => return false,
        }
    }
}
