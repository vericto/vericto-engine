//! Snowflake AST parser.
//!
//! Uses `sqlparser-rs` with `SnowflakeDialect`, walked by the shared
//! sqlparser walker (`parser::walk`), which records the Snowflake-only
//! statement kinds (`COPY INTO`, stages, `PUT`, `USE ROLE`, scripting blocks,
//! warehouses, shares, …) for the Snowflake rules.
//!
//! sqlparser does not parse every Snowflake statement. Those it rejects are
//! parse errors, which **fail closed** on Snowflake (see
//! [`crate::EnforcementPolicy::effective_parse_error_for`]), except the
//! known-dangerous ones the pre-classifier below recognises by their leading
//! keywords (`UNDROP`, `CREATE TASK`, `ALTER WAREHOUSE … SET WAREHOUSE_SIZE`,
//! `GET`, …): those become findings of the rule that names them, so the
//! message says what the statement is. The pre-classifier runs only when the
//! parse fails, on a single statement, and never makes an outcome more
//! permissive: a pre-classified statement is still unread code, so the rule
//! engine keeps the stricter of the finding and the parse-error outcome.

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
            Err(ProxyError::ParseError(e)) => match preclassify(sql) {
                Some((what, statements)) => Ok(ParsedQuery {
                    statements,
                    ast: SourceAst::Classified {
                        what: what.to_string(),
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

/// A lexical token of the text, as far as the pre-classifier needs: words
/// (upper-cased when unquoted), `=`, and everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An unquoted word (keyword, name, number), upper-cased.
    Word(String),
    /// A quoted name or string literal.
    Quoted,
    Eq,
    Semi,
    Other,
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
                out.push(Tok::Quoted);
            }
            b'$' if b.get(i + 1) == Some(&b'$') => {
                let end = sql[i + 2..].find("$$")?;
                i += 2 + end + 2;
                out.push(Tok::Quoted);
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
                // A non-ASCII byte belongs to a character the statement's
                // keywords never contain: skip the whole character.
                let len = sql[i..].chars().next().map_or(1, char::len_utf8);
                out.push(Tok::Other);
                i += len;
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
