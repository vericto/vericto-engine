// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! SQLite AST parser.
//!
//! Uses `sqlparser-rs` with `SQLiteDialect`, walked by the shared sqlparser
//! walker (`parser::walk`), which records the SQLite-only statement kinds
//! (`ATTACH`, `PRAGMA`, `VACUUM`) for the SQLite rules (VERICTO-098 to
//! VERICTO-101), SQLite's truthiness for VERICTO-003 / VERICTO-090 and its
//! time probe for VERICTO-070.
//!
//! SQLite is a library linked into the application: there is no wire protocol
//! and so no proxy. The host evaluates the statement before the application
//! runs it (the Runtime API and the SDK wrappers, the CLI, MCP).
//!
//! sqlparser 0.63 does not parse every SQLite statement. Before a text is a
//! parse error, and only when the parse fails:
//!
//! - `INDEXED BY <index>` and `NOT INDEXED` (query-planner hints that change
//!   no result) are read through: the statement is parsed without them, and
//!   the client's text is kept as it was;
//! - a `PRAGMA` whose value is a keyword or a name (`PRAGMA foreign_keys =
//!   OFF`, `PRAGMA table_info(users)`) is read with the grammar SQLite gives
//!   it (`PRAGMA [schema.]name [= value | (value)]`), as the same statement
//!   with a quoted value;
//! - a short [`allowlisted`] set of legitimate statements (`DETACH`,
//!   `REINDEX`) is analysed with no finding;
//! - the keyword pre-classifier ([`preclassify`]) turns the known-dangerous
//!   ones (`VACUUM … INTO`, `ATTACH` forms sqlparser does not read, a call to
//!   `load_extension()` anywhere) into findings of the rule that names them.
//!   Unless the whole statement matched its pattern, such a statement is
//!   still unread code, so the rule engine keeps the stricter of the finding
//!   and the parse-error outcome.
//!
//! Everything else stays a parse error, resolved as on every dialect (see
//! [`crate::EnforcementPolicy::effective_parse_error_for`]).
//!
//! `load_extension()` (VERICTO-100) is found in the tokens of the whole text,
//! whatever clause holds it (`INSERT … VALUES (load_extension(…))`, a
//! quoted function name), not only where the walker visits expressions.

use crate::error::{ProxyError, Result};
use crate::parser::walk::{from_statements, parse_text, parse_with_dialect};
use crate::parser::{Dialect, ParsedQuery, SourceAst, SqlParser, SqliteRisk, StatementInfo};

use sqlparser::ast::{Ident, ObjectName, Statement, Value};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::tokenizer::{Token, Tokenizer};

pub struct SqliteParser {
    dialect: SQLiteDialect,
}

impl SqliteParser {
    pub fn new() -> Self {
        Self {
            dialect: SQLiteDialect {},
        }
    }
}

impl Default for SqliteParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlParser for SqliteParser {
    /// Parses with sqlparser; on a parse error (and only then), tries the
    /// planner-hint read-through, the `PRAGMA` grammar, the allowlist and the
    /// pre-classifier, in that order. Nesting past the limits is never
    /// pre-classified.
    fn parse(&self, sql: &str) -> Result<ParsedQuery> {
        let parsed = match parse_with_dialect(&self.dialect, Dialect::Sqlite, sql) {
            Err(ProxyError::ParseError(e)) => self.fallback(sql, e)?,
            other => other?,
        };
        Ok(with_native_calls(parsed, sql))
    }

    fn dialect_name(&self) -> &'static str {
        "sqlite"
    }
}

impl SqliteParser {
    fn fallback(&self, sql: &str, e: String) -> Result<ParsedQuery> {
        if let Some(stripped) = without_planner_hints(sql) {
            if let Ok(p) = parse_text(&self.dialect, Dialect::Sqlite, &stripped, sql) {
                return Ok(p);
            }
        }
        if let Some(stmt) = pragma_statement(sql) {
            return from_statements(vec![stmt], Dialect::Sqlite, sql);
        }
        let classified = |what: &str, statements: Vec<StatementInfo>, unread: Option<String>| {
            Ok(ParsedQuery {
                statements,
                ast: SourceAst::Classified {
                    what: what.to_string(),
                    dialect: Dialect::Sqlite,
                },
                mysql: None,
                unread,
            })
        };
        if let Some(what) = allowlisted(sql) {
            // Read, not unread: analysed with no finding.
            return classified(
                what,
                vec![StatementInfo {
                    ast_node_path: format!("Allowlisted > {what}"),
                    ..Default::default()
                }],
                None,
            );
        }
        match preclassify(sql) {
            Some(found) => {
                let unread = (!found.whole).then(|| {
                    format!(
                        "{}: recognised by its keywords, not parsed ({e})",
                        found.what
                    )
                });
                classified(found.what, found.statements, unread)
            }
            None => Err(ProxyError::ParseError(e)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// The tokens of `sql` as SQLite's tokenizer (sqlparser's) reads them,
/// whitespace and comments removed. `None` when the text does not tokenize.
fn significant(sql: &str) -> Option<Vec<Token>> {
    Tokenizer::new(&SQLiteDialect {}, sql)
        .with_unescape(false)
        .tokenize()
        .ok()
        .map(|toks| {
            toks.into_iter()
                .filter(|t| !matches!(t, Token::Whitespace(_)))
                .collect()
        })
}

/// The tokens of one statement: a trailing `;` is dropped. `None` when the
/// text holds more than one statement, does not tokenize, or is empty.
fn statement_tokens(sql: &str) -> Option<Vec<Token>> {
    let mut toks = significant(sql)?;
    while toks.last() == Some(&Token::SemiColon) {
        toks.pop();
    }
    if toks.is_empty() || toks.contains(&Token::SemiColon) {
        return None;
    }
    Some(toks)
}

/// The unquoted word `t` is, upper-cased (`""` for anything else).
fn word(t: Option<&Token>) -> String {
    match t {
        Some(Token::Word(w)) if w.quote_style.is_none() => w.value.to_ascii_uppercase(),
        _ => String::new(),
    }
}

/// A name part: a word, quoted or not.
fn name_part(t: Option<&Token>) -> Option<Ident> {
    match t {
        Some(Token::Word(w)) => Some(match w.quote_style {
            Some(q) => Ident::with_quote(q, w.value.clone()),
            None => Ident::new(w.value.clone()),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Planner hints
// ---------------------------------------------------------------------------

/// `sql` with every `INDEXED BY <index>` and `NOT INDEXED` that follows a
/// table name (or its alias), and the `IF NOT EXISTS` of a `CREATE TRIGGER`,
/// blanked out, byte for byte, so the rest keeps its offsets. `None` when
/// there is none, or the text does not tokenize.
///
/// The first two are query-planner hints: SQLite returns the same rows with
/// or without them (it errors when the named index cannot be used), so the
/// statement read without them is the statement that runs. The third only
/// makes an existing trigger a no-op; the body the rules read is the same.
fn without_planner_hints(sql: &str) -> Option<String> {
    let toks = Tokenizer::new(&SQLiteDialect {}, sql)
        .with_unescape(false)
        .tokenize_with_location()
        .ok()?;
    let offs = crate::parser::byte_offsets(sql, &toks);
    // Indices of the significant tokens.
    let sig: Vec<usize> = (0..toks.len())
        .filter(|&i| !matches!(toks[i].token, Token::Whitespace(_)))
        .collect();
    let is_word = |i: usize, kw: &str| matches!(&toks[i].token, Token::Word(w) if w.quote_style.is_none() && w.value.eq_ignore_ascii_case(kw));
    let mut cut: Vec<(usize, usize)> = Vec::new();
    let end_of = |j: usize| offs.get(j + 1).copied().unwrap_or(sql.len());
    // `CREATE [TEMP] TRIGGER IF NOT EXISTS`: sqlparser reads the trigger
    // without the guard, which changes nothing the rules read (its body is
    // walked either way).
    let head = match sig.get(1) {
        Some(&j) if is_word(j, "TEMP") || is_word(j, "TEMPORARY") => 2,
        _ => 1,
    };
    if sig.len() > head + 3
        && is_word(sig[0], "CREATE")
        && is_word(sig[head], "TRIGGER")
        && is_word(sig[head + 1], "IF")
        && is_word(sig[head + 2], "NOT")
        && is_word(sig[head + 3], "EXISTS")
    {
        cut.push((offs[sig[head + 1]], end_of(sig[head + 3])));
    }
    for (k, &i) in sig.iter().enumerate() {
        // A hint follows a table name or alias: a word.
        let after_name = k > 0 && matches!(toks[sig[k - 1]].token, Token::Word(_));
        if !after_name {
            continue;
        }
        if is_word(i, "INDEXED")
            && sig.get(k + 1).is_some_and(|&j| is_word(j, "BY"))
            && sig
                .get(k + 2)
                .is_some_and(|&j| matches!(toks[j].token, Token::Word(_)))
        {
            cut.push((offs[i], end_of(sig[k + 2])));
        } else if is_word(i, "NOT") && sig.get(k + 1).is_some_and(|&j| is_word(j, "INDEXED")) {
            cut.push((offs[i], end_of(sig[k + 1])));
        }
    }
    if cut.is_empty() {
        return None;
    }
    let mut text = sql.as_bytes().to_vec();
    for (a, b) in cut {
        for c in &mut text[a..b] {
            // Keep line breaks, so line numbers stay the client's.
            if *c != b'\n' {
                *c = b' ';
            }
        }
    }
    String::from_utf8(text).ok()
}

// ---------------------------------------------------------------------------
// PRAGMA
// ---------------------------------------------------------------------------

/// `PRAGMA [schema.]name [= value | (value)]` read with SQLite's grammar,
/// for the forms sqlparser rejects (a keyword or a name as the value:
/// `PRAGMA journal_mode = WAL`, `PRAGMA table_info(users)`, a signed number:
/// `PRAGMA cache_size = -2000`). The value becomes a string literal, which
/// SQLite reads the same way. `None` for anything else.
pub(crate) fn pragma_statement(sql: &str) -> Option<Statement> {
    let toks = statement_tokens(sql)?;
    if word(toks.first()) != "PRAGMA" {
        return None;
    }
    let mut k = 1;
    let mut parts = vec![name_part(toks.get(k))?];
    k += 1;
    if toks.get(k) == Some(&Token::Period) {
        parts.push(name_part(toks.get(k + 1))?);
        k += 2;
    }
    let name = ObjectName::from(parts);
    let value_at = |k: usize| -> Option<(Value, usize)> {
        match toks.get(k)? {
            Token::Word(w) => Some((Value::SingleQuotedString(w.value.clone()), k + 1)),
            Token::SingleQuotedString(s) => Some((Value::SingleQuotedString(s.clone()), k + 1)),
            Token::DoubleQuotedString(s) => Some((Value::SingleQuotedString(s.clone()), k + 1)),
            Token::Number(n, l) => Some((Value::Number(n.clone(), *l), k + 1)),
            Token::Minus | Token::Plus => match toks.get(k + 1)? {
                Token::Number(n, l) => {
                    let sign = if toks[k] == Token::Minus { "-" } else { "" };
                    Some((Value::Number(format!("{sign}{n}"), *l), k + 2))
                }
                _ => None,
            },
            _ => None,
        }
    };
    let (value, is_eq, end) = match toks.get(k) {
        None => (None, false, k),
        Some(Token::Eq) => {
            let (v, next) = value_at(k + 1)?;
            (Some(v), true, next)
        }
        Some(Token::LParen) => {
            let (v, next) = value_at(k + 1)?;
            if toks.get(next) != Some(&Token::RParen) {
                return None;
            }
            (Some(v), false, next + 1)
        }
        Some(_) => return None,
    };
    (end == toks.len()).then(|| Statement::Pragma {
        name,
        value: value.map(Value::with_empty_span),
        is_eq,
    })
}

/// The pragma's name, lower-cased, without its schema.
fn pragma_name(name: &ObjectName) -> String {
    name.0
        .last()
        .and_then(|p| p.as_ident())
        .map(|i| i.value.to_ascii_lowercase())
        .unwrap_or_default()
}

/// A pragma value as text, lower-cased (`ON`, `'off'`, `0`).
fn pragma_value(value: Option<&Value>) -> Option<String> {
    value.map(|v| match v {
        Value::SingleQuotedString(s) | Value::DoubleQuotedString(s) => s.to_ascii_lowercase(),
        other => other.to_string().to_ascii_lowercase(),
    })
}

/// SQLite's reading of a boolean pragma value: `on`, `yes`, `true` or a
/// non-zero integer is true; `off`, `no`, `false` or `0` false.
fn pragma_bool(v: &str) -> Option<bool> {
    match v {
        "on" | "yes" | "true" => Some(true),
        "off" | "no" | "false" => Some(false),
        n => n.parse::<i64>().ok().map(|n| n != 0),
    }
}

/// Why a `PRAGMA` turns a safety off (VERICTO-099), or `None` for a read or
/// any other setting. A pragma without a value reads the setting.
///
/// | Pragma | Reported when | Why |
/// |---|---|---|
/// | `writable_schema` | any value | `sqlite_schema` becomes writable: one bad write corrupts the database |
/// | `trusted_schema` | ON | functions with side effects run from views, triggers and defaults |
/// | `foreign_keys` | OFF | foreign keys stop being enforced |
/// | `ignore_check_constraints` | ON | `CHECK` constraints stop being enforced |
/// | `journal_mode` | OFF | no rollback journal: a crash or `ROLLBACK` can corrupt the file |
/// | `synchronous` | OFF / 0 | no fsync: power loss can corrupt the file |
/// | `cell_size_check` | OFF | corruption checks on b-tree pages stop |
/// | `query_only` | OFF | lifts a read-only connection back to read/write |
/// | `schema_version` | any value | the schema cookie, misuse corrupts the database |
/// | `temp_store_directory`, `data_store_directory` | any value | points SQLite at a directory of the caller's choice |
pub(crate) fn pragma_risk(name: &ObjectName, value: Option<&Value>) -> Option<String> {
    let pragma = pragma_name(name);
    let v = pragma_value(value)?;
    let set = |why: &str| Some(format!("PRAGMA {pragma} = {v} ({why})"));
    match pragma.as_str() {
        "writable_schema" => set("the schema table becomes writable"),
        "schema_version" => set("rewrites the schema cookie"),
        "temp_store_directory" | "data_store_directory" => {
            set("a directory of the caller's choice")
        }
        "trusted_schema" if pragma_bool(&v) == Some(true) => {
            set("schema functions run with side effects")
        }
        "ignore_check_constraints" if pragma_bool(&v) == Some(true) => {
            set("CHECK constraints are not enforced")
        }
        "foreign_keys" if pragma_bool(&v) == Some(false) => set("foreign keys are not enforced"),
        "cell_size_check" if pragma_bool(&v) == Some(false) => set("corruption checks are off"),
        "query_only" if pragma_bool(&v) == Some(false) => set("a read-only connection can write"),
        "journal_mode" if v == "off" => set("no rollback journal"),
        "synchronous" if v == "off" || v == "0" => set("no fsync"),
        _ => None,
    }
}

/// How an allowlist (VERICTO-087) treats a `PRAGMA`.
pub(crate) enum PragmaAccess {
    /// Reads the structure of a table: every column of it.
    ReadsTable(ObjectName),
    /// A connection setting drivers and ORMs send: allowed.
    Allowed,
    /// Anything else: denied, as DDL.
    Denied(String),
}

/// The `PRAGMA` reads and connection settings an allowlist lets through;
/// every other pragma is denied as DDL.
pub(crate) fn pragma_access(name: &ObjectName, value: Option<&Value>) -> PragmaAccess {
    let pragma = pragma_name(name);
    let v = pragma_value(value);
    let denied = || PragmaAccess::Denied(format!("PRAGMA {pragma}"));
    match pragma.as_str() {
        // `PRAGMA [schema.]table_info(t)`: the table's columns.
        "table_info" | "table_xinfo" | "index_list" | "foreign_key_list" => match v {
            Some(_) => {
                let table = match value {
                    Some(Value::SingleQuotedString(s) | Value::DoubleQuotedString(s)) => s.clone(),
                    _ => return denied(),
                };
                let mut parts: Vec<Ident> = name
                    .0
                    .iter()
                    .rev()
                    .skip(1)
                    .filter_map(|p| p.as_ident().cloned())
                    .collect();
                parts.push(Ident::new(table));
                PragmaAccess::ReadsTable(ObjectName::from(parts))
            }
            None => denied(),
        },
        "foreign_keys" => match v.as_deref().map(pragma_bool) {
            None | Some(Some(true)) => PragmaAccess::Allowed,
            _ => denied(),
        },
        "journal_mode" => match v.as_deref() {
            None | Some("wal" | "delete" | "truncate" | "persist") => PragmaAccess::Allowed,
            _ => denied(),
        },
        "synchronous" => match v.as_deref() {
            None | Some("normal" | "full" | "extra" | "1" | "2" | "3") => PragmaAccess::Allowed,
            _ => denied(),
        },
        "busy_timeout"
        | "cache_size"
        | "temp_store"
        | "defer_foreign_keys"
        | "recursive_triggers"
        | "case_sensitive_like" => PragmaAccess::Allowed,
        _ => denied(),
    }
}

// ---------------------------------------------------------------------------
// Native code (VERICTO-100)
// ---------------------------------------------------------------------------

/// Functions that load native code or reach the file system:
/// `load_extension` (a shared library, when extension loading is enabled),
/// `fts3_tokenizer` (registers a tokenizer by raw pointer), the sqlite3
/// shell's `readfile`, `writefile` and `edit` (present wherever its fileio
/// extension is loaded), and the file-system table-valued functions and
/// virtual-table modules of the same extensions, `fsdir(…)` and
/// `zipfile(…)`.
const NATIVE_FUNCTIONS: &[&str] = &[
    "load_extension",
    "fts3_tokenizer",
    "readfile",
    "writefile",
    "edit",
    "fsdir",
    "zipfile",
];

/// The native-code functions the text calls, in order, as written: a name
/// (quoted or not) followed by `(`. String literals and comments never
/// count.
fn native_calls(toks: &[Token]) -> Vec<String> {
    let mut out = Vec::new();
    for w in toks.windows(2) {
        if let (Token::Word(name), Token::LParen) = (&w[0], &w[1]) {
            let lower = name.value.to_ascii_lowercase();
            if NATIVE_FUNCTIONS.contains(&lower.as_str()) && !out.contains(&lower) {
                out.push(lower);
            }
        }
    }
    out
}

/// `parsed` with an entry for each native-code call the text holds (a
/// pre-classified statement already has them).
fn with_native_calls(mut parsed: ParsedQuery, sql: &str) -> ParsedQuery {
    if matches!(parsed.ast, SourceAst::Classified { .. }) {
        return parsed;
    }
    let calls = match significant(sql) {
        Some(toks) => native_calls(&toks),
        // A text sqlparser parsed always tokenizes; be safe anyway.
        None => Vec::new(),
    };
    for f in calls {
        parsed.statements.push(native_entry(&f));
    }
    parsed
}

fn native_entry(f: &str) -> StatementInfo {
    StatementInfo {
        ast_node_path: format!("FunctionCall > {f}() (native code or the file system)"),
        sqlite: Some(SqliteRisk::NativeCode),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

/// **The allowlist**: legitimate SQLite statements sqlparser 0.63 rejects,
/// which change no data, run no code and widen no access. Each entry is an
/// anchored pattern over the whole statement (its keywords and names,
/// nothing else). An allowlisted statement is analysed with no finding; under
/// an agent allowlist it is still denied as DDL.
///
/// | Entry | Example | Why it is safe |
/// |---|---|---|
/// | `DETACH [DATABASE] <name>` | `DETACH DATABASE reports` | closes an attached database; nothing is read or written |
/// | `REINDEX [[<schema>.]<name>]` | `REINDEX idx_users_email` | rebuilds indexes from the table's own rows |
/// | `CREATE [TEMP] VIRTUAL TABLE [IF NOT EXISTS] <name> USING fts3\|fts4\|fts5\|rtree\|rtree_i32\|geopoly(<args>)` | `CREATE VIRTUAL TABLE docs_fts USING fts5(title, body, content='docs')` | a full-text or spatial index of the database's own rows; the arguments are names, literals and `name = literal` options only |
pub(crate) fn allowlisted(sql: &str) -> Option<&'static str> {
    let toks = statement_tokens(sql)?;
    let is_name = |t: Option<&Token>| matches!(t, Some(Token::Word(_)));
    match word(toks.first()).as_str() {
        "CREATE" => {
            let mut k = 1;
            if matches!(word(toks.get(k)).as_str(), "TEMP" | "TEMPORARY") {
                k += 1;
            }
            if word(toks.get(k)) != "VIRTUAL" || word(toks.get(k + 1)) != "TABLE" {
                return None;
            }
            k += 2;
            if word(toks.get(k)) == "IF" {
                (word(toks.get(k + 1)) == "NOT" && word(toks.get(k + 2)) == "EXISTS")
                    .then_some(())?;
                k += 3;
            }
            is_name(toks.get(k)).then_some(())?;
            k += 1;
            if toks.get(k) == Some(&Token::Period) {
                is_name(toks.get(k + 1)).then_some(())?;
                k += 2;
            }
            (word(toks.get(k)) == "USING").then_some(())?;
            const MODULES: &[&str] = &["FTS3", "FTS4", "FTS5", "RTREE", "RTREE_I32", "GEOPOLY"];
            MODULES
                .contains(&word(toks.get(k + 1)).as_str())
                .then_some(())?;
            (toks.get(k + 2) == Some(&Token::LParen) && toks.last() == Some(&Token::RParen))
                .then_some(())?;
            let args = &toks[k + 3..toks.len() - 1];
            args.iter()
                .all(|t| {
                    matches!(
                        t,
                        Token::Word(_)
                            | Token::SingleQuotedString(_)
                            | Token::Number(..)
                            | Token::Eq
                            | Token::Comma
                    )
                })
                .then_some("CREATE VIRTUAL TABLE (full-text / spatial index)")
        }
        "DETACH" => {
            let k = if word(toks.get(1)) == "DATABASE" {
                2
            } else {
                1
            };
            (is_name(toks.get(k)) && toks.len() == k + 1).then_some("DETACH")
        }
        "REINDEX" => {
            let ok = match toks.len() {
                1 => true,
                2 => is_name(toks.get(1)),
                4 => is_name(toks.get(1)) && toks[2] == Token::Period && is_name(toks.get(3)),
                _ => false,
            };
            ok.then_some("REINDEX")
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pre-classifier
// ---------------------------------------------------------------------------

/// A statement the pre-classifier recognised.
pub(crate) struct Classified {
    /// Its name (`VACUUM INTO`).
    pub(crate) what: &'static str,
    /// The entries the rules read.
    pub(crate) statements: Vec<StatementInfo>,
    /// Whether its pattern covers the whole statement (then it is read, not
    /// unread code).
    pub(crate) whole: bool,
}

/// The pragma names [`pragma_risk`] reports for some value.
const SAFETY_PRAGMAS: &[&str] = &[
    "writable_schema",
    "schema_version",
    "temp_store_directory",
    "data_store_directory",
    "trusted_schema",
    "ignore_check_constraints",
    "foreign_keys",
    "cell_size_check",
    "query_only",
    "journal_mode",
    "synchronous",
];

/// The statement `sql` is, when sqlparser rejected it but its keywords name
/// a statement a SQLite rule covers. `None` for anything else, which stays a
/// parse error.
pub(crate) fn preclassify(sql: &str) -> Option<Classified> {
    let toks = statement_tokens(sql)?;
    let entry = |risk: SqliteRisk, path: String| StatementInfo {
        ast_node_path: path,
        sqlite: Some(risk),
        ..Default::default()
    };
    let mut out: Vec<StatementInfo> = Vec::new();
    let mut whole = false;
    let what: &'static str = match word(toks.first()).as_str() {
        // `VACUUM [schema] INTO <file>`: a copy of the whole database.
        "VACUUM" => {
            let into = toks.iter().position(|t| word(Some(t)) == "INTO")?;
            whole = matches!(into, 1 | 2)
                && (into == 1 || matches!(toks.get(1), Some(Token::Word(_))))
                && matches!(toks.get(into + 1), Some(Token::SingleQuotedString(_)))
                && toks.len() == into + 2;
            let target = match toks.get(into + 1) {
                Some(Token::SingleQuotedString(s)) => format!("'{s}'"),
                _ => "an expression".to_string(),
            };
            out.push(entry(
                SqliteRisk::VacuumInto,
                format!("VacuumStmt > INTO {target} (a full copy of the database)"),
            ));
            "VACUUM INTO"
        }
        // An `ATTACH` sqlparser does not read (`… KEY '…'`, an expression
        // it rejects): still a file opened on the connection.
        "ATTACH" => {
            out.push(entry(
                SqliteRisk::Attach,
                "AttachStmt (opens another database file)".to_string(),
            ));
            "ATTACH"
        }
        // A `PRAGMA` outside SQLite's grammar but naming a safety pragma.
        "PRAGMA" => {
            let name = match (toks.get(2), toks.get(3)) {
                (Some(Token::Period), Some(t)) => name_part(Some(t)),
                _ => name_part(toks.get(1)),
            }?;
            let lower = name.value.to_ascii_lowercase();
            if !SAFETY_PRAGMAS.contains(&lower.as_str()) {
                return None;
            }
            out.push(entry(
                SqliteRisk::SafetyPragma,
                format!("PragmaStmt > {lower} (a safety pragma, not parsed)"),
            ));
            "PRAGMA"
        }
        _ => "statement",
    };
    // A native-code call anywhere in the text (VERICTO-100).
    for f in native_calls(&toks) {
        out.push(native_entry(&f));
    }
    if out.is_empty() {
        return None;
    }
    // A native call in a statement only its keywords identify is not read.
    let whole = whole && !out.iter().any(|s| s.sqlite == Some(SqliteRisk::NativeCode));
    let what = if what == "statement" {
        "load_extension()"
    } else {
        what
    };
    Some(Classified {
        what,
        statements: out,
        whole,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_prefix_reads_like_sqlite() {
        use crate::parser::walk::sqlite_numeric_prefix as n;
        assert_eq!(n("1abc"), 1.0);
        assert_eq!(n("  2.5x"), 2.5);
        assert_eq!(n("abc"), 0.0);
        assert_eq!(n(""), 0.0);
        assert_eq!(n("-3"), -3.0);
        assert_eq!(n(".5"), 0.5);
        assert_eq!(n("1e3x"), 1000.0);
        assert_eq!(n("1ex"), 1.0);
        assert_eq!(n("0x10"), 0.0);
        assert_eq!(n("+"), 0.0);
        assert_eq!(n("."), 0.0);
    }

    #[test]
    fn pragma_grammar_reads_keyword_and_name_values() {
        for (sql, printed) in [
            ("PRAGMA foreign_keys = OFF", "PRAGMA foreign_keys = 'OFF'"),
            ("PRAGMA table_info(users)", "PRAGMA table_info('users')"),
            (
                "pragma main.table_info(\"Users\");",
                "PRAGMA main.table_info('Users')",
            ),
            ("PRAGMA cache_size = -2000", "PRAGMA cache_size = -2000"),
            ("PRAGMA journal_mode=WAL", "PRAGMA journal_mode = 'WAL'"),
            ("PRAGMA optimize", "PRAGMA optimize"),
        ] {
            let st = pragma_statement(sql).unwrap_or_else(|| panic!("{sql}"));
            assert_eq!(st.to_string(), printed, "{sql}");
        }
        for sql in [
            "PRAGMA",
            "PRAGMA a = b c",
            "PRAGMA a(b",
            "PRAGMA a = 1; DROP TABLE t",
            "PRAGMA a = (SELECT 1)",
            "SELECT 1",
        ] {
            assert!(pragma_statement(sql).is_none(), "{sql}");
        }
    }

    #[test]
    fn planner_hints_are_blanked_after_a_name_only() {
        assert_eq!(
            without_planner_hints("SELECT a FROM t INDEXED BY i WHERE a = 1").as_deref(),
            Some("SELECT a FROM t              WHERE a = 1")
        );
        assert_eq!(
            without_planner_hints("SELECT a FROM t AS x NOT INDEXED").as_deref(),
            Some("SELECT a FROM t AS x            ")
        );
        assert!(without_planner_hints("SELECT 'INDEXED BY i' FROM t").is_none());
        assert_eq!(
            without_planner_hints(
                "CREATE TEMP TRIGGER IF NOT EXISTS t AFTER INSERT ON x BEGIN SELECT 1; END"
            )
            .as_deref(),
            Some("CREATE TEMP TRIGGER               t AFTER INSERT ON x BEGIN SELECT 1; END")
        );
        assert!(without_planner_hints("SELECT a FROM t").is_none());
    }

    #[test]
    fn native_calls_ignore_strings_and_comments() {
        let toks = significant(
            "SELECT 'load_extension(1)', x /* load_extension( */ FROM t WHERE \"LOAD_EXTENSION\"('a')",
        )
        .unwrap();
        assert_eq!(native_calls(&toks), vec!["load_extension".to_string()]);
    }
}
