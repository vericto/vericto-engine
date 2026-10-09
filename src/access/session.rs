//! Session boilerplate: the statements drivers and ORMs send on every
//! connection (transaction control, isolation level, character set, time
//! zone, timeouts, application name). Under an allowlist they are allowed
//! whether or not the parser reads them — sqlparser 0.52 rejects several
//! (`SET SESSION TRANSACTION ISOLATION LEVEL …`, `SET CHARACTER SET …`), and a
//! parse error blocks under an enforced allowlist.
//!
//! A **closed list**, matched on the text (after the MySQL lexical
//! normalization), case-insensitively, one statement only, every value a
//! literal. Nothing here can change who the session is, where names resolve
//! or how text is lexed: `SET ROLE`, `SET SESSION AUTHORIZATION`,
//! `SET search_path`, `USE`, `sql_mode`, `GLOBAL`/`PERSIST` and any computed
//! value are not on it.

use crate::parser::Dialect;
use crate::parser::mysql_lex::{Readings, readings};

/// Whether `sql` is one session statement on the closed list, in every
/// reading MySQL may give it.
pub(crate) fn is_session_boilerplate(sql: &str, dialect: Dialect) -> bool {
    match dialect {
        Dialect::Mysql => match readings(sql) {
            Readings::Plain => matches(sql),
            Readings::Normalized { base, alternatives } => {
                matches(&base) && alternatives.iter().all(|a| matches(a))
            }
            Readings::Ambiguous(_) => false,
        },
        _ => matches(sql),
    }
}

#[derive(Debug, PartialEq)]
enum Tok {
    /// A bare word (keyword, name, number), uppercased.
    Word(String),
    /// A quoted string literal (its content).
    Str(String),
    Eq,
    Comma,
    /// `(` / `)`: only meaningful inside a `sql_mode` `CONCAT(…)`.
    Open,
    Close,
}

/// Words, `'…'` literals, `=` and `,`; anything else (comments, `;` inside,
/// parentheses, operators, backslashes, other quotes) makes the text
/// unrecognised.
fn tokens(sql: &str) -> Option<Vec<Tok>> {
    let text = sql.trim();
    let text = text.strip_suffix(';').unwrap_or(text).trim_end();
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '=' {
            chars.next();
            out.push(Tok::Eq);
        } else if c == ',' {
            chars.next();
            out.push(Tok::Comma);
        } else if c == '(' {
            chars.next();
            out.push(Tok::Open);
        } else if c == ')' {
            chars.next();
            out.push(Tok::Close);
        } else if c == '\'' {
            chars.next();
            let mut lit = String::new();
            loop {
                match chars.next()? {
                    '\\' => return None,
                    '\'' if chars.peek() == Some(&'\'') => {
                        chars.next();
                        lit.push('\'');
                    }
                    '\'' => break,
                    c => lit.push(c),
                }
            }
            out.push(Tok::Str(lit));
        } else if c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '+' | '-' | ':') {
            let mut w = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '+' | '-' | ':') {
                    w.push(c.to_ascii_uppercase());
                    chars.next();
                } else {
                    break;
                }
            }
            // `--` starts a comment.
            if w.contains("--") {
                return None;
            }
            out.push(Tok::Word(w));
        } else {
            return None;
        }
    }
    Some(out)
}

fn word(t: Option<&Tok>) -> Option<&str> {
    match t {
        Some(Tok::Word(w)) => Some(w),
        _ => None,
    }
}

/// Transaction characteristics: `ISOLATION LEVEL …`, `READ ONLY|WRITE`,
/// `[NOT] DEFERRABLE`, `WITH CONSISTENT SNAPSHOT`, comma-separated.
fn transaction_modes(rest: &[Tok]) -> bool {
    rest.iter().all(|t| match t {
        Tok::Comma => true,
        Tok::Word(w) => matches!(
            w.as_str(),
            "ISOLATION"
                | "LEVEL"
                | "READ"
                | "COMMITTED"
                | "UNCOMMITTED"
                | "REPEATABLE"
                | "SERIALIZABLE"
                | "ONLY"
                | "WRITE"
                | "NOT"
                | "DEFERRABLE"
                | "WITH"
                | "CONSISTENT"
                | "SNAPSHOT"
        ),
        _ => false,
    })
}

/// A literal: a quoted string, a number, or a bare word (`DEFAULT`, `ON`,
/// `UTF8`, `ISO`). A word with `@` would be a variable: not a literal.
fn literal(t: &Tok) -> bool {
    match t {
        Tok::Str(_) => true,
        Tok::Word(w) => !w.contains('@'),
        _ => false,
    }
}

/// How a session setting is treated under an allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    /// Harmless connector / ORM setting: any literal value.
    Listed,
    /// MySQL `sql_mode`: only values that cannot change lexing
    /// ([`sql_mode_ok`]).
    SqlMode,
    /// Postgres `standard_conforming_strings`: only `on` (`off` changes how
    /// backslashes in string literals are read).
    StandardConformingStrings,
    /// Anything else: denied by default (`session_replication_role`,
    /// `foreign_key_checks`, `sql_log_bin`, `default_transaction_read_only`, …).
    Unlisted,
}

/// The rule for setting `name` (any case, without `@@SESSION.` / `@@`).
pub(crate) fn setting(name: &str) -> Setting {
    let n = name.to_ascii_lowercase();
    if n.starts_with("session_track_") {
        return Setting::Listed;
    }
    match n.as_str() {
        "sql_mode" => Setting::SqlMode,
        "standard_conforming_strings" => Setting::StandardConformingStrings,
        "autocommit"
        | "time_zone"
        | "timezone"
        | "client_encoding"
        | "statement_timeout"
        | "lock_timeout"
        | "idle_in_transaction_session_timeout"
        | "idle_session_timeout"
        | "application_name"
        | "datestyle"
        | "intervalstyle"
        | "extra_float_digits"
        | "character_set_results"
        | "character_set_client"
        | "character_set_connection"
        | "collation_connection"
        | "sql_auto_is_null"
        | "wait_timeout"
        | "interactive_timeout"
        | "net_read_timeout"
        | "net_write_timeout"
        | "max_execution_time"
        | "sql_select_limit"
        | "transaction_isolation"
        | "tx_isolation"
        | "work_mem"
        | "maintenance_work_mem"
        | "temp_buffers"
        | "bytea_output" => Setting::Listed,
        _ => Setting::Unlisted,
    }
}

/// `standard_conforming_strings` values that keep it on.
pub(crate) fn scs_on(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "on" | "true" | "yes" | "1" | "default"
    )
}

/// sql_mode names that switch on `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES` or
/// `PIPES_AS_CONCAT`, directly or as a combination mode.
const LEXING_MODES: &[&str] = &[
    "ANSI_QUOTES",
    "NO_BACKSLASH_ESCAPES",
    "ANSI",
    "PIPES_AS_CONCAT",
    "ORACLE",
    "MSSQL",
    "DB2",
    "POSTGRESQL",
    "MAXDB",
];

/// One piece of a `sql_mode` value: a string literal, or the current mode
/// (`@@sql_mode`), concatenated in order.
pub(crate) enum ModePiece {
    Literal(String),
    Current,
}

/// Whether the concatenation of `pieces` cannot switch on a mode that
/// changes lexing. The current mode is a list of valid names, so it is only
/// safe next to a comma (else `@@sql_mode` + `'_QUOTES'` could complete a
/// name); the literal parts, joined, are split on commas and checked token
/// by token (so `CONCAT('ANSI_', 'QUOTES')` is caught).
pub(crate) fn sql_mode_ok(pieces: &[ModePiece]) -> bool {
    const MARK: char = '\u{1}';
    let mut text = String::new();
    for p in pieces {
        match p {
            ModePiece::Literal(s) => {
                if s.contains(MARK) {
                    return false;
                }
                text.push_str(s);
            }
            ModePiece::Current => text.push(MARK),
        }
    }
    let chars: Vec<char> = text.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == MARK {
            let before = i == 0 || matches!(chars[i - 1], ',' | MARK);
            let after = i + 1 == chars.len() || matches!(chars[i + 1], ',' | MARK);
            if !before || !after {
                return false;
            }
        }
    }
    text.split([',', MARK]).all(|tok| {
        let t = tok.trim().to_ascii_uppercase();
        !LEXING_MODES.contains(&t.as_str())
    })
}

/// A setting name as written, without the session scope: `None` for a
/// server-wide one (`@@GLOBAL.x`, `@@PERSIST.x`) or a user variable (`@x`).
pub(crate) fn session_name(name: &str) -> Option<&str> {
    let up = name.to_ascii_uppercase();
    for p in ["@@GLOBAL.", "@@PERSIST.", "@@PERSIST_ONLY."] {
        if up.starts_with(p) {
            return None;
        }
    }
    for p in ["@@SESSION.", "@@LOCAL."] {
        if up.starts_with(p) {
            return Some(&name[p.len()..]);
        }
    }
    if let Some(n) = name.strip_prefix("@@") {
        return Some(n);
    }
    if name.starts_with('@') {
        return None;
    }
    Some(name)
}

/// Whether `name = values` is allowed, for the text form (values are tokens).
fn assignment_ok(name: &str, values: &[&Tok]) -> bool {
    let Some(name) = session_name(name) else {
        return false;
    };
    match setting(name) {
        Setting::Listed => values.iter().all(|t| literal(t)),
        Setting::StandardConformingStrings => match values {
            [Tok::Word(v)] | [Tok::Str(v)] => scs_on(v),
            _ => false,
        },
        Setting::SqlMode => {
            let pieces: Option<Vec<ModePiece>> = values
                .iter()
                .map(|t| match t {
                    Tok::Str(s) => Some(ModePiece::Literal(s.clone())),
                    Tok::Word(w) if w == "DEFAULT" => Some(ModePiece::Literal(String::new())),
                    _ => None,
                })
                .collect();
            // Several literals in the text form would be `'a', 'b'`: not a
            // sql_mode value.
            matches!(pieces, Some(p) if p.len() == 1 && sql_mode_ok(&p))
        }
        Setting::Unlisted => false,
    }
}

/// A `sql_mode` value: `'…'`, `DEFAULT`, `@@sql_mode`, `@@SESSION.sql_mode`,
/// or `CONCAT(<value>, …)`, nested.
fn mode_expr(toks: &[Tok], i: &mut usize, out: &mut Vec<ModePiece>, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match toks.get(*i) {
        Some(Tok::Str(s)) => {
            out.push(ModePiece::Literal(s.clone()));
            *i += 1;
            true
        }
        Some(Tok::Word(w)) if w == "DEFAULT" => {
            out.push(ModePiece::Literal(String::new()));
            *i += 1;
            true
        }
        Some(Tok::Word(w))
            if matches!(
                w.as_str(),
                "@@SQL_MODE" | "@@SESSION.SQL_MODE" | "@@LOCAL.SQL_MODE"
            ) =>
        {
            out.push(ModePiece::Current);
            *i += 1;
            true
        }
        Some(Tok::Word(w)) if w == "CONCAT" && toks.get(*i + 1) == Some(&Tok::Open) => {
            *i += 2;
            loop {
                if !mode_expr(toks, i, out, depth + 1) {
                    return false;
                }
                match toks.get(*i) {
                    Some(Tok::Comma) => *i += 1,
                    Some(Tok::Close) => {
                        *i += 1;
                        return true;
                    }
                    _ => return false,
                }
            }
        }
        _ => false,
    }
}

/// `name {=|TO} literal[, literal…] [, name = …]…`, every assignment allowed.
fn assignments(toks: &[Tok]) -> bool {
    let mut i = 0;
    loop {
        let Some(name) = word(toks.get(i)) else {
            return false;
        };
        match toks.get(i + 1) {
            Some(Tok::Eq) => {}
            Some(Tok::Word(w)) if w == "TO" => {}
            _ => return false,
        }
        i += 2;
        // `sql_mode = <CONCAT of literals and @@sql_mode>`: its own grammar.
        if session_name(name).is_some_and(|n| setting(n) == Setting::SqlMode) {
            let mut pieces = Vec::new();
            if !mode_expr(toks, &mut i, &mut pieces, 0) || !sql_mode_ok(&pieces) {
                return false;
            }
            match toks.get(i) {
                None => return true,
                Some(Tok::Comma) => {
                    i += 1;
                    continue;
                }
                Some(_) => return false,
            }
        }
        // At least one value; values separated by commas until `, name =`.
        let mut values: Vec<&Tok> = Vec::new();
        match toks.get(i) {
            Some(t) if literal(t) => values.push(t),
            _ => return false,
        }
        i += 1;
        let mut more = false;
        loop {
            match toks.get(i) {
                None => break,
                Some(Tok::Comma) => {
                    let next_is_assignment = matches!(toks.get(i + 2), Some(Tok::Eq))
                        || word(toks.get(i + 2)) == Some("TO");
                    if next_is_assignment {
                        i += 1;
                        more = true;
                        break;
                    }
                    match toks.get(i + 1) {
                        Some(t) if literal(t) => values.push(t),
                        _ => return false,
                    }
                    i += 2;
                }
                Some(_) => return false,
            }
        }
        if !assignment_ok(name, &values) {
            return false;
        }
        if !more {
            return true;
        }
    }
}

fn matches(sql: &str) -> bool {
    let Some(toks) = tokens(sql) else {
        return false;
    };
    let w = |i: usize| word(toks.get(i));
    let ident = |i: usize| w(i).is_some_and(|x| !x.contains('@')) && toks.len() == i + 1;
    match w(0) {
        Some("BEGIN") => {
            let rest = match w(1) {
                Some("WORK" | "TRANSACTION") => &toks[2..],
                _ => &toks[1..],
            };
            transaction_modes(rest)
        }
        Some("START") => w(1) == Some("TRANSACTION") && transaction_modes(&toks[2..]),
        Some("COMMIT" | "ROLLBACK") => {
            let mut i = 1;
            if matches!(w(i), Some("WORK" | "TRANSACTION")) {
                i += 1;
            }
            if w(0) == Some("ROLLBACK") && w(i) == Some("TO") {
                i += 1;
                if w(i) == Some("SAVEPOINT") {
                    i += 1;
                }
                return ident(i);
            }
            match &toks[i..] {
                [] => true,
                [Tok::Word(a), Tok::Word(c)] => a == "AND" && c == "CHAIN",
                [Tok::Word(a), Tok::Word(n), Tok::Word(c)] => {
                    a == "AND" && n == "NO" && c == "CHAIN"
                }
                _ => false,
            }
        }
        Some("SAVEPOINT") => ident(1),
        Some("RELEASE") => {
            if w(1) == Some("SAVEPOINT") {
                ident(2)
            } else {
                ident(1)
            }
        }
        Some("SET") => {
            let mut i = 1;
            if matches!(w(i), Some("SESSION" | "LOCAL")) {
                i += 1;
            }
            match (w(i), w(i + 1)) {
                (Some("TRANSACTION"), _) => transaction_modes(&toks[i + 1..]),
                (Some("CHARACTERISTICS"), Some("AS")) => {
                    w(i + 2) == Some("TRANSACTION") && transaction_modes(&toks[i + 3..])
                }
                (Some("NAMES"), _) => match &toks[i + 1..] {
                    [v] => literal(v),
                    [v, Tok::Word(c), v2] => literal(v) && c == "COLLATE" && literal(v2),
                    _ => false,
                },
                (Some("CHARACTER"), Some("SET")) => {
                    matches!(&toks[i + 2..], [v] if literal(v))
                }
                // `SET TIME ZONE 'UTC'`, `… LOCAL`, `… INTERVAL '+00:00' HOUR TO MINUTE`
                (Some("TIME"), Some("ZONE")) => {
                    toks.len() > i + 2 && toks[i + 2..].iter().all(literal)
                }
                _ => assignments(&toks[i..]),
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn the_closed_list_matches_only_its_forms() {
        for ok in [
            "BEGIN",
            "begin work",
            "START TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ ONLY",
            "COMMIT AND NO CHAIN",
            "ROLLBACK WORK TO SAVEPOINT s1",
            "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "SET NAMES 'utf8mb4'",
            "SET time_zone = DEFAULT",
            "SET @@SESSION.autocommit = 0",
            "SET DateStyle = ISO, MDY",
            "SET TIME ZONE INTERVAL '+00:00' HOUR TO MINUTE",
            "SET sql_mode = ''",
            "SET work_mem = '1GB'",
            "SET character_set_results = NULL",
            "SET session_track_gtids = OWN_GTID",
            "SET standard_conforming_strings TO 'on'",
        ] {
            assert!(matches(ok), "{ok}");
        }
        for no in [
            "SET foreign_key_checks = 0",
            "SET sql_mode = 'ANSI'",
            "SET standard_conforming_strings = off",
            "SET session_replication_role = replica",
            "SET GLOBAL autocommit = 1",
            "SET @@GLOBAL.time_zone = '+00:00'",
            "SET time_zone = @x",
            "SET time_zone = (SELECT 1)",
            "SET time_zone = CONCAT('a', 'b')",
            "SET NAMES 'x' /* c */",
            "SET NAMES utf8 -- c",
            "BEGIN; SELECT 1",
            "SET application_name = 'a\\'b'",
            "COMMIT PREPARED 'x'",
            "SAVEPOINT",
            "SET ROLE admin",
            "SET search_path = x",
            "SET SESSION AUTHORIZATION x",
        ] {
            assert!(!matches(no), "{no}");
        }
    }
}
