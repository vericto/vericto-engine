//! MySQL front end and renderer for VERICTO-085.
//!
//! sqlparser is not MySQL. Where the two read the same text differently, the
//! analysis must follow MySQL (that is what runs) and the rewrite must never
//! forward a text MySQL reads differently from what the client sent. This
//! module owns both sides:
//!
//! **Reading** ([`prepare`]): the client's text is tokenized again, without
//! unescaping string literals, and checked for the places where sqlparser and
//! MySQL disagree before it is parsed for the analysis:
//! - Comments MySQL executes, nests or starts differently from sqlparser: the
//!   text cannot be analysed: [`Unreadable`], which resolves like a parse
//!   error.
//! - SELECT modifiers sqlparser does not know, which it misreads as a column
//!   and an alias: they are removed before parsing (the analysis then sees
//!   what MySQL reads), and a rewrite of such a statement is refused (they
//!   cannot be put back).
//! - Every `?` is renumbered `?1`, `?2`, … in textual order, so the rewrite can
//!   prove each bind parameter is still the same one, in the same position.
//!
//! **Writing** ([`Prepared::render`]): the rewritten tree is printed with
//! `Display` and only forwarded when three checks pass:
//! 1. the *unmodified* tree prints to a token stream equal to the client's,
//!    up to a short list of spellings MySQL treats identically (keyword case,
//!    an inserted `AS` before an alias, `LIMIT a, b` / `LIMIT b OFFSET a`,
//!    `INNER`/`OUTER` before `JOIN`). String literals compare **verbatim**,
//!    byte for byte inside the quotes, so the result does not depend on the
//!    server's string-escape mode;
//! 2. the rewritten text parses back to exactly the rewritten tree;
//! 3. its placeholders are `?1 … ?n`, each once, in order, with the client's
//!    `n`. Only then are they turned back into `?`.
//!
//! Any failure is a reason string; the verdict turns it into a block.

use sqlparser::ast::{Expr, Statement};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, TokenWithLocation, Tokenizer, Whitespace};

/// The text cannot be analysed the way MySQL reads it.
#[derive(Debug, Clone)]
pub(crate) struct Unreadable(pub(crate) String);

/// SELECT modifiers sqlparser 0.52 does not know: it parses a modifier
/// followed by a column as a column with an alias.
const MODIFIERS: &[&str] = &[
    "HIGH_PRIORITY",
    "STRAIGHT_JOIN",
    "SQL_SMALL_RESULT",
    "SQL_BIG_RESULT",
    "SQL_BUFFER_RESULT",
    "SQL_NO_CACHE",
    "SQL_CACHE",
    "SQL_CALC_FOUND_ROWS",
];

/// A significant (non-whitespace) token and its byte span in the text it came
/// from. `gap` = whitespace or a comment precedes it.
#[derive(Debug, Clone)]
struct Sig {
    tok: Token,
    start: usize,
    end: usize,
    gap: bool,
}

/// The client's statement, read the way MySQL reads it.
pub(crate) struct Prepared<'s> {
    sql: &'s str,
    /// Parsed from the normalised tokens; owned, so the walker may rewrite it.
    pub(crate) statements: Vec<Statement>,
    sig: Vec<Sig>,
    /// Why this text cannot be reproduced by the renderer, if it cannot. Only
    /// matters when a projection is actually rewritten.
    unfaithful: Option<String>,
    /// Number of `?` in the client's text.
    params: usize,
}

fn dialect() -> MySqlDialect {
    MySqlDialect {}
}

/// Byte offset of every token start (tokenizer locations are 1-based line and
/// character column).
fn byte_offsets(sql: &str, toks: &[TokenWithLocation]) -> Vec<usize> {
    let mut out = Vec::with_capacity(toks.len());
    let mut chars = sql.char_indices().peekable();
    let (mut line, mut col) = (1u64, 1u64);
    for t in toks {
        let want = (t.location.line, t.location.column);
        while (line, col) < want {
            match chars.next() {
                Some((_, '\n')) => {
                    line += 1;
                    col = 1;
                }
                Some(_) => col += 1,
                None => break,
            }
        }
        out.push(chars.peek().map_or(sql.len(), |(b, _)| *b));
    }
    out
}

fn raw_tokens(sql: &str) -> Result<(Vec<TokenWithLocation>, Vec<usize>), String> {
    let d = dialect();
    let toks = Tokenizer::new(&d, sql)
        .with_unescape(false)
        .tokenize_with_location()
        .map_err(|e| e.to_string())?;
    let offs = byte_offsets(sql, &toks);
    Ok((toks, offs))
}

fn is_word(t: &Token, kw: &str) -> bool {
    matches!(t, Token::Word(w) if w.quote_style.is_none() && w.value.eq_ignore_ascii_case(kw))
}

/// Whether a raw (not unescaped) literal body holds `\` + the quote: an
/// escaped quote, which only exists when backslash escapes are on.
fn escapes_quote(raw: &str, quote: char) -> bool {
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.next() == Some(quote) {
            return true;
        }
    }
    false
}

/// Reads `sql` (which must already parse) for the analysis. `numbered` = the
/// text is a rendering of ours, whose placeholders are already `?1 … ?n`.
fn read(sql: &str, numbered: bool) -> Result<Prepared<'_>, Unreadable> {
    let (toks, offs) = raw_tokens(sql).map_err(Unreadable)?;
    let mut out: Vec<TokenWithLocation> = Vec::with_capacity(toks.len());
    let mut sig: Vec<Sig> = Vec::new();
    let mut unfaithful: Option<String> = None;
    let mut params = 0usize;
    let mut gap = false;
    fn flag(why: String, slot: &mut Option<String>) {
        if slot.is_none() {
            *slot = Some(why);
        }
    }
    for (i, t) in toks.iter().enumerate() {
        let start = offs[i];
        let end = offs.get(i + 1).copied().unwrap_or(sql.len());
        let mut tok = t.token.clone();
        match &tok {
            Token::Whitespace(Whitespace::MultiLineComment(c)) => {
                if c.starts_with('!') || c.starts_with("M!") {
                    return Err(Unreadable(
                        "MySQL executes `/*! … */` comments; the engine cannot read them".into(),
                    ));
                }
                if c.contains("/*") {
                    return Err(Unreadable(
                        "a `/*` inside a comment: MySQL does not nest comments".into(),
                    ));
                }
                if c.starts_with('+') {
                    flag(
                        "optimizer hints `/*+ … */` are dropped by the renderer".into(),
                        &mut unfaithful,
                    );
                }
            }
            Token::Whitespace(Whitespace::SingleLineComment { prefix, comment })
                if prefix == "--"
                    && !comment.starts_with(|c: char| c.is_whitespace() || c.is_control()) =>
            {
                return Err(Unreadable(
                    "`--` not followed by a space is not a comment in MySQL".into(),
                ));
            }
            Token::Placeholder(p) => {
                params += 1;
                if numbered {
                    if *p != format!("?{params}") {
                        flag(format!("placeholder `{p}` out of order"), &mut unfaithful);
                    }
                } else if p == "?" {
                    tok = Token::Placeholder(format!("?{params}"));
                } else {
                    flag(
                        format!("placeholder `{p}` is not a MySQL `?`"),
                        &mut unfaithful,
                    );
                }
            }
            Token::Word(w) if w.quote_style.is_none() => {
                let up = w.value.to_ascii_uppercase();
                let after_select = sig.last().is_some_and(|s| {
                    is_word(&s.tok, "SELECT")
                        || is_word(&s.tok, "DISTINCT")
                        || is_word(&s.tok, "ALL")
                });
                if after_select && MODIFIERS.contains(&up.as_str()) {
                    flag(
                        format!("the SELECT modifier {up} cannot be reproduced"),
                        &mut unfaithful,
                    );
                    gap = true;
                    continue;
                }
                if after_select && up == "DISTINCTROW" {
                    tok = Token::make_keyword("DISTINCT");
                }
            }
            _ => {}
        }
        if let Token::SingleQuotedString(raw)
        | Token::DoubleQuotedString(raw)
        | Token::NationalStringLiteral(raw) = &tok
        {
            // Where a literal with a backslash-escaped quote ends depends on
            // the server's string-escape mode, which the engine cannot see:
            // in one mode the following text is code, in the other it is not.
            let q = if matches!(tok, Token::DoubleQuotedString(_)) {
                '"'
            } else {
                '\''
            };
            if escapes_quote(raw, q) {
                return Err(Unreadable(
                    "a backslash-escaped quote inside a string literal ends the literal elsewhere under NO_BACKSLASH_ESCAPES; double the quote instead".into(),
                ));
            }
            // A bit-value literal `b'101'`: sqlparser reads `b AS '101'`.
            // (`X'…'`, `N'…'` and `_charset'…'` are read correctly.)
            if !gap && sig.last().is_some_and(|p| is_word(&p.tok, "b")) {
                flag(
                    "the bit-value literal `b'…'` cannot be reproduced".into(),
                    &mut unfaithful,
                );
            }
        }
        if let Token::Whitespace(_) = tok {
            gap = true;
        } else {
            sig.push(Sig {
                tok: tok.clone(),
                start,
                end,
                gap,
            });
            gap = false;
        }
        out.push(TokenWithLocation {
            token: tok,
            location: t.location,
        });
    }
    let d = dialect();
    let statements = Parser::new(&d)
        .with_tokens_with_locations(out)
        .parse_statements()
        .map_err(|e| Unreadable(format!("cannot be parsed as MySQL reads it: {e}")))?;
    Ok(Prepared {
        sql,
        statements,
        sig,
        unfaithful,
        params,
    })
}

/// Reads the client's text for the analysis.
pub(crate) fn prepare(sql: &str) -> Result<Prepared<'_>, Unreadable> {
    read(sql, false)
}

/// Token equality for the fidelity check: unquoted words compare
/// case-insensitively; everything else (strings verbatim) exactly.
fn same(a: &Token, b: &Token) -> bool {
    match (a, b) {
        (Token::Word(x), Token::Word(y)) => {
            x.quote_style == y.quote_style
                && if x.quote_style.is_none() {
                    x.value.eq_ignore_ascii_case(&y.value)
                } else {
                    x.value == y.value
                }
        }
        (Token::Number(x, _), Token::Number(y, _)) => x == y,
        _ => a == b,
    }
}

/// MySQL reserved words (8.0, plus the operator words `SOUNDS` and `MEMBER`).
/// One of these after an expression is never an alias to MySQL, so an `AS`
/// the renderer inserts before it would change what the text means.
const RESERVED: &[&str] = &[
    "ACCESSIBLE",
    "ADD",
    "ALL",
    "ALTER",
    "ANALYZE",
    "AND",
    "AS",
    "ASC",
    "ASENSITIVE",
    "BEFORE",
    "BETWEEN",
    "BIGINT",
    "BINARY",
    "BLOB",
    "BOTH",
    "BY",
    "CALL",
    "CASCADE",
    "CASE",
    "CHANGE",
    "CHAR",
    "CHARACTER",
    "CHECK",
    "COLLATE",
    "COLUMN",
    "CONDITION",
    "CONSTRAINT",
    "CONTINUE",
    "CONVERT",
    "CREATE",
    "CROSS",
    "CUBE",
    "CUME_DIST",
    "CURRENT_DATE",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "CURRENT_USER",
    "CURSOR",
    "DATABASE",
    "DATABASES",
    "DAY_HOUR",
    "DAY_MICROSECOND",
    "DAY_MINUTE",
    "DAY_SECOND",
    "DEC",
    "DECIMAL",
    "DECLARE",
    "DEFAULT",
    "DELAYED",
    "DELETE",
    "DENSE_RANK",
    "DESC",
    "DESCRIBE",
    "DETERMINISTIC",
    "DISTINCT",
    "DISTINCTROW",
    "DIV",
    "DOUBLE",
    "DROP",
    "DUAL",
    "EACH",
    "ELSE",
    "ELSEIF",
    "EMPTY",
    "ENCLOSED",
    "ESCAPED",
    "EXCEPT",
    "EXISTS",
    "EXIT",
    "EXPLAIN",
    "FALSE",
    "FETCH",
    "FIRST_VALUE",
    "FLOAT",
    "FLOAT4",
    "FLOAT8",
    "FOR",
    "FORCE",
    "FOREIGN",
    "FROM",
    "FULLTEXT",
    "FUNCTION",
    "GENERATED",
    "GET",
    "GRANT",
    "GROUP",
    "GROUPING",
    "GROUPS",
    "HAVING",
    "HIGH_PRIORITY",
    "HOUR_MICROSECOND",
    "HOUR_MINUTE",
    "HOUR_SECOND",
    "IF",
    "IGNORE",
    "IN",
    "INDEX",
    "INFILE",
    "INNER",
    "INOUT",
    "INSENSITIVE",
    "INSERT",
    "INT",
    "INT1",
    "INT2",
    "INT3",
    "INT4",
    "INT8",
    "INTEGER",
    "INTERSECT",
    "INTERVAL",
    "INTO",
    "IO_AFTER_GTIDS",
    "IO_BEFORE_GTIDS",
    "IS",
    "ITERATE",
    "JOIN",
    "JSON_TABLE",
    "KEY",
    "KEYS",
    "KILL",
    "LAG",
    "LAST_VALUE",
    "LATERAL",
    "LEAD",
    "LEADING",
    "LEAVE",
    "LEFT",
    "LIKE",
    "LIMIT",
    "LINEAR",
    "LINES",
    "LOAD",
    "LOCALTIME",
    "LOCALTIMESTAMP",
    "LOCK",
    "LONG",
    "LONGBLOB",
    "LONGTEXT",
    "LOOP",
    "LOW_PRIORITY",
    "MATCH",
    "MAXVALUE",
    "MEDIUMBLOB",
    "MEDIUMINT",
    "MEDIUMTEXT",
    "MEMBER",
    "MIDDLEINT",
    "MINUTE_MICROSECOND",
    "MINUTE_SECOND",
    "MOD",
    "MODIFIES",
    "NATURAL",
    "NOT",
    "NO_WRITE_TO_BINLOG",
    "NTH_VALUE",
    "NTILE",
    "NULL",
    "NUMERIC",
    "OF",
    "ON",
    "OPTIMIZE",
    "OPTION",
    "OPTIONALLY",
    "OR",
    "ORDER",
    "OUT",
    "OUTER",
    "OUTFILE",
    "OVER",
    "PARTITION",
    "PERCENT_RANK",
    "PRECISION",
    "PRIMARY",
    "PROCEDURE",
    "PURGE",
    "RANGE",
    "RANK",
    "READ",
    "READS",
    "READ_WRITE",
    "REAL",
    "RECURSIVE",
    "REFERENCES",
    "REGEXP",
    "RELEASE",
    "RENAME",
    "REPEAT",
    "REPLACE",
    "REQUIRE",
    "RESIGNAL",
    "RESTRICT",
    "RETURN",
    "REVOKE",
    "RIGHT",
    "RLIKE",
    "ROW",
    "ROWS",
    "ROW_NUMBER",
    "SCHEMA",
    "SCHEMAS",
    "SECOND_MICROSECOND",
    "SELECT",
    "SENSITIVE",
    "SEPARATOR",
    "SET",
    "SHOW",
    "SIGNAL",
    "SMALLINT",
    "SOUNDS",
    "SPATIAL",
    "SPECIFIC",
    "SQL",
    "SQLEXCEPTION",
    "SQLSTATE",
    "SQLWARNING",
    "SQL_BIG_RESULT",
    "SQL_CALC_FOUND_ROWS",
    "SQL_SMALL_RESULT",
    "SSL",
    "STARTING",
    "STORED",
    "STRAIGHT_JOIN",
    "SYSTEM",
    "TABLE",
    "TERMINATED",
    "THEN",
    "TINYBLOB",
    "TINYINT",
    "TINYTEXT",
    "TO",
    "TRAILING",
    "TRIGGER",
    "TRUE",
    "UNDO",
    "UNION",
    "UNIQUE",
    "UNLOCK",
    "UNSIGNED",
    "UPDATE",
    "USAGE",
    "USE",
    "USING",
    "UTC_DATE",
    "UTC_TIME",
    "UTC_TIMESTAMP",
    "VALUES",
    "VARBINARY",
    "VARCHAR",
    "VARCHARACTER",
    "VARYING",
    "VIRTUAL",
    "WHEN",
    "WHERE",
    "WHILE",
    "WINDOW",
    "WITH",
    "WRITE",
    "XOR",
    "YEAR_MONTH",
    "ZEROFILL",
];

/// A word MySQL accepts as an alias without `AS`.
fn is_alias_token(t: &Token) -> bool {
    match t {
        Token::Word(w) if w.quote_style.is_some() => true,
        Token::Word(w) => !RESERVED.iter().any(|r| w.value.eq_ignore_ascii_case(r)),
        _ => false,
    }
}

fn is_limit_arg(t: &Token) -> bool {
    matches!(t, Token::Number(..) | Token::Placeholder(_))
}

/// Aligns `b` (tokens the renderer printed) with `a` (the client's tokens)
/// from `a[i0]`, up to spellings MySQL treats identically: keyword case, an
/// `AS` inserted before an alias, `LIMIT a, b` printed `LIMIT b OFFSET a`,
/// `INNER`/`OUTER` dropped before `JOIN`. `whole` = `a` must be consumed to
/// its end (ignoring trailing `;`). Returns how many tokens of `a` the match
/// covered, or the index in `a` where it failed.
fn align(a: &[Sig], i0: usize, b: &[Token], whole: bool) -> std::result::Result<usize, usize> {
    let trim = |n: usize, at: &dyn Fn(usize) -> bool| {
        let mut n = n;
        while n > 0 && at(n - 1) {
            n -= 1;
        }
        n
    };
    let na = if whole {
        trim(a.len(), &|k| a[k].tok == Token::SemiColon)
    } else {
        a.len()
    };
    let nb = trim(b.len(), &|k| b[k] == Token::SemiColon);
    let (mut i, mut j) = (i0, 0);
    while j < nb || (whole && i < na) {
        if i >= na || j >= nb {
            return Err(i);
        }
        let (x, y) = (&a[i].tok, &b[j]);
        if same(x, y) {
            // `LIMIT a, b` is printed `LIMIT b OFFSET a`.
            if is_word(x, "LIMIT") && i + 3 < na && j + 3 < nb {
                let (a1, a2, a3) = (&a[i + 1].tok, &a[i + 2].tok, &a[i + 3].tok);
                let (b1, b2, b3) = (&b[j + 1], &b[j + 2], &b[j + 3]);
                if is_limit_arg(a1)
                    && *a2 == Token::Comma
                    && is_limit_arg(a3)
                    && is_word(b2, "OFFSET")
                    && same(a1, b3)
                    && same(a3, b1)
                {
                    i += 4;
                    j += 4;
                    continue;
                }
            }
            i += 1;
            j += 1;
        } else if is_word(y, "AS")
            && !is_word(x, "AS")
            && a[i].gap
            && is_alias_token(x)
            && j + 1 < nb
            && same(x, &b[j + 1])
        {
            // An `AS` the renderer inserts before an alias.
            j += 1;
        } else if (is_word(x, "INNER") || is_word(x, "OUTER"))
            && i + 1 < na
            && is_word(&a[i + 1].tok, "JOIN")
            && is_word(y, "JOIN")
        {
            i += 1;
        } else {
            return Err(i);
        }
    }
    Ok(i - i0)
}

/// Whether `b` (a rendering) is token-equivalent to `a` (the client's text).
fn equivalent(a: &[Sig], b: &[Sig]) -> Result<(), String> {
    let b: Vec<Token> = b.iter().map(|s| s.tok.clone()).collect();
    align(a, 0, &b, true).map(|_| ()).map_err(|i| {
        let near = a
            .get(i)
            .map_or_else(|| "the end".to_string(), |s| s.tok.to_string());
        format!("the text differs near `{near}`")
    })
}

/// Prints statements the way they are sent: `; `-separated.
fn print(statements: &[Statement]) -> String {
    statements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// `LIMIT ?2 OFFSET ?1` → `LIMIT ?1, ?2`: the comma form keeps the client's
/// parameter order (the renderer always prints the OFFSET form).
fn limit_comma(text: String) -> String {
    let Ok((toks, offs)) = raw_tokens(&text) else {
        return text;
    };
    let sig: Vec<(usize, &Token, usize)> = toks
        .iter()
        .enumerate()
        .filter(|(_, t)| !matches!(t.token, Token::Whitespace(_)))
        .map(|(k, t)| {
            (
                offs[k],
                &t.token,
                offs.get(k + 1).copied().unwrap_or(text.len()),
            )
        })
        .collect();
    let num = |t: &Token| -> Option<usize> {
        match t {
            Token::Placeholder(p) => p.strip_prefix('?')?.parse().ok(),
            _ => None,
        }
    };
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for w in sig.windows(4) {
        let [(_, l, _), (s1, x, e1), (_, o, _), (s3, y, e3)] = w else {
            continue;
        };
        if is_word(l, "LIMIT") && is_word(o, "OFFSET") {
            if let (Some(nx), Some(ny)) = (num(x), num(y)) {
                if ny < nx {
                    let (xs, ys) = (&text[*s1..*e1], &text[*s3..*e3]);
                    edits.push((*s1, *e3, format!("{ys}, {xs}")));
                }
            }
        }
    }
    let mut out = text.clone();
    for (s, e, r) in edits.into_iter().rev() {
        out.replace_range(s..e, &r);
    }
    out
}

impl Prepared<'_> {
    /// Why a rewrite of this text would not be faithful, checked against the
    /// rendering of the unmodified tree. `original` is that tree.
    pub(crate) fn check_original(&self, original: &[Statement]) -> Result<(), String> {
        if let Some(why) = &self.unfaithful {
            return Err(why.clone());
        }
        let text = limit_comma(print(original));
        let again = read(&text, true).map_err(|e| e.0)?;
        equivalent(&self.sig, &again.sig)
    }

    /// Renders the rewritten statements, checks them (see the module docs) and
    /// returns the SQL to forward, with `?` restored.
    pub(crate) fn render(&self, rewritten: &[Statement]) -> Result<String, String> {
        let text = limit_comma(print(rewritten));
        let again = read(&text, true).map_err(|e| e.0)?;
        if let Some(why) = &again.unfaithful {
            return Err(why.clone());
        }
        if again.statements != rewritten {
            return Err("the rewritten text does not parse back to the rewritten query".into());
        }
        if again.params != self.params {
            return Err(format!(
                "the rewrite has {} bind parameters instead of {}",
                again.params, self.params
            ));
        }
        // Placeholders are `?1 … ?n` in order (checked by `read`); put the
        // client's `?` back.
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for s in &again.sig {
            if let Token::Placeholder(_) = s.tok {
                out.push_str(&text[last..s.start]);
                out.push('?');
                last = s.end;
            }
        }
        out.push_str(&text[last..]);
        Ok(out)
    }

    /// MySQL names an unaliased expression after its own text, as the client
    /// wrote it (`LOWER( email )`). Finds that text: the expression's tokens,
    /// where a select item can start and end. `None` when absent or ambiguous.
    pub(crate) fn verbatim(&self, e: &Expr) -> Option<String> {
        let shown = e.to_string();
        let (toks, _) = raw_tokens(&shown).ok()?;
        let want: Vec<Token> = toks
            .into_iter()
            .map(|t| t.token)
            .filter(|t| !matches!(t, Token::Whitespace(_)))
            .collect();
        if want.is_empty() {
            return None;
        }
        let starts = |t: &Token| {
            *t == Token::Comma
                || is_word(t, "SELECT")
                || is_word(t, "DISTINCT")
                || is_word(t, "ALL")
        };
        let ends = |t: Option<&Token>| match t {
            None | Some(Token::Comma | Token::SemiColon | Token::RParen) => true,
            Some(t) => [
                "FROM",
                "UNION",
                "INTO",
                "WHERE",
                "GROUP",
                "HAVING",
                "ORDER",
                "LIMIT",
                "WINDOW",
                "FOR",
                "EXCEPT",
                "INTERSECT",
                "LOCK",
            ]
            .iter()
            .any(|k| is_word(t, k)),
        };
        let mut found: Option<String> = None;
        for k in 1..self.sig.len() {
            if !starts(&self.sig[k - 1].tok) || !same(&self.sig[k].tok, &want[0]) {
                continue;
            }
            let Ok(n) = align(&self.sig, k, &want, false) else {
                continue;
            };
            if n == 0 || !ends(self.sig.get(k + n).map(|s| &s.tok)) {
                continue;
            }
            let text = self.sql[self.sig[k].start..self.sig[k + n - 1].end].to_string();
            match &found {
                Some(f) if *f != text => return None,
                _ => found = Some(text),
            }
        }
        found
    }
}

/// `?1` … in a rendered fragment back to `?` (for a fallback output name).
pub(crate) fn plain_placeholders(text: &str) -> String {
    let Ok((toks, offs)) = raw_tokens(text) else {
        return text.to_string();
    };
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (k, t) in toks.iter().enumerate() {
        if let Token::Placeholder(p) = &t.token {
            out.push_str(&text[last..offs[k]]);
            out.push('?');
            last = offs[k] + p.len();
        }
    }
    out.push_str(&text[last..]);
    out
}

/// Whether an expression holds a bind parameter.
pub(crate) fn has_param(e: &Expr) -> bool {
    match raw_tokens(&e.to_string()) {
        Ok((toks, _)) => toks
            .iter()
            .any(|t| matches!(t.token, Token::Placeholder(_))),
        // Cannot tell: assume it does (the parameter-keeping form is correct
        // either way).
        Err(_) => true,
    }
}

/// Whether `e` mentions any of `names` as a bare identifier (conservative: a
/// function or a qualified part with the same name also counts).
pub(crate) fn mentions(e: &Expr, names: &[&str]) -> bool {
    match raw_tokens(&e.to_string()) {
        Ok((toks, _)) => toks.iter().any(|t| match &t.token {
            Token::Word(w) => names.iter().any(|n| w.value.eq_ignore_ascii_case(n)),
            _ => false,
        }),
        Err(_) => true,
    }
}

// ── mask expressions ───────────────────────────────────────────────────────

const MASK_ARG: &str = "vericto_mask_arg";

/// The value as text, independent of the column's charset and of the
/// connection's: `CONVERT(… USING utf8mb4)` gives the same characters (and the
/// same UTF-8 bytes to hash) as Postgres's `::text`, and the explicit
/// `COLLATE utf8mb4_bin` makes every comparison inside the mask codepoint-exact
/// (`LOCATE('@', …)` must not match a full-width `＠` the way `_ai_ci`
/// collations do) and gives the result EXPLICIT coercibility, so it can be
/// compared, concatenated or `UNION`ed with a column of any collation without
/// "Illegal mix of collations". `CAST(col AS CHAR)` does raise that error
/// against a non-default collation (measured on 5.7 and 8.0), as does a bare
/// `CONVERT`.
const X: &str = "(CONVERT((vericto_mask_arg) USING utf8mb4) COLLATE utf8mb4_bin)";

static TEMPLATES: std::sync::OnceLock<[Expr; 6]> = std::sync::OnceLock::new();

fn templates() -> &'static [Expr; 6] {
    TEMPLATES.get_or_init(|| {
        let parse = |sql: &str| -> Expr {
            let d = dialect();
            let mut st = Parser::parse_sql(&d, &format!("SELECT {sql}")).expect("mask template parses");
            match st.pop() {
                Some(Statement::Query(q)) => match *q.body {
                    sqlparser::ast::SetExpr::Select(s) => match s.projection.into_iter().next() {
                        Some(sqlparser::ast::SelectItem::UnnamedExpr(e)) => e,
                        _ => unreachable!("template is one expression"),
                    },
                    _ => unreachable!("template is a SELECT"),
                },
                _ => unreachable!("template is a query"),
            }
        };
        [
            parse("'[redacted]'"),
            parse(&format!("CONCAT('****', RIGHT({X}, 4))")),
            // Postgres: regexp_replace(x, '^(.)[^@]*(@.*)?$', '\1***\2').
            // The domain starts at the first `@` AFTER the first character
            // (`(.)` consumes the first one even if it is an `@`); `''` stays
            // `''` (the regex does not match it); NULL stays NULL.
            parse(&format!(
                "CASE WHEN CHAR_LENGTH({X}) = 0 THEN {X} \
                 WHEN LOCATE('@', {X}, 2) > 0 THEN CONCAT(LEFT({X}, 1), '***', SUBSTRING({X}, LOCATE('@', {X}, 2))) \
                 ELSE CONCAT(LEFT({X}, 1), '***') END"
            )),
            parse(&format!("SHA2({X}, 256)")),
            // `full` over an expression holding `?` (see `mask_expr`).
            parse(&format!("CONCAT('[redacted]', COALESCE(LEFT({X}, 0), ''))")),
            parse("COALESCE(vericto_mask_arg)"),
        ]
    })
}

fn splice(e: &mut Expr, orig: &Expr) {
    use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionArguments};
    match e {
        Expr::Identifier(i) if i.value == MASK_ARG => *e = orig.clone(),
        Expr::Nested(x) | Expr::Collate { expr: x, .. } | Expr::Convert { expr: x, .. } => {
            splice(x, orig)
        }
        Expr::BinaryOp { left, right, .. } => {
            splice(left, orig);
            splice(right, orig);
        }
        Expr::Substring {
            expr,
            substring_from,
            substring_for,
            ..
        } => {
            splice(expr, orig);
            for x in [substring_from, substring_for].into_iter().flatten() {
                splice(x, orig);
            }
        }
        Expr::Case {
            operand,
            conditions,
            results,
            else_result,
        } => {
            for x in operand.iter_mut().chain(else_result.iter_mut()) {
                splice(x, orig);
            }
            for x in conditions.iter_mut().chain(results.iter_mut()) {
                splice(x, orig);
            }
        }
        Expr::Function(f) => {
            if let FunctionArguments::List(list) = &mut f.args {
                for a in list.args.iter_mut() {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(x)) = a {
                        splice(x, orig);
                    }
                }
            }
        }
        _ => {}
    }
}

/// The MySQL mask for `style` over `orig` (same outputs as the Postgres forms
/// in [`super::pg`] for the same text).
///
/// `full` over a bare column discards `orig` (nothing of it, not even
/// NULL-ness, reaches the client). Over a computed expression, or one holding
/// `?`, the expression is kept and its value discarded at run time — each `?`
/// must stay in the statement, in order, or the client's bindings shift, and
/// an aggregate must still aggregate: `CONCAT('[redacted]', COALESCE(LEFT(x, 0), ''))` is exactly
/// `'[redacted]'` for any value and for NULL (MySQL's `CONCAT` is NULL if any
/// argument is, hence the `COALESCE`), and every `?` keeps its context, so
/// the server infers the same parameter types. `email` repeats its argument,
/// so over an expression with `?` it falls back to that same `full` form.
pub(crate) fn mask_expr(style: super::MaskStyle, orig: &Expr) -> Expr {
    use super::MaskStyle::*;
    let t = templates();
    let params = has_param(orig);
    // A bare column or a scalar subquery may become a constant; anything else
    // may be an aggregate (`GROUP_CONCAT(email)`), and a constant in its place
    // would turn one aggregated row into one row per input row.
    let plain = matches!(
        orig,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Subquery(_)
    ) || matches!(orig, Expr::Nested(x) if matches!(**x, Expr::Identifier(_) | Expr::CompoundIdentifier(_)));
    let base = match style {
        Full | Email if params => &t[4],
        Full if !plain => &t[4],
        Full => return t[0].clone(),
        Last4 => &t[1],
        Email => &t[2],
        Hash => &t[3],
    };
    let mut out = base.clone();
    splice(&mut out, orig);
    out
}

/// `COALESCE(col)`: still the input column, but no longer a bare name that
/// MySQL resolves to the select-list alias first in `ORDER BY`.
pub(crate) fn coalesce(orig: &Expr) -> Expr {
    let mut out = templates()[5].clone();
    splice(&mut out, orig);
    out
}
