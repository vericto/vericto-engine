//! SQLite renderer and mask expressions for VERICTO-085.
//!
//! As on Snowflake, the rewrite is printed from the sqlparser tree and only
//! forwarded when the checks of [`render`] pass:
//! 1. the client's text holds no double-quoted name. SQLite reads `"x"` as a
//!    string literal when no column `x` is in scope (its double-quoted-string
//!    fallback, "DQS"), which the engine, having no schema, cannot rule out:
//!    the rewrite could then mask, or fail to mask, the wrong thing. Such a
//!    statement is not rewritten (it blocks); `[x]` and `` `x` `` are always
//!    names and are fine;
//! 2. the *unmodified* tree prints to a token stream equal to the client's, up
//!    to spellings SQLite treats identically (keyword and unquoted identifier
//!    case, an inserted `AS` before an alias). String literals and quoted
//!    identifiers compare **verbatim**;
//! 3. the rewritten text parses back to exactly the rewritten tree;
//! 4. its bind parameters (`?`, `?NNN`, `:name`, `@name`, `$name`) are the
//!    client's, in the client's order.
//!
//! Any failure is a reason string; the verdict turns it into a block. The
//! output column names are kept by aliasing each masked projection with the
//! client's own name; an unaliased expression, whose name SQLite derives from
//! its text, is refused by the walker instead.
//!
//! The `hash` style has no SQLite form: core SQLite has no SHA-256 (it is a
//! loadable extension), so a `hash` mask blocks on SQLite (design open
//! question Q7, resolved the conservative way). `full`, `last4` and `email`
//! are written with core functions only (`substr`, `instr`, `length`, `||`),
//! and give the same outputs as the Postgres forms for the same text value.

use sqlparser::ast::{Expr, Statement};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use super::MaskStyle;

const MASK_ARG: &str = "vericto_mask_arg";

/// The value as text, as SQLite displays it.
const X: &str = "CAST(vericto_mask_arg AS TEXT)";

/// Why a `hash` mask is refused on SQLite.
pub(crate) const NO_HASH: &str = "the hash mask needs SHA-256, which core SQLite does not have; tag the column block, or mask it full, last4 or email";

static TEMPLATES: std::sync::OnceLock<[Expr; 5]> = std::sync::OnceLock::new();

fn templates() -> &'static [Expr; 5] {
    TEMPLATES.get_or_init(|| {
        let parse = |sql: &str| -> Expr {
            let mut st = Parser::parse_sql(&SQLiteDialect {}, &format!("SELECT {sql}"))
                .expect("mask template parses");
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
            // Postgres: '[redacted]' up to LAST4_REDACT_MAX_CHARS characters
            // (`length` of text counts characters), else the last four:
            // `substr(x, -4)` is Postgres `right(x, 4)`. NULL stays NULL.
            parse(&format!(
                "CASE WHEN length({X}) <= {} THEN '[redacted]' ELSE '****' || substr({X}, -4) END",
                super::LAST4_REDACT_MAX_CHARS
            )),
            // The first character, then the domain from the first `@` after
            // it; `''` stays `''`, NULL stays NULL. `instr` over the text from
            // the second character: the position in `x` is one more.
            parse(&format!(
                "CASE WHEN length({X}) = 0 THEN {X} \
                 WHEN instr(substr({X}, 2), '@') > 0 THEN substr({X}, 1, 1) || '***' || substr({X}, instr(substr({X}, 2), '@') + 1) \
                 ELSE substr({X}, 1, 1) || '***' END"
            )),
            // `full` over a computed expression or one holding a bind
            // parameter: the expression is kept (each `?` keeps its position)
            // and its value discarded. `||` is NULL if an operand is, hence
            // the coalesce: `'[redacted]'` for every value and for NULL.
            parse(&format!("'[redacted]' || coalesce(substr({X}, 1, 0), '')")),
            // `last4` over anything but a bare column: '[redacted]', NULL
            // staying NULL (see `super::mysql::mask_expr`).
            parse(&format!("'[redacted]' || substr({X}, 1, 0)")),
        ]
    })
}

/// The SQLite mask for `style` over `orig`. `Err` for `hash` ([`NO_HASH`]).
///
/// `full` over a bare column (or a scalar subquery) discards `orig`; over
/// anything else, or with a bind parameter, the expression stays in place
/// and its value is discarded at run time. `email` repeats its argument, so
/// over an expression with a parameter it falls back to that same `full`
/// form. `last4` repeats it as well, so only a bare column gets its length
/// test; anything else is redacted outright, kept once, NULL staying NULL (the
/// reasons are on [`super::mysql::mask_expr`]).
pub(crate) fn mask_expr(style: MaskStyle, orig: &Expr) -> Result<Expr, String> {
    use MaskStyle::*;
    let t = templates();
    let params = has_param(orig);
    let plain = matches!(
        orig,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Subquery(_)
    );
    let base = match style {
        Hash => return Err(NO_HASH.to_string()),
        Full | Email if params => &t[3],
        Full if !plain => &t[3],
        Full => return Ok(t[0].clone()),
        Last4 if !super::mysql::is_column(orig) => &t[4],
        Last4 => &t[1],
        Email => &t[2],
    };
    let mut out = base.clone();
    super::mysql::splice(&mut out, orig);
    debug_assert!(!out.to_string().contains(MASK_ARG));
    Ok(out)
}

fn tokens(sql: &str) -> Result<Vec<Token>, String> {
    Tokenizer::new(&SQLiteDialect {}, sql)
        .with_unescape(false)
        .tokenize()
        .map(|toks| {
            toks.into_iter()
                .filter(|t| !matches!(t, Token::Whitespace(_)))
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// Whether an expression holds a bind parameter.
fn has_param(e: &Expr) -> bool {
    match tokens(&e.to_string()) {
        Ok(toks) => toks.iter().any(|t| matches!(t, Token::Placeholder(_))),
        // Cannot tell: assume it does (the parameter-keeping form is correct
        // either way).
        Err(_) => true,
    }
}

/// Prints statements the way they are sent: `; `-separated.
fn print(statements: &[Statement]) -> String {
    statements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Two tokens SQLite reads the same: equal, or two unquoted words that
/// differ only in case (keywords, and unquoted names, which SQLite compares
/// case-insensitively).
fn same(a: &Token, b: &Token) -> bool {
    match (a, b) {
        (Token::Word(x), Token::Word(y)) if x.quote_style.is_none() && y.quote_style.is_none() => {
            x.value.eq_ignore_ascii_case(&y.value)
        }
        _ => a == b,
    }
}

fn is_as(t: &Token) -> bool {
    matches!(t, Token::Word(w) if w.quote_style.is_none() && w.value.eq_ignore_ascii_case("AS"))
}

/// The client's tokens and the printed ones are the same statement: equal
/// token for token, except an `AS` the printer inserted before an alias.
fn equivalent(client: &[Token], printed: &[Token]) -> Result<(), String> {
    let (mut i, mut j) = (0, 0);
    while i < client.len() || j < printed.len() {
        match (client.get(i), printed.get(j)) {
            (Some(a), Some(b)) if same(a, b) => {
                i += 1;
                j += 1;
            }
            (_, Some(b)) if is_as(b) => j += 1,
            // A trailing `;` the printer drops.
            (Some(Token::SemiColon), None) if i + 1 == client.len() => i += 1,
            (a, _) => {
                return Err(format!(
                    "the text differs near `{}`",
                    a.map_or_else(|| "the end".to_string(), ToString::to_string)
                ));
            }
        }
    }
    Ok(())
}

fn placeholders(toks: &[Token]) -> Vec<&str> {
    toks.iter()
        .filter_map(|t| match t {
            Token::Placeholder(p) => Some(p.as_str()),
            _ => None,
        })
        .collect()
}

/// Renders the rewritten statements, checks them (see the module docs) and
/// returns the SQL to forward. `original` is the unmodified tree, `sql` the
/// client's text.
pub(crate) fn render(
    sql: &str,
    original: &[Statement],
    rewritten: &[Statement],
) -> Result<String, String> {
    let faithful = |why: String| {
        format!(
            "the SQLite text cannot be reproduced faithfully ({why}); tag the column block or flag, or simplify the query"
        )
    };
    let client = tokens(sql).map_err(faithful)?;
    if let Some(name) = client.iter().find_map(|t| match t {
        Token::Word(w) if w.quote_style == Some('"') => Some(w.value.clone()),
        _ => None,
    }) {
        return Err(format!(
            "the statement holds the double-quoted name \"{name}\", which SQLite reads as a string when no column has that name; write names unquoted, or as [name] or `name`, to mask"
        ));
    }
    let printed = tokens(&print(original)).map_err(faithful)?;
    equivalent(&client, &printed).map_err(faithful)?;
    let text = print(rewritten);
    let again = Parser::parse_sql(&SQLiteDialect {}, &text)
        .map_err(|e| format!("the rewritten text does not parse ({e})"))?;
    if again != rewritten {
        return Err("the rewritten text does not parse back to the rewritten query".into());
    }
    let out = tokens(&text).map_err(faithful)?;
    if placeholders(&out) != placeholders(&client) {
        return Err(format!(
            "the rewrite changes the bind parameters ({} instead of {})",
            placeholders(&out).join(", "),
            placeholders(&client).join(", ")
        ));
    }
    Ok(text)
}
