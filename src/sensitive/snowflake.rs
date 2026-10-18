//! Snowflake renderer and mask expressions for VERICTO-085.
//!
//! The rewrite is printed from the sqlparser tree, as on MySQL, and only
//! forwarded when three checks pass ([`render`]):
//! 1. the *unmodified* tree prints to a token stream equal to the client's,
//!    up to spellings Snowflake treats identically (keyword and unquoted
//!    identifier case, an inserted `AS` before an alias). String literals and
//!    quoted identifiers compare **verbatim**;
//! 2. the rewritten text parses back to exactly the rewritten tree;
//! 3. its bind parameters (`?`, `:1`, `:name`) are the client's, in the
//!    client's order.
//!
//! Any failure is a reason string; the verdict turns it into a block. The
//! output column names are kept by aliasing each masked projection with the
//! client's own name (`email` stays `EMAIL`, `"Email"` stays `Email`); an
//! unaliased expression, whose name Snowflake derives from its text, is
//! refused by the walker instead.

use sqlparser::ast::{Expr, Statement};
use sqlparser::dialect::SnowflakeDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

const MASK_ARG: &str = "vericto_mask_arg";

/// The value as text: `TO_VARCHAR` renders numbers, dates and `VARIANT`
/// values (a JSON string without its quotes) as Snowflake displays them.
const X: &str = "TO_VARCHAR(vericto_mask_arg)";

static TEMPLATES: std::sync::OnceLock<[Expr; 6]> = std::sync::OnceLock::new();

fn templates() -> &'static [Expr; 6] {
    TEMPLATES.get_or_init(|| {
        let parse = |sql: &str| -> Expr {
            let mut st = Parser::parse_sql(&SnowflakeDialect {}, &format!("SELECT {sql}"))
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
            // (LENGTH counts characters), else '****' || right(x, 4). NULL
            // stays NULL.
            parse(&format!(
                "CASE WHEN LENGTH({X}) <= {} THEN '[redacted]' \
                 ELSE CONCAT('****', RIGHT({X}, 4)) END",
                super::LAST4_REDACT_MAX_CHARS
            )),
            // The Postgres form is regexp_replace(x, '^(.)[^@]*(@.*)?$',
            // '\1***\2'): the first character, then the domain from the first
            // `@` after it. Written without a regular expression, so neither
            // the string-literal escapes nor `.` and newlines can change what
            // it keeps (a REGEXP_REPLACE that fails to match returns the value
            // unmasked). `''` stays `''`; NULL stays NULL.
            parse(&format!(
                "CASE WHEN LENGTH({X}) = 0 THEN {X} \
                 WHEN CHARINDEX('@', {X}, 2) > 0 THEN CONCAT(LEFT({X}, 1), '***', SUBSTR({X}, CHARINDEX('@', {X}, 2))) \
                 ELSE CONCAT(LEFT({X}, 1), '***') END"
            )),
            parse(&format!("SHA2({X}, 256)")),
            // `full` over a computed expression or one holding a bind
            // parameter: the expression is kept and its value discarded. Snowflake's
            // CONCAT is NULL if an argument is, hence the COALESCE: the
            // result is `'[redacted]'` for every value and for NULL.
            parse(&format!("CONCAT('[redacted]', COALESCE(LEFT({X}, 0), ''))")),
            // `last4` over anything but a bare column: '[redacted]', NULL
            // staying NULL (see `super::mysql::mask_expr`).
            parse(&format!("CONCAT('[redacted]', LEFT({X}, 0))")),
        ]
    })
}

/// The Snowflake mask for `style` over `orig` (same outputs as the Postgres
/// forms for the same text value).
///
/// `full` over a bare column (or a scalar subquery) discards `orig`; over
/// anything else, which may be an aggregate, or with a bind parameter, the
/// expression stays in place (each `?` keeps its position and context) and
/// its value is discarded at run time. `email` repeats its argument, so over
/// an expression with a parameter it falls back to that same `full` form.
/// `last4` repeats it as well, so only a bare column gets its length test;
/// anything else is redacted outright, kept once, NULL staying NULL (the
/// reasons are on [`super::mysql::mask_expr`]).
pub(crate) fn mask_expr(style: super::MaskStyle, orig: &Expr) -> Expr {
    use super::MaskStyle::*;
    let t = templates();
    let params = has_param(orig);
    let plain = matches!(
        orig,
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Subquery(_)
    );
    let base = match style {
        Full | Email if params => &t[4],
        Full if !plain => &t[4],
        Full => return t[0].clone(),
        Last4 if !super::mysql::is_column(orig) => &t[5],
        Last4 => &t[1],
        Email => &t[2],
        Hash => &t[3],
    };
    let mut out = base.clone();
    super::mysql::splice(&mut out, orig);
    debug_assert!(!out.to_string().contains(MASK_ARG));
    out
}

fn tokens(sql: &str) -> Result<Vec<Token>, String> {
    Tokenizer::new(&SnowflakeDialect {}, sql)
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

/// Whether `e` mentions any of `names` as a word (conservative: a function
/// or a qualified part with the same name also counts).
pub(crate) fn mentions(e: &Expr, names: &[&str]) -> bool {
    match tokens(&e.to_string()) {
        Ok(toks) => toks.iter().any(|t| match t {
            Token::Word(w) => names.iter().any(|n| w.value.eq_ignore_ascii_case(n)),
            _ => false,
        }),
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

/// Two tokens Snowflake reads the same: equal, or two unquoted words that
/// differ only in case (keywords, and unquoted names, which fold).
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
            "the Snowflake text cannot be reproduced faithfully ({why}); tag the column block or flag, or simplify the query"
        )
    };
    let client = tokens(sql).map_err(faithful)?;
    let printed = tokens(&print(original)).map_err(faithful)?;
    equivalent(&client, &printed).map_err(faithful)?;
    let text = print(rewritten);
    let mut again = Parser::parse_sql(&SnowflakeDialect {}, &text)
        .map_err(|e| format!("the rewritten text does not parse ({e})"))?;
    // Read `ORDER BY ALL` as the parse did, so a subquery's `ORDER BY ALL`
    // compares equal (temporary, see the function).
    crate::parser::resolve_snowflake_order_by_all(&mut again);
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
