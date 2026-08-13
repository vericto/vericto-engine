//! Vericto proxy error types.
//!
//! `ProxyError` covers failures in the AST evaluation path. Parse errors get
//! special treatment: a query that does not parse is reported as
//! `PARSE_ERROR`, and whether it is forwarded or rejected is the host's
//! policy decision, not this crate's — see
//! [`EnforcementPolicy::parse_error`](crate::EnforcementPolicy::parse_error).
//! The default is [`ParseErrorAction::AllowReport`](crate::ParseErrorAction)
//! (fail-open: forward + report, R4.8); [`ParseErrorAction::Block`] is the
//! fail-closed opt-in (R4.9).

use thiserror::Error;

/// Recommended maximum query size in bytes (64KB).
///
/// **This crate does not enforce it, and hosts are expected to diverge.** Neither
/// [`crate::evaluate`] nor [`SqlParser::parse`](crate::parser::SqlParser::parse)
/// checks the input length. The host is the layer that can reject an oversized
/// query before deserializing or copying it, and it is also the only layer that
/// knows what its traffic looks like — so this is a starting point, not a value
/// every host should share.
///
/// The two first-party hosts already differ, for reasons particular to each:
///
/// - the HTTP evaluation sidecar applies this value, and derives its request body
///   limit from it. It is multi-tenant and serves one query per request from
///   dashboards and CI, so a small ceiling costs nothing and a large one would
///   mean buffering that much for every tenant;
/// - the TCP proxy applies a much larger limit (10 MiB by default, operator
///   configurable). It carries a customer's production traffic, where batch
///   inserts and long `IN` lists legitimately reach megabytes, and it is inline —
///   refusing a statement is an outage for that workload, not a warning.
///
/// A host raising the limit is taking on the cost knowingly: evaluation time grows
/// linearly with input size, so the ceiling is also a latency budget.
///
/// A host that skips the check hands unbounded input to the parsers. Parse cost
/// grows with input size and [`MAX_AST_DEPTH`] does not bound it — that guard
/// limits nesting *depth*, not breadth, so a wide statement (for example an
/// `INSERT` with hundreds of thousands of value tuples) stays shallow while
/// taking time proportional to its size.
///
/// Enforce it on the way in, and pair it with [`ProxyError::QueryTooLarge`]:
///
/// ```rust
/// use vericto_engine::error::{MAX_QUERY_SIZE_BYTES, ProxyError};
///
/// fn guard(sql: &str) -> Result<(), ProxyError> {
///     if sql.len() > MAX_QUERY_SIZE_BYTES {
///         return Err(ProxyError::QueryTooLarge);
///     }
///     Ok(())
/// }
///
/// assert!(guard("SELECT 1").is_ok());
/// ```
pub const MAX_QUERY_SIZE_BYTES: usize = 64 * 1024;

/// Maximum AST depth that is walked (50 levels).
pub const MAX_AST_DEPTH: usize = 50;

/// Maximum nesting a statement's *text* may show before it is refused unparsed.
///
/// This is not the same guard as [`MAX_AST_DEPTH`], and it exists for a reason
/// that guard cannot cover: `MAX_AST_DEPTH` is enforced while walking a tree that
/// has already been built, but the recursive descent that BUILDS the tree runs
/// inside `pg_query`/`sqlparser` first. Deeply nested input overflows the stack in
/// there, before any Vericto code sees a node.
///
/// A stack overflow is not a catchable error in Rust — it is not a panic, so
/// `catch_unwind` does not see it, and the process aborts. Both consumers compile
/// with `panic = "abort"` anyway. So a single statement of roughly 950 nested
/// `NOT`s (about 4 KB of SQL, well under [`MAX_QUERY_SIZE_BYTES`]) is enough to
/// kill an eval sidecar or a proxy worker outright: a denial of service that costs
/// the sender one request.
///
/// Refusing such input up front is therefore the only available defence. The limit
/// is deliberately far above anything a real query or ORM produces — measured
/// overflow starts between 920 and 950 levels, and 200 leaves an order of
/// magnitude of headroom while still stopping the attack well short of the stack.
pub const MAX_NESTING_DEPTH: usize = 200;

/// Rejects statements whose textual nesting exceeds [`MAX_NESTING_DEPTH`].
///
/// Counts the two constructs that drive recursive descent — parenthesis depth and
/// consecutive prefix operators such as `NOT` — and takes the larger. It runs on
/// raw text on purpose: the point is to decide *before* handing the string to a
/// parser that would recurse on it.
///
/// This is a coarse bound, not a parse. It ignores parentheses inside string
/// literals, which can only make the count too high, never too low; at a limit of
/// 200 versus real queries that nest a handful of levels, that imprecision costs
/// nothing. Call it at the top of every dialect's `parse`.
///
/// ```rust
/// use vericto_engine::error::{ProxyError, guard_nesting_depth};
///
/// assert!(guard_nesting_depth("SELECT 1 WHERE NOT NOT TRUE").is_ok());
///
/// let bomb = format!("SELECT 1 WHERE {}TRUE", "NOT ".repeat(950));
/// assert!(matches!(guard_nesting_depth(&bomb), Err(ProxyError::AstTooDeep)));
/// ```
pub fn guard_nesting_depth(sql: &str) -> std::result::Result<(), ProxyError> {
    let mut paren = 0usize;
    let mut max_paren = 0usize;
    for b in sql.bytes() {
        match b {
            b'(' => {
                paren += 1;
                if paren > max_paren {
                    max_paren = paren;
                    if max_paren > MAX_NESTING_DEPTH {
                        return Err(ProxyError::AstTooDeep);
                    }
                }
            }
            b')' => paren = paren.saturating_sub(1),
            _ => {}
        }
    }

    // Chained prefix operators nest without a single parenthesis: `NOT NOT NOT …`
    // builds one BoolExpr per keyword. Counted case-insensitively on word
    // boundaries so `not_deleted` or a column named `notes` is not mistaken for the
    // operator.
    let mut run = 0usize;
    for word in sql.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        if word.eq_ignore_ascii_case("not") {
            run += 1;
            if run > MAX_NESTING_DEPTH {
                return Err(ProxyError::AstTooDeep);
            }
        } else if !word.is_empty() {
            run = 0;
        }
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum ProxyError {
    /// The SQL query has invalid or malformed syntax.
    /// Client-facing code: `VERICTO-PARSE-ERROR`.
    #[error("VERICTO-PARSE-ERROR: {0}")]
    ParseError(String),

    /// The query exceeds the maximum allowed size (64KB).
    #[error("VERICTO-QUERY-TOO-LARGE: query exceeds the {MAX_QUERY_SIZE_BYTES} byte limit")]
    QueryTooLarge,

    /// The AST exceeds the maximum nesting depth (50 levels).
    /// Possible evasion attempt via excessive nesting.
    #[error("VERICTO-AST-TOO-DEEP: AST exceeds the maximum depth of {MAX_AST_DEPTH} levels")]
    AstTooDeep,

    /// Unsupported dialect.
    #[error("VERICTO-UNSUPPORTED-DIALECT: dialect '{0}' is not supported")]
    UnsupportedDialect(String),

    /// A custom YAML rule is malformed.
    #[error("VERICTO-INVALID-RULE: invalid custom rule: {0}")]
    InvalidCustomRule(String),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
