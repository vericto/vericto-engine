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
