//! `vericto-engine` — Deterministic SQL AST evaluation engine.
//!
//! This crate is the open-core of Vericto: it parses SQL queries into an Abstract
//! Syntax Tree using `pg_query` (PostgreSQL's own parser) and `sqlparser-rs`,
//! then evaluates them against a ruleset deterministically — same input always
//! produces the same result, no ML, no thresholds, no false positives.
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! vericto-engine = { git = "https://github.com/vericto/vericto-engine", tag = "v3.8.1" }
//! ```
//!
//! ```rust
//! use vericto_engine::{
//!     evaluate, Decision, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, Dialect,
//! };
//!
//! let rules = vec![Rule {
//!     rule_id: "r1".into(),
//!     code: "VERICTO-001".into(),
//!     severity: Severity::Critical,
//!     default_action: EnforcementAction::Block,
//!     rule_type: RuleType::Standard,
//!     ast_condition_yaml: None,
//! }];
//!
//! // The host injects the workspace enforcement policy; `default()` maps
//! // Critical/High → BLOCK, Medium → FLAG, Low/Informational → MONITOR.
//! let policy = EnforcementPolicy::default();
//! let result = evaluate("DELETE FROM users", Dialect::Postgres, &rules, &policy);
//! assert!(result.decision == Decision::Block);
//! ```

pub mod access;
pub mod error;
pub mod parser;
pub mod rules;
pub mod sensitive;

// Re-export the most commonly used types at the crate root for ergonomics.
pub use access::{
    ACCESS_RULE_CODE, AccessColumns, AccessEntry, AccessLevel, AccessMode, AccessPolicy,
    AccessPolicyMap, DdlPolicy, DeniedRef, Needed,
};
pub use error::{ProxyError, Result};
pub use parser::Dialect;
pub use rules::engine::{
    Decision, EnforcementAction, EnforcementPolicy, EvaluationOutcome, ParseErrorAction,
    ReportedViolation, Rule, RuleClass, RuleEngine, RuleType, Severity, TEXT_DIVERGENCE_RULE_CODE,
};
pub use sensitive::{
    MaskStyle, SENSITIVE_RULE_CODE, SensitiveColumn, SensitivePolicy, TouchedColumn,
};

/// Convenience function: parse + evaluate in one call.
///
/// On parse error, resolves the decision from `policy.parse_error`
/// (R5.5/R5.6) instead of failing closed unconditionally — except that a
/// `block`/`mask` sensitive column, or an enforced agent allowlist (except for
/// session boilerplate), forces `Block`
/// ([`EnforcementPolicy::effective_parse_error_for`]).
pub fn evaluate(
    sql: &str,
    dialect: Dialect,
    rules: &[Rule],
    policy: &EnforcementPolicy,
) -> EvaluationOutcome {
    let parser = parser::parser_for(dialect);
    match parser.parse(sql) {
        Ok(parsed) => RuleEngine::evaluate(&parsed, rules, policy),
        Err(e) => {
            rules::engine::parse_error_outcome_as(e, policy.effective_parse_error_for(sql, dialect))
        }
    }
}
