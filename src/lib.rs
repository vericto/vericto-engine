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
//! vericto-engine = { git = "https://github.com/vericto/vericto-engine", tag = "v3.5.1" }
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

pub mod error;
pub mod parser;
pub mod rules;

// Re-export the most commonly used types at the crate root for ergonomics.
pub use error::{ProxyError, Result};
pub use parser::Dialect;
pub use rules::engine::{
    Decision, EnforcementAction, EnforcementPolicy, EvaluationOutcome, ParseErrorAction,
    ReportedViolation, Rule, RuleClass, RuleEngine, RuleType, Severity,
};

/// Convenience function: parse + evaluate in one call.
///
/// On parse error, resolves the decision from `policy.parse_error`
/// (R5.5/R5.6) instead of failing closed unconditionally.
pub fn evaluate(
    sql: &str,
    dialect: Dialect,
    rules: &[Rule],
    policy: &EnforcementPolicy,
) -> EvaluationOutcome {
    let parser = parser::parser_for(dialect);
    match parser.parse(sql) {
        Ok(parsed) => RuleEngine::evaluate(&parsed, rules, policy),
        Err(e) => EvaluationOutcome {
            decision: policy.parse_error_decision(),
            action: Some(match policy.parse_error {
                ParseErrorAction::Block => EnforcementAction::Block,
                ParseErrorAction::AllowReport => EnforcementAction::Flag,
            }),
            // Parse-error telemetry severity is Medium by product decision (R8.6).
            severity: Some(Severity::Medium),
            rule_id: None,
            rule_code: Some("VERICTO-PARSE-ERROR".to_string()),
            ast_node_path: Some(format!("PARSE_ERROR: {e}")),
            estimated_rows_affected: None,
            suggested_safe_query: None,
            // A parse error is not a rule violation: nothing was evaluated, so
            // there is no set to report. The pseudo-code in `rule_code` is
            // telemetry, not a catalogue entry, and putting it here would make
            // `violations` disagree with "every rule this query broke".
            violations: Vec::new(),
        },
    }
}
