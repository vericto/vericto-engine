//! `vetro-engine` — Deterministic SQL AST evaluation engine.
//!
//! This crate is the open-core of Vetro: it parses SQL queries into an Abstract
//! Syntax Tree using `pg_query` (PostgreSQL's own parser) and `sqlparser-rs`,
//! then evaluates them against a ruleset deterministically — same input always
//! produces the same result, no ML, no thresholds, no false positives.
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! vetro-engine = { git = "https://github.com/donkan168/vetro-engine", tag = "v1.0.0" }
//! ```
//!
//! ```rust
//! use vetro_engine::{evaluate, Rule, RuleType, Severity, Dialect};
//!
//! let rules = vec![Rule {
//!     rule_id: "r1".into(),
//!     code: "VETRO-001".into(),
//!     severity: Severity::Critical,
//!     rule_type: RuleType::Standard,
//!     ast_condition_yaml: None,
//! }];
//!
//! let result = evaluate("DELETE FROM users", Dialect::Postgres, &rules);
//! assert!(result.decision == vetro_engine::Decision::Blocked);
//! ```

pub mod error;
pub mod parser;
pub mod rules;

// Re-export the most commonly used types at the crate root for ergonomics.
pub use error::{ProxyError, Result};
pub use parser::Dialect;
pub use rules::engine::{Decision, EvaluationOutcome, Rule, RuleEngine, RuleType, Severity};

/// Convenience function: parse + evaluate in one call.
pub fn evaluate(sql: &str, dialect: Dialect, rules: &[Rule]) -> EvaluationOutcome {
    let parser = parser::parser_for(dialect);
    match parser.parse(sql) {
        Ok(parsed) => RuleEngine::evaluate(&parsed, rules),
        Err(e) => EvaluationOutcome {
            decision: Decision::Blocked,
            rule_id: None,
            rule_code: Some("VETRO-PARSE-ERROR".to_string()),
            severity: Some(Severity::Critical),
            ast_node_path: Some(format!("PARSE_ERROR: {e}")),
            estimated_rows_affected: None,
            suggested_safe_query: None,
        },
    }
}
