//! AST rule engine.
//!
//! - [`engine`]: domain types (Rule, Severity, Decision) and the `RuleEngine`
//!   that orchestrates evaluation.
//! - [`evaluator`]: logic that evaluates each rule (built-in and custom) against
//!   the normalized AST.

pub mod engine;
pub mod evaluator;

/// Property-based tests (P1-P8) and example-based engine unit tests for the
/// severity-based-enforcement feature. Test-only; not compiled into the lib.
#[cfg(test)]
mod properties;
