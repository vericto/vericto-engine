// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `vericto-engine` — Deterministic SQL AST evaluation engine.
//!
//! This crate is the source-available core of Vericto (FSL-1.1-ALv2): it
//! parses SQL queries into an Abstract Syntax Tree using `pg_query`
//! (PostgreSQL's own parser) and `sqlparser-rs`, then evaluates them against a
//! ruleset deterministically — the same input always produces the same result,
//! with no ML and no thresholds. Every false positive found so far has been
//! fixed with a regression test; `EnforcementPolicy::monitor_mode` reports a
//! would-be block as a flag, to trial a ruleset without blocking.
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! vericto-engine = { git = "https://github.com/vericto/vericto-engine", tag = "v4.5.0" }
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
//!
//! ## The standard ruleset and versions
//!
//! A host with no ruleset of its own (before a first rule sync, after a failed
//! one, or offline) evaluates with [`standard_rules()`]: every built-in rule at
//! its default severity. [`STANDARD_RULES`] is the same table with each rule's
//! class and default action. [`ENGINE_VERSION`] and [`STANDARD_RULESET_VERSION`]
//! (`standard@<engine version>`) say what a verdict was evaluated with.
//!
//! ```rust
//! use vericto_engine::{
//!     evaluate, standard_rules, Decision, Dialect, EnforcementAction, EnforcementPolicy,
//!     ENGINE_VERSION, STANDARD_RULESET_VERSION,
//! };
//!
//! // A CI channel: schema DDL reports instead of blocking.
//! let ci = EnforcementPolicy {
//!     schema_migration_cap: Some(EnforcementAction::Flag),
//!     ..EnforcementPolicy::default()
//! };
//! let sql = "DROP TABLE a; UPDATE accounts SET balance = 0;";
//! let outcome = evaluate(sql, Dialect::Postgres, &standard_rules(), &ci);
//! // The decision is the strongest action of any violation: the UPDATE blocks.
//! assert_eq!(outcome.decision, Decision::Block);
//! assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-030"));
//! assert_eq!(STANDARD_RULESET_VERSION, format!("standard@{ENGINE_VERSION}"));
//! ```

// No `unsafe` in this crate: the only unsafe code it runs is in its parser
// dependencies (libpg_query over FFI in `pg_query`). Forbidding it keeps a
// future change from adding any without an explicit, reviewed opt-out.
#![forbid(unsafe_code)]

pub mod access;
pub mod error;
pub mod parser;
pub mod policy;
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
    ParseErrorKind, ReportedViolation, Rule, RuleClass, RuleEngine, RuleType, Severity,
    TEXT_DIVERGENCE_RULE_CODE,
};
pub use rules::standard::{
    ENGINE_VERSION, STANDARD_RULES, STANDARD_RULESET_VERSION, StandardRule, standard_rules,
};
pub use sensitive::{
    MaskStyle, SENSITIVE_RULE_CODE, SensitiveColumn, SensitivePolicy, TouchedColumn,
};

/// [`evaluate`] with business policies and the declared context (design
/// "Business policy rules" §4.6). `policies` is compiled once from the same
/// rules ([`policy::PolicySet::compile`]); `ctx` is what the host declares
/// about the statement (principal, database, time, ticket, session).
///
/// With an empty `policies` it is exactly `evaluate`. A statement that does
/// not parse resolves as in `evaluate`, except that it is forced to `Block`
/// when an enforced blocking policy may apply to this principal (a statement
/// the engine cannot read cannot be shown to satisfy a business policy);
/// session boilerplate stays exempt. Since 4.4.0.
pub fn evaluate_with_context(
    sql: &str,
    dialect: Dialect,
    rules: &[Rule],
    policy: &EnforcementPolicy,
    policies: &policy::PolicySet,
    ctx: &policy::EvalContext,
) -> EvaluationOutcome {
    if policies.is_empty() {
        return evaluate(sql, dialect, rules, policy);
    }
    let parser = parser::parser_for(dialect);
    match parser.parse(sql) {
        Ok(parsed) => {
            RuleEngine::evaluate_with_context(&parsed, rules, policy, policies, ctx, Some(sql))
        }
        Err(e) => {
            let resolved = policy.effective_parse_error_for(sql, dialect);
            let mut outcome = rules::engine::parse_error_outcome_as(e, resolved);
            if outcome.decision != Decision::Block
                && !access::session::is_session_boilerplate(sql, dialect)
            {
                let forcing = policies.blocks_unreadable(ctx, policy);
                if !forcing.is_empty() {
                    outcome.decision = Decision::Block;
                    outcome.action = Some(EnforcementAction::Block);
                    outcome.policy_hits = forcing;
                }
            }
            outcome
        }
    }
}

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
