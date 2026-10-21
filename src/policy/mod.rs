// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Business policies: principal-aware rules over SQL facts, in CEL, inside
//! the custom-rule YAML (design "Business policy rules", Phase 1).
//!
//! A policy combines who runs a statement (the [`Principal`], with the
//! [`Trust`] of the signal that identified it), what the statement does
//! (its facts: tables, columns, operation, the values it assigns and the
//! values its `WHERE` pins) and the declared context (database, time,
//! ticket, session), and resolves to allow / monitor / flag / block /
//! require approval.
//!
//! ```rust
//! use vericto_engine::{
//!     evaluate_with_context, Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule,
//!     RuleType, Severity,
//! };
//! use vericto_engine::policy::{EvalContext, PolicySet, Principal, PrincipalType, Trust};
//!
//! let rule = Rule {
//!     rule_id: "r-refunds".into(),
//!     code: "POL-014".into(),
//!     severity: Severity::High,
//!     default_action: EnforcementAction::Block,
//!     rule_type: RuleType::Custom,
//!     ast_condition_yaml: Some(r#"
//! rule: refund-cap
//! applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [agent] }
//! deny_if: stmt.values("public.refunds.amount").exists(v, double(v) > 200.0)
//! action: block
//! "#.into()),
//! };
//! let rules = vec![rule];
//! // Compiled once (at rule sync), shared by every evaluation.
//! let policies = PolicySet::compile(&rules);
//! assert!(policies.errors().is_empty());
//! let ctx = EvalContext::new()
//!     .with_principal(Principal::new("agent-support-bot", PrincipalType::Agent, Trust::Medium));
//! let policy = EnforcementPolicy::default();
//!
//! let small = "INSERT INTO refunds (order_id, amount) VALUES (1, 150)";
//! let large = "INSERT INTO refunds (order_id, amount) VALUES (1, 950)";
//! let ok = evaluate_with_context(small, Dialect::Postgres, &rules, &policy, &policies, &ctx);
//! let no = evaluate_with_context(large, Dialect::Postgres, &rules, &policy, &policies, &ctx);
//! assert_eq!(ok.decision, Decision::Allow);
//! assert_eq!(no.decision, Decision::Block);
//! assert_eq!(no.rule_code.as_deref(), Some("POL-014"));
//! ```
//!
//! **Deterministic.** Evaluation is a pure function of the statement, the
//! rules and the declared context: the engine reads no clock (the host
//! passes `time.*`), no counter and no network.
//!
//! **Conservative.** A fact that cannot be known is UNKNOWN, and the
//! policy's `on_unknown` decides (block by default for blocking policies);
//! a policy that does not compile fails closed in its scope; a statement
//! the engine cannot read blocks when an enforced blocking policy may apply.

pub(crate) mod cel;
pub mod check;
pub mod context;
pub(crate) mod facts;
pub use facts::{StatementFacts, statement_facts};
pub mod set;
pub mod spec;

pub use check::{CheckReport, FixtureResult, ModeDecidability, check_policy, run_policy_tests};
pub use context::{
    DbContext, EvalContext, HostMode, Principal, PrincipalType, SessionContext, Ticket,
    TimeContext, Trust,
};
pub use set::{
    ApprovalRequirement, ApprovalSpec, PolicyError, PolicyHit, PolicyOutcome, PolicySet,
    UnknownField,
};
pub use spec::{Issue, POLICY_KEYS, PolicyAction, is_policy_document};
