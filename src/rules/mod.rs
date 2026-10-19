// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! AST rule engine.
//!
//! - [`engine`]: domain types (Rule, Severity, Decision) and the `RuleEngine`
//!   that orchestrates evaluation.
//! - [`evaluator`]: logic that evaluates each rule (built-in and custom) against
//!   the normalized AST.
//! - [`standard`]: the standard ruleset (every built-in rule at its default)
//!   and the engine and ruleset version strings.

pub mod engine;
pub mod evaluator;
pub mod standard;

/// Property-based tests (P1-P8) and example-based engine unit tests for the
/// severity-based-enforcement feature. Test-only; not compiled into the lib.
#[cfg(test)]
mod properties;
