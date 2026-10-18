// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The standard ruleset: every built-in rule at its default severity.
//!
//! Hosts need it when they have no ruleset of their own to pass: the proxy
//! before its first rule sync and whenever a sync fails, and a CLI checking
//! files offline. Before 4.2.0 each host kept its own copy of this table; this
//! one is the engine's, and `tests/rule_catalogue_sync.rs` keeps it equal to
//! the README catalogue and to the evaluator's match arms.

use crate::rules::engine::{EnforcementAction, Rule, RuleClass, RuleType, Severity};

/// The version of this crate, from `Cargo.toml` (`"4.2.0"`). Hosts print it
/// with their verdicts so a result can be traced to the engine that produced
/// it.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Identifies [`STANDARD_RULES`] and the predicates behind them:
/// `standard@<engine version>` (`"standard@4.2.0"`). A built-in rule's
/// predicate lives in the engine, so what the standard ruleset detects is a
/// function of the engine version, and so is its version string.
pub const STANDARD_RULESET_VERSION: &str = concat!("standard@", env!("CARGO_PKG_VERSION"));

/// One built-in rule at its default: its canonical code, severity and class,
/// and the action [`EnforcementPolicy::default`](crate::EnforcementPolicy) resolves
/// that severity to. `#[non_exhaustive]`: read it, the engine builds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StandardRule {
    pub code: &'static str,
    pub severity: Severity,
    /// The action the default policy maps `severity` to (Critical/High →
    /// Block, Medium → Flag, Low/Informational → Monitor). Informational, as
    /// [`Rule::default_action`] is: at evaluation time the action always comes
    /// from the host's policy.
    pub default_action: EnforcementAction,
    /// Equal to [`RuleClass::for_code`] of `code`.
    pub class: RuleClass,
    /// Driven by the [`EnforcementPolicy`](crate::EnforcementPolicy) rather than by
    /// the `rules` slice: VERICTO-085 (sensitive columns), VERICTO-086 (MySQL
    /// text divergence) and VERICTO-087 (agent allowlists). They are listed so
    /// the catalogue is whole; passing them in `rules` neither enables nor
    /// disables them.
    pub engine_driven: bool,
}

impl StandardRule {
    /// The rule as [`crate::evaluate`] takes it: `rule_id` is the code,
    /// [`RuleType::Standard`], no YAML condition.
    pub fn to_rule(&self) -> Rule {
        Rule {
            rule_id: self.code.to_string(),
            code: self.code.to_string(),
            severity: self.severity,
            default_action: self.default_action,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        }
    }
}

/// The default policy's action for a severity (Critical/High → Block, Medium →
/// Flag, Low → Monitor), spelled out for the table below; a unit test checks it
/// against `EnforcementPolicy::default()`. Macros rather than `const fn`s: the
/// table is data, built at compile time, with no code of its own to run.
macro_rules! default_action {
    (Critical) => {
        EnforcementAction::Block
    };
    (High) => {
        EnforcementAction::Block
    };
    (Medium) => {
        EnforcementAction::Flag
    };
    (Low) => {
        EnforcementAction::Monitor
    };
}

macro_rules! standard_rule {
    ($code:literal, $severity:ident, $class:ident, $engine_driven:literal) => {
        StandardRule {
            code: $code,
            severity: $severity,
            default_action: default_action!($severity),
            class: $class,
            engine_driven: $engine_driven,
        }
    };
}

/// A rule the `rules` slice enables.
macro_rules! std_rule {
    ($code:literal, $severity:ident, $class:ident) => {
        standard_rule!($code, $severity, $class, false)
    };
}

/// A rule the policy drives (VERICTO-085, 086, 087).
macro_rules! engine_driven {
    ($code:literal, $severity:ident, $class:ident) => {
        standard_rule!($code, $severity, $class, true)
    };
}

use RuleClass::{DataMutation, Performance, SchemaMigration, Security};
use Severity::{Critical, High, Low, Medium};

/// Every built-in rule (42), by code ascending, at its default severity. The
/// same set and severities as the README's "Standard rules" table.
pub const STANDARD_RULES: &[StandardRule] = &[
    std_rule!("VERICTO-001", Critical, DataMutation), // DELETE without WHERE
    std_rule!("VERICTO-002", High, DataMutation),     // DELETE with LIMIT 0
    std_rule!("VERICTO-003", Critical, DataMutation), // DELETE with always-true WHERE
    std_rule!("VERICTO-010", Critical, SchemaMigration), // DROP TABLE / DATABASE
    std_rule!("VERICTO-011", Critical, SchemaMigration), // TRUNCATE TABLE
    std_rule!("VERICTO-012", Critical, SchemaMigration), // DROP SCHEMA
    std_rule!("VERICTO-013", High, SchemaMigration),  // DROP INDEX without IF EXISTS
    std_rule!("VERICTO-015", High, SchemaMigration),  // ALTER TABLE DROP COLUMN
    std_rule!("VERICTO-016", High, SchemaMigration),  // ALTER TABLE RENAME
    std_rule!("VERICTO-017", High, SchemaMigration),  // ALTER TABLE DROP CONSTRAINT
    std_rule!("VERICTO-018", High, SchemaMigration),  // ALTER TABLE ALTER COLUMN TYPE
    std_rule!("VERICTO-019", High, SchemaMigration),  // DISABLE TRIGGER / RLS
    std_rule!("VERICTO-030", Critical, DataMutation), // UPDATE without WHERE (primary tables)
    std_rule!("VERICTO-031", High, DataMutation),     // UPDATE in CTE without WHERE
    std_rule!("VERICTO-033", High, DataMutation),     // DELETE in subquery/CTE without WHERE
    std_rule!("VERICTO-040", High, DataMutation),     // INSERT INTO … SELECT without filter
    std_rule!("VERICTO-042", Critical, DataMutation), // UPDATE without WHERE
    std_rule!("VERICTO-050", Medium, Performance),    // SELECT without LIMIT
    std_rule!("VERICTO-051", Medium, Performance),    // SELECT * without WHERE
    std_rule!("VERICTO-060", Low, Performance),       // INSERT without explicit columns
    std_rule!("VERICTO-061", Medium, Performance),    // INSERT batch > 10k rows
    std_rule!("VERICTO-070", High, Security),         // SLEEP() / PG_SLEEP()
    std_rule!("VERICTO-080", Critical, Security),     // COPY … TO/FROM PROGRAM
    std_rule!("VERICTO-081", Critical, Security),     // DO anonymous code block
    std_rule!("VERICTO-082", High, Security),         // GRANT / REVOKE
    std_rule!("VERICTO-083", High, DataMutation),     // MERGE
    std_rule!("VERICTO-084", High, DataMutation),     // CREATE TABLE AS SELECT
    engine_driven!("VERICTO-085", High, Security),    // Read of a sensitive column
    engine_driven!("VERICTO-086", Critical, Security), // MySQL text divergence
    engine_driven!("VERICTO-087", High, Security),    // Access outside the allowlist
    std_rule!("VERICTO-090", Critical, Security),     // OR tautology in WHERE
    std_rule!("VERICTO-091", Critical, Security),     // Stage unload or file transfer
    std_rule!("VERICTO-092", Critical, Security),     // External stage or integration
    std_rule!("VERICTO-093", Critical, Security),     // Share to another account
    std_rule!("VERICTO-094", High, SchemaMigration),  // Recovery reduced
    std_rule!("VERICTO-095", High, Performance),      // Warehouse cost
    std_rule!("VERICTO-096", High, Security),         // Code that runs later
    std_rule!("VERICTO-097", High, Security),         // Role switch
    std_rule!("VERICTO-098", High, Security),         // SQLite ATTACH DATABASE
    std_rule!("VERICTO-099", High, SchemaMigration),  // SQLite safety PRAGMA
    std_rule!("VERICTO-100", Critical, Security),     // SQLite extension loading / file functions
    std_rule!("VERICTO-101", High, Security),         // SQLite VACUUM INTO
];

/// [`STANDARD_RULES`] as a ruleset ready for [`crate::evaluate`], in the same
/// order. What a host evaluates with when it has no ruleset of its own.
pub fn standard_rules() -> Vec<Rule> {
    STANDARD_RULES.iter().map(StandardRule::to_rule).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::engine::EnforcementPolicy;

    #[test]
    fn the_catalogue_is_sorted_and_unique() {
        assert_eq!(STANDARD_RULES.len(), 42);
        for pair in STANDARD_RULES.windows(2) {
            assert!(
                pair[0].code < pair[1].code,
                "{} then {}",
                pair[0].code,
                pair[1].code
            );
        }
    }

    #[test]
    fn class_and_action_are_the_engines() {
        let policy = EnforcementPolicy::default();
        for r in STANDARD_RULES {
            assert_eq!(r.class, RuleClass::for_code(r.code), "{}", r.code);
            assert_eq!(
                r.default_action,
                policy.action_for(r.severity),
                "{}",
                r.code
            );
            assert_eq!(
                r.engine_driven,
                matches!(r.code, "VERICTO-085" | "VERICTO-086" | "VERICTO-087"),
                "{}",
                r.code
            );
        }
    }

    #[test]
    fn standard_rules_is_the_table_as_rules() {
        let rules = standard_rules();
        assert_eq!(rules.len(), STANDARD_RULES.len());
        for (rule, std) in rules.iter().zip(STANDARD_RULES) {
            assert_eq!(rule.rule_id, std.code);
            assert_eq!(rule.code, std.code);
            assert_eq!(rule.severity, std.severity);
            assert_eq!(rule.default_action, std.default_action);
            assert_eq!(rule.rule_type, RuleType::Standard);
            assert!(rule.ast_condition_yaml.is_none());
        }
    }

    #[test]
    fn versions_follow_the_manifest() {
        assert_eq!(ENGINE_VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            STANDARD_RULESET_VERSION,
            format!("standard@{ENGINE_VERSION}")
        );
    }
}
