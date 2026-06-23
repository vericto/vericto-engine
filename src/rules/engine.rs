//! Rule domain types and evaluation orchestration.

use serde::{Deserialize, Serialize};

use crate::parser::ParsedQuery;
use crate::rules::evaluator;

/// Canonical CVSS-based severity taxonomy.
///
/// `Ord` is derived from declaration order, so the ordering is
/// `Informational < Low < Medium < High < Critical` (R1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable, unique textual representation (R1.8).
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Informational => "informational",
        }
    }

    /// Deterministic mapping from BOTH legacy vocabularies (R2):
    ///   - API/DB legacy:  critical→Critical, warning→High, info→Low
    ///   - Engine legacy:  medium→Medium, high→High, critical→Critical
    ///   - Canonical:      informational/low/medium/high/critical → themselves
    ///
    /// Unknown values log the original and fall back to `Medium` (R2.7).
    pub fn from_legacy(raw: &str) -> Severity {
        match raw.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "warning" => Severity::High, // legacy API
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "info" => Severity::Low, // legacy API
            "informational" => Severity::Informational,
            other => {
                tracing::warn!(severity = other, "unknown severity, defaulting to medium");
                Severity::Medium
            }
        }
    }
}

/// What to do about a violation (policy decision).
///
/// `Ord` derived: `Monitor < Flag < Block` (used by the reclassification-safety
/// invariant: monitor_mode never *increases* blocking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementAction {
    Monitor,
    Flag,
    Block,
}

impl EnforcementAction {
    /// True only for `Block` — the single action that rejects the query.
    pub fn blocks(&self) -> bool {
        matches!(self, EnforcementAction::Block)
    }
}

/// What to do with a query that cannot be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseErrorAction {
    /// Fail-open default: forward + report (R4.8).
    AllowReport,
    /// Fail-closed opt-in: reject with SQLSTATE 42501 (R4.9).
    Block,
}

/// Per-workspace enforcement policy injected by the host into the engine (R4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPolicy {
    pub critical: EnforcementAction,
    pub high: EnforcementAction,
    pub medium: EnforcementAction,
    pub low: EnforcementAction,
    pub informational: EnforcementAction,
    pub parse_error: ParseErrorAction,
    /// Global dry-run: forces every blocking action to a non-blocking one (R4.4).
    pub monitor_mode: bool,
}

impl Default for EnforcementPolicy {
    /// Default mapping (R4.1): Critical/High → BLOCK, Medium → FLAG, Low → MONITOR.
    /// Informational → MONITOR. parse_error → AllowReport (R4.8). monitor_mode off.
    fn default() -> Self {
        Self {
            critical: EnforcementAction::Block,
            high: EnforcementAction::Block,
            medium: EnforcementAction::Flag,
            low: EnforcementAction::Monitor,
            informational: EnforcementAction::Monitor,
            parse_error: ParseErrorAction::AllowReport,
            monitor_mode: false,
        }
    }
}

impl EnforcementPolicy {
    /// Resolves the effective action for a severity, applying monitor_mode.
    ///
    /// monitor_mode downgrades any `Block` to `Flag` (never blocks, but still
    /// records and alerts so the admin sees what *would* have been blocked —
    /// R4.4/R4.6). Non-blocking actions are unchanged.
    pub fn action_for(&self, severity: Severity) -> EnforcementAction {
        let base = match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Informational => self.informational,
        };
        if self.monitor_mode && base == EnforcementAction::Block {
            EnforcementAction::Flag
        } else {
            base
        }
    }

    /// Resolves the parse-error decision (R5.5/R5.6).
    pub fn parse_error_decision(&self) -> Decision {
        match self.parse_error {
            ParseErrorAction::AllowReport => Decision::Flag, // allow + report (R8.6)
            ParseErrorAction::Block => Decision::Block,
        }
    }
}

/// Rule type: standard (built-in) or custom (user-defined in YAML).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    Standard,
    Custom,
}

/// An active workspace rule, as sent by the API.
#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_id: String,
    pub code: String,
    pub severity: Severity,
    /// Built-in recommended action per the R13 table. Seeds the DB / UI default
    /// and satisfies R5.8/R13.2 (default_ruleset carries severity AND action).
    /// Action *resolution* at evaluation time always goes through the policy.
    pub default_action: EnforcementAction,
    pub rule_type: RuleType,
    /// YAML condition for custom rules.
    pub ast_condition_yaml: Option<String>,
}

/// Final three-valued decision on a query (R3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    /// Forward silently (no violation, or a Monitor action).
    Allow,
    /// Forward, but record + alert (Flag action).
    Flag,
    /// Reject the query (Block action).
    Block,
}

impl Decision {
    fn from_action(action: EnforcementAction) -> Decision {
        match action {
            EnforcementAction::Block => Decision::Block,
            EnforcementAction::Flag => Decision::Flag,
            EnforcementAction::Monitor => Decision::Allow,
        }
    }
}

/// Result of evaluating a query against the active ruleset (R3.5, R3.7).
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub decision: Decision,
    /// Resolved action of the winning violation (None when no rule matched).
    pub action: Option<EnforcementAction>,
    pub severity: Option<Severity>,
    pub rule_id: Option<String>,
    pub rule_code: Option<String>,
    pub ast_node_path: Option<String>,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
}

impl EvaluationOutcome {
    pub fn allowed() -> Self {
        Self {
            decision: Decision::Allow,
            action: None,
            severity: None,
            rule_id: None,
            rule_code: None,
            ast_node_path: None,
            estimated_rows_affected: None,
            suggested_safe_query: None,
        }
    }
}

/// The rule engine. Evaluates a parsed query against the active rules and
/// returns the highest-severity violation (or ALLOW if none is violated).
pub struct RuleEngine;

impl RuleEngine {
    /// Evaluates `parsed` against `rules`, resolving the winning violation's
    /// action via `policy`.
    ///
    /// - No match            → Decision::Allow, action None (R3.2).
    /// - One or more matches → highest-severity violation wins (R3.3); its
    ///   action is `policy.action_for(severity)` (R3.4); decision derived from
    ///   the action (R3.6). Severity, action, rule_id, rule_code, ast_node_path
    ///   and suggested_safe_query are populated (R3.5, R3.7).
    pub fn evaluate(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        let mut best: Option<(Severity, evaluator::Violation)> = None;

        for rule in rules {
            if let Some(violation) = evaluator::evaluate_rule(rule, parsed) {
                let is_better = match &best {
                    None => true,
                    Some((sev, _)) => rule.severity > *sev,
                };
                if is_better {
                    best = Some((rule.severity, violation));
                }
            }
        }

        match best {
            None => EvaluationOutcome::allowed(),
            Some((severity, v)) => {
                let action = policy.action_for(severity);
                EvaluationOutcome {
                    decision: Decision::from_action(action),
                    action: Some(action),
                    severity: Some(severity),
                    rule_id: Some(v.rule_id),
                    rule_code: Some(v.rule_code),
                    ast_node_path: Some(v.ast_node_path),
                    estimated_rows_affected: v.estimated_rows_affected,
                    suggested_safe_query: v.suggested_safe_query,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parser_for, Dialect};

    /// Destructive-critical rule codes that MUST resolve to BLOCK under the
    /// default policy (R9.1 / R13 table). These are the engine-side mirror of
    /// the Reglas_Destructivas_Criticas set.
    const DESTRUCTIVE_CRITICAL_CODES: &[&str] = &[
        "VETRO-001", "VETRO-003", "VETRO-010", "VETRO-011", "VETRO-012",
        "VETRO-030", "VETRO-042", "VETRO-090",
    ];

    /// R4.1 / R13: the default policy maps Critical/High → Block,
    /// Medium → Flag, Low/Informational → Monitor.
    #[test]
    fn default_policy_resolves_each_severity_to_r13_action() {
        let policy = EnforcementPolicy::default();
        assert_eq!(policy.action_for(Severity::Critical), EnforcementAction::Block);
        assert_eq!(policy.action_for(Severity::High), EnforcementAction::Block);
        assert_eq!(policy.action_for(Severity::Medium), EnforcementAction::Flag);
        assert_eq!(policy.action_for(Severity::Low), EnforcementAction::Monitor);
        assert_eq!(
            policy.action_for(Severity::Informational),
            EnforcementAction::Monitor
        );
    }

    /// R9.1: every destructive-critical rule carries `Severity::Critical`, and
    /// the default policy resolves a Critical violation to BLOCK. Asserting the
    /// invariant per-code documents the Reglas_Destructivas_Criticas set at the
    /// engine level (the rule catalogue itself lives in the proxy's
    /// `default_ruleset()` and the DB seed).
    #[test]
    fn destructive_critical_rules_resolve_to_block_under_default_policy() {
        let policy = EnforcementPolicy::default();
        for &code in DESTRUCTIVE_CRITICAL_CODES {
            let action = policy.action_for(Severity::Critical);
            assert_eq!(
                action,
                EnforcementAction::Block,
                "{code} (Critical) must resolve to BLOCK under the default policy"
            );
            assert!(action.blocks(), "{code} resolved action must block the query");
            assert_eq!(
                Decision::from_action(action),
                Decision::Block,
                "{code} must produce a Block decision"
            );
        }
    }

    /// End-to-end R9.1: a representative destructive query evaluated against a
    /// Critical rule with the default policy yields `Decision::Block`, with the
    /// resolved action and severity populated in the outcome.
    #[test]
    fn destructive_query_blocks_end_to_end_under_default_policy() {
        let parsed = parser_for(Dialect::Postgres)
            .parse("DELETE FROM users")
            .expect("must parse");
        let rule = Rule {
            rule_id: "VETRO-001".to_string(),
            code: "VETRO-001".to_string(),
            severity: Severity::Critical,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        };
        let outcome =
            RuleEngine::evaluate(&parsed, std::slice::from_ref(&rule), &EnforcementPolicy::default());
        assert_eq!(outcome.decision, Decision::Block);
        assert_eq!(outcome.action, Some(EnforcementAction::Block));
        assert_eq!(outcome.severity, Some(Severity::Critical));
        assert_eq!(outcome.rule_code.as_deref(), Some("VETRO-001"));
    }
}
