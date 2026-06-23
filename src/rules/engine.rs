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
    pub rule_type: RuleType,
    /// YAML condition for custom rules.
    pub ast_condition_yaml: Option<String>,
}

/// Final decision on a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allowed,
    Blocked,
}

/// Result of evaluating a query against the active ruleset.
#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub decision: Decision,
    pub rule_id: Option<String>,
    pub rule_code: Option<String>,
    pub severity: Option<Severity>,
    pub ast_node_path: Option<String>,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
}

impl EvaluationOutcome {
    pub fn allowed() -> Self {
        Self {
            decision: Decision::Allowed,
            rule_id: None,
            rule_code: None,
            severity: None,
            ast_node_path: None,
            estimated_rows_affected: None,
            suggested_safe_query: None,
        }
    }
}

/// The rule engine. Evaluates a parsed query against the active rules and
/// returns the highest-severity violation (or ALLOWED if none is violated).
pub struct RuleEngine;

impl RuleEngine {
    /// Evaluates `parsed` against `rules`. All rules are evaluated; the
    /// highest-severity violation wins. AST parsing has already guaranteed the
    /// query is syntactically valid.
    pub fn evaluate(parsed: &ParsedQuery, rules: &[Rule]) -> EvaluationOutcome {
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
            Some((severity, v)) => EvaluationOutcome {
                decision: Decision::Blocked,
                rule_id: Some(v.rule_id),
                rule_code: Some(v.rule_code),
                severity: Some(severity),
                ast_node_path: Some(v.ast_node_path),
                estimated_rows_affected: v.estimated_rows_affected,
                suggested_safe_query: v.suggested_safe_query,
            },
        }
    }
}
