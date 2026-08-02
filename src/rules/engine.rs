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

/// The kind of risk a rule represents — a *static* property of the rule,
/// independent of the channel it is evaluated on. Lets the host apply a
/// different enforcement ceiling per class per channel (e.g. schema DDL is
/// routine in a CI migration but high-risk against a live production database),
/// without the engine's detection logic ever needing to know the channel.
///
/// This does NOT change *what* a rule detects — only gives the host a lever to
/// modulate the resulting action. See `EnforcementPolicy::schema_migration_cap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleClass {
    /// Schema/DDL changes: DROP TABLE/DATABASE/SCHEMA, TRUNCATE, ALTER TABLE,
    /// DROP INDEX. Destructive against a live DB, but normal in a versioned
    /// migration — the class a CI channel may want to soften to Flag.
    SchemaMigration,
    /// Data mutation without adequate scope: DELETE/UPDATE without WHERE,
    /// INSERT..SELECT / CREATE TABLE AS with no filter, MERGE. Dangerous on
    /// *any* channel — a WHERE-less DELETE is never intended, even in a migration.
    DataMutation,
    /// Security-sensitive: SQL-injection tautologies, COPY..PROGRAM, DO blocks,
    /// GRANT/REVOKE, sleep-based probing. Never softened by channel.
    Security,
    /// Best-practice / performance hints: SELECT without LIMIT, SELECT *,
    /// INSERT without column list. Advisory (Medium/Low by default).
    Performance,
}

impl RuleClass {
    /// Classifies a built-in rule by its code. Custom rules and any unknown code
    /// fall back to `DataMutation` (the conservative default: never softened by
    /// a channel cap, so an unclassified rule can't be accidentally weakened).
    pub fn for_code(code: &str) -> RuleClass {
        match code {
            // Schema / DDL
            "VERICTO-010" | "VERICTO-011" | "VERICTO-012" | "VERICTO-013" | "VERICTO-015"
            | "VERICTO-016" | "VERICTO-017" | "VERICTO-018" | "VERICTO-019" => {
                RuleClass::SchemaMigration
            }
            // Data mutation (destructive DML)
            "VERICTO-001" | "VERICTO-002" | "VERICTO-003" | "VERICTO-030" | "VERICTO-031"
            | "VERICTO-033" | "VERICTO-040" | "VERICTO-042" | "VERICTO-083" | "VERICTO-084" => {
                RuleClass::DataMutation
            }
            // Security
            "VERICTO-070" | "VERICTO-080" | "VERICTO-081" | "VERICTO-082" | "VERICTO-090" => {
                RuleClass::Security
            }
            // Performance / best-practice
            "VERICTO-050" | "VERICTO-051" | "VERICTO-060" | "VERICTO-061" => RuleClass::Performance,
            // Custom rules / unknown codes: conservative default.
            _ => RuleClass::DataMutation,
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
    /// Per-channel ceiling for `RuleClass::SchemaMigration` violations. When set,
    /// a schema/DDL violation's action is capped at (i.e. never exceeds) this
    /// value — so a CI channel can pass `Some(Flag)` to make DROP/ALTER/TRUNCATE
    /// *report* rather than *block* (migrations legitimately contain them), while
    /// a runtime channel leaves it `None` to keep the full policy in force.
    ///
    /// Only ever *lowers* the action (`action.min(cap)`), so it can never make a
    /// channel more aggressive than the base policy. `None` = no cap = today's
    /// behavior exactly (backward-compatible; absent in older serialized policies).
    #[serde(default)]
    pub schema_migration_cap: Option<EnforcementAction>,
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
            schema_migration_cap: None,
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

    /// Resolves the effective action for a violation, applying both the
    /// severity mapping (`action_for`) and any per-class ceiling.
    ///
    /// The only class-specific cap today is `schema_migration_cap`: when set, a
    /// `RuleClass::SchemaMigration` violation is lowered to at most that action
    /// (`min`, since Monitor < Flag < Block). All other classes — DataMutation,
    /// Security, Performance — are unaffected, so a WHERE-less DELETE or a
    /// COPY..PROGRAM is never softened by a channel that only means to relax
    /// schema DDL. With no cap set this is identical to `action_for`.
    pub fn action_for_class(&self, severity: Severity, class: RuleClass) -> EnforcementAction {
        let action = self.action_for(severity);
        match (class, self.schema_migration_cap) {
            (RuleClass::SchemaMigration, Some(cap)) => action.min(cap),
            _ => action,
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
    /// Maps an enforcement action to the final decision. `pub(crate)` so the
    /// property tests (Property 7) can assert the mapping directly.
    pub(crate) fn from_action(action: EnforcementAction) -> Decision {
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
                // Resolve the action through the per-class path so a channel's
                // schema-migration cap (if any) can soften DDL without touching
                // DataMutation / Security violations. Class is derived from the
                // winning rule's code — a static property, not a channel input.
                let action = policy.action_for_class(severity, RuleClass::for_code(&v.rule_code));
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
    use crate::parser::{Dialect, parser_for};

    /// Destructive-critical rule codes that MUST resolve to BLOCK under the
    /// default policy (R9.1 / R13 table). These are the engine-side mirror of
    /// the Reglas_Destructivas_Criticas set.
    const DESTRUCTIVE_CRITICAL_CODES: &[&str] = &[
        "VERICTO-001",
        "VERICTO-003",
        "VERICTO-010",
        "VERICTO-011",
        "VERICTO-012",
        "VERICTO-030",
        "VERICTO-042",
        "VERICTO-090",
    ];

    /// R4.1 / R13: the default policy maps Critical/High → Block,
    /// Medium → Flag, Low/Informational → Monitor.
    #[test]
    fn default_policy_resolves_each_severity_to_r13_action() {
        let policy = EnforcementPolicy::default();
        assert_eq!(
            policy.action_for(Severity::Critical),
            EnforcementAction::Block
        );
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
            assert!(
                action.blocks(),
                "{code} resolved action must block the query"
            );
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
            rule_id: "VERICTO-001".to_string(),
            code: "VERICTO-001".to_string(),
            severity: Severity::Critical,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        };
        let outcome = RuleEngine::evaluate(
            &parsed,
            std::slice::from_ref(&rule),
            &EnforcementPolicy::default(),
        );
        assert_eq!(outcome.decision, Decision::Block);
        assert_eq!(outcome.action, Some(EnforcementAction::Block));
        assert_eq!(outcome.severity, Some(Severity::Critical));
        assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-001"));
    }

    // ── RuleClass classification ──────────────────────────────────────────────
    #[test]
    fn rule_class_partitions_the_catalogue() {
        use RuleClass::*;
        // Schema/DDL
        for c in [
            "VERICTO-010",
            "VERICTO-011",
            "VERICTO-012",
            "VERICTO-013",
            "VERICTO-015",
            "VERICTO-016",
            "VERICTO-017",
            "VERICTO-018",
            "VERICTO-019",
        ] {
            assert_eq!(RuleClass::for_code(c), SchemaMigration, "{c}");
        }
        // Data mutation
        for c in [
            "VERICTO-001",
            "VERICTO-002",
            "VERICTO-003",
            "VERICTO-030",
            "VERICTO-031",
            "VERICTO-033",
            "VERICTO-040",
            "VERICTO-042",
            "VERICTO-083",
            "VERICTO-084",
        ] {
            assert_eq!(RuleClass::for_code(c), DataMutation, "{c}");
        }
        // Security
        for c in [
            "VERICTO-070",
            "VERICTO-080",
            "VERICTO-081",
            "VERICTO-082",
            "VERICTO-090",
        ] {
            assert_eq!(RuleClass::for_code(c), Security, "{c}");
        }
        // Performance
        for c in ["VERICTO-050", "VERICTO-051", "VERICTO-060", "VERICTO-061"] {
            assert_eq!(RuleClass::for_code(c), Performance, "{c}");
        }
        // Unknown / custom → conservative default (never softened by a cap).
        assert_eq!(RuleClass::for_code("CUSTOM-001"), DataMutation);
        assert_eq!(RuleClass::for_code("VERICTO-999"), DataMutation);
    }

    // ── schema_migration_cap (per-channel ceiling) ────────────────────────────
    #[test]
    fn no_cap_is_identical_to_action_for() {
        // Backward-compat: default policy (cap None) resolves every class exactly
        // as the plain severity mapping does.
        let policy = EnforcementPolicy::default();
        for class in [
            RuleClass::SchemaMigration,
            RuleClass::DataMutation,
            RuleClass::Security,
            RuleClass::Performance,
        ] {
            for sev in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Informational,
            ] {
                assert_eq!(policy.action_for_class(sev, class), policy.action_for(sev));
            }
        }
    }

    #[test]
    fn ci_cap_softens_schema_but_not_data_or_security() {
        // A CI-style policy: schema DDL capped at Flag, everything else full force.
        let ci = EnforcementPolicy {
            schema_migration_cap: Some(EnforcementAction::Flag),
            ..EnforcementPolicy::default()
        };
        // Critical schema (DROP TABLE) → capped Block down to Flag.
        assert_eq!(
            ci.action_for_class(Severity::Critical, RuleClass::SchemaMigration),
            EnforcementAction::Flag
        );
        // Critical data mutation (DELETE without WHERE) → still Block.
        assert_eq!(
            ci.action_for_class(Severity::Critical, RuleClass::DataMutation),
            EnforcementAction::Block
        );
        // Critical security → still Block.
        assert_eq!(
            ci.action_for_class(Severity::Critical, RuleClass::Security),
            EnforcementAction::Block
        );
    }

    #[test]
    fn cap_only_lowers_never_raises() {
        // A cap of Block on a Medium-severity schema rule (base Flag) must not
        // *raise* it to Block — the cap is a ceiling (min), not a floor.
        let policy = EnforcementPolicy {
            schema_migration_cap: Some(EnforcementAction::Block),
            ..EnforcementPolicy::default()
        };
        assert_eq!(
            policy.action_for_class(Severity::Medium, RuleClass::SchemaMigration),
            EnforcementAction::Flag
        );
    }

    #[test]
    fn ci_cap_end_to_end_drop_table_flags_delete_blocks() {
        // The whole point, end to end: on a CI policy, DROP TABLE reports (Flag)
        // while DELETE-without-WHERE still blocks.
        let ci = EnforcementPolicy {
            schema_migration_cap: Some(EnforcementAction::Flag),
            ..EnforcementPolicy::default()
        };
        let drop_rule = Rule {
            rule_id: "VERICTO-010".into(),
            code: "VERICTO-010".into(),
            severity: Severity::Critical,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        };
        let del_rule = Rule {
            rule_id: "VERICTO-001".into(),
            code: "VERICTO-001".into(),
            severity: Severity::Critical,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        };

        let drop = parser_for(Dialect::Postgres)
            .parse("DROP TABLE users")
            .unwrap();
        let out = RuleEngine::evaluate(&drop, std::slice::from_ref(&drop_rule), &ci);
        assert_eq!(out.decision, Decision::Flag, "DROP TABLE should FLAG in CI");

        let del = parser_for(Dialect::Postgres)
            .parse("DELETE FROM users")
            .unwrap();
        let out = RuleEngine::evaluate(&del, std::slice::from_ref(&del_rule), &ci);
        assert_eq!(
            out.decision,
            Decision::Block,
            "DELETE w/o WHERE must still BLOCK in CI"
        );
    }
}
