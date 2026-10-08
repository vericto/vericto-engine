//! Rule domain types and evaluation orchestration.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::parser::ParsedQuery;
use crate::rules::evaluator;
use crate::sensitive::{
    self, SENSITIVE_RULE_CODE, SensitiveColumn, SensitivePolicy, TouchedColumn,
};

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
            "VERICTO-070" | "VERICTO-080" | "VERICTO-081" | "VERICTO-082" | "VERICTO-085"
            | "VERICTO-090" => RuleClass::Security,
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
///
/// Not `Copy` since 3.6.0: it carries the sensitive-column tags. Hosts that
/// build it with `EnforcementPolicy::default()` / `..Default::default()` and
/// pass `&policy` are unaffected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Columns tagged as sensitive, with their policy (VERICTO-085). Empty =
    /// the rule does not run at all, and the outcome is exactly what it was
    /// before the field existed. Not enabled through the `rules` slice: the
    /// tags alone drive it. See [`crate::sensitive`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_columns: Vec<SensitiveColumn>,
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
            sensitive_columns: Vec::new(),
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

    /// Resolves the parse-error decision (R5.5/R5.6), via
    /// [`effective_parse_error`](Self::effective_parse_error).
    pub fn parse_error_decision(&self) -> Decision {
        match self.effective_parse_error() {
            ParseErrorAction::AllowReport => Decision::Flag, // allow + report (R8.6)
            ParseErrorAction::Block => Decision::Block,
        }
    }

    /// The parse-error action actually in force. Equal to `parse_error`,
    /// except that it is `Block` whenever a `block` or `mask` sensitive column
    /// is configured: a query the engine cannot read cannot be shown not to
    /// read a tagged column, and forwarding it (the fail-open default) would
    /// hand the column to anyone who finds syntax the parser rejects and the
    /// database accepts. `flag`-only tags keep the host's choice — flagging is
    /// what a parse error already does.
    ///
    /// Hosts that branch on the parse-error action themselves must use this,
    /// not the raw field.
    pub fn effective_parse_error(&self) -> ParseErrorAction {
        let protective = self
            .sensitive_columns
            .iter()
            .any(|c| c.policy != SensitivePolicy::Flag);
        if protective {
            ParseErrorAction::Block
        } else {
            self.parse_error
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

/// One rule violation, with its severity and action already resolved.
///
/// The winner is reported in the flat fields of [`EvaluationOutcome`] because the
/// hosts need exactly one: the TCP proxy builds a native protocol error carrying a
/// single rule code and node path, and `query_events.rule_id_triggered` is one
/// column. `EvaluationOutcome::violations` carries the full set alongside it, for
/// the callers that want everything a query is guilty of rather than only the worst
/// of it — a CI run reporting every problem in one pass, or an audit trail keeping
/// the evidence that a statement was both a WHERE-less DELETE *and* an injection
/// tautology.
///
/// `action` is resolved per violation through the same per-class path the winner
/// uses, so a caller rendering the set does not have to re-derive it — and cannot
/// get it wrong in a way that disagrees with the decision.
#[derive(Debug, Clone)]
pub struct ReportedViolation {
    pub rule_id: String,
    pub rule_code: String,
    pub severity: Severity,
    /// Action this violation resolves to on its own, via
    /// [`EnforcementPolicy::action_for_class`].
    pub action: EnforcementAction,
    pub ast_node_path: String,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
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
    /// Every violation the query triggered, including the one reported above.
    ///
    /// Ordered exactly as the winner is chosen — severity descending, then rule
    /// code ascending — so `violations.first()` IS the winner and the order never
    /// depends on how the host assembled the `rules` slice.
    ///
    /// `decision` is derived from the winner alone. Adding to this vector cannot
    /// change whether a query is blocked, which is what makes it safe to consume
    /// or ignore.
    ///
    /// Empty exactly when no rule matched, i.e. when `rule_code` is `None`.
    pub violations: Vec<ReportedViolation>,
    /// The SQL to execute INSTEAD of the original, when a `mask` tag was
    /// applied (Postgres only). `Some` only when the final decision is not
    /// `Block` and `monitor_mode` is off. A host that executes queries must
    /// send this text whenever it is `Some`; one that only advises returns it
    /// as the approved query. Regenerated by `pg_query`'s deparser, so
    /// comments and formatting are not preserved: audit the original too.
    pub rewritten_query: Option<String>,
    /// Every tagged column the query reads (VERICTO-085), deduplicated and
    /// sorted, for the audit trail. Empty when none is read, and always empty
    /// when the policy carries no tags.
    pub sensitive_columns: Vec<TouchedColumn>,
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
            violations: Vec::new(),
            rewritten_query: None,
            sensitive_columns: Vec::new(),
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
    ///
    /// When several violated rules share the top severity, the one with the
    /// lowest `code` wins. The order of `rules` never affects the outcome, so
    /// the same query and ruleset always report the same violation regardless of
    /// how the host assembled the slice.
    pub fn evaluate(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        // Collect every violation, then order them. The loop already evaluated
        // every rule to find the worst one — the previous version simply discarded
        // the rest — so keeping them costs a push, not extra evaluation.
        let mut violations: Vec<ReportedViolation> = rules
            .iter()
            .filter_map(|rule| {
                evaluator::evaluate_rule(rule, parsed).map(|v| ReportedViolation {
                    // Resolve each action through the per-class path so a channel's
                    // schema-migration cap (if any) softens DDL without touching
                    // DataMutation / Security violations. Class comes from the rule
                    // code — a static property, not a channel input.
                    action: policy
                        .action_for_class(rule.severity, RuleClass::for_code(&v.rule_code)),
                    severity: rule.severity,
                    rule_id: v.rule_id,
                    rule_code: v.rule_code,
                    ast_node_path: v.ast_node_path,
                    estimated_rows_affected: v.estimated_rows_affected,
                    suggested_safe_query: v.suggested_safe_query,
                })
            })
            .collect();

        // Highest severity first, then lowest rule code. This is the same
        // comparison that used to pick the winner inline, lifted to a total order
        // so the whole set is deterministic and `violations[0]` is the winner.
        //
        // Sorting on (severity, code) — never on position in `rules` — is the point:
        // the host supplies that slice, the control plane serves it from a query
        // with no ORDER BY, so position is not a property of the query being
        // evaluated. Letting it decide made the reported code vary between runs on
        // identical input (fixed in 3.2.4).
        violations.sort_by(|a, b| match b.severity.cmp(&a.severity) {
            Ordering::Equal => a.rule_code.cmp(&b.rule_code),
            other => other,
        });

        let outcome = match violations.first() {
            None => EvaluationOutcome::allowed(),
            Some(winner) => {
                // `decision` and `action` come from the winner alone, exactly as
                // before. The vector is additional evidence, never an input to
                // the verdict.
                let action = winner.action;
                EvaluationOutcome {
                    decision: Decision::from_action(action),
                    action: Some(action),
                    severity: Some(winner.severity),
                    rule_id: Some(winner.rule_id.clone()),
                    rule_code: Some(winner.rule_code.clone()),
                    ast_node_path: Some(winner.ast_node_path.clone()),
                    estimated_rows_affected: winner.estimated_rows_affected,
                    suggested_safe_query: winner.suggested_safe_query.clone(),
                    violations,
                    rewritten_query: None,
                    sensitive_columns: Vec::new(),
                }
            }
        };

        // The only cost when no column is tagged: this check.
        if policy.sensitive_columns.is_empty() {
            return outcome;
        }
        match sensitive::evaluate(parsed, &policy.sensitive_columns) {
            Some(verdict) => apply_sensitive(outcome, verdict, policy),
            None => outcome,
        }
    }
}

/// Folds the sensitive-column verdict into the rule engine's outcome.
///
/// The column verdict is a **floor**: the final decision is the stricter of
/// the two, so a tag can only ever make a query stricter, and a rule set to
/// Flag cannot let a blocked column through (nor a flagged column let a
/// blocked DELETE through).
///
/// - Column verdict strictly stricter: VERICTO-085 becomes the winner — the
///   flat fields are its, and it is `violations[0]`.
/// - Otherwise the rule winner keeps the flat fields and `violations[0]`;
///   VERICTO-085 joins the rest of the vector at its (severity desc, code asc)
///   position.
///
/// Under `monitor_mode` a column block becomes a flag and a mask is NOT
/// applied (dry-run never changes what runs); the would-be rewrite stays in
/// VERICTO-085's `suggested_safe_query`.
fn apply_sensitive(
    mut outcome: EvaluationOutcome,
    verdict: sensitive::SensitiveVerdict,
    policy: &EnforcementPolicy,
) -> EvaluationOutcome {
    let base = match verdict.outcome {
        SensitivePolicy::Block => EnforcementAction::Block,
        // A mask forwards the rewritten query and records it: a Flag. It must
        // rank above a plain flag tag and below a block (block > mask > flag),
        // and every mask is an audit event.
        SensitivePolicy::Mask | SensitivePolicy::Flag => EnforcementAction::Flag,
    };
    let action = if policy.monitor_mode && base == EnforcementAction::Block {
        EnforcementAction::Flag
    } else {
        base
    };
    let severity = match verdict.outcome {
        SensitivePolicy::Block | SensitivePolicy::Mask => Severity::High,
        SensitivePolicy::Flag => Severity::Medium,
    };
    let v = ReportedViolation {
        rule_id: SENSITIVE_RULE_CODE.to_string(),
        rule_code: SENSITIVE_RULE_CODE.to_string(),
        severity,
        action,
        ast_node_path: verdict.ast_node_path,
        estimated_rows_affected: None,
        suggested_safe_query: verdict.suggested_safe_query,
    };

    let column_decision = Decision::from_action(action);
    let stricter = decision_rank(column_decision) > decision_rank(outcome.decision);
    if stricter || outcome.violations.is_empty() {
        outcome.decision = column_decision;
        outcome.action = Some(action);
        outcome.severity = Some(v.severity);
        outcome.rule_id = Some(v.rule_id.clone());
        outcome.rule_code = Some(v.rule_code.clone());
        outcome.ast_node_path = Some(v.ast_node_path.clone());
        outcome.estimated_rows_affected = None;
        outcome.suggested_safe_query = v.suggested_safe_query.clone();
        outcome.violations.insert(0, v);
    } else {
        let pos = outcome.violations[1..]
            .iter()
            .position(|o| match v.severity.cmp(&o.severity) {
                Ordering::Greater => true,
                Ordering::Equal => v.rule_code < o.rule_code,
                Ordering::Less => false,
            })
            .map_or(outcome.violations.len(), |p| p + 1);
        outcome.violations.insert(pos, v);
    }

    outcome.rewritten_query = if verdict.outcome == SensitivePolicy::Mask
        && !policy.monitor_mode
        && outcome.decision != Decision::Block
    {
        verdict.rewritten_query
    } else {
        None
    };
    outcome.sensitive_columns = verdict.touched;
    outcome
}

fn decision_rank(d: Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::Flag => 1,
        Decision::Block => 2,
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

    // ── Deterministic tie-break on equal severity ─────────────────────────────

    fn rule_at(code: &str, severity: Severity) -> Rule {
        Rule {
            rule_id: format!("id-{code}"),
            code: code.to_string(),
            severity,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        }
    }

    /// `SELECT * FROM users` violates VERICTO-050 (no LIMIT) and VERICTO-051
    /// (star, no WHERE) at once. Given both at the same severity, the reported
    /// code must come from the codes themselves, not from the order the host
    /// happened to assemble the slice in.
    #[test]
    fn equal_severity_tie_is_broken_by_rule_code_not_input_order() {
        let parsed = parser_for(Dialect::Postgres)
            .parse("SELECT * FROM users")
            .expect("must parse");
        let low_code = rule_at("VERICTO-050", Severity::Medium);
        let high_code = rule_at("VERICTO-051", Severity::Medium);
        let policy = EnforcementPolicy::default();

        let forward =
            RuleEngine::evaluate(&parsed, &[low_code.clone(), high_code.clone()], &policy);
        let reversed = RuleEngine::evaluate(&parsed, &[high_code, low_code], &policy);

        assert_eq!(forward.rule_code.as_deref(), Some("VERICTO-050"));
        assert_eq!(
            forward.rule_code, reversed.rule_code,
            "reordering the rules slice changed the reported violation"
        );
    }

    /// The tie-break must not override severity: a higher-severity rule still
    /// wins even when its code sorts after the lower-severity one, in either
    /// input order.
    #[test]
    fn higher_severity_wins_over_lower_code_in_either_order() {
        let parsed = parser_for(Dialect::Postgres)
            .parse("SELECT * FROM users")
            .expect("must parse");
        // Lower code, lower severity — must lose to VERICTO-051 below.
        let weak = rule_at("VERICTO-050", Severity::Low);
        let strong = rule_at("VERICTO-051", Severity::High);
        let policy = EnforcementPolicy::default();

        for slice in [
            [weak.clone(), strong.clone()],
            [strong.clone(), weak.clone()],
        ] {
            let outcome = RuleEngine::evaluate(&parsed, &slice, &policy);
            assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-051"));
            assert_eq!(outcome.severity, Some(Severity::High));
        }
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
