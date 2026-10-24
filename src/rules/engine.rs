// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Rule domain types and evaluation orchestration.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use crate::access::{self, ACCESS_RULE_CODE, AccessMode, AccessPolicy, DeniedRef};
use crate::parser::{MysqlReadings, ParsedQuery};
use crate::policy::{ApprovalRequirement, EvalContext, PolicyHit, PolicySet, UnknownField};
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
    /// DROP INDEX, DROP TRIGGER. Destructive against a live DB, but normal in a
    /// versioned migration — the class a CI channel may want to soften to Flag.
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
            // Snowflake: recovery reduced (retention 0, CREATE OR REPLACE,
            // INSERT OVERWRITE, UNDROP, ALTER ACCOUNT) is schema DDL, which a
            // CI channel may soften like DROP TABLE.
            "VERICTO-094" => RuleClass::SchemaMigration,
            // Security
            "VERICTO-070" | "VERICTO-080" | "VERICTO-081" | "VERICTO-082" | "VERICTO-085"
            | "VERICTO-086" | "VERICTO-087" | "VERICTO-090" => RuleClass::Security,
            // Snowflake: stage unload and file transfer, external stages and
            // integrations, shares, persistent code, role switches. DDL in
            // form for some, but each moves data out of the account or runs
            // code no check sees, so a CI channel never softens them (as
            // GRANT, VERICTO-082).
            "VERICTO-091" | "VERICTO-092" | "VERICTO-093" | "VERICTO-096" | "VERICTO-097" => {
                RuleClass::Security
            }
            // SQLite: ATTACH (another file on the connection), native code
            // or file functions, VACUUM INTO (a copy of the database to a
            // path). Never softened by a CI channel.
            "VERICTO-098" | "VERICTO-100" | "VERICTO-101" => RuleClass::Security,
            // SQLite: a safety PRAGMA. `PRAGMA foreign_keys = OFF` is the
            // standard step of a SQLite table rebuild in migrations (Prisma,
            // Drizzle, Django, Alembic), so a CI channel may soften it like
            // other schema DDL; at run time it blocks under the default policy.
            "VERICTO-099" => RuleClass::SchemaMigration,
            // Performance / best-practice
            "VERICTO-050" | "VERICTO-051" | "VERICTO-060" | "VERICTO-061" => RuleClass::Performance,
            // Snowflake warehouse cost.
            "VERICTO-095" => RuleClass::Performance,
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

/// Why a statement did not parse (design §4.6), for telemetry: it tells a gap
/// in what the engine reads (a statement kind it does not know, worth adding
/// to a corpus) from SQL that is simply invalid. Read it from an outcome with
/// [`EvaluationOutcome::parse_error_kind`]. Since 4.1.0; `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// A statement kind the parser does not know (`DETACH` on 0.63's SQLite
    /// dialect, a Snowflake `CREATE TASK`), one the engine does not analyse,
    /// or one only the pre-classifier recognised by its keywords.
    UnknownStatement,
    /// A known statement kind whose text the parser rejects: invalid SQL, or
    /// syntax the parser does not support. PostgreSQL's parser reports every
    /// failure this way.
    Syntax,
    /// Refused before it was read: nesting past the limits.
    TooComplex,
}

impl ParseErrorKind {
    /// `unknown_statement`, `syntax` or `too_complex`.
    pub fn as_str(self) -> &'static str {
        match self {
            ParseErrorKind::UnknownStatement => "unknown_statement",
            ParseErrorKind::Syntax => "syntax",
            ParseErrorKind::TooComplex => "too_complex",
        }
    }

    /// The kind of a parse-error message (an outcome's `ast_node_path`, with
    /// or without its `PARSE_ERROR: ` prefix, or a [`crate::ProxyError`]'s text).
    pub fn classify(message: &str) -> ParseErrorKind {
        if message.contains("VERICTO-AST-TOO-DEEP") || message.contains("VERICTO-QUERY-TOO-LARGE") {
            ParseErrorKind::TooComplex
        } else if message.contains(crate::parser::walk::UNSUPPORTED_STATEMENT)
            || message.contains("recognised by its keywords")
            || message.contains("Expected: an SQL statement")
        {
            ParseErrorKind::UnknownStatement
        } else {
            ParseErrorKind::Syntax
        }
    }
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
    /// The allowlist of the identity making this call (VERICTO-087): the API
    /// key, or the database user of a proxy session; the host picks it (see
    /// [`crate::AccessPolicyMap`]). `None` = no allowlist for this identity:
    /// the analysis does not run and the outcome is exactly what it was
    /// before the field existed. See [`crate::access`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AccessPolicy>,
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
            access_policy: None,
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

    /// [`effective_parse_error`](Self::effective_parse_error) for the text
    /// `sql` that did not parse. Identical, except when `sql` is one of the
    /// session statements drivers and ORMs send on every connection (`SET
    /// SESSION TRANSACTION ISOLATION LEVEL …`, `SET NAMES …`, `BEGIN`, … — a
    /// closed list, see `crate::access::session`): then nothing forces a
    /// block, neither an enforced allowlist nor a `block`/`mask` tag, and the
    /// host's `parse_error` stands. Those statements read no table and no
    /// column, so there is nothing for either protection to guard; sqlparser
    /// rejects some of them (Django's MySQL isolation level), and blocking
    /// them would break every connection of a tagged workspace or an agent
    /// identity.
    ///
    /// Hosts that parse themselves and branch on the parse-error action must
    /// call this (with the client's text) instead of `effective_parse_error`.
    ///
    /// Snowflake and SQLite follow the same rule as every dialect (fail-open
    /// flag by default; block under `parse_error: block`, a `block`/`mask` tag
    /// or an enforced allowlist). Their statements sqlparser does not read but
    /// the engine knows are either findings (the pre-classifier) or, for a
    /// short allowlist of legitimate forms, analysed with no finding (see
    /// `parser::snowflake` and `parser::sqlite`).
    pub fn effective_parse_error_for(
        &self,
        sql: &str,
        dialect: crate::parser::Dialect,
    ) -> ParseErrorAction {
        let forced = self.effective_parse_error();
        // The session list is only consulted when a protection would force
        // the block: with neither, this is exactly `effective_parse_error`.
        if forced != self.parse_error && access::session::is_session_boilerplate(sql, dialect) {
            self.parse_error
        } else {
            forced
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
    /// The same holds for an agent allowlist in `enforce` mode (VERICTO-087):
    /// a statement the engine cannot read cannot be shown to stay inside it.
    /// In `observe` mode the host's choice stands.
    ///
    /// Hosts that branch on the parse-error action themselves must use
    /// [`effective_parse_error_for`](Self::effective_parse_error_for) (which
    /// exempts session boilerplate), not the raw field.
    pub fn effective_parse_error(&self) -> ParseErrorAction {
        let protective = self
            .sensitive_columns
            .iter()
            .any(|c| c.policy != SensitivePolicy::Flag)
            || self
                .access_policy
                .as_ref()
                .is_some_and(|p| p.mode == AccessMode::Enforce);
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
/// get it wrong in a way that disagrees with the decision. The winner is the
/// violation with the strongest `action` (then severity, then code), so no entry
/// is ever stronger than the decision.
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
    /// Ordered exactly as the winner is chosen — resolved action descending
    /// (Block, Flag, Monitor), then severity descending, then rule code
    /// ascending — so `violations.first()` IS the winner and the order never
    /// depends on how the host assembled the `rules` slice (since 4.2.0; before,
    /// severity came first).
    ///
    /// `decision` is the winner's action, which is the strongest action in this
    /// vector: no entry resolves to an action stronger than the decision.
    ///
    /// Empty exactly when no rule matched, i.e. when `rule_code` is `None`.
    pub violations: Vec<ReportedViolation>,
    /// The SQL to execute INSTEAD of the original, when a `mask` tag was
    /// applied, or (since 4.5.0) a `rewrite_limit` policy bounded the
    /// statement (on top of the mask when both apply). `Some` only when the
    /// final decision is not `Block` and `monitor_mode` is off. A host that executes queries must
    /// send this text whenever it is `Some`; one that only advises returns it
    /// as the approved query. Regenerated by `pg_query`'s deparser, so
    /// comments and formatting are not preserved: audit the original too.
    pub rewritten_query: Option<String>,
    /// Every tagged column the query reads (VERICTO-085), deduplicated and
    /// sorted, for the audit trail. Empty when none is read, and always empty
    /// when the policy carries no tags.
    pub sensitive_columns: Vec<TouchedColumn>,
    /// Every reference the identity's allowlist denied (VERICTO-087),
    /// deduplicated and sorted, for the audit trail. Filled in `observe` mode
    /// too. Always empty when the policy carries no `access_policy`.
    pub access_denied: Vec<DeniedRef>,
    /// What each business policy found ([`crate::evaluate_with_context`]),
    /// for the audit trail and the simulator: violations, inconclusive
    /// results, insufficient trust, exemptions. Always empty without
    /// policies. Since 4.4.0.
    pub policy_hits: Vec<PolicyHit>,
    /// `Some` when the decision is `Block` only because of
    /// `require_approval` policies: a host that knows approvals may unblock
    /// it with a grant; one that does not, blocks. Since 4.4.0.
    pub approval_required: Option<ApprovalRequirement>,
    /// The values policies needed and could not know (UNKNOWN), and genuine
    /// evaluation errors, for operator alerts. Since 4.4.0.
    pub unknowns: Vec<UnknownField>,
}

impl EvaluationOutcome {
    /// Why the statement did not parse, when the outcome is a parse error
    /// (`rule_code` `VERICTO-PARSE-ERROR`, including the floor of a statement
    /// only the pre-classifier recognised); `None` for every other outcome.
    /// Since 4.1.0.
    pub fn parse_error_kind(&self) -> Option<ParseErrorKind> {
        if self.rule_code.as_deref() != Some("VERICTO-PARSE-ERROR") {
            return None;
        }
        Some(ParseErrorKind::classify(
            self.ast_node_path.as_deref().unwrap_or_default(),
        ))
    }

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
            access_denied: Vec::new(),
            policy_hits: Vec::new(),
            approval_required: None,
            unknowns: Vec::new(),
        }
    }
}

/// VERICTO-086: SQL text that MySQL and the engine would read differently.
///
/// Returned (Critical, Security) when the MySQL text holds a construct the
/// lexical normalization cannot resolve with certainty. The engine cannot know which
/// statement the server would execute, so it blocks. Like VERICTO-085 it is
/// not enabled through the `rules` slice and does not go through the severity
/// mapping: it always blocks, except under `monitor_mode`, which never blocks.
/// Deliberately not a `VERICTO-PARSE-ERROR`: a fail-open host forwards those.
pub const TEXT_DIVERGENCE_RULE_CODE: &str = "VERICTO-086";

/// The rule engine. Evaluates a parsed query against the active rules and
/// returns the violation with the strongest resolved action (or ALLOW if none
/// is violated).
pub struct RuleEngine;

impl RuleEngine {
    /// Evaluates `parsed` against `rules`, resolving every violation's action
    /// via `policy`.
    ///
    /// - No match            → Decision::Allow, action None (R3.2).
    /// - One or more matches → each violation's action is
    ///   `policy.action_for_class(severity, class)` (R3.4); the violation with
    ///   the strongest action wins, so the decision (R3.6) is the strongest
    ///   action of the set and never weaker than any one violation's. Severity,
    ///   action, rule_id, rule_code, ast_node_path and suggested_safe_query are
    ///   the winner's (R3.5, R3.7).
    ///
    /// Among violations with the same action the highest severity wins (R3.3),
    /// then the lowest `code`. The order of `rules` never affects the outcome,
    /// so the same query and ruleset always report the same violation
    /// regardless of how the host assembled the slice. Before 4.2.0 severity
    /// came first, so a softened violation (a `schema_migration_cap`, a host's
    /// severity mapping) could outrank a blocking one and decide.
    ///
    /// MySQL text that MySQL reads differently from sqlparser (see
    /// `parser::mysql_lex`) carries every statement the server may execute:
    /// each is evaluated and the outcome whose winner ranks first by the same
    /// order wins (block, then flag or mask, then monitor, then allow; then
    /// severity, then code; on a full tie the base reading's). Text that
    /// cannot be read with certainty blocks with [`TEXT_DIVERGENCE_RULE_CODE`].
    pub fn evaluate(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        let alternatives = match parsed.mysql.as_deref() {
            None => return Self::evaluate_reading(parsed, rules, policy),
            Some(MysqlReadings::Ambiguous(why)) => return divergence_outcome(why, policy),
            Some(MysqlReadings::Alternatives(alts)) => alts,
        };
        let mut outcome = Self::evaluate_reading(parsed, rules, policy);
        for alt in alternatives {
            // VERICTO-085 already ran on the client's text, through a front
            // end that refuses every one of these constructs; the other
            // readings need the rules and the identity's allowlist (each is a
            // statement the server may execute).
            let mut other = match alt {
                Ok(p) => Self::with_access(Self::evaluate_rules(p, rules, policy), p, policy),
                Err(e) => parse_error_outcome(e, policy),
            };
            if outranks(other.precedence(), outcome.precedence()) {
                // The tagged columns the client's text reads stay in the audit
                // trail. A block never forwards a rewrite; a reading that
                // outranks a masked one on severity or code alone (the same
                // flag) keeps the mask, so ranking never unmasks a column.
                let touched = std::mem::take(&mut outcome.sensitive_columns);
                let denied = std::mem::take(&mut outcome.access_denied);
                let rewrite = outcome.rewritten_query.take();
                std::mem::swap(&mut outcome, &mut other);
                outcome.sensitive_columns = touched;
                outcome.rewritten_query = if outcome.decision == Decision::Block {
                    None
                } else {
                    rewrite
                };
                other.access_denied = denied;
            }
            // Every reading's denials stay in the audit trail.
            union_denied(&mut outcome.access_denied, other.access_denied);
        }
        outcome
    }

    /// [`evaluate`](Self::evaluate) with the business policies of
    /// `policies` and the declared context `ctx` (design §4.6). `sql` is the
    /// statement text when the host has it (the Postgres function facts read
    /// it).
    ///
    /// With an empty `policies` this is exactly `evaluate`: the same code
    /// path, nothing else runs. Otherwise each reading is evaluated as
    /// `evaluate` does, and then:
    ///
    /// - exemptions that applied cap their rule classes (never Security or
    ///   DataMutation);
    /// - every violated or inconclusive policy joins `violations` with its
    ///   own action (not the severity mapping), after every rule, VERICTO-085
    ///   and VERICTO-087 finding of the same action, and require-approval
    ///   policies after policy blocks: the strictest outcome still wins;
    /// - `policy_hits`, `unknowns` and `approval_required` are filled.
    pub fn evaluate_with_context(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
        policies: &PolicySet,
        ctx: &EvalContext,
        sql: Option<&str>,
    ) -> EvaluationOutcome {
        if policies.is_empty() {
            return Self::evaluate(parsed, rules, policy);
        }
        let alternatives = match parsed.mysql.as_deref() {
            None => return Self::evaluate_reading_ctx(parsed, rules, policy, policies, ctx, sql),
            Some(MysqlReadings::Ambiguous(why)) => return divergence_outcome(why, policy),
            Some(MysqlReadings::Alternatives(alts)) => alts,
        };
        let mut outcome = Self::evaluate_reading_ctx(parsed, rules, policy, policies, ctx, sql);
        for alt in alternatives {
            let mut other = match alt {
                Ok(p) => {
                    let verdict = crate::policy::set::evaluate(policies, p, ctx, policy, None);
                    let base = Self::evaluate_rules_with(
                        p,
                        rules,
                        policy,
                        Some(policies),
                        &verdict.exemptions,
                    );
                    with_policies(Self::with_access(base, p, policy), verdict)
                }
                Err(e) => parse_error_outcome(e, policy),
            };
            if outranks(other.precedence(), outcome.precedence()) {
                let touched = std::mem::take(&mut outcome.sensitive_columns);
                let denied = std::mem::take(&mut outcome.access_denied);
                let hits = std::mem::take(&mut outcome.policy_hits);
                let unknowns = std::mem::take(&mut outcome.unknowns);
                let rewrite = outcome.rewritten_query.take();
                std::mem::swap(&mut outcome, &mut other);
                outcome.sensitive_columns = touched;
                outcome.rewritten_query = if outcome.decision == Decision::Block {
                    None
                } else {
                    rewrite
                };
                other.access_denied = denied;
                other.policy_hits = hits;
                other.unknowns = unknowns;
            }
            union_denied(&mut outcome.access_denied, other.access_denied);
            for h in other.policy_hits {
                if !outcome.policy_hits.contains(&h) {
                    outcome.policy_hits.push(h);
                }
            }
            for u in other.unknowns {
                if !outcome.unknowns.contains(&u) {
                    outcome.unknowns.push(u);
                }
            }
        }
        outcome
    }

    /// One reading with the policies: [`evaluate_reading`](Self::evaluate_reading),
    /// with the exemptions applied to the rules and the policy findings
    /// merged after VERICTO-085 and VERICTO-087.
    fn evaluate_reading_ctx(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
        policies: &PolicySet,
        ctx: &EvalContext,
        sql: Option<&str>,
    ) -> EvaluationOutcome {
        let mut verdict = crate::policy::set::evaluate(policies, parsed, ctx, policy, sql);
        let rewrites = std::mem::take(&mut verdict.rewrites);
        let mut outcome =
            Self::evaluate_rules_with(parsed, rules, policy, Some(policies), &verdict.exemptions);
        if !policy.sensitive_columns.is_empty() {
            if let Some(v) = sensitive::evaluate(parsed, &policy.sensitive_columns) {
                outcome = apply_sensitive(outcome, v, policy);
            }
        }
        let outcome = Self::with_access(outcome, parsed, policy);
        let outcome = with_policies(outcome, verdict);
        // The only cost without a `rewrite_limit` policy: this check.
        let outcome = if rewrites.is_empty() {
            outcome
        } else {
            with_rewrites(outcome, parsed, sql, rewrites, policy)
        };
        Self::with_unread(outcome, parsed, policy)
    }

    /// One reading: the rules, then the sensitive columns, then the
    /// identity's allowlist (design §6.1 precedence: applied after 085, so a
    /// `block` tag keeps the flat fields and an allowed `mask` keeps its
    /// rewrite).
    fn evaluate_reading(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        let mut outcome = Self::evaluate_rules(parsed, rules, policy);
        // The only cost when no column is tagged: this check.
        if !policy.sensitive_columns.is_empty() {
            if let Some(verdict) = sensitive::evaluate(parsed, &policy.sensitive_columns) {
                outcome = apply_sensitive(outcome, verdict, policy);
            }
        }
        let outcome = Self::with_access(outcome, parsed, policy);
        Self::with_unread(outcome, parsed, policy)
    }

    /// Snowflake or SQLite code the engine did not read (a scripting block,
    /// `EXECUTE IMMEDIATE`, a statement only the pre-classifier recognised): the
    /// parse-error outcome is a floor, resolved as for any parse error (a
    /// flag by default, a block under `parse_error: block`, a protective tag
    /// or an enforced allowlist). The findings keep the flat fields unless
    /// the floor outranks their winner in the shared order (a stronger
    /// action; at the same action, the floor's Medium above a Low or
    /// Informational finding), so what cannot be read is never
    /// treated more leniently than a parse error, and what was recognised is
    /// still named in the report.
    fn with_unread(
        outcome: EvaluationOutcome,
        parsed: &ParsedQuery,
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        let Some(why) = parsed.unread.as_deref() else {
            return outcome;
        };
        let floor = parse_error_outcome(why, policy);
        if outranks(floor.precedence(), outcome.precedence()) {
            let mut floor = floor;
            // Keep the audit trail (the decision comes from the floor alone).
            floor.sensitive_columns = outcome.sensitive_columns;
            floor.access_denied = outcome.access_denied;
            if !outcome.violations.is_empty() {
                let codes: Vec<&str> = outcome
                    .violations
                    .iter()
                    .map(|v| v.rule_code.as_str())
                    .collect();
                floor.ast_node_path = floor
                    .ast_node_path
                    .map(|p| format!("{p} (also reported: {})", codes.join(", ")));
            }
            floor
        } else {
            outcome
        }
    }

    /// Folds the identity's allowlist (VERICTO-087) into `outcome`. The only
    /// cost without a policy: this check.
    fn with_access(
        outcome: EvaluationOutcome,
        parsed: &ParsedQuery,
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        let Some(access_policy) = policy.access_policy.as_ref() else {
            return outcome;
        };
        match access::evaluate(parsed, access_policy) {
            Some(verdict) => apply_access(outcome, verdict, policy),
            None => outcome,
        }
    }

    fn evaluate_rules(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
    ) -> EvaluationOutcome {
        Self::evaluate_rules_with(parsed, rules, policy, None, &[])
    }

    /// [`evaluate_rules`](Self::evaluate_rules), leaving out the rules a
    /// policy set evaluates itself, and with the class caps of the
    /// exemptions that applied (`action.min(cap)`, like
    /// `schema_migration_cap`).
    fn evaluate_rules_with(
        parsed: &ParsedQuery,
        rules: &[Rule],
        policy: &EnforcementPolicy,
        policies: Option<&PolicySet>,
        caps: &[(RuleClass, EnforcementAction)],
    ) -> EvaluationOutcome {
        // Collect every violation, then order them. The loop already evaluated
        // every rule to find the worst one — the previous version simply discarded
        // the rest — so keeping them costs a push, not extra evaluation.
        let mut violations: Vec<ReportedViolation> = rules
            .iter()
            .filter(|rule| {
                rule.rule_type != RuleType::Custom
                    || policies.is_none_or(|set| !set.contains_rule(&rule.rule_id))
            })
            .filter_map(|rule| {
                evaluator::evaluate_rule(rule, parsed).map(|v| ReportedViolation {
                    // Resolve each action through the per-class path so a channel's
                    // schema-migration cap (if any) softens DDL without touching
                    // DataMutation / Security violations. Class comes from the rule
                    // code — a static property, not a channel input.
                    action: {
                        let class = RuleClass::for_code(&v.rule_code);
                        let base = policy.action_for_class(rule.severity, class);
                        caps.iter()
                            .filter(|(c, _)| *c == class)
                            .fold(base, |a, (_, cap)| a.min(*cap))
                    },
                    severity: rule.severity,
                    rule_id: v.rule_id,
                    rule_code: v.rule_code,
                    ast_node_path: v.ast_node_path,
                    estimated_rows_affected: v.estimated_rows_affected,
                    suggested_safe_query: v.suggested_safe_query,
                })
            })
            .collect();

        // Strongest resolved action first, then highest severity, then lowest
        // rule code (`by_precedence`), so `violations[0]` is the winner and its
        // action is the strongest of the set. Every statement of the input is
        // in this one set, so this is also where a multi-statement script gets
        // its single verdict.
        //
        // Sorting on the violations themselves — never on position in `rules` — is
        // the point: the host supplies that slice, the control plane serves it from
        // a query with no ORDER BY, so position is not a property of the query
        // being evaluated. Letting it decide made the reported code vary between
        // runs on identical input (fixed in 3.2.4).
        violations.sort_by(|a, b| by_precedence(a.precedence(), b.precedence()));

        match violations.first() {
            None => EvaluationOutcome::allowed(),
            Some(winner) => {
                // The winner holds the strongest action, so the decision is the
                // strongest action of the set: never weaker than any violation.
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
                    access_denied: Vec::new(),
                    policy_hits: Vec::new(),
                    approval_required: None,
                    unknowns: Vec::new(),
                }
            }
        }
    }
}

/// The outcome for text that does not parse (R5.5/R5.6): resolved from
/// [`EnforcementPolicy::effective_parse_error`], reported as
/// `VERICTO-PARSE-ERROR` at Medium.
pub(crate) fn parse_error_outcome(
    err: impl std::fmt::Display,
    policy: &EnforcementPolicy,
) -> EvaluationOutcome {
    parse_error_outcome_as(err, policy.effective_parse_error())
}

/// [`parse_error_outcome`] with the action already resolved (see
/// [`EnforcementPolicy::effective_parse_error_for`]).
pub(crate) fn parse_error_outcome_as(
    err: impl std::fmt::Display,
    resolved: ParseErrorAction,
) -> EvaluationOutcome {
    EvaluationOutcome {
        decision: match resolved {
            ParseErrorAction::AllowReport => Decision::Flag,
            ParseErrorAction::Block => Decision::Block,
        },
        action: Some(match resolved {
            ParseErrorAction::Block => EnforcementAction::Block,
            ParseErrorAction::AllowReport => EnforcementAction::Flag,
        }),
        // Parse-error telemetry severity is Medium by product decision (R8.6).
        severity: Some(Severity::Medium),
        rule_id: None,
        rule_code: Some("VERICTO-PARSE-ERROR".to_string()),
        ast_node_path: Some(format!("PARSE_ERROR: {err}")),
        estimated_rows_affected: None,
        suggested_safe_query: None,
        // A parse error is not a rule violation: nothing was evaluated, so
        // there is no set to report. The pseudo-code in `rule_code` is
        // telemetry, not a catalogue entry, and putting it here would make
        // `violations` disagree with "every rule this query broke".
        violations: Vec::new(),
        rewritten_query: None,
        sensitive_columns: Vec::new(),
        access_denied: Vec::new(),
        policy_hits: Vec::new(),
        approval_required: None,
        unknowns: Vec::new(),
    }
}

/// VERICTO-086: the text cannot be read the way MySQL reads it.
fn divergence_outcome(why: &str, policy: &EnforcementPolicy) -> EvaluationOutcome {
    // monitor_mode never blocks (dry-run), and still reports.
    let action = if policy.monitor_mode {
        EnforcementAction::Flag
    } else {
        EnforcementAction::Block
    };
    let v = ReportedViolation {
        rule_id: TEXT_DIVERGENCE_RULE_CODE.to_string(),
        rule_code: TEXT_DIVERGENCE_RULE_CODE.to_string(),
        severity: Severity::Critical,
        action,
        ast_node_path: format!("LexicalDivergence > MySQL may read this text differently ({why})"),
        estimated_rows_affected: None,
        suggested_safe_query: None,
    };
    EvaluationOutcome {
        decision: Decision::from_action(action),
        action: Some(action),
        severity: Some(v.severity),
        rule_id: Some(v.rule_id.clone()),
        rule_code: Some(v.rule_code.clone()),
        ast_node_path: Some(v.ast_node_path.clone()),
        estimated_rows_affected: None,
        suggested_safe_query: None,
        violations: vec![v],
        rewritten_query: None,
        sensitive_columns: Vec::new(),
        access_denied: Vec::new(),
        policy_hits: Vec::new(),
        approval_required: None,
        unknowns: Vec::new(),
    }
}

/// What a finding is ranked by: its resolved action, its severity and its code.
/// `None` fields (an outcome with no violation) rank below every `Some`.
#[derive(Debug, Clone, Copy)]
struct Precedence<'a> {
    action: Option<EnforcementAction>,
    severity: Option<Severity>,
    code: Option<&'a str>,
}

impl ReportedViolation {
    fn precedence(&self) -> Precedence<'_> {
        Precedence {
            action: Some(self.action),
            severity: Some(self.severity),
            code: Some(&self.rule_code),
        }
    }
}

impl EvaluationOutcome {
    /// The precedence of the winner the flat fields carry.
    fn precedence(&self) -> Precedence<'_> {
        Precedence {
            action: self.action,
            severity: self.severity,
            code: self.rule_code.as_deref(),
        }
    }
}

/// The one order every winner in the engine is chosen by: the strongest
/// resolved action first (Block > Flag > Monitor > none), then the highest
/// severity, then the lowest rule code. `Ordering::Less` means `a` ranks
/// ahead of `b`. It is total, and nothing in it depends on the order of the
/// host's `rules` slice, so the result is deterministic.
///
/// Action comes first because the decision is the strongest action of the
/// set: ranking by severity first let a violation whose action a policy
/// softened (a `schema_migration_cap`, `monitor_mode`, a host's severity
/// mapping) outrank one that blocks, and the weaker action became the
/// decision (fixed in 4.2.0). It governs the order of
/// [`EvaluationOutcome::violations`], the slot VERICTO-085 and VERICTO-087
/// take in it, the MySQL reading kept when the text has several
/// (VERICTO-086), and the parse-error floor of unread code.
fn by_precedence(a: Precedence<'_>, b: Precedence<'_>) -> Ordering {
    b.action
        .cmp(&a.action)
        .then_with(|| b.severity.cmp(&a.severity))
        .then_with(|| a.code.cmp(&b.code))
}

/// True when `a` ranks strictly ahead of `b`: on a full tie the finding
/// already in place stays.
fn outranks(a: Precedence<'_>, b: Precedence<'_>) -> bool {
    by_precedence(a, b) == Ordering::Less
}

/// Inserts an engine-driven violation (VERICTO-085, VERICTO-087) into the
/// outcome's ordered set. When it ranks first it becomes the winner and takes
/// the flat fields; otherwise the winner keeps them.
fn merge_violation(outcome: &mut EvaluationOutcome, v: ReportedViolation) {
    let pos = outcome
        .violations
        .iter()
        .position(|o| outranks(v.precedence(), o.precedence()))
        .unwrap_or(outcome.violations.len());
    if pos == 0 {
        outcome.decision = Decision::from_action(v.action);
        outcome.action = Some(v.action);
        outcome.severity = Some(v.severity);
        outcome.rule_id = Some(v.rule_id.clone());
        outcome.rule_code = Some(v.rule_code.clone());
        outcome.ast_node_path = Some(v.ast_node_path.clone());
        outcome.estimated_rows_affected = None;
        outcome.suggested_safe_query = v.suggested_safe_query.clone();
    }
    outcome.violations.insert(pos, v);
}

/// Folds the sensitive-column verdict into the rule engine's outcome.
///
/// The column verdict is a **floor**: the final decision is the stricter of
/// the two, so a tag can only ever make a query stricter, and a rule set to
/// Flag cannot let a blocked column through (nor a flagged column let a
/// blocked DELETE through).
///
/// VERICTO-085 joins `violations` at its place in the shared order (action,
/// then severity, then code; see `by_precedence`). When that place is first it
/// is the winner and the flat fields are its; otherwise the rule winner keeps
/// them.
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

    merge_violation(&mut outcome, v);

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

/// Folds the allowlist verdict (VERICTO-087) into the outcome so far (rules,
/// then VERICTO-085).
///
/// Like the column verdict, a floor: the final decision is the strictest.
/// VERICTO-087 joins `violations` at its place in the shared order and takes
/// the flat fields only when it ranks first, so a VERICTO-085 block keeps
/// them (same action and severity, lower code: design §6.1 step 1, a `block`
/// tag always wins). A block clears any mask rewrite: a refused query is never
/// forwarded, masked or not. Under `mode = observe` (and `monitor_mode`) it
/// flags and never blocks, and an allowed mask keeps its rewrite (steps 3/4
/// still apply).
fn apply_access(
    mut outcome: EvaluationOutcome,
    verdict: access::AccessVerdict,
    policy: &EnforcementPolicy,
) -> EvaluationOutcome {
    let action = if verdict.mode == AccessMode::Observe || policy.monitor_mode {
        EnforcementAction::Flag
    } else {
        EnforcementAction::Block
    };
    let v = ReportedViolation {
        rule_id: ACCESS_RULE_CODE.to_string(),
        rule_code: ACCESS_RULE_CODE.to_string(),
        severity: Severity::High,
        action,
        ast_node_path: verdict.ast_node_path,
        estimated_rows_affected: None,
        suggested_safe_query: verdict.suggested_safe_query,
    };
    merge_violation(&mut outcome, v);
    if outcome.decision == Decision::Block {
        outcome.rewritten_query = None;
    }
    union_denied(&mut outcome.access_denied, verdict.denied);
    outcome
}

/// Folds the policy verdict into the outcome so far (rules, VERICTO-085,
/// VERICTO-087): a floor, like the column and allowlist verdicts. A policy
/// violation joins `violations` after every non-policy finding of the same
/// action (design §4.6: 085 block, then 087 deny, then policy block), and an
/// approval policy after the other policy findings of the same action; it
/// takes the flat fields only when its action is strictly stronger than
/// everything before it. A block clears any mask rewrite.
fn with_policies(
    mut outcome: EvaluationOutcome,
    verdict: crate::policy::set::Verdict,
) -> EvaluationOutcome {
    let approval_codes: Vec<&str> = verdict.approvals.iter().map(|(c, _)| c.as_str()).collect();
    let mut vs = verdict.violations;
    vs.sort_by(|a, b| {
        b.action
            .cmp(&a.action)
            .then_with(|| {
                approval_codes
                    .contains(&a.rule_code.as_str())
                    .cmp(&approval_codes.contains(&b.rule_code.as_str()))
            })
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.rule_code.cmp(&b.rule_code))
    });
    for v in vs {
        let pos = outcome
            .violations
            .iter()
            .position(|o| o.action < v.action)
            .unwrap_or(outcome.violations.len());
        if pos == 0 {
            outcome.decision = Decision::from_action(v.action);
            outcome.action = Some(v.action);
            outcome.severity = Some(v.severity);
            outcome.rule_id = Some(v.rule_id.clone());
            outcome.rule_code = Some(v.rule_code.clone());
            outcome.ast_node_path = Some(v.ast_node_path.clone());
            outcome.estimated_rows_affected = None;
            outcome.suggested_safe_query = None;
        }
        outcome.violations.insert(pos, v);
    }
    if outcome.decision == Decision::Block {
        outcome.rewritten_query = None;
        // Approval can unblock only when every block is an approval policy.
        let only_approvals = outcome
            .violations
            .iter()
            .filter(|v| v.action == EnforcementAction::Block)
            .all(|v| approval_codes.contains(&v.rule_code.as_str()));
        if only_approvals {
            outcome.approval_required = outcome
                .violations
                .iter()
                .find(|v| v.action == EnforcementAction::Block)
                .and_then(|v| {
                    verdict
                        .approvals
                        .iter()
                        .find(|(c, _)| *c == v.rule_code)
                        .map(|(_, a)| a.clone())
                });
        }
    }
    outcome.policy_hits.extend(verdict.hits);
    outcome.unknowns.extend(verdict.unknowns);
    outcome
}

/// Applies the violated `rewrite_limit` policies (design §4.6 step 6: after
/// every other finding, on top of a VERICTO-085 mask) and folds what they
/// did into the outcome:
///
/// - a statement that cannot be bounded safely blocks (failure blocks), and
///   so does an UNKNOWN bound under `on_unknown: block`;
/// - a bounded statement is a monitor finding of the policy, and
///   `rewritten_query` carries the LIMIT, unless the outcome blocks anyway or
///   the policy (or `monitor_mode`) only observes: then the would-be text is
///   the finding's `suggested_safe_query` and nothing is rewritten.
fn with_rewrites(
    outcome: EvaluationOutcome,
    parsed: &ParsedQuery,
    sql: Option<&str>,
    requests: Vec<crate::policy::set::RewriteRequest>,
    policy: &EnforcementPolicy,
) -> EvaluationOutcome {
    use crate::policy::rewrite::{self, LimitRewrite, StatementLimit};
    use crate::policy::set::{OnUnknown, RewriteRequest, Verdict};
    use crate::policy::{PolicyAction, PolicyOutcome};

    let observed = |r: &RewriteRequest| r.monitor || policy.monitor_mode;
    // The lowest cap per statement among `requests` that pass `keep`.
    let caps = |keep: &dyn Fn(&RewriteRequest) -> bool| -> Vec<(usize, u64)> {
        let mut out: Vec<(usize, u64)> = Vec::new();
        for r in requests.iter().filter(|r| keep(r)) {
            match out.iter_mut().find(|(i, _)| *i == r.statement) {
                Some((_, n)) => *n = (*n).min(r.limit),
                None => out.push((r.statement, r.limit)),
            }
        }
        out
    };
    let enforced = caps(&|r| !observed(r));
    let every = caps(&|_| true);

    // The text to bound: the mask's when one applied, else the client's.
    let masked = outcome.rewritten_query.clone();
    let reparsed = masked
        .as_deref()
        .and_then(|m| parsed.dialect().and_then(|d| rewrite::reparse(m, d)));
    let run = |caps: &[(usize, u64)]| -> Option<LimitRewrite> {
        if caps.is_empty() {
            return None;
        }
        Some(match (&masked, &reparsed) {
            (None, _) => rewrite::rewrite(parsed, sql, caps),
            (Some(m), Some(p)) => rewrite::rewrite(p, Some(m), caps),
            (Some(_), None) => LimitRewrite {
                statements: caps
                    .iter()
                    .map(|(i, _)| {
                        (
                            *i,
                            StatementLimit::Failed(
                                "the masked text does not parse back for the LIMIT rewrite".into(),
                            ),
                        )
                    })
                    .collect(),
                sql: None,
            },
        })
    };
    let applied = run(&enforced);
    let would = if every == enforced {
        applied.clone()
    } else {
        run(&every)
    };
    let status = |r: &RewriteRequest| -> StatementLimit {
        let from = if observed(r) { &would } else { &applied };
        from.as_ref()
            .and_then(|lr| lr.statements.iter().find(|(i, _)| *i == r.statement))
            .map_or(StatementLimit::Unchanged, |(_, s)| s.clone())
    };
    let path = |r: &RewriteRequest, extra: &str| match &r.label {
        Some(l) => format!("Policy > {} ({l}): {}{extra}", r.code, r.message),
        None => format!("Policy > {}: {}{extra}", r.code, r.message),
    };
    let soften = |a: EnforcementAction, r: &RewriteRequest| {
        if observed(r) && a == EnforcementAction::Block {
            EnforcementAction::Flag
        } else {
            a
        }
    };

    // 1. Failures and UNKNOWN bounds.
    let mut first = Verdict::default();
    let mut blocks = false;
    for r in &requests {
        let (outcome_kind, a, reason) = match status(r) {
            StatementLimit::Failed(why) => (
                PolicyOutcome::RewriteFailed,
                soften(EnforcementAction::Block, r),
                format!("rewrite failed: {why}"),
            ),
            StatementLimit::Unknown(why) => {
                first.unknowns.push(UnknownField {
                    rule_code: r.code.clone(),
                    detail: why.clone(),
                    error: false,
                });
                let a = match r.on_unknown {
                    OnUnknown::Skip => continue,
                    OnUnknown::Flag => EnforcementAction::Flag,
                    OnUnknown::Block => soften(EnforcementAction::Block, r),
                };
                (PolicyOutcome::Inconclusive, a, format!("UNKNOWN: {why}"))
            }
            StatementLimit::Unchanged | StatementLimit::Bounded { .. } => continue,
        };
        blocks |= a == EnforcementAction::Block;
        first.violations.push(ReportedViolation {
            rule_id: r.rule_id.clone(),
            rule_code: r.code.clone(),
            severity: r.severity,
            action: a,
            ast_node_path: path(r, &format!(" [{reason}]")),
            estimated_rows_affected: None,
            suggested_safe_query: None,
        });
        first.hits.push(PolicyHit {
            rule_id: r.rule_id.clone(),
            rule_code: r.code.clone(),
            severity: r.severity,
            statement: r.statement,
            outcome: outcome_kind,
            requested: PolicyAction::RewriteLimit,
            action: Some(a),
            message: r.message.clone(),
            reason: Some(reason),
        });
    }
    let mut outcome = with_policies(outcome, first);
    if blocks {
        // A block that is not an approval: no grant can unblock it.
        outcome.approval_required = None;
    }

    // 2. Bounded statements: applied when nothing blocks and the policy enforces.
    let apply = outcome.decision != Decision::Block;
    let mut second = Verdict::default();
    let mut any_applied = false;
    for r in &requests {
        let StatementLimit::Bounded { ordered } = status(r) else {
            continue;
        };
        let text = if observed(r) { &would } else { &applied }
            .as_ref()
            .and_then(|lr| lr.sql.clone());
        let applies_here = apply && !observed(r);
        any_applied |= applies_here;
        let mut notes = Vec::new();
        if !applies_here {
            notes.push(if observed(r) {
                "monitor: would rewrite, not applied"
            } else {
                "not applied: the statement is blocked"
            });
        }
        if !ordered {
            notes.push("no ORDER BY: the rows kept are an arbitrary subset");
        }
        second.violations.push(ReportedViolation {
            rule_id: r.rule_id.clone(),
            rule_code: r.code.clone(),
            severity: r.severity,
            action: EnforcementAction::Monitor,
            ast_node_path: path(r, &format!(" [LIMIT {}]", r.limit)),
            estimated_rows_affected: None,
            suggested_safe_query: text,
        });
        second.hits.push(PolicyHit {
            rule_id: r.rule_id.clone(),
            rule_code: r.code.clone(),
            severity: r.severity,
            statement: r.statement,
            outcome: PolicyOutcome::Rewritten,
            requested: PolicyAction::RewriteLimit,
            action: Some(EnforcementAction::Monitor),
            message: r.message.clone(),
            reason: (!notes.is_empty()).then(|| notes.join("; ")),
        });
    }
    let mut outcome = with_policies(outcome, second);
    if any_applied && outcome.decision != Decision::Block {
        if let Some(sql) = applied.and_then(|lr| lr.sql) {
            outcome.rewritten_query = Some(sql);
        }
    }
    outcome
}

/// Adds `more` to `into`, keeping it sorted and free of duplicates.
fn union_denied(into: &mut Vec<DeniedRef>, more: Vec<DeniedRef>) {
    if more.is_empty() {
        return;
    }
    into.extend(more);
    into.sort();
    into.dedup();
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

    /// The codes of `violations`, in reported order.
    fn violation_codes(o: &EvaluationOutcome) -> Vec<&str> {
        o.violations.iter().map(|v| v.rule_code.as_str()).collect()
    }

    /// VERICTO-085 and VERICTO-087 join the rule violations without taking the
    /// flat fields when they are not stricter. Their slot must follow the same
    /// (severity desc, code asc) order as the rules, whatever the order of the
    /// caller's slice: the audit trail is part of the deterministic outcome.
    #[test]
    fn engine_driven_codes_join_the_violation_list_in_severity_then_code_order() {
        let sql = "SELECT * FROM users";
        let tagged = EnforcementPolicy {
            sensitive_columns: vec![crate::sensitive::SensitiveColumn {
                schema: None,
                table: "users".into(),
                column: "email".into(),
                policy: crate::sensitive::SensitivePolicy::Flag,
                mask_style: crate::sensitive::MaskStyle::Full,
            }],
            ..EnforcementPolicy::default()
        };
        // A `flag` tag reports at Medium: between a High and a Low rule.
        let high = rule_at("VERICTO-050", Severity::High);
        let low = rule_at("VERICTO-051", Severity::Low);
        for slice in [[high.clone(), low.clone()], [low.clone(), high.clone()]] {
            let o = crate::evaluate(sql, Dialect::Postgres, &slice, &tagged);
            assert_eq!(o.decision, Decision::Block);
            assert_eq!(o.rule_code.as_deref(), Some("VERICTO-050"));
            assert_eq!(
                violation_codes(&o),
                ["VERICTO-050", "VERICTO-085", "VERICTO-051"]
            );
        }
        // At equal severity the lower code goes first: VERICTO-051 < 085.
        let medium = rule_at("VERICTO-051", Severity::Medium);
        let o = crate::evaluate(sql, Dialect::Postgres, &[high.clone(), medium], &tagged);
        assert_eq!(
            violation_codes(&o),
            ["VERICTO-050", "VERICTO-051", "VERICTO-085"]
        );

        // VERICTO-087 (High, Block under enforce) is not strictly stricter
        // than a blocking Critical rule, so it also takes its ordered slot.
        let denied = EnforcementPolicy {
            access_policy: Some(crate::access::AccessPolicy {
                mode: crate::access::AccessMode::Enforce,
                entries: Vec::new(),
                ddl: crate::access::DdlPolicy::Deny,
                default_schema: None,
                default_database: None,
                quoted_identifiers_ignore_case: None,
            }),
            ..EnforcementPolicy::default()
        };
        let critical = rule_at("VERICTO-050", Severity::Critical);
        for (other, want) in [
            (
                rule_at("VERICTO-051", Severity::High),
                ["VERICTO-050", "VERICTO-051", "VERICTO-087"],
            ),
            (
                rule_at("VERICTO-051", Severity::Medium),
                ["VERICTO-050", "VERICTO-087", "VERICTO-051"],
            ),
        ] {
            for slice in [
                [critical.clone(), other.clone()],
                [other.clone(), critical.clone()],
            ] {
                let o = crate::evaluate(sql, Dialect::Postgres, &slice, &denied);
                assert_eq!(o.decision, Decision::Block);
                assert_eq!(o.rule_code.as_deref(), Some("VERICTO-050"));
                assert_eq!(violation_codes(&o), want);
            }
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
            "VERICTO-085",
            "VERICTO-086",
            "VERICTO-087",
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
