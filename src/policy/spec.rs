// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The policy document: the custom-rule YAML with the policy keys (design
//! §4.4), parsed and validated into a [`PolicySpec`].
//!
//! **Backward compatibility.** A document is a policy only when it carries
//! one of [`POLICY_KEYS`]. Every other custom rule, including one with keys
//! today's engine already ignores (`severity:`, `metadata:`), is a custom
//! rule exactly as before, evaluated by the same code as 4.3.0.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_norway::Value as Yaml;

use super::cel::{Const, Program, time};
use super::context::{HostMode, PrincipalType, Trust};
use super::rewrite::MAX_REWRITE_LIMIT;
use crate::parser::StatementKind;
use crate::rules::engine::{EnforcementAction, RuleClass};

/// The keys that make a custom-rule document a policy.
pub const POLICY_KEYS: &[&str] = &[
    "when",
    "deny_if",
    "require",
    "action",
    "applies_to",
    "min_trust",
    "exempt",
    "modes",
    "vars",
    "on_unknown",
];

/// Keys of later phases: refused, with the phase that brings them.
const LATER_KEYS: &[(&str, &str)] = &[
    ("deny_after", "post-execution checks are Phase 3"),
    ("limits", "runtime row caps are Phase 2"),
    ("budget", "stateful budgets are Phase 3"),
    ("params", "bind values are Phase 2"),
];

/// Most policies one set compiles (design §4.7: 200 CEL rules per
/// workspace). Policies past it, in code order, fail closed.
pub const MAX_POLICIES: usize = 200;

/// Longest `message:`.
const MAX_MESSAGE_BYTES: usize = 512;

/// Whether a custom rule's YAML is a policy document (and not one of
/// today's custom rules). Malformed YAML is not a policy: it stays on the
/// custom-rule path, which skips it as before.
pub fn is_policy_document(yaml: &str) -> bool {
    match serde_norway::from_str::<Yaml>(yaml) {
        Ok(Yaml::Mapping(m)) => m
            .keys()
            .any(|k| k.as_str().is_some_and(|k| POLICY_KEYS.contains(&k))),
        _ => false,
    }
}

/// What a policy does when it is violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyAction {
    Allow,
    Monitor,
    Flag,
    Block,
    /// Reported as a block with [`crate::EvaluationOutcome::approval_required`]:
    /// a host that does not know approvals blocks (the fail-safe direction).
    RequireApproval,
    /// `{ rewrite_limit: n }`: bound a top-level SELECT to `n` rows by adding
    /// or clamping its outer `LIMIT` (design §8.1). An applied rewrite is a
    /// monitor finding with [`crate::EvaluationOutcome::rewritten_query`]; a
    /// rewrite that cannot be verified blocks. Since 4.5.0.
    RewriteLimit,
}

impl PolicyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyAction::Allow => "allow",
            PolicyAction::Monitor => "monitor",
            PolicyAction::Flag => "flag",
            PolicyAction::Block => "block",
            PolicyAction::RequireApproval => "require_approval",
            PolicyAction::RewriteLimit => "rewrite_limit",
        }
    }

    fn parse(s: &str) -> Option<PolicyAction> {
        Some(match s {
            "allow" => PolicyAction::Allow,
            "monitor" => PolicyAction::Monitor,
            "flag" => PolicyAction::Flag,
            "block" => PolicyAction::Block,
            "require_approval" => PolicyAction::RequireApproval,
            _ => return None,
        })
    }

    pub(crate) fn blocking(self) -> bool {
        matches!(self, PolicyAction::Block | PolicyAction::RequireApproval)
    }
}

/// What an UNKNOWN does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnUnknown {
    Block,
    Flag,
    Skip,
}

/// Who may approve, and for how long (Phase 3 consumes it; Phase 1 reports
/// it so hosts and the simulator can count approval load).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ApprovalSpec {
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub quorum: u32,
    pub request_timeout_secs: u64,
    pub grant_ttl_secs: u64,
}

/// The ops `applies_to.ops` and `stmt.op` know.
pub(crate) const OPS: &[&str] = &[
    "select", "insert", "update", "delete", "merge", "ddl", "copy", "call", "set", "other",
];

#[derive(Debug, Clone, Default)]
pub(crate) struct AppliesTo {
    /// Bit i: OPS[i]. 0: every op.
    pub(crate) ops: u16,
    pub(crate) tables: Vec<String>,
    /// PrincipalType bits. 0: every type.
    pub(crate) principal_types: u8,
    pub(crate) databases: Vec<String>,
}

impl AppliesTo {
    pub(crate) fn op_bit(op: &str) -> u16 {
        OPS.iter().position(|o| *o == op).map_or(0, |i| 1 << i)
    }

    pub(crate) fn matches_type(&self, t: PrincipalType) -> bool {
        self.principal_types == 0 || self.principal_types & t.bit() != 0
    }

    pub(crate) fn matches_op(&self, op: &str) -> bool {
        self.ops == 0 || self.ops & Self::op_bit(op) != 0
    }

    pub(crate) fn can_match_type(&self, t: PrincipalType) -> bool {
        self.matches_type(t)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Exempt {
    pub(crate) classes: Vec<RuleClass>,
    pub(crate) cap: EnforcementAction,
}

/// A legacy `node_type:` / `condition:` guard kept with CEL.
#[derive(Debug, Clone)]
pub(crate) struct Guard {
    pub(crate) kind: StatementKind,
    pub(crate) condition: Yaml,
}

/// A validated policy document.
#[derive(Debug, Clone)]
pub(crate) struct PolicySpec {
    pub(crate) label: Option<String>,
    pub(crate) monitor: bool,
    pub(crate) applies: AppliesTo,
    pub(crate) modes: Vec<HostMode>,
    pub(crate) guard: Option<Guard>,
    pub(crate) min_trust: Option<Trust>,
    pub(crate) insufficient_flags: bool,
    pub(crate) when: Option<Program>,
    /// (`deny_if` → true, `require` → false, program).
    pub(crate) test: Option<(bool, Program)>,
    pub(crate) on_unknown: OnUnknown,
    pub(crate) action: PolicyAction,
    /// The row count of `action: { rewrite_limit: n }`.
    pub(crate) rewrite_limit: Option<u64>,
    pub(crate) approval: Option<ApprovalSpec>,
    pub(crate) fallback: BTreeMap<PrincipalType, PolicyAction>,
    pub(crate) exempt: Option<Exempt>,
    pub(crate) message: Option<String>,
    pub(crate) warnings: Vec<Issue>,
}

/// A finding on a document, with the key it is about.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Issue {
    /// The YAML key (`deny_if`, `applies_to.ops`, …), or empty for the
    /// document itself.
    pub key: String,
    /// Byte offset in the key's CEL expression, when it is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    pub message: String,
}

impl Issue {
    fn new(key: &str, message: impl Into<String>) -> Self {
        Issue {
            key: key.to_string(),
            offset: None,
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    rule: Option<String>,
    code: Option<Yaml>,
    version: Option<Yaml>,
    severity: Option<Yaml>,
    mode: Option<String>,
    metadata: Option<Yaml>,
    description: Option<Yaml>,
    message: Option<String>,
    tests: Option<Yaml>,
    applies_to: Option<RawApplies>,
    modes: Option<Vec<String>>,
    node_type: Option<String>,
    condition: Option<Yaml>,
    vars: Option<Yaml>,
    min_trust: Option<Yaml>,
    on_insufficient_trust: Option<String>,
    when: Option<Yaml>,
    deny_if: Option<Yaml>,
    require: Option<Yaml>,
    on_unknown: Option<String>,
    action: Option<Yaml>,
    exempt: Option<RawExempt>,
    approval: Option<RawApproval>,
    deny_after: Option<Yaml>,
    limits: Option<Yaml>,
    budget: Option<Yaml>,
    params: Option<Yaml>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawApplies {
    #[serde(default)]
    ops: Vec<String>,
    #[serde(default)]
    tables: Vec<String>,
    #[serde(default)]
    principal_types: Vec<String>,
    #[serde(default)]
    databases: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExempt {
    rule_classes: Vec<String>,
    cap: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawApproval {
    #[serde(default)]
    approvers: Option<RawApprovers>,
    quorum: Option<u32>,
    request_timeout: Option<String>,
    grant_ttl: Option<String>,
    #[serde(default)]
    fallback_for: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawApprovers {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

/// A YAML scalar or tree as a CEL constant (`vars:`).
fn to_const(y: &Yaml, path: &str, errors: &mut Vec<Issue>) -> Const {
    match y {
        Yaml::Null => Const::Null,
        Yaml::Bool(b) => Const::Bool(*b),
        Yaml::Number(n) => {
            if let Some(i) = n.as_i64() {
                Const::Int(i)
            } else if let Some(u) = n.as_u64() {
                Const::Uint(u)
            } else {
                Const::Double(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Yaml::String(s) => Const::Str(s.clone()),
        Yaml::Sequence(items) => Const::List(
            items
                .iter()
                .enumerate()
                .map(|(i, x)| to_const(x, &format!("{path}[{i}]"), errors))
                .collect(),
        ),
        Yaml::Mapping(m) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                match k.as_str() {
                    Some(k) => {
                        let child = to_const(v, &format!("{path}.{k}"), errors);
                        out.insert(k.to_string(), child);
                    }
                    None => errors.push(Issue::new(path, "`vars:` keys must be strings")),
                }
            }
            Const::Map(out)
        }
        Yaml::Tagged(_) => {
            errors.push(Issue::new(path, "YAML tags are not supported in `vars:`"));
            Const::Null
        }
    }
}

/// An expression key: a string, or a YAML bool (`when: true`).
fn expr_src(y: &Yaml, key: &str, errors: &mut Vec<Issue>) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Bool(b) => Some(b.to_string()),
        _ => {
            errors.push(Issue::new(
                key,
                "must be a CEL expression (quote it when it starts with `!`, `[` or `{`)",
            ));
            None
        }
    }
}

fn duration_secs(s: &str, key: &str, max: u64, errors: &mut Vec<Issue>) -> u64 {
    match time::parse_duration(s) {
        Some(n) if n > 0 => {
            let secs = (n as u64).div_ceil(1_000_000_000);
            if secs > max {
                errors.push(Issue::new(key, format!("must be at most {}h", max / 3600)));
            }
            secs
        }
        _ => {
            errors.push(Issue::new(
                key,
                format!("`{s}` is not a positive duration (30m, 15m, 2h)"),
            ));
            0
        }
    }
}

/// Parses and validates a policy document. Errors are every problem found
/// (not only the first), so the editor shows them together.
pub(crate) fn parse(yaml: &str) -> Result<PolicySpec, Vec<Issue>> {
    let raw: Raw = match serde_norway::from_str(yaml) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            // An unknown key: name the ones of later phases.
            for (k, why) in LATER_KEYS {
                if msg.contains(&format!("unknown field `{k}`")) {
                    return Err(vec![Issue::new(
                        k,
                        format!("not available in this engine version: {why}"),
                    )]);
                }
            }
            return Err(vec![Issue::new(
                "",
                format!("invalid policy document: {msg}"),
            )]);
        }
    };
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let _ = (
        &raw.code,
        &raw.version,
        &raw.severity,
        &raw.metadata,
        &raw.description,
        &raw.tests,
    );

    for (val, key, why) in [
        (&raw.deny_after, "deny_after", LATER_KEYS[0].1),
        (&raw.limits, "limits", LATER_KEYS[1].1),
        (&raw.budget, "budget", LATER_KEYS[2].1),
        (&raw.params, "params", LATER_KEYS[3].1),
    ] {
        if val.is_some() {
            errors.push(Issue::new(
                key,
                format!("not available in this engine version: {why}"),
            ));
        }
    }

    let monitor = match raw.mode.as_deref() {
        None | Some("enforce") => false,
        Some("monitor") => true,
        Some(other) => {
            errors.push(Issue::new(
                "mode",
                format!("`{other}` is not a mode (monitor, enforce)"),
            ));
            false
        }
    };

    // applies_to
    let mut applies = AppliesTo::default();
    if let Some(a) = &raw.applies_to {
        for op in &a.ops {
            match AppliesTo::op_bit(op) {
                0 => errors.push(Issue::new(
                    "applies_to.ops",
                    format!("`{op}` is not an op ({})", OPS.join(", ")),
                )),
                bit => applies.ops |= bit,
            }
        }
        for t in &a.principal_types {
            match PrincipalType::parse(t) {
                Some(pt) => applies.principal_types |= pt.bit(),
                None => errors.push(Issue::new(
                    "applies_to.principal_types",
                    format!("`{t}` is not a principal type (agent, service, human, pipeline, tool, unknown)"),
                )),
            }
        }
        for t in &a.tables {
            if t.trim().is_empty() {
                errors.push(Issue::new("applies_to.tables", "an empty table name"));
            }
        }
        applies.tables = a.tables.clone();
        applies.databases = a.databases.clone();
    }

    let mut modes = Vec::new();
    for m in raw.modes.iter().flatten() {
        match HostMode::parse(m) {
            Some(hm) => modes.push(hm),
            None => errors.push(Issue::new(
                "modes",
                format!("`{m}` is not a mode (proxy, runtime_api, mcp, ci)"),
            )),
        }
    }

    // The legacy guard.
    let guard = match (&raw.node_type, &raw.condition) {
        (Some(nt), cond) => match crate::rules::evaluator::node_kind(nt) {
            Some(kind) => Some(Guard {
                kind,
                condition: cond.clone().unwrap_or(Yaml::Null),
            }),
            None => {
                errors.push(Issue::new(
                    "node_type",
                    format!("`{nt}` is not a node type"),
                ));
                None
            }
        },
        (None, Some(_)) => {
            errors.push(Issue::new("condition", "`condition:` needs a `node_type:`"));
            None
        }
        (None, None) => None,
    };

    // vars
    let vars: BTreeMap<String, Const> = match &raw.vars {
        None => BTreeMap::new(),
        Some(y @ Yaml::Mapping(_)) => match to_const(y, "vars", &mut errors) {
            Const::Map(m) => m,
            _ => BTreeMap::new(),
        },
        Some(_) => {
            errors.push(Issue::new(
                "vars",
                "`vars:` must be a mapping of names to constants",
            ));
            BTreeMap::new()
        }
    };

    let min_trust = match &raw.min_trust {
        None => None,
        Some(y) => {
            let s = match y {
                Yaml::String(s) => s.clone(),
                Yaml::Number(n) => n.to_string(),
                _ => String::new(),
            };
            match Trust::parse(&s) {
                Some(t) => Some(t),
                None => {
                    errors.push(Issue::new(
                        "min_trust",
                        "must be weak, medium or strong (or 1, 2, 3)",
                    ));
                    None
                }
            }
        }
    };
    let insufficient_flags = match raw.on_insufficient_trust.as_deref() {
        None | Some("block") => false,
        Some("flag") => true,
        Some(other) => {
            errors.push(Issue::new(
                "on_insufficient_trust",
                format!("`{other}` is not allowed (block, flag): insufficient trust never passes silently"),
            ));
            false
        }
    };

    let mut sources = Vec::new();
    let mut compile = |key: &'static str,
                       y: &Option<Yaml>,
                       errors: &mut Vec<Issue>,
                       warnings: &mut Vec<Issue>| {
        let src = expr_src(y.as_ref()?, key, errors)?;
        sources.push((key, src.clone()));
        match Program::compile(&src, &vars) {
            Ok(p) => {
                if !matches!(
                    p.compiled.ty,
                    super::cel::compile::Ty::Bool | super::cel::compile::Ty::Dyn
                ) {
                    errors.push(Issue::new(key, "must evaluate to a bool"));
                }
                for w in p.warnings() {
                    warnings.push(Issue {
                        key: key.to_string(),
                        offset: Some(w.offset),
                        message: w.message.clone(),
                    });
                }
                Some(p)
            }
            Err(diags) => {
                for d in diags {
                    errors.push(Issue {
                        key: key.to_string(),
                        offset: Some(d.offset),
                        message: d.message,
                    });
                }
                None
            }
        }
    };
    let when = compile("when", &raw.when, &mut errors, &mut warnings);
    if raw.deny_if.is_some() && raw.require.is_some() {
        errors.push(Issue::new(
            "require",
            "use exactly one of `deny_if` and `require`",
        ));
    }
    let test = match (&raw.deny_if, &raw.require) {
        (Some(_), _) => {
            compile("deny_if", &raw.deny_if, &mut errors, &mut warnings).map(|p| (true, p))
        }
        (None, Some(_)) => {
            compile("require", &raw.require, &mut errors, &mut warnings).map(|p| (false, p))
        }
        (None, None) => None,
    };
    for (_, src) in &sources {
        if src.contains("filter_values(") && src.contains(".all(") {
            warnings.push(Issue::new(
                "",
                "`stmt.filter_values(…).all(…)` is true when the column is not filtered at all \
                 (an empty list): pair it with `stmt.has_filter(…)`",
            ));
        }
    }

    // action
    let mut rewrite_limit = None;
    let action = match &raw.action {
        None => None,
        Some(Yaml::String(s)) => match PolicyAction::parse(s) {
            Some(a) => Some(a),
            None => {
                errors.push(Issue::new(
                    "action",
                    format!(
                        "`{s}` is not an action (allow, monitor, flag, block, require_approval)"
                    ),
                ));
                None
            }
        },
        Some(Yaml::Mapping(m)) => {
            let key = m.keys().next().and_then(Yaml::as_str).unwrap_or("");
            if m.len() != 1 {
                errors.push(Issue::new(
                    "action",
                    "an action mapping has exactly one key (`{ rewrite_limit: 1000 }`)",
                ));
                None
            } else if key == "rewrite_limit" {
                let n = m.values().next().and_then(Yaml::as_u64);
                match n {
                    Some(n) if (1..=MAX_REWRITE_LIMIT).contains(&n) => {
                        rewrite_limit = Some(n);
                        Some(PolicyAction::RewriteLimit)
                    }
                    _ => {
                        errors.push(Issue::new(
                            "action.rewrite_limit",
                            format!("must be a whole number of rows from 1 to {MAX_REWRITE_LIMIT}"),
                        ));
                        None
                    }
                }
            } else {
                let why = match key {
                    "inject_predicate" => "the tenant predicate rewrite is Phase 2",
                    _ => "unknown action",
                };
                errors.push(Issue::new(
                    "action",
                    format!("`{key}`: not available in this engine version: {why}"),
                ));
                None
            }
        }
        Some(_) => {
            errors.push(Issue::new("action", "must be an action name"));
            None
        }
    };

    // exempt
    let exempt = match &raw.exempt {
        None => None,
        Some(e) => {
            let mut classes = Vec::new();
            for c in &e.rule_classes {
                match c.as_str() {
                    "schema_migration" => classes.push(RuleClass::SchemaMigration),
                    "performance" => classes.push(RuleClass::Performance),
                    "security" | "data_mutation" => errors.push(Issue::new(
                        "exempt.rule_classes",
                        format!(
                            "`{c}` can never be exempted (never softened by channel or principal)"
                        ),
                    )),
                    other => errors.push(Issue::new(
                        "exempt.rule_classes",
                        format!("`{other}` is not a rule class (schema_migration, performance)"),
                    )),
                }
            }
            let cap = match e.cap.as_str() {
                "monitor" => EnforcementAction::Monitor,
                "flag" => EnforcementAction::Flag,
                other => {
                    errors.push(Issue::new(
                        "exempt.cap",
                        format!("`{other}` is not a cap (monitor, flag)"),
                    ));
                    EnforcementAction::Flag
                }
            };
            if min_trust != Some(Trust::Strong) {
                errors.push(Issue::new(
                    "min_trust",
                    "an exemption loosens rules: it needs `min_trust: strong` (weak signals never loosen)",
                ));
            }
            if raw.deny_if.is_some()
                || raw.require.is_some()
                || raw.action.is_some()
                || raw.approval.is_some()
            {
                errors.push(Issue::new(
                    "exempt",
                    "an exemption cannot also deny: write the restriction as a separate policy",
                ));
            }
            if guard.is_some() {
                errors.push(Issue::new(
                    "exempt",
                    "an exemption cannot use `node_type:`/`condition:` (their match is not per statement)",
                ));
            }
            Some(Exempt { classes, cap })
        }
    };

    let action = action.unwrap_or(PolicyAction::Block);
    if action == PolicyAction::RewriteLimit {
        // A LIMIT rewrite bounds reads: it applies to SELECT only.
        let select = AppliesTo::op_bit("select");
        if applies.ops & !select != 0 {
            errors.push(Issue::new(
                "applies_to.ops",
                "`rewrite_limit` bounds SELECT statements only: use `ops: [select]` or leave `ops` out",
            ));
        }
        applies.ops = select;
        if sources.iter().any(|(_, src)| src.contains("stmt.limit")) {
            warnings.push(Issue::new(
                "",
                "`rewrite_limit` only ever lowers a LIMIT, so a condition on `stmt.limit` is not needed; \
                 it makes `LIMIT $1` UNKNOWN instead of rewriting it to `LEAST($1, n)`",
            ));
        }
    }
    if action == PolicyAction::Allow {
        warnings.push(Issue::new(
            "action",
            "`allow` has no effect on other rules; use `exempt:` to loosen a rule class",
        ));
    }

    // approval
    let mut fallback = BTreeMap::new();
    let approval = match (&raw.approval, action) {
        (raw_appr, PolicyAction::RequireApproval) => {
            let def = RawApproval::default();
            let a = raw_appr.as_ref().unwrap_or(&def);
            let approvers = a.approvers.as_ref();
            let mut roles = approvers.map(|x| x.roles.clone()).unwrap_or_default();
            let groups = approvers.map(|x| x.groups.clone()).unwrap_or_default();
            if roles.is_empty() && groups.is_empty() {
                roles.push("admin".to_string());
            }
            let quorum = a.quorum.unwrap_or(1);
            if quorum == 0 || quorum > 2 {
                errors.push(Issue::new("approval.quorum", "must be 1 or 2"));
            }
            let request_timeout_secs = duration_secs(
                a.request_timeout.as_deref().unwrap_or("30m"),
                "approval.request_timeout",
                24 * 3600,
                &mut errors,
            );
            let grant_ttl_secs = duration_secs(
                a.grant_ttl.as_deref().unwrap_or("15m"),
                "approval.grant_ttl",
                24 * 3600,
                &mut errors,
            );
            for (k, v) in &a.fallback_for {
                let pt = PrincipalType::parse(k);
                let act = match v.as_str() {
                    "block" => Some(PolicyAction::Block),
                    "flag" => Some(PolicyAction::Flag),
                    _ => None,
                };
                match (pt, act) {
                    (Some(pt), Some(act)) => {
                        fallback.insert(pt, act);
                    }
                    _ => errors.push(Issue::new(
                        "approval.fallback_for",
                        format!("`{k}: {v}`: a principal type mapped to block or flag"),
                    )),
                }
            }
            // Services, pipelines and tools never wait for a human.
            for pt in [
                PrincipalType::Service,
                PrincipalType::Pipeline,
                PrincipalType::Tool,
            ] {
                if applies.can_match_type(pt) && !fallback.contains_key(&pt) {
                    errors.push(Issue::new(
                        "approval.fallback_for",
                        format!(
                            "this policy can match `{}` principals, which never wait for a human: \
                             map them to block or flag in `fallback_for`, or narrow `applies_to.principal_types`",
                            pt.as_str()
                        ),
                    ));
                }
            }
            Some(ApprovalSpec {
                roles,
                groups,
                quorum,
                request_timeout_secs,
                grant_ttl_secs,
            })
        }
        (Some(_), _) => {
            errors.push(Issue::new(
                "approval",
                "`approval:` needs `action: require_approval`",
            ));
            None
        }
        (None, _) => None,
    };

    let on_unknown = match raw.on_unknown.as_deref() {
        None => {
            if action.blocking() {
                OnUnknown::Block
            } else {
                OnUnknown::Flag
            }
        }
        Some("block") => OnUnknown::Block,
        Some("flag") => OnUnknown::Flag,
        Some("skip") => {
            if modes.is_empty() {
                errors.push(Issue::new(
                    "on_unknown",
                    "`skip` needs an explicit `modes:` list, so a policy cannot silently vanish everywhere",
                ));
            }
            OnUnknown::Skip
        }
        Some(other) => {
            errors.push(Issue::new(
                "on_unknown",
                format!("`{other}` is not allowed (block, flag, skip)"),
            ));
            OnUnknown::Block
        }
    };

    let message = match raw.message {
        Some(m) if m.len() > MAX_MESSAGE_BYTES => {
            errors.push(Issue::new(
                "message",
                format!("at most {MAX_MESSAGE_BYTES} bytes"),
            ));
            None
        }
        Some(m) => Some(interpolate(&m, &vars)),
        None => None,
    };

    if exempt.is_none()
        && raw.applies_to.is_none()
        && when.is_none()
        && test.is_none()
        && guard.is_none()
        && min_trust.is_none()
    {
        warnings.push(Issue::new(
            "",
            "this policy applies to every statement of every principal",
        ));
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(PolicySpec {
        label: raw.rule,
        monitor,
        applies,
        modes,
        guard,
        min_trust,
        insufficient_flags,
        when,
        test,
        on_unknown,
        action,
        rewrite_limit,
        approval,
        fallback,
        exempt,
        message,
        warnings,
    })
}

/// `{{vars.name}}` in a message, from the constants.
fn interpolate(msg: &str, vars: &BTreeMap<String, Const>) -> String {
    let mut out = String::new();
    let mut rest = msg;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let key = after[..end].trim();
                let shown = key
                    .strip_prefix("vars.")
                    .and_then(|k| vars.get(k))
                    .map(display_const);
                match shown {
                    Some(s) => out.push_str(&s),
                    None => {
                        out.push_str("{{");
                        out.push_str(&after[..end]);
                        out.push_str("}}");
                    }
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn display_const(c: &Const) -> String {
    match c {
        Const::Null => "null".into(),
        Const::Bool(b) => b.to_string(),
        Const::Int(i) => i.to_string(),
        Const::Uint(u) => u.to_string(),
        Const::Double(d) => super::cel::value::format_double(*d),
        Const::Str(s) => s.clone(),
        Const::Timestamp(t) => t.to_rfc3339(),
        Const::Duration(d) => time::format_duration(*d),
        Const::List(l) => format!(
            "[{}]",
            l.iter().map(display_const).collect::<Vec<_>>().join(", ")
        ),
        Const::Map(_) => "{…}".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errs(yaml: &str) -> String {
        match parse(yaml) {
            Ok(_) => panic!("should not parse:\n{yaml}"),
            Err(e) => e
                .iter()
                .map(|i| format!("{}: {}", i.key, i.message))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    #[test]
    fn detects_policy_documents_conservatively() {
        assert!(!is_policy_document(
            "rule: x\nnode_type: SelectStmt\ncondition:\n  target_list: '*'"
        ));
        // Keys today's engine already ignores keep the custom-rule path.
        assert!(!is_policy_document(
            "node_type: DropStmt\nseverity: high\nmetadata: {a: 1}\ntests: []"
        ));
        assert!(is_policy_document("when: principal.type == 'agent'"));
        assert!(is_policy_document("node_type: InsertStmt\naction: block"));
        assert!(!is_policy_document("this: [is: not, valid"));
        assert!(!is_policy_document("- a\n- b"));
    }

    #[test]
    fn the_design_examples_parse() {
        let docs = [
            r#"
rule: refunds-over-limit-need-approval
applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [agent, human] }
vars: { limit: 200 }
min_trust: medium
when: principal.type in ["agent", "human"]
deny_if: stmt.values("public.refunds.amount").exists(v, v > vars.limit)
on_unknown: block
action: require_approval
approval:
  approvers: { roles: [admin], groups: ["payments-leads"] }
  quorum: 1
  request_timeout: 30m
  grant_ttl: 15m
message: "Refunds above {{vars.limit}} need approval from payments-leads"
"#,
            r#"
rule: tenant-filter-required
applies_to: { ops: [select, update, delete], principal_types: [service, agent, human, tool] }
vars: { tenant_tables: ["public.invoices", "public.customers"] }
require: >
  stmt.tables.all(t, !(t in vars.tenant_tables) || stmt.has_filter(t + ".tenant_id"))
action: block
"#,
            r#"
rule: prod-ddl-change-window
applies_to: { ops: [ddl] }
when: db.env == "prod"
min_trust: strong
require: >
  principal.type == "pipeline" && principal.id == "ci-migrations" &&
  in_window(time.now, "Tue,Thu 14:00-16:00", "UTC")
action: block
"#,
            r#"
rule: migrations-ddl-exemption
applies_to: { principal_types: [pipeline] }
min_trust: strong
when: principal.id == "ci-migrations"
exempt: { rule_classes: [schema_migration], cap: flag }
"#,
            r#"
rule: ledger-adjustments-four-eyes
applies_to: { ops: [insert, update, delete], tables: ["public.ledger_adjustments"] }
min_trust: medium
action: require_approval
approval:
  approvers: { roles: [admin, owner], groups: ["finance-controllers"] }
  fallback_for: { service: block, pipeline: block, tool: block }
"#,
        ];
        for d in docs {
            parse(d).unwrap_or_else(|e| panic!("{d}\n{e:?}"));
        }
        let p = parse(docs[0]).unwrap();
        assert_eq!(
            p.message.as_deref(),
            Some("Refunds above 200 need approval from payments-leads")
        );
        assert_eq!(p.action, PolicyAction::RequireApproval);
        assert_eq!(p.on_unknown, OnUnknown::Block);
    }

    #[test]
    fn refusals() {
        assert!(errs("when: 'true'\ndeny-if: 'true'").contains("unknown field `deny-if`"));
        assert!(errs("when: 'true'\nlimits: {max_rows_returned: 1}").contains("Phase 2"));
        assert!(errs("action: {rewrite_limit: 0}").contains("from 1 to 1000000"));
        assert!(errs("action: {rewrite_limit: 1000001}").contains("from 1 to 1000000"));
        assert!(errs("action: {rewrite_limit: '10'}").contains("whole number"));
        assert!(errs("action: {rewrite_limit: 10.5}").contains("whole number"));
        assert!(
            errs("action: {rewrite_limit: 10, inject_predicate: {}}").contains("exactly one key")
        );
        assert!(
            errs("applies_to: {ops: [select, update]}\naction: {rewrite_limit: 10}")
                .contains("SELECT statements only")
        );
        assert!(
            errs("applies_to: {principal_types: [agent]}\naction: {rewrite_limit: 10}\napproval: {quorum: 1}")
                .contains("needs `action: require_approval`")
        );
        assert!(errs("action: {inject_predicate: {column: tenant_id}}").contains("Phase 2"));
        assert!(errs("action: nuke").contains("not an action"));
        assert!(errs("deny_if: 'true'\nrequire: 'true'").contains("exactly one"));
        assert!(
            errs("exempt: {rule_classes: [schema_migration], cap: flag}")
                .contains("min_trust: strong")
        );
        assert!(
            errs("min_trust: strong\nexempt: {rule_classes: [security], cap: flag}")
                .contains("never be exempted")
        );
        assert!(errs("min_trust: strong\nexempt: {rule_classes: [schema_migration], cap: flag}\naction: block").contains("cannot also deny"));
        assert!(errs("action: require_approval").contains("fallback_for"));
        assert!(
            errs("action: flag\napproval: {quorum: 1}")
                .contains("needs `action: require_approval`")
        );
        assert!(errs("on_unknown: skip\nwhen: 'true'").contains("explicit `modes:`"));
        assert!(
            errs("when: 'true'\non_insufficient_trust: allow").contains("never passes silently")
        );
        assert!(errs("applies_to: {ops: [drop]}").contains("not an op"));
        assert!(errs("applies_to: {principal_types: [robot]}").contains("not a principal type"));
        assert!(errs("modes: [web]").contains("not a mode"));
        assert!(errs("when: 'principal.typ == \"x\"'").contains("did you mean"));
        assert!(errs("when: '1 + 1'").contains("bool"));
        assert!(errs("when: 42").contains("CEL expression"));
        assert!(errs("node_type: Bogus\nwhen: 'true'").contains("not a node type"));
        assert!(errs("condition: {relation: x}\nwhen: 'true'").contains("needs a `node_type:`"));
        assert!(errs("min_trust: high\nwhen: 'true'").contains("weak, medium or strong"));
        let long = format!("when: 'true'\nmessage: \"{}\"", "x".repeat(600));
        assert!(errs(&long).contains("512"));
        assert!(errs("action: require_approval\napplies_to: {principal_types: [agent]}\napproval: {request_timeout: 48h}").contains("24h"));
    }

    #[test]
    fn defaults_and_warnings() {
        let p = parse("applies_to: {principal_types: [agent]}\naction: flag").unwrap();
        assert_eq!(p.on_unknown, OnUnknown::Flag);
        assert!(!p.monitor);
        let p = parse("when: 'true'").unwrap();
        assert_eq!(p.action, PolicyAction::Block);
        assert_eq!(p.on_unknown, OnUnknown::Block);
        let p = parse("action: allow\nwhen: 'true'").unwrap();
        assert!(p.warnings.iter().any(|w| w.message.contains("no effect")));
        let p = parse("action: block").unwrap();
        assert!(
            p.warnings
                .iter()
                .any(|w| w.message.contains("every statement"))
        );
        let p = parse(r#"require: 'stmt.filter_values("public.t.c").all(v, v == "a")'"#).unwrap();
        assert!(p.warnings.iter().any(|w| w.message.contains("has_filter")));
        let p =
            parse("applies_to: {principal_types: [agent]}\naction: {rewrite_limit: 1000}").unwrap();
        assert_eq!(
            (p.action, p.rewrite_limit),
            (PolicyAction::RewriteLimit, Some(1000))
        );
        assert_eq!(p.on_unknown, OnUnknown::Flag);
        assert_eq!(p.applies.ops, AppliesTo::op_bit("select"));
        let p = parse("when: '!has(stmt.limit) || stmt.limit > 10'\naction: {rewrite_limit: 10}")
            .unwrap();
        assert!(p.warnings.iter().any(|w| w.message.contains("LEAST")));
        let p = parse("action: require_approval\napplies_to: {principal_types: [agent, human]}")
            .unwrap();
        let a = p.approval.unwrap();
        assert_eq!(a.roles, ["admin"]);
        assert_eq!(
            (a.request_timeout_secs, a.grant_ttl_secs, a.quorum),
            (1800, 900, 1)
        );
    }
}
