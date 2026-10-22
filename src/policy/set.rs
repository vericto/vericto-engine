// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The compiled policy set, and how one statement is evaluated against it.
//!
//! Compiled once (when the host's rule sync arrives, or when a rule is
//! saved), shared by every evaluation: `PolicySet` is `Send + Sync` and
//! holds no state between evaluations.

use std::collections::HashSet;

use serde::Serialize;

use super::cel::compile::Func;
use super::cel::{Activation, FaultKind, Field};
use super::context::{EvalContext, HostMode, PrincipalType};
use super::facts::{self, FactList, Facts, Want};
use super::spec::{self, AppliesTo, OnUnknown, PolicyAction, PolicySpec};
use crate::parser::ParsedQuery;
use crate::rules::engine::{
    EnforcementAction, EnforcementPolicy, ReportedViolation, Rule, RuleClass, RuleType, Severity,
};

pub use super::spec::ApprovalSpec;

/// A policy that did not compile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyError {
    pub rule_id: String,
    pub rule_code: String,
    pub issues: Vec<spec::Issue>,
}

/// What a policy found on one statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyOutcome {
    /// The policy's condition holds (a `deny_if` true, a `require` false, or
    /// no condition at all).
    Violated,
    /// The decision needed a value that is not known here; the policy's
    /// `on_unknown` decided (INCONCLUSIVE in the audit trail).
    Inconclusive,
    /// The principal's trust is below the policy's `min_trust`.
    InsufficientTrust,
    /// An exemption applied: rule classes were capped for this principal.
    Exempted,
    /// The policy did not compile: it fails closed in its scope.
    CompileError,
    /// The statement did not parse, and this enforced policy may apply to
    /// it: the parse error is forced to block.
    Unreadable,
}

/// One policy result, for the audit trail and the simulator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyHit {
    pub rule_id: String,
    pub rule_code: String,
    pub severity: Severity,
    /// 0-based top-level statement.
    pub statement: usize,
    pub outcome: PolicyOutcome,
    /// The action the policy asks for.
    pub requested: PolicyAction,
    /// The action it resolved to (after monitor mode and fallbacks);
    /// `None` for `allow` and for exemptions.
    pub action: Option<EnforcementAction>,
    pub message: String,
    /// Why, for inconclusive, insufficient-trust and compile-error hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A required approval: the decision is `Block`, and a host that knows
/// approvals (Phase 3) may unblock it with a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRequirement {
    pub rule_id: String,
    pub rule_code: String,
    pub approval: ApprovalSpec,
}

/// A value a policy needed and could not know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnknownField {
    pub rule_code: String,
    pub detail: String,
    /// `true` for a genuine evaluation error (type mismatch, no such key),
    /// which also deserves an operator alert.
    pub error: bool,
}

#[derive(Debug, Clone)]
struct Broken {
    applies: AppliesTo,
    modes: Vec<HostMode>,
    fail: EnforcementAction,
    monitor: bool,
}

#[derive(Debug, Clone)]
enum Body {
    Ok(Box<PolicySpec>),
    Broken(Broken),
}

#[derive(Debug, Clone)]
struct Compiled {
    rule_id: String,
    code: String,
    severity: Severity,
    body: Body,
    want: Want,
    /// Needs the shape (op, assignments, filters) of the statement.
    needs_facts: bool,
}

/// The policies among a rule set, compiled once.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    policies: Vec<Compiled>,
    ids: HashSet<String>,
    errors: Vec<PolicyError>,
}

impl PolicySet {
    /// An empty set: [`crate::evaluate_with_context`] with it is exactly
    /// [`crate::evaluate`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// Compiles every custom rule of `rules` that is a policy document
    /// ([`spec::is_policy_document`]); every other rule is left to the
    /// rule engine as before. A policy that does not compile is kept, and
    /// fails closed in its scope; [`errors`](Self::errors) lists it.
    pub fn compile(rules: &[Rule]) -> Self {
        let mut docs: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.rule_type == RuleType::Custom)
            .filter(|r| {
                r.ast_condition_yaml
                    .as_deref()
                    .is_some_and(spec::is_policy_document)
            })
            .collect();
        // Deterministic whatever the order of the host's slice.
        docs.sort_by(|a, b| a.code.cmp(&b.code).then_with(|| a.rule_id.cmp(&b.rule_id)));
        let mut set = PolicySet::default();
        for (i, r) in docs.into_iter().enumerate() {
            let yaml = r.ast_condition_yaml.as_deref().unwrap_or_default();
            let parsed = if i >= spec::MAX_POLICIES {
                Err(vec![spec::Issue {
                    key: String::new(),
                    offset: None,
                    message: format!(
                        "more than {} policies: this one fails closed",
                        spec::MAX_POLICIES
                    ),
                }])
            } else {
                spec::parse(yaml)
            };
            let (body, want, needs_facts) = match parsed {
                Ok(s) => {
                    let (want, needs) = wants(&s);
                    (Body::Ok(Box::new(s)), want, needs)
                }
                Err(issues) => {
                    set.errors.push(PolicyError {
                        rule_id: r.rule_id.clone(),
                        rule_code: r.code.clone(),
                        issues,
                    });
                    let b = broken_scope(yaml);
                    let want = Want {
                        refs: !b.applies.tables.is_empty(),
                        functions: false,
                    };
                    let needs = b.applies.ops != 0 || want.refs;
                    (Body::Broken(b), want, needs)
                }
            };
            set.ids.insert(r.rule_id.clone());
            set.policies.push(Compiled {
                rule_id: r.rule_id.clone(),
                code: r.code.clone(),
                severity: r.severity,
                body,
                want,
                needs_facts,
            });
        }
        set
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// The policies that did not compile (they fail closed in their scope).
    pub fn errors(&self) -> &[PolicyError] {
        &self.errors
    }

    /// Whether the rule with this id is one of the set's policies (the rule
    /// engine leaves those to the set).
    pub fn contains_rule(&self, rule_id: &str) -> bool {
        !self.ids.is_empty() && self.ids.contains(rule_id)
    }

    /// Whether a statement the engine cannot read must block for this
    /// context: an enforced blocking policy may apply to it (design §4.6).
    pub(crate) fn blocks_unreadable(
        &self,
        ctx: &EvalContext,
        policy: &EnforcementPolicy,
    ) -> Vec<PolicyHit> {
        if policy.monitor_mode {
            return Vec::new();
        }
        let ptype = ctx.principal_type();
        let mut out = Vec::new();
        for p in &self.policies {
            let (applies, modes, blocking, monitor, requested) = match &p.body {
                Body::Ok(s) => (
                    &s.applies,
                    &s.modes,
                    s.exempt.is_none() && (s.action.blocking() || s.on_unknown == OnUnknown::Block),
                    s.monitor,
                    s.action,
                ),
                Body::Broken(b) => (
                    &b.applies,
                    &b.modes,
                    b.fail.blocks(),
                    b.monitor,
                    PolicyAction::Block,
                ),
            };
            if !blocking || monitor || !in_scope(applies, modes, ctx, ptype) {
                continue;
            }
            out.push(PolicyHit {
                rule_id: p.rule_id.clone(),
                rule_code: p.code.clone(),
                severity: p.severity,
                statement: 0,
                outcome: PolicyOutcome::Unreadable,
                requested,
                action: Some(EnforcementAction::Block),
                message:
                    "the statement could not be read, and this enforced policy may apply to it"
                        .into(),
                reason: None,
            });
        }
        out
    }
}

/// What a valid policy needs extracted.
fn wants(s: &PolicySpec) -> (Want, bool) {
    let progs = s.when.iter().chain(s.test.as_ref().map(|(_, p)| p));
    let mut want = Want {
        refs: !s.applies.tables.is_empty(),
        functions: false,
    };
    let mut needs = s.applies.ops != 0 || want.refs;
    for p in progs {
        let f = p.fields();
        if f.iter().any(|x| {
            matches!(
                x,
                Field::StmtTables
                    | Field::StmtTablesWritten
                    | Field::StmtColumnsRead
                    | Field::StmtColumnsWritten
            )
        }) || [
            Func::StmtValues,
            Func::StmtReads,
            Func::StmtWrites,
            Func::StmtTouches,
        ]
        .iter()
        .any(|g| p.uses(*g))
        {
            want.refs = true;
        }
        if f.contains(&Field::StmtFunctions) {
            want.functions = true;
        }
        needs |= p.reads_stmt();
    }
    (want, needs || want.refs || want.functions)
}

/// The scope of a policy that did not compile, read leniently: so it fails
/// closed where it was meant to apply. What cannot be read applies to
/// everything.
fn broken_scope(yaml: &str) -> Broken {
    use serde_norway::Value as Y;
    let doc: Y = serde_norway::from_str(yaml).unwrap_or(Y::Null);
    let strs = |v: Option<&Y>| -> Vec<String> {
        v.and_then(Y::as_sequence)
            .map(|s| {
                s.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let at = doc.get("applies_to");
    let mut applies = AppliesTo::default();
    for op in strs(at.and_then(|a| a.get("ops"))) {
        applies.ops |= AppliesTo::op_bit(&op);
    }
    for t in strs(at.and_then(|a| a.get("principal_types"))) {
        if let Some(pt) = PrincipalType::parse(&t) {
            applies.principal_types |= pt.bit();
        }
    }
    applies.tables = strs(at.and_then(|a| a.get("tables")));
    applies.databases = strs(at.and_then(|a| a.get("databases")));
    let modes = strs(doc.get("modes"))
        .iter()
        .filter_map(|m| HostMode::parse(m))
        .collect();
    let action = doc.get("action").and_then(Y::as_str).unwrap_or("block");
    let on_unknown = doc.get("on_unknown").and_then(Y::as_str).unwrap_or("");
    let fail = if matches!(action, "flag" | "monitor" | "allow") && on_unknown != "block" {
        EnforcementAction::Flag
    } else {
        EnforcementAction::Block
    };
    Broken {
        applies,
        modes,
        fail,
        monitor: doc.get("mode").and_then(Y::as_str) == Some("monitor"),
    }
}

fn in_scope(
    applies: &AppliesTo,
    modes: &[HostMode],
    ctx: &EvalContext,
    ptype: PrincipalType,
) -> bool {
    if let (Some(m), false) = (ctx.mode, modes.is_empty()) {
        if !modes.contains(&m) {
            return false;
        }
    }
    if !applies.matches_type(ptype) {
        return false;
    }
    if !applies.databases.is_empty() {
        if let Some(db) = &ctx.db {
            let hit = applies.databases.iter().any(|d| {
                db.id.as_deref() == Some(d.as_str()) || db.name.as_deref() == Some(d.as_str())
            });
            if !hit {
                return false;
            }
        }
        // No database context: the conservative reading applies it.
    }
    true
}

fn tables_match(applies: &AppliesTo, f: &Facts) -> bool {
    if applies.tables.is_empty() {
        return true;
    }
    match &f.tables {
        // Not known: assume it may touch them.
        FactList::Unknown(_) => true,
        FactList::Known(tables) => applies.tables.iter().any(|g| {
            let g = f.fold_arg(g);
            let table_part = g.rsplit_once('.').map(|(_, t)| t.to_string());
            tables.iter().any(|t| {
                super::cel::glob::glob(t, &g)
                    || (!t.contains('.')
                        && table_part
                            .as_deref()
                            .is_some_and(|tp| super::cel::glob::glob(t, tp)))
                    || (!g.contains('.')
                        && t.rsplit_once('.')
                            .is_some_and(|(_, tt)| super::cel::glob::glob(tt, &g)))
            })
        }),
    }
}

/// Everything the policies decided on one reading of a statement.
#[derive(Debug, Default)]
pub(crate) struct Verdict {
    pub(crate) hits: Vec<PolicyHit>,
    pub(crate) violations: Vec<ReportedViolation>,
    /// Requires approval: one per approval policy violated, by precedence.
    pub(crate) approvals: Vec<(String, ApprovalRequirement)>,
    pub(crate) exemptions: Vec<(RuleClass, EnforcementAction)>,
    pub(crate) unknowns: Vec<UnknownField>,
}

/// The resolved action of a violated policy for this principal.
fn resolve(
    requested: PolicyAction,
    spec_monitor: bool,
    fallback: &std::collections::BTreeMap<PrincipalType, PolicyAction>,
    ptype: PrincipalType,
    policy: &EnforcementPolicy,
) -> (Option<EnforcementAction>, bool) {
    let (action, approval) = match requested {
        PolicyAction::Allow => return (None, false),
        PolicyAction::Monitor => (EnforcementAction::Monitor, false),
        PolicyAction::Flag => (EnforcementAction::Flag, false),
        PolicyAction::Block => (EnforcementAction::Block, false),
        PolicyAction::RequireApproval => match ptype {
            PrincipalType::Agent | PrincipalType::Human => (EnforcementAction::Block, true),
            other => match fallback.get(&other) {
                Some(PolicyAction::Flag) => (EnforcementAction::Flag, false),
                // Never wait on a human; unknown principals never request.
                _ => (EnforcementAction::Block, false),
            },
        },
    };
    if (spec_monitor || policy.monitor_mode) && action == EnforcementAction::Block {
        (Some(EnforcementAction::Flag), false)
    } else {
        (Some(action), approval)
    }
}

fn soften(
    a: EnforcementAction,
    spec_monitor: bool,
    policy: &EnforcementPolicy,
) -> EnforcementAction {
    if (spec_monitor || policy.monitor_mode) && a == EnforcementAction::Block {
        EnforcementAction::Flag
    } else {
        a
    }
}

pub(crate) fn evaluate(
    set: &PolicySet,
    parsed: &ParsedQuery,
    ctx: &EvalContext,
    policy: &EnforcementPolicy,
    sql: Option<&str>,
) -> Verdict {
    let mut verdict = Verdict::default();
    if set.policies.is_empty() {
        return verdict;
    }
    let ptype = ctx.principal_type();
    // 1. Scope without facts: mode, principal type, database, legacy guard.
    let candidates: Vec<&Compiled> = set
        .policies
        .iter()
        .filter(|p| {
            let (applies, modes) = match &p.body {
                Body::Ok(s) => (&s.applies, &s.modes),
                Body::Broken(b) => (&b.applies, &b.modes),
            };
            if !in_scope(applies, modes, ctx, ptype) {
                return false;
            }
            match &p.body {
                Body::Ok(s) => s.guard.as_ref().is_none_or(|g| {
                    crate::rules::evaluator::condition_matches(g.kind, &g.condition, parsed)
                        .is_some()
                }),
                Body::Broken(_) => true,
            }
        })
        .collect();
    if candidates.is_empty() {
        return verdict;
    }
    // 2. Facts, once per statement, only as far as the candidates need.
    let want = candidates.iter().fold(Want::default(), |w, p| Want {
        refs: w.refs || p.want.refs,
        functions: w.functions || p.want.functions,
    });
    let need_facts = candidates.iter().any(|p| p.needs_facts);
    let dialect = parsed.dialect().map_or("unknown", |d| d.as_str());
    let all_facts: Vec<Facts> = if need_facts {
        facts::extract(parsed, sql, ctx.default_schema.as_deref(), want)
    } else {
        Vec::new()
    };
    // A statement count even when facts were not needed (principal-only
    // policies): one evaluation for the whole input.
    let statements = if need_facts {
        all_facts.len().max(1)
    } else {
        1
    };

    // Exemptions: (index into candidates, matched statements, in-scope statements).
    let mut exempt_track: Vec<(usize, usize, usize)> = Vec::new();

    for (ci, p) in candidates.iter().enumerate() {
        let mut best: Option<(EnforcementAction, ReportedViolation, bool)> = None;
        for i in 0..statements {
            let f = all_facts.get(i);
            let (applies, monitor) = match &p.body {
                Body::Ok(s) => (&s.applies, s.monitor),
                Body::Broken(b) => (&b.applies, b.monitor),
            };
            if let Some(f) = f {
                if !applies.matches_op(f.op) || !tables_match(applies, f) {
                    continue;
                }
            } else if need_facts && (applies.ops != 0 || !applies.tables.is_empty()) {
                // Facts were extracted but there is no statement: nothing to match.
                continue;
            }
            let s = match &p.body {
                Body::Broken(b) => {
                    let action = soften(b.fail, monitor, policy);
                    let hit = PolicyHit {
                        rule_id: p.rule_id.clone(),
                        rule_code: p.code.clone(),
                        severity: p.severity,
                        statement: i,
                        outcome: PolicyOutcome::CompileError,
                        requested: PolicyAction::Block,
                        action: Some(action),
                        message: format!("policy {} did not compile and fails closed", p.code),
                        reason: set
                            .errors
                            .iter()
                            .find(|e| e.rule_id == p.rule_id)
                            .and_then(|e| e.issues.first())
                            .map(|i| i.message.clone()),
                    };
                    record(&mut best, &mut verdict, hit, p, false);
                    continue;
                }
                Body::Ok(s) => s,
            };
            let act = Activation::new(ctx, f, dialect);
            let message = s
                .message
                .clone()
                .unwrap_or_else(|| format!("policy {} violated", p.code));

            if let Some(ex) = &s.exempt {
                if !exempt_track.iter().any(|(c, _, _)| *c == ci) {
                    exempt_track.push((ci, 0, 0));
                }
                let entry = exempt_track
                    .iter_mut()
                    .find(|(c, _, _)| *c == ci)
                    .expect("pushed");
                entry.2 += 1;
                let trusted = s.min_trust.is_none_or(|m| ctx.trust() >= m);
                let when = s.when.as_ref().map_or(Ok(true), |w| w.eval_bool(&act));
                if trusted && when == Ok(true) {
                    entry.1 += 1;
                }
                let _ = ex;
                continue;
            }

            if let Some(m) = s.min_trust {
                if ctx.trust() < m {
                    let a = if s.insufficient_flags {
                        EnforcementAction::Flag
                    } else {
                        EnforcementAction::Block
                    };
                    let action = soften(a, s.monitor, policy);
                    let hit = PolicyHit {
                        rule_id: p.rule_id.clone(),
                        rule_code: p.code.clone(),
                        severity: p.severity,
                        statement: i,
                        outcome: PolicyOutcome::InsufficientTrust,
                        requested: s.action,
                        action: Some(action),
                        message: message.clone(),
                        reason: Some(format!(
                            "principal trust {} is below min_trust {}",
                            ctx.trust().as_str(),
                            m.as_str()
                        )),
                    };
                    record(&mut best, &mut verdict, hit, p, false);
                    continue;
                }
            }

            let mut unknown: Option<super::cel::Fault> = None;
            let mut violated = match s.when.as_ref().map_or(Ok(true), |w| w.eval_bool(&act)) {
                Ok(false) => false,
                Ok(true) => true,
                Err(fault) => {
                    unknown = Some(fault);
                    false
                }
            };
            if unknown.is_none() && violated {
                if let Some((deny_if, prog)) = &s.test {
                    match prog.eval_bool(&act) {
                        Ok(b) => violated = b == *deny_if,
                        Err(fault) => {
                            unknown = Some(fault);
                            violated = false;
                        }
                    }
                }
            }

            if let Some(fault) = unknown {
                verdict.unknowns.push(UnknownField {
                    rule_code: p.code.clone(),
                    detail: fault.detail.clone(),
                    error: fault.kind == FaultKind::Error,
                });
                let a = match s.on_unknown {
                    OnUnknown::Skip => continue,
                    OnUnknown::Block => EnforcementAction::Block,
                    OnUnknown::Flag => EnforcementAction::Flag,
                };
                let action = soften(a, s.monitor, policy);
                let hit = PolicyHit {
                    rule_id: p.rule_id.clone(),
                    rule_code: p.code.clone(),
                    severity: p.severity,
                    statement: i,
                    outcome: PolicyOutcome::Inconclusive,
                    requested: s.action,
                    action: Some(action),
                    message: message.clone(),
                    reason: Some(format!("UNKNOWN: {}", fault.detail)),
                };
                record(&mut best, &mut verdict, hit, p, false);
                continue;
            }
            if !violated {
                continue;
            }
            let (action, approval) = resolve(s.action, s.monitor, &s.fallback, ptype, policy);
            let hit = PolicyHit {
                rule_id: p.rule_id.clone(),
                rule_code: p.code.clone(),
                severity: p.severity,
                statement: i,
                outcome: PolicyOutcome::Violated,
                requested: s.action,
                action,
                message,
                reason: None,
            };
            if action.is_none() {
                verdict.hits.push(hit);
                continue;
            }
            record(&mut best, &mut verdict, hit, p, approval);
        }
        if let Some((_, v, approval)) = best {
            if approval {
                if let Body::Ok(s) = &p.body {
                    if let Some(a) = &s.approval {
                        verdict.approvals.push((
                            v.rule_code.clone(),
                            ApprovalRequirement {
                                rule_id: p.rule_id.clone(),
                                rule_code: p.code.clone(),
                                approval: a.clone(),
                            },
                        ));
                    }
                }
            }
            verdict.violations.push(v);
        }
    }

    // An exemption applies when it matched every statement in its scope
    // (and at least one): a script never gets a rule softened for a
    // statement the exemption did not cover.
    for (ci, matched, in_scope) in exempt_track {
        if matched == 0 || matched != in_scope {
            continue;
        }
        let p = candidates[ci];
        let Body::Ok(s) = &p.body else { continue };
        let Some(ex) = &s.exempt else { continue };
        // An exemption in monitor mode (or under monitor_mode) is observed,
        // never applied: monitoring never loosens anything.
        let observed = s.monitor || policy.monitor_mode;
        if !observed {
            for c in &ex.classes {
                verdict.exemptions.push((*c, ex.cap));
            }
        }
        verdict.hits.push(PolicyHit {
            rule_id: p.rule_id.clone(),
            rule_code: p.code.clone(),
            severity: p.severity,
            statement: 0,
            outcome: PolicyOutcome::Exempted,
            requested: s.action,
            action: None,
            reason: observed.then(|| "monitor: observed, not applied".to_string()),
            message: s.message.clone().unwrap_or_else(|| {
                format!(
                    "{} capped at {} for this principal",
                    ex.classes
                        .iter()
                        .map(|c| match c {
                            RuleClass::SchemaMigration => "schema_migration",
                            RuleClass::Performance => "performance",
                            RuleClass::DataMutation => "data_mutation",
                            RuleClass::Security => "security",
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    match ex.cap {
                        EnforcementAction::Monitor => "monitor",
                        EnforcementAction::Flag => "flag",
                        EnforcementAction::Block => "block",
                    }
                )
            }),
        });
    }
    verdict
}

/// Keeps the hit, and the strongest violation of a policy across statements.
fn record(
    best: &mut Option<(EnforcementAction, ReportedViolation, bool)>,
    verdict: &mut Verdict,
    hit: PolicyHit,
    p: &Compiled,
    approval: bool,
) {
    let action = hit.action.expect("recorded hits carry an action");
    let label = match &p.body {
        Body::Ok(s) => s.label.clone(),
        Body::Broken(_) => None,
    };
    let mut path = match label {
        Some(l) => format!("Policy > {} ({l}): {}", p.code, hit.message),
        None => format!("Policy > {}: {}", p.code, hit.message),
    };
    if let Some(r) = &hit.reason {
        path.push_str(&format!(" [{r}]"));
    }
    if approval {
        path.push_str(" [approval required]");
    }
    let v = ReportedViolation {
        rule_id: p.rule_id.clone(),
        rule_code: p.code.clone(),
        severity: p.severity,
        action,
        ast_node_path: path,
        estimated_rows_affected: None,
        suggested_safe_query: None,
    };
    let stronger = best.as_ref().is_none_or(|(a, _, _)| action > *a);
    if stronger {
        *best = Some((action, v, approval));
    }
    verdict.hits.push(hit);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hosts share one compiled set across threads (ArcSwap in the proxy).
    #[test]
    fn a_policy_set_is_send_and_sync() {
        fn shared<T: Send + Sync + 'static>() {}
        shared::<PolicySet>();
        shared::<EvalContext>();
        shared::<PolicyHit>();
    }
}
