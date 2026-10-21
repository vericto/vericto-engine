// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Authoring support (design §4.8): the save-time check of a policy
//! document and the runner of its `tests:` fixtures. Hosts expose them
//! (the eval sidecar's `/policies/check` and `/ci/rules/test`); the
//! dashboard and the CLI call those, so this checker is the only one.

use serde::{Deserialize, Serialize};

use super::cel::compile::availability;
use super::context::{
    DbContext, EvalContext, HostMode, Principal, PrincipalType, SessionContext, Ticket,
    TimeContext, Trust,
};
use super::set::{PolicyOutcome, PolicySet};
use super::spec::{self, Issue};
use crate::parser::Dialect;
use crate::rules::engine::{
    Decision, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity,
};

/// Whether a policy can be decided in one mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeDecidability {
    pub mode: HostMode,
    /// `static` (decided from the SQL and the host), `declared` (needs the
    /// caller to pass a field), or `unknown` (a field is absent in this
    /// mode: the policy's `on_unknown` decides every time).
    pub status: &'static str,
    pub declared: Vec<String>,
    pub absent: Vec<String>,
    pub message: String,
}

/// The save-time check of a policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    /// `false`: the document is one of today's custom rules (no policy key);
    /// the custom-rule checker validates it, and it evaluates as before.
    pub is_policy: bool,
    pub valid: bool,
    pub errors: Vec<Issue>,
    pub warnings: Vec<Issue>,
    /// The context fields the policy reads (`stmt.tables`, `session.tenant`).
    pub fields: Vec<String>,
    pub decidability: Vec<ModeDecidability>,
    /// `static`: every Phase 1 policy (AST facts plus declared context).
    pub phase: &'static str,
    /// The number of `tests:` fixtures.
    pub tests: usize,
}

/// How a caller declares a field in a mode.
fn how_to_declare(field: &str, mode: HostMode) -> Option<&'static str> {
    Some(match (field, mode) {
        ("session.tenant", HostMode::Proxy) => {
            "SET vericto.tenant (or -c vericto.tenant at startup)"
        }
        ("session.tenant", HostMode::RuntimeApi) => "context.tenant",
        ("ticket.id" | "ticket.source" | "ticket.verified", HostMode::Proxy) => {
            "SET vericto.ticket"
        }
        ("ticket.id" | "ticket.source" | "ticket.verified", HostMode::RuntimeApi) => {
            "context.ticket"
        }
        ("ticket.id" | "ticket.source" | "ticket.verified", HostMode::Mcp) => {
            "the ticket parameter of check_sql"
        }
        ("ticket.id" | "ticket.source" | "ticket.verified", HostMode::Ci) => "--ticket",
        ("principal.end_user", HostMode::RuntimeApi) => "end_user",
        (f, HostMode::Ci) if f.starts_with("db.") => "--database",
        _ => return None,
    })
}

fn on_unknown_word(s: &spec::PolicySpec) -> &'static str {
    match s.on_unknown {
        spec::OnUnknown::Block => "block",
        spec::OnUnknown::Flag => "flag",
        spec::OnUnknown::Skip => "skip",
    }
}

/// Checks a policy document: errors with their key and offset, warnings,
/// the fields it reads, and per mode whether it is decidable there.
pub fn check_policy(yaml: &str) -> CheckReport {
    let tests = fixtures(yaml).map(|t| t.len()).unwrap_or(0);
    if !spec::is_policy_document(yaml) {
        return CheckReport {
            is_policy: false,
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            fields: Vec::new(),
            decidability: Vec::new(),
            phase: "static",
            tests,
        };
    }
    let mut errors = Vec::new();
    if let Err(e) = fixtures(yaml) {
        errors.push(Issue {
            key: "tests".into(),
            offset: None,
            message: e,
        });
    }
    match spec::parse(yaml) {
        Err(mut issues) => {
            issues.extend(errors);
            CheckReport {
                is_policy: true,
                valid: false,
                errors: issues,
                warnings: Vec::new(),
                fields: Vec::new(),
                decidability: Vec::new(),
                phase: "static",
                tests,
            }
        }
        Ok(s) => {
            let mut fields = std::collections::BTreeSet::new();
            for p in s.when.iter().chain(s.test.as_ref().map(|(_, p)| p)) {
                fields.extend(p.fields().iter().copied());
            }
            let modes: Vec<HostMode> = if s.modes.is_empty() {
                HostMode::ALL.to_vec()
            } else {
                s.modes.clone()
            };
            let decidability = modes
                .into_iter()
                .map(|mode| {
                    let mut declared = Vec::new();
                    let mut absent = Vec::new();
                    for f in &fields {
                        match availability(*f, mode) {
                            Ok(()) => {}
                            Err(true) => declared.push(f.path()),
                            Err(false) => absent.push(f.path()),
                        }
                    }
                    let (status, message) = if !absent.is_empty() {
                        (
                            "unknown",
                            format!(
                                "In {} this policy reads {}, which is absent there: it is UNKNOWN \
                                 on every statement (on_unknown: {})",
                                mode.as_str(),
                                absent.join(", "),
                                on_unknown_word(&s)
                            ),
                        )
                    } else if !declared.is_empty() {
                        let how: Vec<String> = declared
                            .iter()
                            .map(|f| match how_to_declare(f, mode) {
                                Some(h) => format!("{f} (pass {h})"),
                                None => f.clone(),
                            })
                            .collect();
                        (
                            "declared",
                            format!(
                                "In {} this policy needs {} declared by the caller; without it, \
                                 on_unknown: {} decides",
                                mode.as_str(),
                                how.join(", "),
                                on_unknown_word(&s)
                            ),
                        )
                    } else {
                        ("static", format!("Static in {}", mode.as_str()))
                    };
                    ModeDecidability {
                        mode,
                        status,
                        declared,
                        absent,
                        message,
                    }
                })
                .collect();
            CheckReport {
                is_policy: true,
                valid: errors.is_empty(),
                errors,
                warnings: s.warnings.clone(),
                fields: fields.iter().map(|f| f.path()).collect(),
                decidability,
                phase: "static",
                tests,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fixtures

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    name: String,
    sql: String,
    #[serde(default)]
    dialect: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    principal: Option<FixturePrincipal>,
    #[serde(default)]
    db: Option<DbContext>,
    #[serde(default)]
    time: Option<FixtureTime>,
    #[serde(default)]
    ticket: Option<serde_norway::Value>,
    #[serde(default)]
    session: Option<SessionContext>,
    #[serde(default)]
    default_schema: Option<String>,
    #[serde(default)]
    params: Option<serde_norway::Value>,
    expect: String,
    #[serde(default)]
    expect_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePrincipal {
    #[serde(rename = "type", default)]
    principal_type: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    trust: Option<Trust>,
    #[serde(default)]
    via: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    attrs: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    end_user: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTime {
    /// RFC 3339.
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    now_unix: Option<i64>,
    #[serde(default)]
    tz: Option<String>,
    #[serde(default)]
    utc_offset_secs: Option<i32>,
}

fn fixtures(yaml: &str) -> Result<Vec<Fixture>, String> {
    let doc: serde_norway::Value = serde_norway::from_str(yaml).map_err(|e| e.to_string())?;
    match doc.get("tests") {
        None | Some(serde_norway::Value::Null) => Ok(Vec::new()),
        Some(t) => serde_norway::from_value(t.clone()).map_err(|e| format!("invalid tests: {e}")),
    }
}

/// The result of one `tests:` fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureResult {
    pub name: String,
    pub passed: bool,
    /// Why the fixture was not run (it needs a later phase).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub expected: String,
    pub actual: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_reason: Option<String>,
    /// The outcome's node path, for a failing fixture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn context(f: &Fixture) -> Result<EvalContext, String> {
    let mut ctx = EvalContext::new();
    if let Some(m) = &f.mode {
        ctx.mode = Some(HostMode::parse(m).ok_or_else(|| format!("unknown mode `{m}`"))?);
    }
    if let Some(p) = &f.principal {
        let t = match p.principal_type.as_deref() {
            None => PrincipalType::Unknown,
            Some(s) => {
                PrincipalType::parse(s).ok_or_else(|| format!("unknown principal type `{s}`"))?
            }
        };
        let mut pr = Principal::new(
            p.id.clone().unwrap_or_default(),
            t,
            p.trust.unwrap_or(Trust::Medium),
        );
        pr.via = p.via.clone();
        pr.owner = p.owner.clone();
        pr.attrs = p.attrs.clone();
        pr.groups = p.groups.clone();
        pr.end_user = p.end_user.clone();
        ctx.principal = Some(pr);
    }
    ctx.db = f.db.clone();
    ctx.session = f.session.clone();
    ctx.default_schema = f.default_schema.clone();
    if let Some(t) = &f.time {
        let now = match (&t.now, t.now_unix) {
            (_, Some(n)) => n,
            (Some(s), None) => {
                super::cel::time::parse_timestamp(s, false)
                    .ok_or_else(|| format!("`{s}` is not an RFC 3339 timestamp"))?
                    .secs
            }
            (None, None) => return Err("time needs `now` or `now_unix`".into()),
        };
        ctx.time = Some(TimeContext::in_zone(
            now,
            t.tz.clone().unwrap_or_else(|| "UTC".into()),
            t.utc_offset_secs.unwrap_or(0),
        ));
    }
    ctx.ticket = match &f.ticket {
        None => None,
        Some(serde_norway::Value::String(s)) => Some(Ticket::declared(s.clone())),
        Some(v) => {
            Some(serde_norway::from_value(v.clone()).map_err(|e| format!("invalid ticket: {e}"))?)
        }
    };
    Ok(ctx)
}

/// Runs the `tests:` fixtures of a policy document against the policy
/// alone, on `dialect` unless a fixture names another. A fixture with
/// `params:` is skipped: bind values are Phase 2.
pub fn run_policy_tests(yaml: &str, dialect: Dialect) -> Result<Vec<FixtureResult>, String> {
    let list = fixtures(yaml)?;
    let rule = Rule {
        rule_id: "policy-under-test".into(),
        code: serde_norway::from_str::<serde_norway::Value>(yaml)
            .ok()
            .and_then(|d| d.get("code").and_then(|c| c.as_str()).map(str::to_string))
            .unwrap_or_else(|| "POL-TEST".into()),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.to_string()),
    };
    let rules = vec![rule];
    let set = PolicySet::compile(&rules);
    if set.is_empty() {
        return Err("not a policy document: today's custom rules have no fixtures".into());
    }
    let policy = EnforcementPolicy::default();
    let mut out = Vec::new();
    for f in list {
        let expected = f.expect.clone();
        if f.params.is_some() {
            out.push(FixtureResult {
                name: f.name,
                passed: true,
                skipped: Some("needs bind values (Phase 2)".into()),
                expected,
                actual: String::new(),
                expected_reason: f.expect_reason,
                actual_reason: None,
                detail: None,
            });
            continue;
        }
        let d = match &f.dialect {
            Some(s) => Dialect::parse_dialect(s).map_err(|e| e.to_string())?,
            None => dialect,
        };
        let ctx = context(&f)?;
        let o = crate::evaluate_with_context(&f.sql, d, &rules, &policy, &set, &ctx);
        let monitor_hit = o
            .policy_hits
            .iter()
            .any(|h| h.action == Some(EnforcementAction::Monitor));
        let actual = if o.approval_required.is_some() {
            "require_approval"
        } else {
            match o.decision {
                Decision::Block => "block",
                Decision::Flag => "flag",
                Decision::Allow if monitor_hit => "monitor",
                Decision::Allow => "allow",
            }
        }
        .to_string();
        let actual_reason = o.policy_hits.first().map(|h| {
            match h.outcome {
                PolicyOutcome::Violated => "VIOLATION",
                PolicyOutcome::Inconclusive => "UNKNOWN",
                PolicyOutcome::InsufficientTrust => "INSUFFICIENT_TRUST",
                PolicyOutcome::CompileError => "COMPILE_ERROR",
                PolicyOutcome::Unreadable => "PARSE_ERROR",
                PolicyOutcome::Exempted => "EXEMPTED",
            }
            .to_string()
        });
        let passed = actual == expected
            && f.expect_reason
                .as_ref()
                .is_none_or(|r| actual_reason.as_deref() == Some(r.as_str()));
        out.push(FixtureResult {
            name: f.name,
            passed,
            skipped: None,
            expected,
            actual,
            expected_reason: f.expect_reason,
            actual_reason,
            detail: (!passed).then(|| o.ast_node_path.unwrap_or_default()),
        });
    }
    Ok(out)
}
