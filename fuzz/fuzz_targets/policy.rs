// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Fuzz target: the business-policy language and its evaluation.
//!
//! The input is split at the first NUL byte: the part before it is a CEL
//! expression, the part after it a SQL statement. The expression is
//! compiled as the `deny_if` of a policy (the checker, the static bounds
//! and the compile-time constant folding all run on it), and the statement
//! is evaluated against the policy with a fixed, fully populated context,
//! on the dialect the first byte selects. The engine must return for any
//! input: a panic, an abort, a stack overflow or a timeout is a finding.
//! A second policy, fixed, reads every fact helper so the facts extraction
//! runs on every statement, and a third bounds every SELECT
//! (`rewrite_limit`), so the LIMIT rewrite and its verification run too.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vericto_engine::error::MAX_QUERY_SIZE_BYTES;
use vericto_engine::policy::{
    DbContext, EvalContext, HostMode, PolicySet, Principal, PrincipalType, SessionContext, Ticket,
    TimeContext, Trust, check_policy,
};
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate_with_context,
};

const DIALECTS: [Dialect; 4] = [Dialect::Postgres, Dialect::Mysql, Dialect::MsSql, Dialect::Oracle];

const FACTS: &str = r#"
applies_to: { principal_types: [agent] }
deny_if: >
  stmt.values("public.t.c").exists(v, v == 1) ||
  stmt.filter_values("public.t.c").size() > 3 ||
  stmt.has_filter("t.c") ||
  stmt.lower_bound("public.t.c") > 1 ||
  stmt.upper_bound("t.c") < 1 ||
  stmt.reads("public.*") || stmt.writes("x*") || stmt.touches("?") ||
  stmt.tables.exists(t, glob(t, "*.t")) || stmt.functions.size() > 9 ||
  stmt.columns_read.size() + stmt.columns_written.size() > 99 || stmt.op == "x"
on_unknown: flag
action: flag
"#;

const LIMIT: &str = "applies_to: { principal_types: [agent] }\naction: { rewrite_limit: 7 }\n";

fn rule(code: &str, yaml: String) -> Rule {
    Rule {
        rule_id: code.into(),
        code: code.into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if text.len() > MAX_QUERY_SIZE_BYTES {
        return;
    }
    let (expr, sql) = text.split_once('\0').unwrap_or((text, "SELECT 1"));
    // The expression as a YAML block scalar, so any text is a valid document.
    let indented: String = expr.lines().map(|l| format!("  {l}\n")).collect();
    let yaml = format!("applies_to: {{ principal_types: [agent] }}\ndeny_if: |\n{indented}action: block\n");
    let _ = check_policy(&yaml);
    let rules = vec![
        rule("POL-F1", yaml),
        rule("POL-F2", FACTS.to_string()),
        rule("POL-F3", LIMIT.to_string()),
    ];
    let set = PolicySet::compile(&rules);
    let mut p = Principal::new("fuzz", PrincipalType::Agent, Trust::Medium);
    p.attrs.insert("k".into(), "v".into());
    let ctx = EvalContext::new()
        .with_mode(HostMode::Proxy)
        .with_principal(p)
        .with_db(DbContext::new().with_env("prod"))
        .with_time(TimeContext::in_zone(1_792_540_800, "Europe/Madrid", 7200))
        .with_ticket(Ticket::declared("OPS-1"))
        .with_session(SessionContext::new().with_tenant("t").with_client_ip("10.0.0.1"));
    let d = DIALECTS[usize::from(first) % DIALECTS.len()];
    let _ = evaluate_with_context(sql, d, &rules, &EnforcementPolicy::default(), &set, &ctx);
});
