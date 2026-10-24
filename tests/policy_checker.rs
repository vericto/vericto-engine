// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The save-time checker (design §4.8), golden: every report — errors with
//! their key and offset, warnings, the fields read, the per-mode
//! decidability — is pinned in `tests/fixtures/policy_check.golden`. A
//! change to any message or verdict shows up here, in review.
//!
//! Regenerate after a deliberate change with
//! `VERICTO_CHECK_BLESS=1 cargo test --test policy_checker` and review the diff.

use vericto_engine::Dialect;
use vericto_engine::policy::{check_policy, run_policy_tests};

const GOLDEN: &str = "tests/fixtures/policy_check.golden";

const DOCS: &[(&str, &str)] = &[
    (
        "legacy custom rule",
        "rule: block-select-star\nnode_type: SelectStmt\ncondition:\n  target_list: \"*\"",
    ),
    (
        "refund approval (design 4.4)",
        r#"
rule: refunds-over-limit-need-approval
applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [agent, human] }
vars: { limit: 200 }
min_trust: medium
deny_if: stmt.values("public.refunds.amount").exists(v, v > vars.limit)
action: require_approval
approval: { approvers: { groups: ["payments-leads"] } }
"#,
    ),
    (
        "tenant value matches session",
        r#"
modes: [proxy, runtime_api, mcp]
applies_to: { tables: ["public.invoices"] , principal_types: [agent] }
require: has(session.tenant) && stmt.filter_values("public.invoices.tenant_id").all(v, string(v) == session.tenant)
action: block
"#,
    ),
    (
        "weak signal read in CI",
        "modes: [ci, proxy]\napplies_to: {principal_types: [tool]}\nwhen: session.application_name.startsWith('Metabase')\naction: flag",
    ),
    (
        "change window in a named zone",
        "applies_to: {ops: [ddl]}\nrequire: in_window(time.now, 'Tue,Thu 14:00-16:00', 'Europe/Madrid')\naction: block",
    ),
    ("typo in a field", "deny_if: principal.typ == 'agent'"),
    ("unknown root", "deny_if: principl.type == 'agent'"),
    (
        "a clock",
        "deny_if: now() > timestamp('2026-01-01T00:00:00Z')",
    ),
    ("a later phase", "deny_if: params[0] > 1"),
    ("a type error", "deny_if: principal.trust == 'high'"),
    ("not a bool", "deny_if: principal.trust + 1"),
    ("two conditions", "deny_if: 'true'\nrequire: 'true'"),
    ("an unknown key", "deny-if: 'true'\nwhen: 'true'"),
    (
        "rewrite_limit over its bound",
        "when: 'true'\naction: { rewrite_limit: 5000000 }",
    ),
    (
        "an exemption without strong trust",
        "exempt: { rule_classes: [schema_migration], cap: flag }",
    ),
    ("approval for services", "action: require_approval"),
    ("skip without modes", "when: 'true'\non_unknown: skip"),
    (
        "over the cost bound",
        "deny_if: stmt.tables.all(a, stmt.columns_read.exists(b, b.startsWith(a)))",
    ),
    (
        "vacuous all",
        "require: stmt.filter_values('public.t.c').all(v, v == 1)",
    ),
    ("everything", "action: flag"),
    (
        "LIMIT cap (design 5.3a)",
        "rule: cap-select-rows\napplies_to: { ops: [select], principal_types: [agent, human] }\nwhen: '!has(stmt.limit) || stmt.limit > 1000'\naction: { rewrite_limit: 1000 }",
    ),
    (
        "rewrite_limit on writes",
        "applies_to: { ops: [select, delete] }\naction: { rewrite_limit: 1000 }",
    ),
];

fn render() -> String {
    let mut out = String::new();
    for (name, doc) in DOCS {
        let report = check_policy(doc);
        out.push_str(&format!(
            "## {name}\n{}\n",
            serde_json::to_string(&report).expect("serializable")
        ));
    }
    out
}

#[test]
fn checker_reports_are_unchanged() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    let got = render();
    if std::env::var_os("VERICTO_CHECK_BLESS").is_some() {
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).expect("golden file");
    if got != want {
        let diffs: Vec<String> = got
            .lines()
            .zip(want.lines())
            .filter(|(g, w)| g != w)
            .map(|(g, w)| format!("- {w}\n+ {g}"))
            .collect();
        panic!("checker reports changed:\n{}", diffs.join("\n"));
    }
}

#[test]
fn checker_verdicts() {
    let valid: Vec<bool> = DOCS.iter().map(|(_, d)| check_policy(d).valid).collect();
    // The first five are valid; then every refusal; the last two only warn.
    assert_eq!(&valid[..5], &[true; 5]);
    assert!(valid[5..18].iter().all(|v| !v));
    assert_eq!(&valid[18..21], &[true, true, true]);
    assert!(!valid[21]);
    let legacy = check_policy(DOCS[0].1);
    assert!(!legacy.is_policy);
    let tenant = check_policy(DOCS[2].1);
    let modes: Vec<(&str, &str)> = tenant
        .decidability
        .iter()
        .map(|m| (m.mode.as_str(), m.status))
        .collect();
    // The proxy reads the tenant the session sets (SET vericto.tenant):
    // declared by the client there too.
    assert_eq!(
        modes,
        [
            ("proxy", "declared"),
            ("runtime_api", "declared"),
            ("mcp", "unknown")
        ]
    );
    assert!(tenant.decidability[1].message.contains("context.tenant"));
    assert!(
        tenant.decidability[0]
            .message
            .contains("SET vericto.tenant")
    );
}

const WITH_TESTS: &str = r#"
rule: refunds-over-limit-need-approval
code: POL-014
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
tests:
  - name: small refund passes
    sql: "INSERT INTO refunds (order_id, amount) VALUES (1, 150)"
    principal: { type: agent, id: agent-support-bot, trust: 2 }
    expect: allow
  - name: large refund needs approval
    sql: "INSERT INTO refunds (order_id, amount) VALUES (1, 950)"
    principal: { type: agent }
    expect: require_approval
  - name: bound value is checked in the proxy
    sql: "INSERT INTO refunds (order_id, amount) VALUES ($1, $2)"
    params: [1, 950]
    mode: proxy
    expect: require_approval
  - name: unbound value is unknown elsewhere
    sql: "INSERT INTO refunds (order_id, amount) VALUES ($1, $2)"
    principal: { type: agent }
    mode: mcp
    expect: block
    expect_reason: UNKNOWN
  - name: weakly identified agent
    sql: "INSERT INTO refunds (order_id, amount) VALUES (1, 950)"
    principal: { type: agent, trust: weak }
    expect: block
    expect_reason: INSUFFICIENT_TRUST
  - name: a wrong expectation is reported
    sql: "INSERT INTO refunds (order_id, amount) VALUES (1, 950)"
    principal: { type: agent }
    expect: allow
"#;

#[test]
fn fixtures_of_the_design_example_run() {
    let r = run_policy_tests(WITH_TESTS, Dialect::Postgres).unwrap();
    let summary: Vec<(&str, bool, Option<&str>)> = r
        .iter()
        .map(|f| (f.name.as_str(), f.passed, f.skipped.as_deref()))
        .collect();
    assert_eq!(
        summary,
        [
            ("small refund passes", true, None),
            ("large refund needs approval", true, None),
            (
                "bound value is checked in the proxy",
                true,
                Some("needs bind values (Phase 2)")
            ),
            ("unbound value is unknown elsewhere", true, None),
            ("weakly identified agent", true, None),
            ("a wrong expectation is reported", false, None),
        ]
    );
    let wrong = &r[5];
    assert_eq!(
        (wrong.expected.as_str(), wrong.actual.as_str()),
        ("allow", "require_approval")
    );
    assert!(wrong.detail.as_deref().unwrap().contains("POL-014"));
    assert_eq!(check_policy(WITH_TESTS).tests, 6);
    assert!(run_policy_tests(DOCS[0].1, Dialect::Postgres).is_err());
    assert!(run_policy_tests("when: 'true'\ntests: [{name: x}]", Dialect::Postgres).is_err());
}
