// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Business policies end to end (design "Business policy rules" §4–§6):
//! the design's examples, their alternate flows, and the decision
//! resolution and precedence of §4.6.

use vericto_engine::policy::{
    DbContext, EvalContext, HostMode, PolicyAction, PolicyOutcome, PolicySet, Principal,
    PrincipalType, SessionContext, Ticket, TimeContext, Trust,
};
use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome, Rule, RuleType,
    SensitiveColumn, Severity, evaluate, evaluate_with_context, standard_rules,
};

fn pol(code: &str, yaml: &str) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.to_string(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.to_string()),
    }
}

fn principal(t: PrincipalType, id: &str, trust: Trust) -> Principal {
    Principal::new(id, t, trust)
}

fn agent() -> EvalContext {
    EvalContext::new().with_principal(principal(
        PrincipalType::Agent,
        "agent-support-bot",
        Trust::Medium,
    ))
}

fn run(rules: &[Rule], sql: &str, d: Dialect, ctx: &EvalContext) -> EvaluationOutcome {
    let set = PolicySet::compile(rules);
    assert!(set.errors().is_empty(), "{:?}", set.errors());
    evaluate_with_context(sql, d, rules, &EnforcementPolicy::default(), &set, ctx)
}

const REFUND_CAP: &str = r#"
rule: refund-cap
applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [agent, human] }
vars: { limit: 200 }
deny_if: stmt.values("public.refunds.amount").exists(v, double(v) > double(vars.limit))
action: block
message: "Refunds above {{vars.limit}} need approval"
"#;

#[test]
fn refund_cap_on_literals_parameters_and_scope() {
    let rules = [pol("POL-001", REFUND_CAP)];
    let ctx = agent();
    let small = run(
        &rules,
        "INSERT INTO refunds (order_id, amount) VALUES (1, 150)",
        Dialect::Postgres,
        &ctx,
    );
    assert_eq!(small.decision, Decision::Allow);
    assert!(small.policy_hits.is_empty());
    let large = run(
        &rules,
        "INSERT INTO refunds (order_id, amount) VALUES (1, 950)",
        Dialect::Postgres,
        &ctx,
    );
    assert_eq!(large.decision, Decision::Block);
    assert_eq!(large.rule_code.as_deref(), Some("POL-001"));
    assert!(
        large
            .ast_node_path
            .as_deref()
            .unwrap()
            .contains("Refunds above 200 need approval")
    );
    assert_eq!(large.policy_hits[0].outcome, PolicyOutcome::Violated);
    // Also on UPDATE, and on MySQL / SQL Server / Oracle.
    for d in [Dialect::Mysql, Dialect::MsSql, Dialect::Oracle] {
        let ctx = agent().with_default_schema("public");
        let o = run(
            &rules,
            "UPDATE refunds SET amount = 300 WHERE id = 1",
            d,
            &ctx,
        );
        assert_eq!(o.decision, Decision::Block, "{d:?}");
    }
    // A parameter is UNKNOWN: on_unknown (block by default) decides.
    let p = run(
        &rules,
        "INSERT INTO refunds (order_id, amount) VALUES ($1, $2)",
        Dialect::Postgres,
        &ctx,
    );
    assert_eq!(p.decision, Decision::Block);
    assert_eq!(p.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
    assert!(p.unknowns[0].detail.contains("$2"));
    // Out of scope: another table, another op, a service principal.
    assert_eq!(
        run(
            &rules,
            "INSERT INTO orders (amount) VALUES (950)",
            Dialect::Postgres,
            &ctx
        )
        .decision,
        Decision::Allow
    );
    assert_eq!(
        run(
            &rules,
            "SELECT amount FROM refunds",
            Dialect::Postgres,
            &ctx
        )
        .decision,
        Decision::Allow
    );
    let svc = EvalContext::new().with_principal(principal(
        PrincipalType::Service,
        "svc-billing",
        Trust::Strong,
    ));
    assert_eq!(
        run(
            &rules,
            "INSERT INTO refunds (amount) VALUES (950)",
            Dialect::Postgres,
            &svc
        )
        .decision,
        Decision::Allow
    );
    // No principal at all: `unknown`, outside `principal_types`.
    assert_eq!(
        run(
            &rules,
            "INSERT INTO refunds (amount) VALUES (950)",
            Dialect::Postgres,
            &EvalContext::new()
        )
        .decision,
        Decision::Allow
    );
}

#[test]
fn on_unknown_flag_and_skip() {
    let flag = REFUND_CAP.replace("action: block", "action: block\non_unknown: flag");
    let rules = [pol("POL-001", &flag)];
    let o = run(
        &rules,
        "INSERT INTO refunds (amount) VALUES ($1)",
        Dialect::Postgres,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
    let skip = REFUND_CAP.replace(
        "action: block",
        "action: block\non_unknown: skip\nmodes: [mcp]",
    );
    let rules = [pol("POL-001", &skip)];
    let ctx = agent().with_mode(HostMode::Mcp);
    let o = run(
        &rules,
        "INSERT INTO refunds (amount) VALUES ($1)",
        Dialect::Postgres,
        &ctx,
    );
    assert_eq!(o.decision, Decision::Allow);
    // And the policy does not run at all in a mode it is not for.
    let proxy = agent().with_mode(HostMode::Proxy);
    let o = run(
        &rules,
        "INSERT INTO refunds (amount) VALUES (950)",
        Dialect::Postgres,
        &proxy,
    );
    assert_eq!(o.decision, Decision::Allow);
}

const TENANT_FILTER: &str = r#"
rule: tenant-filter-required
applies_to: { ops: [select, update, delete], principal_types: [service, agent, human, tool] }
vars: { tenant_tables: ["public.invoices", "public.customers"] }
require: >
  stmt.tables.all(t, !(t in vars.tenant_tables) || stmt.has_filter(t + ".tenant_id"))
action: block
"#;

#[test]
fn tenant_filter_required() {
    let rules = [pol("POL-002", TENANT_FILTER)];
    let ctx = agent();
    let ok = [
        "SELECT * FROM invoices WHERE tenant_id = 7",
        "SELECT * FROM invoices WHERE tenant_id = $1 AND id = 3",
        "SELECT i.id FROM invoices i JOIN customers c ON c.id = i.cid WHERE i.tenant_id = 1 AND c.tenant_id = 1",
        "UPDATE invoices SET paid = true WHERE tenant_id IN (1) AND id = 2",
        "SELECT * FROM products",
    ];
    for sql in ok {
        assert_eq!(
            run(&rules, sql, Dialect::Postgres, &ctx).decision,
            Decision::Allow,
            "{sql}"
        );
    }
    let blocked = [
        "SELECT * FROM invoices",
        "SELECT * FROM invoices WHERE tenant_id = 1 OR 1 = 1",
        "SELECT * FROM invoices i JOIN customers c ON c.tenant_id = i.tenant_id WHERE i.tenant_id = 1",
        "SELECT * FROM products WHERE id IN (SELECT pid FROM invoices)",
        "DELETE FROM customers WHERE id = 1",
    ];
    for sql in blocked {
        assert_eq!(
            run(&rules, sql, Dialect::Postgres, &ctx).decision,
            Decision::Block,
            "{sql}"
        );
    }
    // Unqualified with two tables in scope: UNKNOWN, and the default
    // on_unknown of a blocking policy is block.
    let o = run(
        &rules,
        "SELECT * FROM invoices i JOIN customers c ON true WHERE tenant_id = 1",
        Dialect::Postgres,
        &ctx,
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
}

#[test]
fn tenant_value_matches_the_session() {
    let yaml = r#"
rule: tenant-value-matches-session
modes: [proxy, runtime_api]
applies_to: { tables: ["public.invoices"], principal_types: [service, agent] }
require: >
  has(session.tenant) && stmt.has_filter("public.invoices.tenant_id") &&
  stmt.filter_values("public.invoices.tenant_id").all(v, string(v) == session.tenant)
on_unknown: block
action: block
"#;
    let rules = [pol("POL-003", yaml)];
    let with_tenant = agent()
        .with_mode(HostMode::Proxy)
        .with_session(SessionContext::new().with_tenant("7"));
    let sql_ok = "SELECT * FROM invoices WHERE tenant_id = 7";
    let sql_other = "SELECT * FROM invoices WHERE tenant_id = 8";
    assert_eq!(
        run(&rules, sql_ok, Dialect::Postgres, &with_tenant).decision,
        Decision::Allow
    );
    assert_eq!(
        run(&rules, sql_other, Dialect::Postgres, &with_tenant).decision,
        Decision::Block
    );
    // No tenant in the session: `has()` is false, the policy blocks.
    let no_tenant = agent().with_mode(HostMode::Proxy);
    assert_eq!(
        run(&rules, sql_ok, Dialect::Postgres, &no_tenant).decision,
        Decision::Block
    );
}

#[test]
fn time_window_on_bounds() {
    let yaml = r#"
rule: events-last-90-days
applies_to: { ops: [select], tables: ["public.events"], principal_types: [agent, tool] }
require: stmt.lower_bound("public.events.created_at") >= time.now - duration("2160h")
action: block
"#;
    let rules = [pol("POL-004", yaml)];
    // 2026-10-21T00:00:00Z
    let ctx = agent().with_time(TimeContext::utc(1_792_540_800));
    let recent = "SELECT * FROM events WHERE created_at >= '2026-09-01'";
    let old = "SELECT * FROM events WHERE created_at >= '2025-01-01'";
    let none = "SELECT * FROM events";
    let param = "SELECT * FROM events WHERE created_at >= $1";
    assert_eq!(
        run(&rules, recent, Dialect::Postgres, &ctx).decision,
        Decision::Allow
    );
    assert_eq!(
        run(&rules, old, Dialect::Postgres, &ctx).decision,
        Decision::Block
    );
    assert_eq!(
        run(&rules, none, Dialect::Postgres, &ctx).decision,
        Decision::Block
    );
    let o = run(&rules, param, Dialect::Postgres, &ctx);
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
    // Without a time from the host: UNKNOWN, never a guess.
    let o = run(&rules, recent, Dialect::Postgres, &agent());
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
    // The bound is the tightest literal; BETWEEN counts.
    let between = "SELECT * FROM events WHERE created_at BETWEEN '2026-09-01' AND '2026-10-01'";
    assert_eq!(
        run(
            &rules,
            between,
            Dialect::Mysql,
            &ctx.clone().with_default_schema("public")
        )
        .decision,
        Decision::Allow
    );
}

const PROD_READ_ONLY: &str = r#"
rule: prod-read-only-without-ticket
applies_to: { principal_types: [human] }
when: db.env == "prod"
deny_if: stmt.op != "select" && !(has(ticket.id) && ticket.id.matches("^OPS-[0-9]+$"))
action: block
message: "Production is read-only. Set a ticket: SET vericto.ticket = 'OPS-123'"
"#;

#[test]
fn prod_read_only_unless_ticket() {
    let rules = [pol("POL-005", PROD_READ_ONLY)];
    let dev = EvalContext::new()
        .with_principal(principal(PrincipalType::Human, "dev_ana", Trust::Medium))
        .with_db(DbContext::new().with_env("prod"));
    let write = "UPDATE orders SET status = 'x' WHERE id = 1";
    assert_eq!(
        run(&rules, "SELECT * FROM orders", Dialect::Postgres, &dev).decision,
        Decision::Allow
    );
    assert_eq!(
        run(&rules, write, Dialect::Postgres, &dev).decision,
        Decision::Block
    );
    let with_ticket = dev.clone().with_ticket(Ticket::declared("OPS-123"));
    assert_eq!(
        run(&rules, write, Dialect::Postgres, &with_ticket).decision,
        Decision::Allow
    );
    let bad_ticket = dev.clone().with_ticket(Ticket::declared("whatever"));
    assert_eq!(
        run(&rules, write, Dialect::Postgres, &bad_ticket).decision,
        Decision::Block
    );
    let staging = EvalContext::new()
        .with_principal(principal(PrincipalType::Human, "dev_ana", Trust::Medium))
        .with_db(DbContext::new().with_env("staging"));
    assert_eq!(
        run(&rules, write, Dialect::Postgres, &staging).decision,
        Decision::Allow
    );
    // No database context: `db.env` is UNKNOWN → block (fail-closed).
    let unknown_db = EvalContext::new().with_principal(principal(
        PrincipalType::Human,
        "dev_ana",
        Trust::Medium,
    ));
    assert_eq!(
        run(&rules, write, Dialect::Postgres, &unknown_db).decision,
        Decision::Block
    );
}

#[test]
fn change_window_with_min_trust() {
    let yaml = r#"
rule: prod-ddl-change-window
applies_to: { ops: [ddl] }
when: db.env == "prod"
min_trust: strong
require: >
  principal.type == "pipeline" && principal.id == "ci-migrations" &&
  in_window(time.now, "Tue,Thu 14:00-16:00", "Europe/Madrid")
action: block
"#;
    let rules = [pol("POL-006", yaml)];
    let ddl = "ALTER TABLE orders ADD COLUMN note text";
    // Tuesday 2026-10-20 14:30 in Madrid (UTC+2): 12:30 UTC.
    let tue_1430 = 1_792_499_400;
    let pipeline = |trust| {
        EvalContext::new()
            .with_principal(principal(PrincipalType::Pipeline, "ci-migrations", trust))
            .with_db(DbContext::new().with_env("prod"))
            .with_time(TimeContext::in_zone(tue_1430, "Europe/Madrid", 7200))
    };
    assert_eq!(
        run(&rules, ddl, Dialect::Postgres, &pipeline(Trust::Strong)).decision,
        Decision::Allow
    );
    // Medium trust: insufficient, blocks whatever the window.
    let o = run(&rules, ddl, Dialect::Postgres, &pipeline(Trust::Medium));
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::InsufficientTrust);
    // Outside the window (Tuesday 18:00 Madrid).
    let late = EvalContext::new()
        .with_principal(principal(
            PrincipalType::Pipeline,
            "ci-migrations",
            Trust::Strong,
        ))
        .with_db(DbContext::new().with_env("prod"))
        .with_time(TimeContext::in_zone(
            tue_1430 + 3.5 as i64 * 3600,
            "Europe/Madrid",
            7200,
        ));
    assert_eq!(
        run(&rules, ddl, Dialect::Postgres, &late).decision,
        Decision::Block
    );
    // A host in another zone cannot decide a Madrid window: UNKNOWN → block.
    let utc_host = EvalContext::new()
        .with_principal(principal(
            PrincipalType::Pipeline,
            "ci-migrations",
            Trust::Strong,
        ))
        .with_db(DbContext::new().with_env("prod"))
        .with_time(TimeContext::utc(tue_1430));
    let o = run(&rules, ddl, Dialect::Postgres, &utc_host);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Inconclusive);
    // Not DDL: out of scope.
    assert_eq!(
        run(
            &rules,
            "SELECT 1",
            Dialect::Postgres,
            &pipeline(Trust::Weak)
        )
        .decision,
        Decision::Allow
    );
}

#[test]
fn weak_signals_tighten_bi_tool() {
    let yaml = r#"
rule: bi-reporting-schema-only
applies_to: { principal_types: [tool] }
deny_if: stmt.op != "select" || stmt.tables.exists(t, !t.startsWith("reporting."))
action: block
"#;
    let rules = [pol("POL-007", yaml)];
    let bi =
        EvalContext::new().with_principal(principal(PrincipalType::Tool, "metabase", Trust::Weak));
    assert_eq!(
        run(
            &rules,
            "SELECT * FROM reporting.sales",
            Dialect::Postgres,
            &bi
        )
        .decision,
        Decision::Allow
    );
    assert_eq!(
        run(&rules, "SELECT * FROM public.users", Dialect::Postgres, &bi).decision,
        Decision::Block
    );
    assert_eq!(
        run(
            &rules,
            "SELECT * FROM reporting.sales s JOIN public.users u ON true",
            Dialect::Postgres,
            &bi
        )
        .decision,
        Decision::Block
    );
    assert_eq!(
        run(
            &rules,
            "DELETE FROM reporting.sales WHERE id = 1",
            Dialect::Postgres,
            &bi
        )
        .decision,
        Decision::Block
    );
}

const EXEMPTION: &str = r#"
rule: migrations-ddl-exemption
applies_to: { principal_types: [pipeline] }
min_trust: strong
when: principal.id == "ci-migrations"
exempt: { rule_classes: [schema_migration], cap: flag }
"#;

#[test]
fn exemptions_loosen_only_at_strong_trust_and_never_security() {
    let mut rules = standard_rules();
    rules.push(pol("POL-008", EXEMPTION));
    let set = PolicySet::compile(&rules);
    assert!(set.errors().is_empty());
    let policy = EnforcementPolicy::default();
    let ctx = |trust| {
        EvalContext::new().with_principal(principal(
            PrincipalType::Pipeline,
            "ci-migrations",
            trust,
        ))
    };
    let drop = "DROP TABLE old_orders";
    let strong = evaluate_with_context(
        drop,
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &ctx(Trust::Strong),
    );
    assert_eq!(strong.decision, Decision::Flag);
    assert!(
        strong
            .policy_hits
            .iter()
            .any(|h| h.outcome == PolicyOutcome::Exempted)
    );
    let medium = evaluate_with_context(
        drop,
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &ctx(Trust::Medium),
    );
    assert_eq!(medium.decision, Decision::Block);
    // A DataMutation finding is never softened: DELETE without WHERE.
    let del = evaluate_with_context(
        "DELETE FROM orders",
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &ctx(Trust::Strong),
    );
    assert_eq!(del.decision, Decision::Block);
    // Another pipeline: not exempt.
    let other = EvalContext::new().with_principal(principal(
        PrincipalType::Pipeline,
        "ci-other",
        Trust::Strong,
    ));
    assert_eq!(
        evaluate_with_context(drop, Dialect::Postgres, &rules, &policy, &set, &other).decision,
        Decision::Block
    );
    // A script: the exemption must cover every statement in its scope.
    let script = "DROP TABLE a; DROP TABLE b";
    assert_eq!(
        evaluate_with_context(
            script,
            Dialect::Postgres,
            &rules,
            &policy,
            &set,
            &ctx(Trust::Strong)
        )
        .decision,
        Decision::Flag
    );
}

const FOUR_EYES: &str = r#"
rule: ledger-adjustments-four-eyes
applies_to: { ops: [insert, update, delete], tables: ["public.ledger_adjustments"] }
min_trust: medium
action: require_approval
approval:
  approvers: { roles: [admin, owner], groups: ["finance-controllers"] }
  fallback_for: { service: block, pipeline: block, tool: flag }
"#;

#[test]
fn approvals_block_with_a_requirement_and_fall_back_for_machines() {
    let rules = [pol("POL-009", FOUR_EYES)];
    let sql = "INSERT INTO ledger_adjustments (amount) VALUES (10)";
    let human =
        EvalContext::new().with_principal(principal(PrincipalType::Human, "ana", Trust::Medium));
    let o = run(&rules, sql, Dialect::Postgres, &human);
    assert_eq!(o.decision, Decision::Block);
    let req = o.approval_required.expect("approval required");
    assert_eq!(req.rule_code, "POL-009");
    assert_eq!(req.approval.groups, ["finance-controllers"]);
    assert_eq!(o.policy_hits[0].requested, PolicyAction::RequireApproval);
    // Services never wait for a human: the fallback decides.
    let svc =
        EvalContext::new().with_principal(principal(PrincipalType::Service, "svc", Trust::Medium));
    let o = run(&rules, sql, Dialect::Postgres, &svc);
    assert_eq!(o.decision, Decision::Block);
    assert!(o.approval_required.is_none());
    let tool =
        EvalContext::new().with_principal(principal(PrincipalType::Tool, "etl", Trust::Medium));
    assert_eq!(
        run(&rules, sql, Dialect::Postgres, &tool).decision,
        Decision::Flag
    );
    // A weak principal is below min_trust: a plain block, no approval.
    let weak =
        EvalContext::new().with_principal(principal(PrincipalType::Human, "ana", Trust::Weak));
    let o = run(&rules, sql, Dialect::Postgres, &weak);
    assert_eq!(o.decision, Decision::Block);
    assert!(o.approval_required.is_none());
    // A harder block next to the approval: approval cannot unblock it.
    let mut rules = standard_rules();
    rules.push(pol("POL-009", FOUR_EYES));
    let set = PolicySet::compile(&rules);
    let o = evaluate_with_context(
        "DELETE FROM ledger_adjustments",
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
        &set,
        &human,
    );
    assert_eq!(o.decision, Decision::Block);
    assert!(o.approval_required.is_none());
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"));
}

#[test]
fn monitor_mode_and_policy_mode_never_block() {
    let rules = [pol("POL-001", REFUND_CAP)];
    let set = PolicySet::compile(&rules);
    let sql = "INSERT INTO refunds (amount) VALUES (950)";
    let monitor = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let o = evaluate_with_context(sql, Dialect::Postgres, &rules, &monitor, &set, &agent());
    assert_eq!(o.decision, Decision::Flag);
    let observed = REFUND_CAP.replace("action: block", "action: block\nmode: monitor");
    let rules = [pol("POL-001", &observed)];
    let o = run(&rules, sql, Dialect::Postgres, &agent());
    assert_eq!(o.decision, Decision::Flag);
    let approvals = [pol("POL-009", FOUR_EYES)];
    let set = PolicySet::compile(&approvals);
    let human =
        EvalContext::new().with_principal(principal(PrincipalType::Human, "ana", Trust::Medium));
    let o = evaluate_with_context(
        "DELETE FROM ledger_adjustments WHERE id = 1",
        Dialect::Postgres,
        &approvals,
        &monitor,
        &set,
        &human,
    );
    assert_eq!(o.decision, Decision::Flag);
    assert!(o.approval_required.is_none());
}

#[test]
fn precedence_085_block_then_087_then_policy() {
    let rules = [pol("POL-001", REFUND_CAP)];
    let set = PolicySet::compile(&rules);
    let tagged = EnforcementPolicy {
        sensitive_columns: vec![
            serde_json::from_str::<SensitiveColumn>(
                r#"{"table":"refunds","column":"amount","policy":"block"}"#,
            )
            .unwrap(),
        ],
        ..EnforcementPolicy::default()
    };
    let o = evaluate_with_context(
        "UPDATE refunds SET amount = 950 WHERE id = 1 RETURNING amount",
        Dialect::Postgres,
        &rules,
        &tagged,
        &set,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Block);
    // Same action: the 085 block keeps the flat fields; the policy is in the set.
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"));
    let codes: Vec<&str> = o.violations.iter().map(|v| v.rule_code.as_str()).collect();
    assert!(codes.contains(&"POL-001"));
    assert!(
        codes.iter().position(|c| *c == "VERICTO-085") < codes.iter().position(|c| *c == "POL-001")
    );
    // A policy block over a rule flag takes the decision and the flat fields.
    let mut rules = standard_rules();
    rules.push(pol("POL-001", REFUND_CAP));
    let set = PolicySet::compile(&rules);
    let o = evaluate_with_context(
        "INSERT INTO refunds VALUES (1, 950)",
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
        &set,
        &agent(),
    );
    // VERICTO-060 (insert without columns) flags; the policy is UNKNOWN
    // (no column list) and blocks.
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("POL-001"));
}

#[test]
fn compile_errors_fail_closed_in_scope_only() {
    let broken = r#"
applies_to: { ops: [delete], principal_types: [agent] }
deny_if: stmt.valuez("public.t.c").size() > 0
action: block
"#;
    let rules = [pol("POL-010", broken)];
    let set = PolicySet::compile(&rules);
    assert_eq!(set.errors().len(), 1);
    let policy = EnforcementPolicy::default();
    let o = evaluate_with_context(
        "DELETE FROM t WHERE id = 1",
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::CompileError);
    // Outside its scope nothing changes.
    let o = evaluate_with_context(
        "SELECT 1",
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Allow);
    let human =
        EvalContext::new().with_principal(principal(PrincipalType::Human, "h", Trust::Medium));
    let o = evaluate_with_context(
        "DELETE FROM t WHERE id = 1",
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &human,
    );
    assert_eq!(o.decision, Decision::Allow);
    // A broken flag policy flags instead.
    let rules = [pol(
        "POL-011",
        &broken.replace("action: block", "action: flag"),
    )];
    let set = PolicySet::compile(&rules);
    let o = evaluate_with_context(
        "DELETE FROM t WHERE id = 1",
        Dialect::Postgres,
        &rules,
        &policy,
        &set,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Flag);
}

#[test]
fn unreadable_statements_block_under_an_enforced_policy() {
    let rules = [pol("POL-001", REFUND_CAP)];
    let set = PolicySet::compile(&rules);
    let policy = EnforcementPolicy::default();
    let garbage = "INSERT INTO refunds (amount) VALUE (950";
    // Without policies: the host's fail-open default.
    assert_eq!(
        evaluate(garbage, Dialect::Postgres, &rules, &policy).decision,
        Decision::Flag
    );
    let o = evaluate_with_context(garbage, Dialect::Postgres, &rules, &policy, &set, &agent());
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"));
    assert_eq!(o.policy_hits[0].outcome, PolicyOutcome::Unreadable);
    // Not for a principal no blocking policy applies to.
    let svc =
        EvalContext::new().with_principal(principal(PrincipalType::Service, "svc", Trust::Medium));
    assert_eq!(
        evaluate_with_context(garbage, Dialect::Postgres, &rules, &policy, &set, &svc).decision,
        Decision::Flag
    );
    // Not for a monitor-mode policy, nor under monitor_mode.
    let observed = [pol(
        "POL-001",
        &REFUND_CAP.replace("action: block", "action: block\nmode: monitor"),
    )];
    let set_m = PolicySet::compile(&observed);
    assert_eq!(
        evaluate_with_context(
            garbage,
            Dialect::Postgres,
            &observed,
            &policy,
            &set_m,
            &agent()
        )
        .decision,
        Decision::Flag
    );
    // Session boilerplate stays exempt.
    let boiler = "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED";
    let o = evaluate_with_context(boiler, Dialect::Mysql, &rules, &policy, &set, &agent());
    assert_ne!(o.decision, Decision::Block);
}

#[test]
fn principal_only_policies_need_no_facts() {
    let yaml = r#"
rule: no-unknown-principals
when: principal.type == "unknown"
action: flag
"#;
    let rules = [pol("POL-012", yaml)];
    let o = run(&rules, "SELECT 1", Dialect::Postgres, &EvalContext::new());
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(
        run(&rules, "SELECT 1", Dialect::Postgres, &agent()).decision,
        Decision::Allow
    );
}

#[test]
fn legacy_guard_ands_with_cel() {
    let yaml = r#"
node_type: DeleteStmt
condition: { relation: ledger }
when: principal.type == "agent"
action: block
"#;
    let rules = [pol("POL-013", yaml)];
    assert_eq!(
        run(
            &rules,
            "DELETE FROM ledger WHERE id = 1",
            Dialect::Postgres,
            &agent()
        )
        .decision,
        Decision::Block
    );
    assert_eq!(
        run(
            &rules,
            "DELETE FROM orders WHERE id = 1",
            Dialect::Postgres,
            &agent()
        )
        .decision,
        Decision::Allow
    );
    let human =
        EvalContext::new().with_principal(principal(PrincipalType::Human, "h", Trust::Medium));
    assert_eq!(
        run(
            &rules,
            "DELETE FROM ledger WHERE id = 1",
            Dialect::Postgres,
            &human
        )
        .decision,
        Decision::Allow
    );
}

#[test]
fn multi_statement_scripts_take_the_strictest() {
    let rules = [pol("POL-001", REFUND_CAP)];
    let o = run(
        &rules,
        "INSERT INTO refunds (amount) VALUES (10); INSERT INTO refunds (amount) VALUES (950)",
        Dialect::Postgres,
        &agent(),
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.policy_hits.len(), 1);
    assert_eq!(o.policy_hits[0].statement, 1);
    assert_eq!(
        o.violations
            .iter()
            .filter(|v| v.rule_code == "POL-001")
            .count(),
        1
    );
}

#[test]
fn principal_attributes_and_groups() {
    let yaml = r#"
rule: refund-cap-services
applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [service] }
deny_if: stmt.values("public.refunds.amount").exists(v, double(v) > double(principal.attrs.max_refund))
action: block
"#;
    let rules = [pol("POL-014", yaml)];
    let mut p = principal(PrincipalType::Service, "svc-billing", Trust::Medium);
    p.attrs.insert("max_refund".into(), "500".into());
    let ctx = EvalContext::new().with_principal(p);
    assert_eq!(
        run(
            &rules,
            "INSERT INTO refunds (amount) VALUES (400)",
            Dialect::Postgres,
            &ctx
        )
        .decision,
        Decision::Allow
    );
    assert_eq!(
        run(
            &rules,
            "INSERT INTO refunds (amount) VALUES (600)",
            Dialect::Postgres,
            &ctx
        )
        .decision,
        Decision::Block
    );
    // A missing attribute is an error → UNKNOWN → block, and reported as an error.
    let bare =
        EvalContext::new().with_principal(principal(PrincipalType::Service, "svc", Trust::Medium));
    let o = run(
        &rules,
        "INSERT INTO refunds (amount) VALUES (1)",
        Dialect::Postgres,
        &bare,
    );
    assert_eq!(o.decision, Decision::Block);
    assert!(o.unknowns[0].error);
}

#[test]
fn a_monitored_exemption_is_observed_not_applied() {
    let mut rules = standard_rules();
    rules.push(pol("POL-008", &format!("{EXEMPTION}mode: monitor\n")));
    let set = PolicySet::compile(&rules);
    assert!(set.errors().is_empty());
    let ctx = EvalContext::new().with_principal(principal(
        PrincipalType::Pipeline,
        "ci-migrations",
        Trust::Strong,
    ));
    let o = evaluate_with_context(
        "DROP TABLE old_orders",
        Dialect::Postgres,
        &rules,
        &EnforcementPolicy::default(),
        &set,
        &ctx,
    );
    assert_eq!(o.decision, Decision::Block);
    let hit = o
        .policy_hits
        .iter()
        .find(|h| h.outcome == PolicyOutcome::Exempted)
        .unwrap();
    assert_eq!(
        hit.reason.as_deref(),
        Some("monitor: observed, not applied")
    );
}
