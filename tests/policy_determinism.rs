// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Determinism of business policies (design §6.1, §17): the same statement,
//! rules and declared context always give the same outcome, whatever the
//! order of the host's rule slice, and however many times it is evaluated.

use proptest::prelude::*;
use vericto_engine::policy::{
    DbContext, EvalContext, PolicySet, Principal, PrincipalType, SessionContext, Ticket,
    TimeContext, Trust,
};
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate_with_context,
    standard_rules,
};

fn pol(code: &str, sev: Severity, yaml: &str) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.into(),
        severity: sev,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml.into()),
    }
}

fn policy_rules() -> Vec<Rule> {
    vec![
        pol(
            "POL-001",
            Severity::High,
            "applies_to: {ops: [insert, update], principal_types: [agent, human]}\ndeny_if: stmt.values('public.refunds.amount').exists(v, double(v) > 200.0)\naction: block",
        ),
        pol(
            "POL-002",
            Severity::Critical,
            "applies_to: {ops: [select, update, delete]}\nrequire: stmt.tables.all(t, t != 'public.invoices' || stmt.has_filter(t + '.tenant_id'))\naction: block",
        ),
        pol(
            "POL-003",
            Severity::Medium,
            "when: db.env == 'prod'\ndeny_if: stmt.op != 'select' && !has(ticket.id)\naction: flag",
        ),
        pol(
            "POL-004",
            Severity::High,
            "applies_to: {ops: [delete], tables: ['public.ledger*']}\nmin_trust: strong\naction: block",
        ),
        pol(
            "POL-005",
            Severity::Low,
            "applies_to: {principal_types: [agent]}\nwhen: '!has(stmt.limit) || stmt.limit > 1000'\naction: monitor",
        ),
        pol(
            "POL-006",
            Severity::High,
            "applies_to: {principal_types: [pipeline]}\nmin_trust: strong\nexempt: {rule_classes: [schema_migration], cap: flag}",
        ),
        pol(
            "POL-007",
            Severity::High,
            "applies_to: {ops: [insert], principal_types: [agent, human]}\naction: require_approval",
        ),
        // A broken one too.
        pol(
            "POL-008",
            Severity::High,
            "applies_to: {ops: [update]}\ndeny_if: nope.x\naction: block",
        ),
    ]
}

const SQL: &[&str] = &[
    "INSERT INTO refunds (amount) VALUES (950)",
    "INSERT INTO refunds (amount) VALUES ($1)",
    "UPDATE refunds SET amount = 10 WHERE id = 1",
    "SELECT * FROM invoices",
    "SELECT * FROM invoices WHERE tenant_id = 3 LIMIT 10",
    "DELETE FROM ledger_2026 WHERE id = 1",
    "DELETE FROM ledger",
    "DROP TABLE orders",
    "SELECT * FROM a; DELETE FROM b WHERE id = 1",
    "garbage statement here",
];

fn ctx_strategy() -> impl Strategy<Value = EvalContext> {
    let types = prop::sample::select(vec![
        PrincipalType::Agent,
        PrincipalType::Human,
        PrincipalType::Service,
        PrincipalType::Pipeline,
        PrincipalType::Tool,
        PrincipalType::Unknown,
    ]);
    let trust = prop::sample::select(vec![Trust::Weak, Trust::Medium, Trust::Strong]);
    (
        types,
        trust,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0i64..2_000_000_000,
    )
        .prop_map(|(t, tr, prod, ticket, tenant, now)| {
            let mut c = EvalContext::new()
                .with_principal(Principal::new("p", t, tr))
                .with_time(TimeContext::utc(now));
            if prod {
                c = c.with_db(DbContext::new().with_env("prod"));
            }
            if ticket {
                c = c.with_ticket(Ticket::declared("OPS-1"));
            }
            if tenant {
                c = c.with_session(SessionContext::new().with_tenant("t"));
            }
            c
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Shuffling the host's rule slice changes nothing: neither the set
    /// compiled from it nor the outcome.
    #[test]
    fn prop_order_of_rules_never_matters(
        seed in any::<u64>(),
        sql in prop::sample::select(SQL.to_vec()),
        ctx in ctx_strategy(),
        d in prop::sample::select(vec![Dialect::Postgres, Dialect::Mysql]),
    ) {
        let mut rules = standard_rules();
        rules.extend(policy_rules());
        let policy = EnforcementPolicy::default();
        let set = PolicySet::compile(&rules);
        let base = format!("{:?}", evaluate_with_context(sql, d, &rules, &policy, &set, &ctx));
        // A deterministic shuffle from the seed.
        let mut shuffled = rules.clone();
        let mut s = seed;
        for i in (1..shuffled.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (s >> 33) as usize % (i + 1);
            shuffled.swap(i, j);
        }
        let set2 = PolicySet::compile(&shuffled);
        let other = format!("{:?}", evaluate_with_context(sql, d, &shuffled, &policy, &set2, &ctx));
        prop_assert_eq!(base, other);
    }

    /// The same input, evaluated again (with a set compiled again), gives
    /// the same outcome.
    #[test]
    fn prop_same_input_same_outcome(
        sql in prop::sample::select(SQL.to_vec()),
        ctx in ctx_strategy(),
    ) {
        let rules = policy_rules();
        let policy = EnforcementPolicy::default();
        let a = format!("{:?}", evaluate_with_context(sql, Dialect::Postgres, &rules, &policy, &PolicySet::compile(&rules), &ctx));
        let b = format!("{:?}", evaluate_with_context(sql, Dialect::Postgres, &rules, &policy, &PolicySet::compile(&rules), &ctx));
        prop_assert_eq!(a, b);
    }

    /// Monitor mode never makes a decision stricter, and never blocks.
    #[test]
    fn prop_monitor_mode_never_blocks(
        sql in prop::sample::select(SQL.to_vec()),
        ctx in ctx_strategy(),
    ) {
        let rules = policy_rules();
        let set = PolicySet::compile(&rules);
        let monitor = EnforcementPolicy { monitor_mode: true, ..EnforcementPolicy::default() };
        let o = evaluate_with_context(sql, Dialect::Postgres, &rules, &monitor, &set, &ctx);
        // A parse error under monitor mode follows the host's parse_error.
        prop_assert!(o.decision != vericto_engine::Decision::Block || o.rule_code.as_deref() == Some("VERICTO-PARSE-ERROR"));
        prop_assert!(o.approval_required.is_none());
    }

    /// Policies only ever add findings: the decision with policies is never
    /// weaker than without them (exemptions aside, which only an exempt
    /// policy at strong trust can cause, and which never touch DataMutation
    /// or Security).
    #[test]
    fn prop_policies_never_weaken_without_an_exemption(
        sql in prop::sample::select(SQL.to_vec()),
        ctx in ctx_strategy(),
    ) {
        let mut rules = standard_rules();
        let restrictive: Vec<Rule> = policy_rules().into_iter().filter(|r| r.code != "POL-006").collect();
        rules.extend(restrictive);
        let policy = EnforcementPolicy::default();
        let set = PolicySet::compile(&rules);
        let with = evaluate_with_context(sql, Dialect::Postgres, &rules, &policy, &set, &ctx);
        let without = vericto_engine::evaluate(sql, Dialect::Postgres, &rules, &policy);
        let rank = |d: vericto_engine::Decision| match d {
            vericto_engine::Decision::Allow => 0,
            vericto_engine::Decision::Flag => 1,
            vericto_engine::Decision::Block => 2,
        };
        prop_assert!(rank(with.decision) >= rank(without.decision));
    }
}
