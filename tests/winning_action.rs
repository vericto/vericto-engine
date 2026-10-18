// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The decision is the strongest resolved action over every violation, and the
//! winner reported in the flat fields is the violation that holds it.
//!
//! Before 4.2.0 the winner was chosen by severity first and its action resolved
//! afterwards, so a violation whose action a policy softened could outrank one
//! that blocks. Under a CI policy (`schema_migration_cap = Some(Flag)`) the script
//! `DROP TABLE a; UPDATE accounts SET balance = 0;` reported VERICTO-010
//! (Critical, capped to Flag) ahead of the WHERE-less UPDATE (VERICTO-030,
//! Critical, Block), and the whole file passed. Every test here runs on every
//! dialect.

use vericto_engine::{
    AccessMode, AccessPolicy, Decision, Dialect, EnforcementAction, EnforcementPolicy,
    EvaluationOutcome, MaskStyle, SensitiveColumn, SensitivePolicy, evaluate, standard_rules,
};

const ALL_DIALECTS: [Dialect; 6] = [
    Dialect::Postgres,
    Dialect::Mysql,
    Dialect::Oracle,
    Dialect::MsSql,
    Dialect::Sqlite,
    Dialect::Snowflake,
];

/// The CI-check script from the CLI offline spike.
const DROP_THEN_UPDATE: &str = "DROP TABLE a; UPDATE accounts SET balance = 0;";
/// A lower-severity blocking violation (VERICTO-040, High) after a softened one.
const DROP_THEN_COPY: &str = "DROP TABLE a; INSERT INTO b (id) SELECT id FROM c;";

fn ci_policy() -> EnforcementPolicy {
    EnforcementPolicy {
        schema_migration_cap: Some(EnforcementAction::Flag),
        ..EnforcementPolicy::default()
    }
}

fn eval(sql: &str, d: Dialect, policy: &EnforcementPolicy) -> EvaluationOutcome {
    evaluate(sql, d, &standard_rules(), policy)
}

fn codes(o: &EvaluationOutcome) -> Vec<&str> {
    o.violations.iter().map(|v| v.rule_code.as_str()).collect()
}

/// The invariants every outcome with violations must hold: the decision is the
/// strongest action of the set, `violations[0]` is the winner, and the flat fields
/// are its.
fn assert_consistent(o: &EvaluationOutcome, label: &str) {
    let strongest = o.violations.iter().map(|v| v.action).max();
    assert_eq!(o.action, strongest, "{label}: action is not the strongest");
    if let Some(winner) = o.violations.first() {
        assert_eq!(o.decision, decision_of(winner.action), "{label}");
        assert_eq!(
            o.rule_code.as_deref(),
            Some(winner.rule_code.as_str()),
            "{label}"
        );
        assert_eq!(o.severity, Some(winner.severity), "{label}");
    }
    for pair in o.violations.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let ordered = a.action > b.action
            || (a.action == b.action && a.severity > b.severity)
            || (a.action == b.action && a.severity == b.severity && a.rule_code < b.rule_code);
        assert!(ordered, "{label}: {a:?} then {b:?} is out of order");
    }
}

fn decision_of(a: EnforcementAction) -> Decision {
    match a {
        EnforcementAction::Block => Decision::Block,
        EnforcementAction::Flag => Decision::Flag,
        EnforcementAction::Monitor => Decision::Allow,
    }
}

#[test]
fn a_capped_drop_does_not_hide_a_blocking_update() {
    for d in ALL_DIALECTS {
        let o = eval(DROP_THEN_UPDATE, d, &ci_policy());
        assert_eq!(o.decision, Decision::Block, "{d:?}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-030"), "{d:?}: {o:?}");
        assert_eq!(o.action, Some(EnforcementAction::Block), "{d:?}");
        assert_eq!(
            codes(&o),
            ["VERICTO-030", "VERICTO-042", "VERICTO-010"],
            "{d:?}: the capped DROP is still reported, after both blocks"
        );
        assert_eq!(o.violations[2].action, EnforcementAction::Flag, "{d:?}");
        assert_consistent(&o, &format!("{d:?}"));
    }
}

#[test]
fn without_a_cap_the_script_blocks_and_equal_actions_break_on_the_lowest_code() {
    for d in ALL_DIALECTS {
        let o = eval(DROP_THEN_UPDATE, d, &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        // Three Critical blocks: the lowest code wins, as before 4.2.0.
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
        assert_eq!(
            codes(&o),
            ["VERICTO-010", "VERICTO-030", "VERICTO-042"],
            "{d:?}"
        );
        assert_consistent(&o, &format!("{d:?}"));
    }
}

#[test]
fn monitor_mode_still_downgrades_every_block_to_a_flag() {
    for d in ALL_DIALECTS {
        for cap in [None, Some(EnforcementAction::Flag)] {
            let policy = EnforcementPolicy {
                monitor_mode: true,
                schema_migration_cap: cap,
                ..EnforcementPolicy::default()
            };
            let o = eval(DROP_THEN_UPDATE, d, &policy);
            assert_eq!(o.decision, Decision::Flag, "{d:?} cap {cap:?}");
            assert!(o.violations.iter().all(|v| !v.action.blocks()), "{d:?}");
            // Every action is Flag: severity, then the lowest code.
            assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
            assert_consistent(&o, &format!("{d:?} monitor cap {cap:?}"));
        }
    }
}

#[test]
fn a_lower_severity_block_outranks_a_softened_critical() {
    // Through the class cap (Flag and Monitor) ...
    for cap in [EnforcementAction::Flag, EnforcementAction::Monitor] {
        let policy = EnforcementPolicy {
            schema_migration_cap: Some(cap),
            ..EnforcementPolicy::default()
        };
        for d in ALL_DIALECTS {
            let o = eval(DROP_THEN_COPY, d, &policy);
            assert_eq!(o.decision, Decision::Block, "{d:?} cap {cap:?}: {o:?}");
            assert_eq!(o.rule_code.as_deref(), Some("VERICTO-040"), "{d:?}");
            assert_eq!(o.severity, Some(vericto_engine::Severity::High), "{d:?}");
            assert_consistent(&o, &format!("{d:?} cap {cap:?}"));
        }
    }
    // ... and through the host's severity mapping: Critical only flags.
    let policy = EnforcementPolicy {
        critical: EnforcementAction::Flag,
        ..EnforcementPolicy::default()
    };
    for d in ALL_DIALECTS {
        let o = eval(DROP_THEN_COPY, d, &policy);
        assert_eq!(o.decision, Decision::Block, "{d:?}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-040"), "{d:?}");
        assert_consistent(&o, &format!("{d:?} critical=flag"));
    }
}

#[test]
fn an_overridden_rule_severity_resolves_through_the_policy() {
    // A host override that lowers VERICTO-030 and 042 to Medium (Flag) while the
    // DROP stays Critical (Block): the DROP wins, both UPDATE rules follow it.
    let mut rules = standard_rules();
    for r in rules.iter_mut() {
        if r.code == "VERICTO-030" || r.code == "VERICTO-042" {
            r.severity = vericto_engine::Severity::Medium;
        }
    }
    for d in ALL_DIALECTS {
        let o = evaluate(DROP_THEN_UPDATE, d, &rules, &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
        // Under the CI cap all three flag: Critical first.
        let o = evaluate(DROP_THEN_UPDATE, d, &rules, &ci_policy());
        assert_eq!(o.decision, Decision::Flag, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
        assert_consistent(&o, &format!("{d:?} override"));
    }
}

#[test]
fn the_rules_slice_order_changes_nothing() {
    let mut reversed = standard_rules();
    reversed.reverse();
    for d in ALL_DIALECTS {
        for sql in [DROP_THEN_UPDATE, DROP_THEN_COPY] {
            let a = eval(sql, d, &ci_policy());
            let b = evaluate(sql, d, &reversed, &ci_policy());
            assert_eq!(a.decision, b.decision, "{d:?} {sql}");
            assert_eq!(a.rule_code, b.rule_code, "{d:?} {sql}");
            assert_eq!(codes(&a), codes(&b), "{d:?} {sql}");
        }
    }
}

fn enforce_nothing_allowed() -> AccessPolicy {
    let mut policy = AccessPolicy::default();
    policy.mode = AccessMode::Enforce;
    policy
}

/// VERICTO-087 joins the set by the same order: a blocking Critical rule keeps the
/// flat fields ahead of the High allowlist block, and a capped DROP goes last.
#[test]
fn the_allowlist_violation_follows_the_same_order() {
    let policy = EnforcementPolicy {
        access_policy: Some(enforce_nothing_allowed()),
        ..ci_policy()
    };
    for d in ALL_DIALECTS {
        let o = eval(DROP_THEN_UPDATE, d, &policy);
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-030"), "{d:?}: {o:?}");
        assert_eq!(
            codes(&o),
            ["VERICTO-030", "VERICTO-042", "VERICTO-087", "VERICTO-010"],
            "{d:?}"
        );
        assert_consistent(&o, &format!("{d:?} allowlist"));
    }
}

/// VERICTO-085 too: a `flag` tag (Medium, Flag) on a script whose only rule
/// violation is a capped DROP shares the Flag action, so the Critical DROP keeps
/// the flat fields; the tag never lowers a block.
#[test]
fn the_sensitive_column_violation_follows_the_same_order() {
    let tag = |policy: SensitivePolicy| SensitiveColumn {
        schema: None,
        table: "accounts".into(),
        column: "balance".into(),
        policy,
        mask_style: MaskStyle::Full,
    };
    let sql = "DROP TABLE a; SELECT balance FROM accounts WHERE id = 1 LIMIT 1;";
    for d in ALL_DIALECTS {
        let flagged = EnforcementPolicy {
            sensitive_columns: vec![tag(SensitivePolicy::Flag)],
            ..ci_policy()
        };
        let o = eval(sql, d, &flagged);
        assert_eq!(o.decision, Decision::Flag, "{d:?}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
        assert_eq!(codes(&o), ["VERICTO-010", "VERICTO-085"], "{d:?}");
        assert_consistent(&o, &format!("{d:?} flag tag"));

        let blocked = EnforcementPolicy {
            sensitive_columns: vec![tag(SensitivePolicy::Block)],
            ..ci_policy()
        };
        let o = eval(sql, d, &blocked);
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"), "{d:?}");
        assert_eq!(codes(&o), ["VERICTO-085", "VERICTO-010"], "{d:?}");
        assert_consistent(&o, &format!("{d:?} block tag"));
    }
}

/// MySQL executes the content of `/*! … */`. The reading that holds the UPDATE
/// blocks, so it is the strictest reading, and inside it the UPDATE outranks the
/// capped DROP.
#[test]
fn mysql_executed_comments_follow_the_same_order() {
    let sql = "DROP TABLE a; /*! UPDATE accounts SET balance = 0 */";
    let o = eval(sql, Dialect::Mysql, &ci_policy());
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-030"), "{o:?}");
    assert_consistent(&o, "mysql executed comment");

    let plain = eval(DROP_THEN_UPDATE, Dialect::Mysql, &ci_policy());
    assert_eq!(o.rule_code, plain.rule_code);
    assert_eq!(codes(&o), codes(&plain));
}

/// A single statement is unchanged: its violations already share one statement,
/// and the cap applies to all of them alike.
#[test]
fn single_statements_keep_their_outcome() {
    for d in ALL_DIALECTS {
        let o = eval("DROP TABLE a", d, &ci_policy());
        assert_eq!(o.decision, Decision::Flag, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-010"), "{d:?}");
        let o = eval("UPDATE accounts SET balance = 0", d, &ci_policy());
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-030"), "{d:?}");
    }
}
