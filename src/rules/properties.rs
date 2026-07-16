//! Property-based and example-based tests for the severity-based-enforcement
//! feature (spec: `severity-based-enforcement`).
//!
//! The engine's severity/action resolution functions (`Severity::from_legacy`,
//! the `Severity` total order, `EnforcementPolicy::action_for`,
//! `Decision::from_action`, `EnforcementPolicy::parse_error_decision`, and the
//! serde round-trips) are pure and deterministic, which makes them ideal for
//! property-based testing. Properties P1-P8 are implemented here with
//! `proptest`; example-based engine unit tests (task 1.15) follow.

use proptest::prelude::*;

use crate::rules::engine::{
    Decision, EnforcementAction, EnforcementPolicy, ParseErrorAction, Severity,
};

// ---------------------------------------------------------------------------
// Strategies (generators)
// ---------------------------------------------------------------------------

/// Uniform generator over the five canonical `Severity` variants.
fn severity_strategy() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Informational),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

/// Uniform generator over the three `EnforcementAction` variants.
fn action_strategy() -> impl Strategy<Value = EnforcementAction> {
    prop_oneof![
        Just(EnforcementAction::Monitor),
        Just(EnforcementAction::Flag),
        Just(EnforcementAction::Block),
    ]
}

/// Uniform generator over the two `ParseErrorAction` variants.
fn parse_error_action_strategy() -> impl Strategy<Value = ParseErrorAction> {
    prop_oneof![
        Just(ParseErrorAction::AllowReport),
        Just(ParseErrorAction::Block),
    ]
}

/// Generator for an arbitrary `EnforcementPolicy`: an arbitrary action per
/// severity level, an arbitrary parse-error action, and an arbitrary
/// monitor_mode flag.
fn policy_strategy() -> impl Strategy<Value = EnforcementPolicy> {
    (
        action_strategy(),
        action_strategy(),
        action_strategy(),
        action_strategy(),
        action_strategy(),
        parse_error_action_strategy(),
        any::<bool>(),
    )
        .prop_map(
            |(critical, high, medium, low, informational, parse_error, monitor_mode)| {
                EnforcementPolicy {
                    critical,
                    high,
                    medium,
                    low,
                    informational,
                    parse_error,
                    monitor_mode,
                }
            },
        )
}

/// The canonical legacy/engine/canonical tokens recognized by `from_legacy`.
const KNOWN_TOKENS: &[&str] = &[
    "critical",
    "warning",
    "info",
    "medium",
    "high",
    "low",
    "informational",
];

/// Re-cases each character of `s` according to `flips` (true → upper).
fn apply_casing(s: &str, flips: &[bool]) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if flips.get(i).copied().unwrap_or(false) {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Generator over the known tokens (any casing) paired with their documented
/// canonical severity.
fn known_token_strategy() -> impl Strategy<Value = (String, Severity)> {
    let tokens = prop_oneof![
        Just(("critical", Severity::Critical)),
        Just(("warning", Severity::High)),
        Just(("info", Severity::Low)),
        Just(("medium", Severity::Medium)),
        Just(("high", Severity::High)),
        Just(("low", Severity::Low)),
        Just(("informational", Severity::Informational)),
    ];
    (tokens, prop::collection::vec(any::<bool>(), 0..16))
        .prop_map(|((tok, sev), flips)| (apply_casing(tok, &flips), sev))
}

// ---------------------------------------------------------------------------
// Properties P1-P8
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    // Feature: severity-based-enforcement, Property 1: `Severity::from_legacy`
    // is total (no panic for any input) and deterministic (same input always
    // yields the same result).
    // Validates: Requirements 2.5, 2.7
    #[test]
    fn p1_from_legacy_is_total_and_deterministic(s in any::<String>()) {
        let first = Severity::from_legacy(&s);
        let second = Severity::from_legacy(&s);
        prop_assert_eq!(first, second);
    }

    // Feature: severity-based-enforcement, Property 2: known legacy/canonical
    // tokens (any casing) map to their documented canonical severity.
    // Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.7
    #[test]
    fn p2_known_tokens_map_to_canonical((raw, expected) in known_token_strategy()) {
        prop_assert_eq!(Severity::from_legacy(&raw), expected);
    }

    // Feature: severity-based-enforcement, Property 2 (fallback): any string
    // that is not (case-insensitively) a known token falls back to `Medium`.
    // Validates: Requirements 2.7
    #[test]
    fn p2_unknown_tokens_fall_back_to_medium(
        s in any::<String>().prop_filter(
            "exclude known tokens",
            |s| {
                let lower = s.to_ascii_lowercase();
                !KNOWN_TOKENS.iter().any(|t| *t == lower)
            },
        )
    ) {
        prop_assert_eq!(Severity::from_legacy(&s), Severity::Medium);
    }

    // Feature: severity-based-enforcement, Property 3: the derived `Ord` on
    // `Severity` is a total order (total, reflexive, antisymmetric, transitive).
    // Validates: Requirements 1.2
    #[test]
    fn p3_severity_is_total_order(
        a in severity_strategy(),
        b in severity_strategy(),
        c in severity_strategy(),
    ) {
        // Reflexive.
        prop_assert!(a <= a);
        // Total: every pair is comparable.
        prop_assert!(a <= b || b <= a);
        // Antisymmetric.
        if a <= b && b <= a {
            prop_assert_eq!(a, b);
        }
        // Transitive.
        if a <= b && b <= c {
            prop_assert!(a <= c);
        }
    }

    // Feature: severity-based-enforcement, Property 4: `action_for` is total
    // and the default policy matches the documented map.
    // Validates: Requirements 4.1
    #[test]
    fn p4_action_for_default_matches_map(s in severity_strategy()) {
        let action = EnforcementPolicy::default().action_for(s);
        // The result is always one of the three valid actions.
        prop_assert!(matches!(
            action,
            EnforcementAction::Block | EnforcementAction::Flag | EnforcementAction::Monitor
        ));
        let expected = match s {
            Severity::Critical => EnforcementAction::Block,
            Severity::High => EnforcementAction::Block,
            Severity::Medium => EnforcementAction::Flag,
            Severity::Low => EnforcementAction::Monitor,
            Severity::Informational => EnforcementAction::Monitor,
        };
        prop_assert_eq!(action, expected);
    }

    // Feature: severity-based-enforcement, Property 5: monitor_mode is safe
    // (never blocks) and monotone (never upgrades an action to Block).
    // Validates: Requirements 4.4, 4.6
    #[test]
    fn p5_monitor_mode_is_safe_and_monotone(
        policy in policy_strategy(),
        s in severity_strategy(),
    ) {
        let mut with_monitor = policy;
        with_monitor.monitor_mode = true;
        let mut without_monitor = policy;
        without_monitor.monitor_mode = false;

        // Safety (R4.4): under monitor_mode no severity resolves to Block.
        prop_assert_ne!(with_monitor.action_for(s), EnforcementAction::Block);

        // Monotonicity (R4.6): under the order Monitor < Flag < Block, enabling
        // monitor_mode never increases the resolved action.
        prop_assert!(with_monitor.action_for(s) <= without_monitor.action_for(s));
    }

    // Feature: severity-based-enforcement, Property 6: under the default policy
    // a Critical violation always resolves to Block, and changing ONLY the
    // non-critical levels cannot alter the Critical resolution.
    // Validates: Requirements 9.1
    #[test]
    fn p6_destructive_critical_invariant_and_column_independence(
        high in action_strategy(),
        medium in action_strategy(),
        low in action_strategy(),
        informational in action_strategy(),
    ) {
        // Default invariant.
        prop_assert_eq!(
            EnforcementPolicy::default().action_for(Severity::Critical),
            EnforcementAction::Block
        );

        // Derive from default() changing only non-critical columns.
        let policy = EnforcementPolicy {
            high,
            medium,
            low,
            informational,
            ..EnforcementPolicy::default()
        };
        prop_assert_eq!(policy.action_for(Severity::Critical), EnforcementAction::Block);
    }

    // Feature: severity-based-enforcement, Property 7: decision/action mapping
    // and parse-error decision are consistent with their configuration.
    // Validates: Requirements 3.6, 5.5, 5.6
    #[test]
    fn p7_decision_action_and_parse_error_consistency(
        action in action_strategy(),
        parse_error in parse_error_action_strategy(),
    ) {
        let expected_decision = match action {
            EnforcementAction::Block => Decision::Block,
            EnforcementAction::Flag => Decision::Flag,
            EnforcementAction::Monitor => Decision::Allow,
        };
        prop_assert_eq!(Decision::from_action(action), expected_decision);

        let policy = EnforcementPolicy {
            parse_error,
            ..EnforcementPolicy::default()
        };
        let expected_parse_error_decision = match parse_error {
            ParseErrorAction::AllowReport => Decision::Flag,
            ParseErrorAction::Block => Decision::Block,
        };
        prop_assert_eq!(policy.parse_error_decision(), expected_parse_error_decision);
    }

    // Feature: severity-based-enforcement, Property 8: serde round-trip for
    // every Severity and EnforcementAction variant yields the original.
    // Validates: Requirements 1.8
    #[test]
    fn p8_serde_round_trip(
        severity in severity_strategy(),
        action in action_strategy(),
    ) {
        let sev_json = serde_json::to_string(&severity).expect("severity serializes");
        let sev_back: Severity =
            serde_json::from_str(&sev_json).expect("severity deserializes");
        prop_assert_eq!(sev_back, severity);

        let act_json = serde_json::to_string(&action).expect("action serializes");
        let act_back: EnforcementAction =
            serde_json::from_str(&act_json).expect("action deserializes");
        prop_assert_eq!(act_back, action);
    }
}

// Feature: severity-based-enforcement, Property 8 (uniqueness): `as_str()` is
// unique per Severity variant (no two variants share a textual representation).
// Validates: Requirements 1.8
#[test]
fn p8_severity_as_str_is_unique_per_variant() {
    let all = [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    let mut seen = std::collections::HashSet::new();
    for sev in all {
        assert!(
            seen.insert(sev.as_str()),
            "as_str() representation must be unique per variant"
        );
    }
    assert_eq!(seen.len(), all.len());
}

// ---------------------------------------------------------------------------
// Example-based engine unit tests (task 1.15)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod examples {
    use crate::parser::{parser_for, Dialect};
    use crate::rules::engine::{
        Decision, EnforcementAction, EnforcementPolicy, ParseErrorAction, Rule, RuleEngine,
        RuleType, Severity,
    };

    /// Builds a standard built-in rule for the given code/severity.
    fn rule(code: &str, severity: Severity, default_action: EnforcementAction) -> Rule {
        Rule {
            rule_id: code.to_string(),
            code: code.to_string(),
            severity,
            default_action,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        }
    }

    // R4.1: action resolution per severity under the default policy.
    #[test]
    fn default_policy_action_resolution_per_severity() {
        let p = EnforcementPolicy::default();
        assert_eq!(p.action_for(Severity::Critical), EnforcementAction::Block);
        assert_eq!(p.action_for(Severity::High), EnforcementAction::Block);
        assert_eq!(p.action_for(Severity::Medium), EnforcementAction::Flag);
        assert_eq!(p.action_for(Severity::Low), EnforcementAction::Monitor);
        assert_eq!(
            p.action_for(Severity::Informational),
            EnforcementAction::Monitor
        );
    }

    // R4.2: a per-severity override replaces the default action for that level
    // (and leaves the others untouched).
    #[test]
    fn custom_policy_overrides_take_effect() {
        let custom = EnforcementPolicy {
            medium: EnforcementAction::Block,
            low: EnforcementAction::Flag,
            ..EnforcementPolicy::default()
        };
        assert_eq!(
            custom.action_for(Severity::Medium),
            EnforcementAction::Block
        );
        assert_eq!(custom.action_for(Severity::Low), EnforcementAction::Flag);
        // Untouched levels keep the default mapping.
        assert_eq!(
            custom.action_for(Severity::Critical),
            EnforcementAction::Block
        );
        assert_eq!(
            custom.action_for(Severity::Informational),
            EnforcementAction::Monitor
        );
    }

    // R5.5: parse-error fail-open (AllowReport) resolves to a Flag decision via
    // the crate-level `evaluate` convenience.
    #[test]
    fn parse_error_allow_report_yields_flag() {
        let policy = EnforcementPolicy {
            parse_error: ParseErrorAction::AllowReport,
            ..EnforcementPolicy::default()
        };
        let outcome = crate::evaluate("DELETE FORM users", Dialect::Postgres, &[], &policy);
        assert_eq!(outcome.decision, Decision::Flag);
        assert_eq!(outcome.action, Some(EnforcementAction::Flag));
        assert_eq!(outcome.severity, Some(Severity::Medium));
        assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"));
    }

    // R5.6: parse-error fail-closed (Block) resolves to a Block decision.
    #[test]
    fn parse_error_block_yields_block() {
        let policy = EnforcementPolicy {
            parse_error: ParseErrorAction::Block,
            ..EnforcementPolicy::default()
        };
        let outcome = crate::evaluate("DELETE FORM users", Dialect::Postgres, &[], &policy);
        assert_eq!(outcome.decision, Decision::Block);
        assert_eq!(outcome.action, Some(EnforcementAction::Block));
    }

    // R2.1-2.4, 2.7: exact `from_legacy` cases, including garbage → Medium.
    #[test]
    fn from_legacy_exact_cases() {
        assert_eq!(Severity::from_legacy("critical"), Severity::Critical);
        assert_eq!(Severity::from_legacy("warning"), Severity::High);
        assert_eq!(Severity::from_legacy("info"), Severity::Low);
        assert_eq!(Severity::from_legacy("medium"), Severity::Medium);
        assert_eq!(Severity::from_legacy("high"), Severity::High);
        assert_eq!(Severity::from_legacy("low"), Severity::Low);
        assert_eq!(
            Severity::from_legacy("informational"),
            Severity::Informational
        );
        // Casing is normalized.
        assert_eq!(Severity::from_legacy("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_legacy("Warning"), Severity::High);
        // Garbage falls back to the safe default.
        assert_eq!(Severity::from_legacy("garbage"), Severity::Medium);
        assert_eq!(Severity::from_legacy(""), Severity::Medium);
    }

    // R3.5, R3.7: a matching violation populates the outcome fields.
    #[test]
    fn matching_violation_populates_outcome() {
        let parsed = parser_for(Dialect::Postgres)
            .parse("SELECT id FROM users")
            .expect("must parse");
        let r = rule("VERICTO-050", Severity::Medium, EnforcementAction::Flag);
        let outcome = RuleEngine::evaluate(
            &parsed,
            std::slice::from_ref(&r),
            &EnforcementPolicy::default(),
        );

        assert_eq!(outcome.decision, Decision::Flag);
        assert_eq!(outcome.action, Some(EnforcementAction::Flag));
        assert_eq!(outcome.severity, Some(Severity::Medium));
        assert_eq!(outcome.rule_id.as_deref(), Some("VERICTO-050"));
        assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-050"));
        assert!(outcome.ast_node_path.is_some());
    }

    // R3.2: no matching rule yields the `allowed()` outcome (Allow, all None).
    #[test]
    fn no_match_yields_allowed_outcome() {
        let parsed = parser_for(Dialect::Postgres)
            .parse("SELECT id FROM users LIMIT 10")
            .expect("must parse");
        let r = rule("VERICTO-050", Severity::Medium, EnforcementAction::Flag);
        let outcome = RuleEngine::evaluate(
            &parsed,
            std::slice::from_ref(&r),
            &EnforcementPolicy::default(),
        );

        assert_eq!(outcome.decision, Decision::Allow);
        assert_eq!(outcome.action, None);
        assert_eq!(outcome.severity, None);
        assert_eq!(outcome.rule_id, None);
        assert_eq!(outcome.rule_code, None);
    }

    // R3.2 / R4.2: under a custom policy where Medium → Block, a Medium
    // violation produces a Block decision end-to-end.
    #[test]
    fn custom_policy_blocks_medium_violation_end_to_end() {
        let parsed = parser_for(Dialect::Postgres)
            .parse("SELECT id FROM users")
            .expect("must parse");
        let r = rule("VERICTO-050", Severity::Medium, EnforcementAction::Flag);
        let policy = EnforcementPolicy {
            medium: EnforcementAction::Block,
            ..EnforcementPolicy::default()
        };
        let outcome = RuleEngine::evaluate(&parsed, std::slice::from_ref(&r), &policy);
        assert_eq!(outcome.decision, Decision::Block);
        assert_eq!(outcome.action, Some(EnforcementAction::Block));
    }
}
