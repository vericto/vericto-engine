//! MySQL reads some text differently from sqlparser: comments and, depending
//! on the server's string-escape mode, where a string literal ends. The
//! engine must evaluate the statement MySQL executes, so each wrapped
//! statement here must get exactly the decision of the equivalent plain
//! statement, under every rule, with or without tags.
//!
//! Text the engine cannot resolve with certainty blocks with VERICTO-086, a
//! Security rule, never with a PARSE_ERROR (which a fail-open policy forwards).

use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome, ParseErrorAction,
    Rule, RuleClass, RuleType, Severity, evaluate,
};

const DIVERGENCE: &str = "VERICTO-086";

fn rule(code: &str, sev: Severity) -> Rule {
    Rule {
        rule_id: code.into(),
        code: code.into(),
        severity: sev,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }
}

fn ruleset() -> Vec<Rule> {
    use Severity::*;
    vec![
        rule("VERICTO-001", Critical),
        rule("VERICTO-003", Critical),
        rule("VERICTO-010", Critical),
        rule("VERICTO-011", Critical),
        rule("VERICTO-030", Critical),
        rule("VERICTO-042", Critical),
        rule("VERICTO-090", Critical),
        rule("VERICTO-070", High),
        rule("VERICTO-050", Medium),
        rule("VERICTO-051", Medium),
        rule("VERICTO-060", Low),
    ]
}

fn my(sql: &str) -> EvaluationOutcome {
    evaluate(
        sql,
        Dialect::Mysql,
        &ruleset(),
        &EnforcementPolicy::default(),
    )
}

/// The fields a host acts on.
fn verdict(o: &EvaluationOutcome) -> (Decision, Option<EnforcementAction>, Option<String>) {
    (o.decision, o.action, o.rule_code.clone())
}

fn assert_same_as_plain(wrapped: &str, plain: &str) {
    let (w, p) = (my(wrapped), my(plain));
    assert_eq!(
        verdict(&w),
        verdict(&p),
        "\nwrapped: {wrapped}\n  plain: {plain}\nwrapped outcome: {w:?}\n  plain outcome: {p:?}"
    );
}

#[test]
fn comment_content_mysql_executes_is_evaluated() {
    for (wrapped, plain) in [
        ("/*! DELETE FROM accounts */", "DELETE FROM accounts"),
        ("/*!50000 DELETE FROM accounts */", "DELETE FROM accounts"),
        ("/*!80000DELETE FROM accounts*/", "DELETE FROM accounts"),
        (
            "SELECT id FROM accounts WHERE id = 1 LIMIT 1; /*!40000 DROP TABLE accounts */",
            "SELECT id FROM accounts WHERE id = 1 LIMIT 1; DROP TABLE accounts",
        ),
        (
            "UPDATE accounts SET n = 1 WHERE id = 1 /*! OR 1 = 1 */",
            "UPDATE accounts SET n = 1 WHERE id = 1 OR 1 = 1",
        ),
        (
            "SELECT id FROM accounts WHERE id = 7 /*!50700 OR 'a' = 'a' */ LIMIT 5",
            "SELECT id FROM accounts WHERE id = 7 OR 'a' = 'a' LIMIT 5",
        ),
        ("/*M! DELETE FROM accounts */", "DELETE FROM accounts"),
        ("/*M!100100 TRUNCATE accounts */", "TRUNCATE accounts"),
    ] {
        assert_same_as_plain(wrapped, plain);
        assert_eq!(my(wrapped).decision, Decision::Block, "{wrapped}");
    }
}

#[test]
fn a_versioned_comment_is_read_for_every_server_version() {
    // A server older than the comment's version skips it: the statement that
    // runs there has no filter. The stricter reading wins.
    assert_same_as_plain(
        "DELETE FROM accounts /*!99999 WHERE id = 1 */",
        "DELETE FROM accounts",
    );
    assert_same_as_plain(
        "UPDATE accounts SET n = 0 /*!90000 WHERE id = 1 */",
        "UPDATE accounts SET n = 0",
    );
    // A current server runs it: the statement that runs there is a
    // tautology.
    assert_same_as_plain(
        "DELETE FROM accounts WHERE id = 3 /*!99999 OR 1 = 1 */",
        "DELETE FROM accounts WHERE id = 3 OR 1 = 1",
    );
    // Both readings filter: nothing to report.
    assert_same_as_plain(
        "DELETE FROM accounts WHERE id = 2 /*!50000 AND n > 0 */",
        "DELETE FROM accounts WHERE id = 2 AND n > 0",
    );
    assert_eq!(
        my("DELETE FROM accounts WHERE id = 2 /*!50000 AND n > 0 */").decision,
        Decision::Allow
    );
}

#[test]
fn comment_start_follows_mysql() {
    for (wrapped, plain) in [
        (
            "DELETE FROM accounts WHERE id = 1 --1 OR 1 = 1",
            "DELETE FROM accounts WHERE id = 1 - -1 OR 1 = 1",
        ),
        (
            "SELECT id FROM accounts WHERE id = 3 --2 OR 2 = 2\nLIMIT 1",
            "SELECT id FROM accounts WHERE id = 3 - -2 OR 2 = 2 LIMIT 1",
        ),
    ] {
        assert_same_as_plain(wrapped, plain);
        assert_eq!(my(wrapped).decision, Decision::Block, "{wrapped}");
    }
    // Comments both readers agree on.
    assert_same_as_plain(
        "DELETE FROM accounts WHERE id = 1 -- OR 1 = 1",
        "DELETE FROM accounts WHERE id = 1",
    );
    assert_same_as_plain(
        "DELETE FROM accounts WHERE id = 1 --\tOR 1 = 1",
        "DELETE FROM accounts WHERE id = 1",
    );
}

#[test]
fn ordinary_comments_are_whitespace() {
    for (wrapped, plain) in [
        (
            "DELETE FROM accounts # trailing note\n WHERE id = 1",
            "DELETE FROM accounts WHERE id = 1",
        ),
        (
            "DELETE FROM accounts /* note */ WHERE id = 1",
            "DELETE FROM accounts WHERE id = 1",
        ),
        ("DELETE/**/FROM/**/accounts", "DELETE FROM accounts"),
        (
            "SELECT id FROM accounts WHERE id = 1 /* it's a note */ LIMIT 1",
            "SELECT id FROM accounts WHERE id = 1 LIMIT 1",
        ),
    ] {
        assert_same_as_plain(wrapped, plain);
    }
}

#[test]
fn string_escapes_are_read_under_both_modes() {
    // The literal ends at a different place in each escape mode, and more
    // follows it in one of them. The stricter reading wins.
    assert_same_as_plain(
        r"SELECT 'a\'; DELETE FROM accounts; -- '",
        r"SELECT 'a\\'; DELETE FROM accounts",
    );
    assert_same_as_plain(
        r#"SELECT "a\" ; UPDATE accounts SET n = 0 ; -- ""#,
        r"SELECT 'a\\'; UPDATE accounts SET n = 0",
    );
    // The other direction.
    assert_same_as_plain(
        r"SELECT id FROM accounts WHERE name = 'x\' OR 1 = 1 -- ' LIMIT 1",
        r"SELECT id FROM accounts WHERE name = 'x\\' OR 1 = 1",
    );
    // Same structure in both modes: unchanged.
    assert_same_as_plain(
        r"SELECT id FROM accounts WHERE name = 'O\'Brien' LIMIT 1",
        r"SELECT id FROM accounts WHERE name = 'O''Brien' LIMIT 1",
    );
    assert_eq!(
        my(r"SELECT id FROM accounts WHERE name = 'O\'Brien' LIMIT 1").decision,
        Decision::Allow
    );
}

#[test]
fn the_stricter_reading_wins_at_every_level() {
    // flag (no LIMIT) over allow.
    let o = my(r"SELECT 'a\'; SELECT id FROM accounts WHERE id = 1; -- ' LIMIT 1");
    assert_eq!(
        (o.decision, o.action),
        (Decision::Flag, Some(EnforcementAction::Flag)),
        "{o:?}"
    );
    // monitor (INSERT without columns, Low) over allow.
    let o = my(r"SELECT 'a\' LIMIT 1; INSERT INTO accounts VALUES (1); -- ' LIMIT 1");
    assert_eq!(
        (o.decision, o.action),
        (Decision::Allow, Some(EnforcementAction::Monitor)),
        "{o:?}"
    );
    // block over flag.
    let o = my(r"SELECT 'a\'; DELETE FROM accounts; -- ' FROM accounts WHERE id = 1");
    assert_eq!(o.decision, Decision::Block, "{o:?}");
}

#[test]
fn unresolvable_text_blocks_with_the_divergence_rule() {
    for sql in [
        // unterminated executable comment
        "/*! DELETE FROM accounts",
        "SELECT 1 /*!50000 , id FROM accounts",
        // a comment inside an executable comment
        "/*! DELETE FROM accounts /* x */ */",
        "/*! DELETE FROM accounts # x\n */",
        "/*! DELETE FROM accounts -- x\n */",
        // nested comment
        "SELECT 1 /* /* */ ; DELETE FROM accounts -- */",
        // unterminated comment
        "SELECT 1 /* DELETE FROM accounts",
        // a statement separator or a comment terminator in a literal inside
        // an executable comment
        "/*! SELECT 1; DELETE FROM accounts */",
        "/*! SELECT '*/' */",
        // a version number MySQL releases do not all read the same way
        "/*!500001 DELETE FROM accounts */",
        "/*!500 DELETE FROM accounts */",
    ] {
        for parse_error in [ParseErrorAction::AllowReport, ParseErrorAction::Block] {
            let p = EnforcementPolicy {
                parse_error,
                ..EnforcementPolicy::default()
            };
            // Blocks with or without rules: it is not a rule the host enables.
            for rules in [ruleset(), Vec::new()] {
                let o = evaluate(sql, Dialect::Mysql, &rules, &p);
                assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
                assert_eq!(o.rule_code.as_deref(), Some(DIVERGENCE), "{sql}: {o:?}");
                assert_eq!(o.severity, Some(Severity::Critical), "{sql}");
                assert_eq!(o.violations.len(), 1, "{sql}");
                assert_eq!(o.violations[0].rule_code, DIVERGENCE);
            }
        }
    }
    assert_eq!(RuleClass::for_code(DIVERGENCE), RuleClass::Security);
}

#[test]
fn hosts_that_parse_then_evaluate_get_the_divergence_rule_not_a_parse_error() {
    // The TCP proxy and the Runtime API call the parser and the rule engine
    // separately and map a parser `Err` through `parse_error`.
    use vericto_engine::RuleEngine;
    use vericto_engine::parser::parser_for;
    let parsed = parser_for(Dialect::Mysql)
        .parse("/*! DELETE FROM accounts")
        .expect("ambiguous text is not a parse error");
    let o = RuleEngine::evaluate(&parsed, &[], &EnforcementPolicy::default());
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some(DIVERGENCE));
    // And the normalized reading reaches the rules through the same calls.
    let parsed = parser_for(Dialect::Mysql)
        .parse("/*!50000 DELETE FROM accounts */")
        .unwrap();
    let o = RuleEngine::evaluate(&parsed, &ruleset(), &EnforcementPolicy::default());
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"), "{o:?}");
}

#[test]
fn the_divergence_rule_respects_monitor_mode() {
    // Dry-run never blocks (the monitor_mode invariant), but still reports.
    let p = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let o = evaluate("/*! DELETE FROM accounts", Dialect::Mysql, &ruleset(), &p);
    assert_eq!(o.decision, Decision::Flag, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some(DIVERGENCE));
}

#[test]
fn constructs_apply_without_tags_and_with_tags() {
    use vericto_engine::{SensitiveColumn, SensitivePolicy};
    let tagged = EnforcementPolicy {
        sensitive_columns: vec![SensitiveColumn {
            schema: None,
            table: "people".into(),
            column: "email".into(),
            policy: SensitivePolicy::Flag,
            mask_style: Default::default(),
        }],
        ..EnforcementPolicy::default()
    };
    for p in [EnforcementPolicy::default(), tagged] {
        let o = evaluate(
            "/*!50000 DELETE FROM accounts */",
            Dialect::Mysql,
            &ruleset(),
            &p,
        );
        assert_eq!(o.decision, Decision::Block, "{o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"), "{o:?}");
    }
}

#[test]
fn postgres_is_unaffected() {
    // Postgres reads comments and standard strings by its own rules. Every
    // fixture above keeps the Postgres reading, and VERICTO-086 never appears.
    let pg = |sql: &str| {
        evaluate(
            sql,
            Dialect::Postgres,
            &ruleset(),
            &EnforcementPolicy::default(),
        )
    };
    for sql in [
        "/*! DELETE FROM accounts */",
        "/*!50000 DELETE FROM accounts */",
        "DELETE FROM accounts /*!99999 WHERE id = 1 */",
        "DELETE FROM accounts WHERE id = 1 --1 OR 1 = 1",
        "SELECT 1 /* /* */ DELETE FROM accounts */",
    ] {
        let o = pg(sql);
        assert_ne!(o.rule_code.as_deref(), Some(DIVERGENCE), "{sql}");
    }
    // Comments are comments to Postgres.
    assert_eq!(pg("/*! DELETE FROM accounts */").decision, Decision::Allow);
    assert_eq!(
        pg("DELETE FROM accounts WHERE id = 1 --1 OR 1 = 1").decision,
        Decision::Allow
    );
    // A nested comment is one comment to Postgres too.
    assert_eq!(
        pg("SELECT 1 /* /* */ DELETE FROM accounts */")
            .rule_code
            .as_deref(),
        Some("VERICTO-050")
    );
    // A Postgres literal has no backslash escapes.
    let o = pg(r"SELECT 'a\'; DELETE FROM accounts; -- '");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"), "{o:?}");
    let o = pg(r"SELECT id FROM accounts WHERE name = 'x\' OR 1 = 1 -- ' LIMIT 1");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-090"), "{o:?}");
}
