//! Verdicts the sqlparser 0.52 → 0.63 upgrade (3.9.0) must keep, or changes
//! it makes on purpose, pinned on statements taken from the existing test
//! suites, documentation and traffic fixtures.
//!
//! sqlparser 0.63 accepts syntax 0.52 rejected and reads some text
//! differently. Where that would have let a statement through that 3.8.2
//! blocked or flagged, the engine keeps the old outcome (see
//! `parser::walk::not_analysed` and `parser::executable_comments`); where the
//! new reading is the one the server executes, the rules now see it.

use vericto_engine::{
    Decision, Dialect, EnforcementAction, EnforcementPolicy, MaskStyle, ParseErrorAction, Rule,
    RuleType, SensitiveColumn, SensitivePolicy, Severity, evaluate,
};

const SQLPARSER_DIALECTS: [Dialect; 3] = [Dialect::Mysql, Dialect::Oracle, Dialect::MsSql];

fn rules() -> Vec<Rule> {
    ["VERICTO-001", "VERICTO-003", "VERICTO-010", "VERICTO-030"]
        .into_iter()
        .map(|code| Rule {
            rule_id: code.into(),
            code: code.into(),
            severity: Severity::Critical,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        })
        .collect()
}

fn eval(sql: &str, d: Dialect, p: &EnforcementPolicy) -> vericto_engine::EvaluationOutcome {
    evaluate(sql, d, &rules(), p)
}

/// A data-modifying CTE was a parse error before; it now parses on every
/// dialect, and the statement inside is evaluated like any nested one.
#[test]
fn data_modifying_ctes_are_evaluated() {
    let p = EnforcementPolicy::default();
    for d in SQLPARSER_DIALECTS {
        let o = eval(
            "WITH x AS (DELETE FROM users RETURNING id) SELECT * FROM x",
            d,
            &p,
        );
        assert_eq!(o.decision, Decision::Block, "{d:?}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"), "{d:?}");
        // 0.52 already parsed the UPDATE form, but the walker skipped it.
        let o = eval(
            "WITH x AS (UPDATE accounts SET balance = 0 RETURNING id) SELECT * FROM x",
            d,
            &p,
        );
        assert_eq!(o.decision, Decision::Block, "{d:?}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-030"), "{d:?}");
    }
}

/// sqlparser 0.53 reads `true`/`false` as identifiers on MS SQL. They stay
/// tautologies to the engine.
#[test]
fn mssql_boolean_words_stay_tautologies() {
    for sql in [
        "DELETE FROM users WHERE true",
        "DELETE FROM users WHERE NOT FALSE",
    ] {
        let o = eval(sql, Dialect::MsSql, &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-003"), "{sql}");
    }
}

/// Statement kinds sqlparser 0.52 could not parse, which the engine does not
/// model, still resolve through the host's `parse_error`, as before.
#[test]
fn statement_kinds_new_to_sqlparser_stay_parse_errors() {
    let strict = EnforcementPolicy {
        parse_error: ParseErrorAction::Block,
        ..EnforcementPolicy::default()
    };
    for sql in [
        "VACUUM jobs",
        "LOCK TABLE jobs",
        "RESET ALL",
        "SET GLOBAL autocommit = 1",
        "SET SESSION AUTHORIZATION admin",
    ] {
        for d in SQLPARSER_DIALECTS {
            let o = eval(sql, d, &EnforcementPolicy::default());
            assert_eq!(o.decision, Decision::Flag, "{d:?} {sql}: {o:?}");
            assert_eq!(
                o.rule_code.as_deref(),
                Some("VERICTO-PARSE-ERROR"),
                "{d:?} {sql}"
            );
            assert_eq!(
                eval(sql, d, &strict).decision,
                Decision::Block,
                "{d:?} {sql}"
            );
        }
    }
    // SQL Server reads `SET NAMES …` as one of its session options now.
    let o = eval("SET NAMES utf8mb4", Dialect::MsSql, &strict);
    assert_eq!(o.decision, Decision::Block, "{o:?}");
}

/// Oracle never executes a `/*! … */` comment, which sqlparser's Generic
/// dialect now reads as code: the comment stays a comment.
#[test]
fn oracle_reads_mysql_executable_comments_as_comments() {
    let p = EnforcementPolicy::default();
    // Oracle deletes every row: the WHERE is inside a comment.
    let o = eval(
        "DELETE FROM accounts /*!99999 WHERE id = 1 */",
        Dialect::Oracle,
        &p,
    );
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"));
    // And runs no DROP here, as 3.8.2 read it.
    let o = eval(
        "SELECT id FROM accounts WHERE id = 1 LIMIT 1; /*!40000 DROP TABLE accounts */",
        Dialect::Oracle,
        &p,
    );
    assert_eq!(o.decision, Decision::Allow, "{o:?}");
}

/// MySQL with `ANSI_QUOTES`: `"public"."User"."email"` is a column, which
/// sqlparser 0.63 reads as a field access on a string. Still a read of it.
#[test]
fn mysql_double_quoted_dotted_names_are_columns() {
    let p = EnforcementPolicy {
        sensitive_columns: vec![SensitiveColumn {
            schema: None,
            table: "User".into(),
            column: "email".into(),
            policy: SensitivePolicy::Block,
            mask_style: MaskStyle::Full,
        }],
        ..EnforcementPolicy::default()
    };
    let sql = "SELECT \"public\".\"User\".\"id\", \"public\".\"User\".\"email\" FROM \"public\".\"User\" WHERE \"public\".\"User\".\"id\" = $1 LIMIT $2 OFFSET $3";
    let o = eval(sql, Dialect::Mysql, &p);
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"), "{o:?}");
}

/// MySQL forms sqlparser 0.52 rejected and 0.63 reads: now evaluated by the
/// rules instead of resolving as parse errors.
#[test]
fn mysql_forms_now_parsed_are_evaluated() {
    let p = EnforcementPolicy::default();
    let o = eval("DROP INDEX idx_users_email ON users", Dialect::Mysql, &p);
    assert_ne!(o.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"), "{o:?}");
    let o = eval(
        "ALTER TABLE orders ALTER COLUMN total TYPE bigint",
        Dialect::Mysql,
        &p,
    );
    assert_ne!(o.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"), "{o:?}");
}
