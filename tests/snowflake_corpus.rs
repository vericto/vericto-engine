// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Snowflake parse-rate corpus (design §8): public, legitimate Snowflake SQL
//! (rendered dbt models and the DDL dbt-snowflake wraps them in, the
//! statements dbt-snowflake sends, sqlglot's Snowflake test statements; see
//! the header of `tests/fixtures/snowflake_corpus.sql` and its `.LICENSES`).
//!
//! For every statement the golden file pins how the engine reads it
//! (`parsed`, `preclassified` by its keywords, `allowlisted`, or `unread`: a
//! parse error) and its verdict under the catalogue, so a
//! sqlparser upgrade or a walker change that moves any of them is a reviewed
//! diff. The rates are printed (`cargo test --test snowflake_corpus --
//! --nocapture`) and pinned as floors.
//!
//! Regenerate (only when an outcome change is intended and reviewed):
//! `VERICTO_CORPUS_BLESS=1 cargo test --test snowflake_corpus`.

use sqlparser::dialect::SnowflakeDialect;
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate,
    parser::parser_for,
};

const CORPUS: &str = include_str!("fixtures/snowflake_corpus.sql");
const GOLDEN: &str = "tests/fixtures/snowflake_corpus.golden";

fn catalogue() -> Vec<Rule> {
    use Severity::*;
    [
        ("VERICTO-001", Critical),
        ("VERICTO-003", Critical),
        ("VERICTO-010", Critical),
        ("VERICTO-011", Critical),
        ("VERICTO-012", Critical),
        ("VERICTO-030", Critical),
        ("VERICTO-042", Critical),
        ("VERICTO-080", Critical),
        ("VERICTO-081", Critical),
        ("VERICTO-090", Critical),
        ("VERICTO-091", Critical),
        ("VERICTO-092", Critical),
        ("VERICTO-093", Critical),
        ("VERICTO-002", High),
        ("VERICTO-013", High),
        ("VERICTO-015", High),
        ("VERICTO-016", High),
        ("VERICTO-017", High),
        ("VERICTO-018", High),
        ("VERICTO-019", High),
        ("VERICTO-031", High),
        ("VERICTO-033", High),
        ("VERICTO-040", High),
        ("VERICTO-070", High),
        ("VERICTO-082", High),
        ("VERICTO-083", High),
        ("VERICTO-084", High),
        ("VERICTO-094", High),
        ("VERICTO-095", High),
        ("VERICTO-096", High),
        ("VERICTO-097", High),
        ("VERICTO-050", Medium),
        ("VERICTO-051", Medium),
        ("VERICTO-061", Medium),
        ("VERICTO-060", Low),
    ]
    .iter()
    .map(|(c, s)| Rule {
        rule_id: c.to_string(),
        code: c.to_string(),
        severity: *s,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    })
    .collect()
}

/// `(source, sql)` for every entry.
fn entries() -> Vec<(String, String)> {
    CORPUS
        .split("\n----\n")
        .skip(1) // the header
        .filter_map(|chunk| {
            let mut lines = chunk.lines();
            let source = lines.next()?.strip_prefix("-- source: ")?.to_string();
            let sql = lines.collect::<Vec<_>>().join("\n").trim().to_string();
            (!sql.is_empty()).then_some((source, sql))
        })
        .collect()
}

/// How the engine reads `sql`.
fn reading(sql: &str) -> &'static str {
    let Ok(parsed) = parser_for(Dialect::Snowflake).parse(sql) else {
        return "unread";
    };
    if parsed
        .statements
        .first()
        .is_some_and(|s| s.ast_node_path.starts_with("Allowlisted >"))
    {
        return "allowlisted";
    }
    // A pre-classified statement is unread code: with no rule, its outcome is
    // the parse-error floor, which names the pre-classifier.
    let o = evaluate(sql, Dialect::Snowflake, &[], &EnforcementPolicy::default());
    if o.ast_node_path
        .as_deref()
        .is_some_and(|p| p.contains("recognised by its keywords"))
    {
        "preclassified"
    } else {
        "parsed"
    }
}

fn group(source: &str) -> &'static str {
    if source.starts_with("tobymao/sqlglot") || source.starts_with("sqlglot") {
        "sqlglot"
    } else if source.starts_with("dbt-snowflake adapter") {
        "dbt-snowflake"
    } else {
        "dbt models"
    }
}

#[test]
fn snowflake_corpus_parse_rate_and_verdicts() {
    let rules = catalogue();
    let policy = EnforcementPolicy::default();
    let entries = entries();
    assert!(entries.len() > 1000, "corpus not read: {}", entries.len());
    let mut golden = String::new();
    // (n, raw sqlparser, parsed, preclassified, allowlisted) per group.
    let mut stats: std::collections::BTreeMap<&str, [usize; 5]> = Default::default();
    for (i, (source, sql)) in entries.iter().enumerate() {
        let raw = sqlparser::parser::Parser::parse_sql(&SnowflakeDialect {}, sql).is_ok();
        let read = reading(sql);
        let s = stats.entry(group(source)).or_default();
        s[0] += 1;
        s[1] += raw as usize;
        s[2] += (read == "parsed") as usize;
        s[3] += (read == "preclassified") as usize;
        s[4] += (read == "allowlisted") as usize;
        let o = evaluate(sql, Dialect::Snowflake, &rules, &policy);
        golden.push_str(&format!(
            "{i}\t{read}\t{:?}\t{}\n",
            o.decision,
            o.rule_code.as_deref().unwrap_or("-")
        ));
    }
    let mut total = [0usize; 5];
    for (g, s) in &stats {
        let [n, raw, parsed, pre, allow] = *s;
        for k in 0..5 {
            total[k] += s[k];
        }
        let pct = |x: usize| 100.0 * x as f64 / n as f64;
        println!(
            "{g}: {n} statements; sqlparser 0.63 parses {raw} ({:.1}%); the engine recognises {} ({:.1}%): {parsed} parsed, {pre} pre-classified, {allow} allowlisted",
            pct(raw),
            parsed + pre + allow,
            pct(parsed + pre + allow)
        );
    }
    let [n, raw, parsed, pre, allow] = total;
    println!(
        "all: {n} statements; sqlparser 0.63 parses {raw} ({:.1}%); recognised {} ({:.1}%)",
        100.0 * raw as f64 / n as f64,
        parsed + pre + allow,
        100.0 * (parsed + pre + allow) as f64 / n as f64
    );
    // Floors measured with 4.0.0: a change that recognises less fails here
    // even before the golden comparison.
    let rate = |g: &str| {
        let [n, _, parsed, pre, allow] = stats[g];
        (parsed + pre + allow) as f64 / n as f64
    };
    assert!(rate("dbt models") >= 1.0, "{stats:?}");
    assert!(rate("dbt-snowflake") >= 1.0, "{stats:?}");
    assert!(rate("sqlglot") >= 0.94, "{stats:?}");

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("VERICTO_CORPUS_BLESS").is_some() {
        std::fs::write(&path, &golden).expect("write golden");
        return;
    }
    let want = std::fs::read_to_string(&path).expect("golden file");
    if want != golden {
        let first = want
            .lines()
            .zip(golden.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        panic!(
            "Snowflake corpus outcomes changed (first at entry {first}: {:?})\n  was: {:?}\n  now: {:?}\nReview, then VERICTO_CORPUS_BLESS=1.",
            entries.get(first).map(|e| &e.1),
            want.lines().nth(first),
            golden.lines().nth(first)
        );
    }
}
