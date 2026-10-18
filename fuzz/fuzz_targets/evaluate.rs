// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Fuzz target: the public parse + evaluate entry point on arbitrary input.
//!
//! The first byte selects the dialect; the rest, when it is UTF-8 and within
//! the host-side size limit, is evaluated against every built-in rule with the
//! default policy. The engine must return an outcome for any input: a panic,
//! an abort, a stack overflow or a timeout is a finding. The inputs come from
//! the fuzzer alone; no seed corpus is committed.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vericto_engine::error::MAX_QUERY_SIZE_BYTES;
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate,
};

/// The built-in rule codes (the `"VERICTO-NNN" =>` arms of
/// src/rules/evaluator.rs), so every detector runs on every input.
const CODES: &[&str] = &[
    "VERICTO-001",
    "VERICTO-002",
    "VERICTO-003",
    "VERICTO-010",
    "VERICTO-011",
    "VERICTO-012",
    "VERICTO-013",
    "VERICTO-015",
    "VERICTO-016",
    "VERICTO-017",
    "VERICTO-018",
    "VERICTO-019",
    "VERICTO-030",
    "VERICTO-031",
    "VERICTO-033",
    "VERICTO-040",
    "VERICTO-042",
    "VERICTO-050",
    "VERICTO-051",
    "VERICTO-060",
    "VERICTO-061",
    "VERICTO-070",
    "VERICTO-080",
    "VERICTO-081",
    "VERICTO-082",
    "VERICTO-083",
    "VERICTO-084",
    "VERICTO-085",
    "VERICTO-086",
    "VERICTO-087",
    "VERICTO-090",
    "VERICTO-091",
    "VERICTO-092",
    "VERICTO-093",
    "VERICTO-094",
    "VERICTO-095",
    "VERICTO-096",
    "VERICTO-097",
    "VERICTO-098",
    "VERICTO-099",
    "VERICTO-100",
    "VERICTO-101",
];

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        CODES
            .iter()
            .map(|code| Rule {
                rule_id: (*code).to_string(),
                code: (*code).to_string(),
                severity: Severity::Critical,
                default_action: EnforcementAction::Block,
                rule_type: RuleType::Standard,
                ast_condition_yaml: None,
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    // Hosts refuse larger statements before they reach the engine.
    if rest.len() > MAX_QUERY_SIZE_BYTES {
        return;
    }
    let Ok(sql) = std::str::from_utf8(rest) else {
        return;
    };
    let dialect = match selector % 6 {
        0 => Dialect::Postgres,
        1 => Dialect::Mysql,
        2 => Dialect::Oracle,
        3 => Dialect::MsSql,
        4 => Dialect::Snowflake,
        _ => Dialect::Sqlite,
    };
    let _ = evaluate(sql, dialect, rules(), &EnforcementPolicy::default());
});
