// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Policy-evaluation micro-benchmark and its budget gate.
//!
//! Budgets (implementation plan §2, against BENCH-2026-11: 0.12 ms added
//! p50 and about 100 µs of proxy CPU per statement), per statement under
//! 2 KiB, added over the same statement through `evaluate` with the
//! standard ruleset:
//!
//! | cell        | what runs                                   | budget            |
//! |-------------|---------------------------------------------|-------------------|
//! | `empty`     | `evaluate_with_context`, empty `PolicySet`  | ratio ≤ 1.05      |
//! | `unselected`| 10 policies, none in scope for the principal| ≤ 1 µs added      |
//! | `typical`   | 3 applicable policies (facts + CEL)         | ≤ 15 µs added     |
//! | `worst50`   | 50 applicable policies                      | ≤ 50 µs added     |
//!
//! `cargo bench --bench policy` measures every cell with criterion, then
//! runs the gate: each cell against the baseline in paired, interleaved
//! rounds (the median of the per-round differences, robust to drift), and
//! fails (exit 1) when a cell is over its budget. Absolute budgets scale
//! with `VERICTO_BENCH_BUDGET_FACTOR` (default 1; CI machines are slower
//! than the proxy's), the ratio with `VERICTO_BENCH_RATIO_MAX` (default
//! 1.05). `VERICTO_BENCH_GATE_ONLY=1` skips the criterion part.

use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion};
use vericto_engine::policy::{
    DbContext, EvalContext, PolicySet, Principal, PrincipalType, Ticket, Trust,
};
use vericto_engine::{
    Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity, evaluate,
    evaluate_with_context, standard_rules,
};

const STATEMENTS: &[(&str, Dialect, &str)] = &[
    (
        "pg_update",
        Dialect::Postgres,
        "UPDATE refunds SET amount = 150, status = 'approved', updated_at = now() WHERE id = $1 AND tenant_id = $2",
    ),
    (
        "pg_join",
        Dialect::Postgres,
        "SELECT i.id, i.total, c.name, c.email FROM invoices i JOIN customers c ON c.id = i.customer_id \
         WHERE i.tenant_id = $1 AND c.tenant_id = $1 AND i.created_at >= '2026-09-01' ORDER BY i.created_at DESC LIMIT 100",
    ),
    (
        "mysql_insert",
        Dialect::Mysql,
        "INSERT INTO refunds (order_id, amount, reason, created_at) VALUES (1, 150, 'damaged', NOW()), (2, 90, 'late', NOW())",
    ),
];

fn pol(code: &str, yaml: String) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.into(),
        severity: Severity::High,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Custom,
        ast_condition_yaml: Some(yaml),
    }
}

/// Three policies a workspace typically has, all applicable to the agent.
fn typical() -> Vec<Rule> {
    vec![
        pol(
            "POL-001",
            r#"applies_to: { ops: [insert, update], tables: ["*.refunds"], principal_types: [agent, human] }
deny_if: stmt.values("refunds.amount").exists(v, double(v) > 200.0)
action: block"#
                .into(),
        ),
        pol(
            "POL-002",
            r#"applies_to: { ops: [select, update, delete], principal_types: [agent, service] }
vars: { tenant_tables: ["public.invoices", "public.customers", "public.refunds"] }
require: stmt.tables.all(t, !(t in vars.tenant_tables) || stmt.has_filter(t + ".tenant_id"))
action: block"#
                .into(),
        ),
        pol(
            "POL-003",
            r#"applies_to: { principal_types: [agent, human] }
when: db.env == "prod"
deny_if: stmt.op != "select" && !(has(ticket.id) && ticket.id.matches("^OPS-[0-9]+$"))
action: flag"#
                .into(),
        ),
    ]
}

/// Ten policies scoped to principals other than the agent.
fn unselected() -> Vec<Rule> {
    (0..10)
        .map(|i| {
            pol(
                &format!("POL-1{i:02}"),
                format!(
                    "applies_to: {{ principal_types: [{}] }}\ndeny_if: stmt.values('public.t.c{i}').exists(v, v == {i})\naction: block",
                    ["tool", "pipeline"][i % 2]
                ),
            )
        })
        .collect()
}

/// Fifty applicable policies reading facts.
fn worst50() -> Vec<Rule> {
    (0..50)
        .map(|i| {
            let body = match i % 5 {
                0 => format!("deny_if: stmt.values('public.refunds.c{i}').exists(v, double(v) > {i}.0)"),
                1 => format!("require: stmt.tables.all(t, !(t in ['public.x{i}', 'public.y{i}']) || stmt.has_filter(t + '.tenant_id'))"),
                2 => format!("deny_if: stmt.reads('public.secret_{i}*') || stmt.columns_read.exists(c, c.endsWith('.ssn{i}'))"),
                3 => format!("deny_if: principal.trust < {} && stmt.op == 'delete'", i % 3 + 1),
                _ => format!("deny_if: has(stmt.limit) && stmt.limit > {}", 1000 + i),
            };
            pol(
                &format!("POL-2{i:02}"),
                format!("applies_to: {{ principal_types: [agent] }}\n{body}\non_unknown: flag\naction: block"),
            )
        })
        .collect()
}

fn ctx() -> EvalContext {
    EvalContext::new()
        .with_principal(Principal::new(
            "agent-support-bot",
            PrincipalType::Agent,
            Trust::Medium,
        ))
        .with_db(DbContext::new().with_env("prod").with_id("db_1"))
        .with_ticket(Ticket::declared("OPS-12"))
}

const CELLS: &[&str] = &["baseline", "empty", "unselected", "typical", "worst50"];

fn bench(c: &mut Criterion) {
    let standard = standard_rules();
    let policy = EnforcementPolicy::default();
    let ctx = ctx();
    let mut group = c.benchmark_group("policy");
    group
        .sample_size(60)
        .warm_up_time(Duration::from_millis(800))
        .measurement_time(Duration::from_secs(2));
    for (name, d, sql) in STATEMENTS {
        group.bench_with_input(BenchmarkId::new("baseline", name), sql, |b, sql| {
            b.iter(|| evaluate(black_box(sql), *d, &standard, &policy))
        });
        for cell in &CELLS[1..] {
            let mut rules = standard.clone();
            match *cell {
                "unselected" => rules.extend(unselected()),
                "typical" => rules.extend(typical()),
                "worst50" => rules.extend(worst50()),
                _ => {}
            }
            let set = PolicySet::compile(&rules);
            assert!(set.errors().is_empty(), "{cell}: {:?}", set.errors());
            group.bench_with_input(BenchmarkId::new(*cell, name), sql, |b, sql| {
                b.iter(|| evaluate_with_context(black_box(sql), *d, &rules, &policy, &set, &ctx))
            });
        }
    }
    group.finish();
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The cost a cell adds over the baseline, measured paired: rounds that
/// alternate a batch of the baseline and a batch of the cell (the order
/// flips every round), so drift and frequency changes hit both alike; the
/// median of the per-round differences. Criterion's numbers above are for
/// people; this is what the gate decides on.
fn paired(base: &dyn Fn(), cell: &dyn Fn(), rounds: usize, batch: usize) -> (f64, f64) {
    use std::time::Instant;
    let time = |f: &dyn Fn()| {
        let t = Instant::now();
        for _ in 0..batch {
            f();
        }
        t.elapsed().as_nanos() as f64 / batch as f64
    };
    for _ in 0..batch {
        base();
        cell();
    }
    let mut deltas = Vec::with_capacity(rounds);
    let mut bases = Vec::with_capacity(rounds);
    for r in 0..rounds {
        let (b, c) = if r % 2 == 0 {
            let b = time(base);
            (b, time(cell))
        } else {
            let c = time(cell);
            (time(base), c)
        };
        deltas.push(c - b);
        bases.push(b);
    }
    let med = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.total_cmp(b));
        v[v.len() / 2]
    };
    (med(&mut deltas), med(&mut bases))
}

/// Fails the run when a cell is over its budget.
fn gate() {
    let factor = env_f64("VERICTO_BENCH_BUDGET_FACTOR", 1.0);
    let ratio_max = env_f64("VERICTO_BENCH_RATIO_MAX", 1.05);
    let standard = standard_rules();
    let policy = EnforcementPolicy::default();
    let ctx = ctx();
    let mut failures = Vec::new();
    println!("\npolicy budget gate (paired medians; factor {factor}, ratio max {ratio_max}):");
    println!(
        "{:<14}{:>12}{:>14}{:>14}{:>14}{:>14}",
        "statement", "baseline", "+empty", "+unselected", "+typical", "+worst50"
    );
    for (name, d, sql) in STATEMENTS {
        let base = || {
            black_box(evaluate(black_box(sql), *d, &standard, &policy));
        };
        let mut row = Vec::new();
        let mut base_ns = 0.0;
        for cell in &CELLS[1..] {
            let mut rules = standard.clone();
            match *cell {
                "unselected" => rules.extend(unselected()),
                "typical" => rules.extend(typical()),
                "worst50" => rules.extend(worst50()),
                _ => {}
            }
            let set = PolicySet::compile(&rules);
            let with = || {
                black_box(evaluate_with_context(
                    black_box(sql),
                    *d,
                    &rules,
                    &policy,
                    &set,
                    &ctx,
                ));
            };
            let (delta, b) = paired(&base, &with, 41, 300);
            base_ns = b;
            row.push(delta);
            let added_us = delta / 1e3;
            let ok = match *cell {
                "empty" => (b + delta) / b <= ratio_max,
                "unselected" => added_us <= 1.0 * factor,
                "typical" => added_us <= 15.0 * factor,
                _ => added_us <= 50.0 * factor,
            };
            if !ok {
                failures.push(format!(
                    "{name}: {cell} adds {added_us:.2} µs over {:.2} µs",
                    b / 1e3
                ));
            }
        }
        println!(
            "{name:<14}{:>10.2}µs{:>12.2}µs{:>12.2}µs{:>12.2}µs{:>12.2}µs",
            base_ns / 1e3,
            row[0] / 1e3,
            row[1] / 1e3,
            row[2] / 1e3,
            row[3] / 1e3
        );
    }
    if failures.is_empty() {
        println!(
            "all cells within budget (empty: ratio ≤ {ratio_max}; unselected ≤ {:.1} µs; typical ≤ {:.1} µs; worst50 ≤ {:.1} µs)",
            1.0 * factor,
            15.0 * factor,
            50.0 * factor
        );
    } else {
        eprintln!("policy budget gate FAILED:\n  {}", failures.join("\n  "));
        std::process::exit(1);
    }
}

fn main() {
    let mut c = Criterion::default().configure_from_args();
    if std::env::var_os("VERICTO_BENCH_GATE_ONLY").is_none() {
        bench(&mut c);
        c.final_summary();
    }
    // `cargo test --benches` runs the bench once as a test: no medians.
    if !std::env::args().any(|a| a == "--test" || a == "--list") {
        gate();
    }
}
