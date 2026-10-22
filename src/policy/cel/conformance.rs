// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Conformance of the CEL subset against cel-rust (`cel` =0.15.0, a
//! test-only dependency): generated context-free expressions over the
//! subset's literals, operators, functions and macros evaluate to the same
//! value in both, or fail in both. Whatever the checker refuses is out of
//! the subset and not compared.

use std::collections::BTreeMap;

use proptest::prelude::*;

use super::Program;
use super::eval::Activation;
use super::value::Value;
use crate::policy::context::EvalContext;

fn ours(src: &str) -> Option<Result<String, ()>> {
    let p = Program::compile(src, &BTreeMap::new()).ok()?;
    let ctx = EvalContext::new();
    let act = Activation::new(&ctx, None, "postgres");
    Some(
        super::eval::run(&p.compiled.node, &act, p.compiled.slots)
            .map(|v| render_ours(&v))
            .map_err(|_| ()),
    )
}

fn theirs(src: &str) -> Result<String, ()> {
    let p = cel::Program::compile(src).map_err(|_| ())?;
    let ctx = cel::Context::default();
    p.execute(&ctx).map(|v| render_theirs(&v)).map_err(|_| ())
}

fn num(d: f64) -> String {
    if d.is_nan() {
        "NaN".into()
    } else {
        format!("{d:?}")
    }
}

fn render_ours(v: &Value<'_>) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => format!("bool:{b}"),
        Value::Int(i) => format!("int:{i}"),
        Value::Uint(u) => format!("uint:{u}"),
        Value::Double(d) => format!("double:{}", num(*d)),
        Value::Timestamp(_) | Value::Duration(_) => "time".into(),
        _ => {
            if let Some(s) = v.as_str() {
                return format!("str:{s:?}");
            }
            if let Some(items) = v.list_items() {
                let parts: Vec<String> = items.iter().map(render_ours).collect();
                return format!("[{}]", parts.join(","));
            }
            let keys = v.map_keys().unwrap_or_default();
            let mut parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    let val = v
                        .map_get(k)
                        .ok()
                        .flatten()
                        .map(|x| render_ours(&x))
                        .unwrap_or_default();
                    format!("{}={}", render_ours(k), val)
                })
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn render_theirs(v: &cel::Value) -> String {
    use cel::Value as V;
    use cel::objects::Key;
    match v {
        V::Null => "null".into(),
        V::Bool(b) => format!("bool:{b}"),
        V::Int(i) => format!("int:{i}"),
        V::UInt(u) => format!("uint:{u}"),
        V::Float(d) => format!("double:{}", num(*d)),
        V::String(s) => format!("str:{:?}", s.as_str()),
        V::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(render_theirs)
                .collect::<Vec<_>>()
                .join(",")
        ),
        V::Map(m) => {
            let mut parts: Vec<String> = m
                .map
                .iter()
                .map(|(k, val)| {
                    let k = match k {
                        Key::Int(i) => format!("int:{i}"),
                        Key::Uint(u) => format!("uint:{u}"),
                        Key::Bool(b) => format!("bool:{b}"),
                        Key::String(s) => format!("str:{:?}", s.as_str()),
                    };
                    format!("{k}={}", render_theirs(val))
                })
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
        other => format!("other:{other:?}"),
    }
}

fn leaf() -> impl Strategy<Value = String> {
    prop_oneof![
        (-5i64..20).prop_map(|i| i.to_string()),
        Just("9223372036854775807".to_string()),
        (0u64..5).prop_map(|u| format!("{u}u")),
        prop::sample::select(vec!["0.5", "1.0", "2.5", "-3.25", "1e3"]).prop_map(str::to_string),
        prop::sample::select(vec![
            "'a'",
            "'abc'",
            "''",
            "'héllo'",
            "\"OPS-12\"",
            "'public.t'"
        ])
        .prop_map(str::to_string),
        prop::sample::select(vec!["true", "false", "null"]).prop_map(str::to_string),
        Just("[1, 2, 3]".to_string()),
        Just("['a', 'b']".to_string()),
        Just("{'k': 1, 'j': 2}".to_string()),
    ]
}

fn expr() -> impl Strategy<Value = String> {
    leaf().prop_recursive(4, 48, 3, |inner| {
        let bin = prop::sample::select(vec![
            "+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=", "&&", "||", "in",
        ]);
        prop_oneof![
            (inner.clone(), bin, inner.clone()).prop_map(|(a, op, b)| format!("({a} {op} {b})")),
            inner.clone().prop_map(|a| format!("!({a})")),
            inner.clone().prop_map(|a| format!("-({a})")),
            (inner.clone(), inner.clone(), inner.clone())
                .prop_map(|(c, a, b)| format!("({c} ? {a} : {b})")),
            inner.clone().prop_map(|a| format!("size({a})")),
            inner.clone().prop_map(|a| format!("int({a})")),
            inner.clone().prop_map(|a| format!("double({a})")),
            inner.clone().prop_map(|a| format!("string({a})")),
            inner.clone().prop_map(|a| format!("uint({a})")),
            (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("{a}.contains({b})")),
            (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("{a}.startsWith({b})")),
            inner
                .clone()
                .prop_map(|a| format!("{a}.matches('^[a-z]+$')")),
            inner
                .clone()
                .prop_map(|a| format!("[1, 2, 3].exists(x, x == {a})")),
            inner
                .clone()
                .prop_map(|a| format!("[1, 2, 3].all(x, x < {a})")),
            inner
                .clone()
                .prop_map(|a| format!("[1, 2, 3].exists_one(x, x >= {a})")),
            inner
                .clone()
                .prop_map(|a| format!("[1, 2, 3].map(x, x + {a})")),
            inner
                .clone()
                .prop_map(|a| format!("[1, 2, 3].filter(x, x != {a})")),
            inner.clone().prop_map(|a| format!("[{a}, 1][0]")),
            Just("has({'k': 1}.k)".to_string()),
            Just("has({'k': 1}.z)".to_string()),
            Just("{'k': 1}.k".to_string()),
            Just("[1, 2] + [3]".to_string()),
            Just("'a' + 'b'".to_string()),
            Just("(1 / 0) == 1 || true".to_string()),
            Just("false && (1 / 0) == 1".to_string()),
            Just("[1, 2].all(x, x / 0 == 1)".to_string()),
            Just("[0, 1].exists(x, 1 / x == 1)".to_string()),
        ]
    })
}

/// Known, deliberate differences: none in the subset is accepted. A
/// divergence found by the generator is a bug in one of the two, and is
/// added below with its explanation once decided.
fn diverges_by_design(_src: &str) -> bool {
    false
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn prop_subset_agrees_with_cel_rust(src in expr()) {
        if let Some(mine) = ours(&src) {
            if !diverges_by_design(&src) {
                let other = theirs(&src);
                prop_assert_eq!(mine, other, "{}", src);
            }
        }
    }
}

#[test]
fn hand_picked_agreement() {
    let cases = [
        "1 + 2 * 3",
        "7 / 2",
        "-7 / 2",
        "-7 % 3",
        "7.0 / 2.0",
        "1 == 1.0",
        "1u == 1",
        "1 < 1.5",
        "'abc' < 'abd'",
        "size('héllo')",
        "string(1.5)",
        "string(100.0)",
        "int(-1.9)",
        "int('42')",
        "double('2.5')",
        "[1, 2, 3].map(x, x * 2)",
        "[1, 2, 3].filter(x, x > 1)",
        "[1, 2, 3].exists_one(x, x > 2)",
        "{'a': 1}.a",
        "'a' in {'a': 1}",
        "2 in [1, 2]",
        "true ? 1 : 2",
        "9223372036854775807 + 1",
        "'x'.matches('^x$')",
        "null == null",
        "[1, 'a'] == [1, 'a']",
        "{'a': 1} == {'a': 1}",
    ];
    for c in cases {
        let mine = ours(c).unwrap_or_else(|| panic!("the checker refused {c}"));
        assert_eq!(mine, theirs(c), "{c}");
    }
}

#[test]
fn the_generator_reaches_the_interpreter() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let (mut compared, mut values, mut errors) = (0, 0, 0);
    for _ in 0..2000 {
        let src = expr().new_tree(&mut runner).unwrap().current();
        if let Some(r) = ours(&src) {
            compared += 1;
            if r.is_ok() {
                values += 1;
            } else {
                errors += 1;
            }
        }
    }
    // Most generated expressions pass the checker, and both outcomes occur.
    assert!(compared > 800, "compared {compared}");
    assert!(
        values > 300 && errors > 50,
        "values {values}, errors {errors}"
    );
}
