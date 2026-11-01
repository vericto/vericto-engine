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
    ours_detailed(src).map(|r| r.map_err(|_| ()))
}

/// [`ours`], keeping the error's detail (for [`diverges_by_design`]).
fn ours_detailed(src: &str) -> Option<Result<String, String>> {
    let p = Program::compile(src, &BTreeMap::new()).ok()?;
    let ctx = EvalContext::new();
    let act = Activation::new(&ctx, None, "postgres");
    Some(
        super::eval::run(&p.compiled.node, &act, p.compiled.slots)
            .map(|v| render_ours(&v))
            .map_err(|fault| fault.detail),
    )
}

fn theirs(src: &str) -> Result<String, ()> {
    theirs_detailed(src).map_err(|_| ())
}

/// What went wrong on cel-rust's side (for [`diverges_by_design`]).
enum TheirError {
    Compile,
    Execution(cel::ExecutionError),
}

/// [`theirs`], keeping cel-rust's error.
fn theirs_detailed(src: &str) -> Result<String, TheirError> {
    let p = cel::Program::compile(src).map_err(|_| TheirError::Compile)?;
    let ctx = cel::Context::default();
    p.execute(&ctx)
        .map(|v| render_theirs(&v))
        .map_err(TheirError::Execution)
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

/// Known differences from cel-rust, each decided against the spec and the
/// other implementations. A divergence the generator finds is a bug in one
/// of the two, and is added here, as narrowly as it can be told apart, once
/// decided.
///
/// - `list + map`: cel-rust 0.15.0 concatenates any iterable onto a list
///   (`DefaultList::add` takes `rhs.as_iterable()`, so a map adds its
///   keys: `[1] + [{'k': 1}, 1][0]` is `[1, 'k']`). The only list overload
///   of `_+_` is `list(A) + list(A) -> list(A)` (cel-spec `doc/langdef.md`,
///   "Standard definitions", `_+_`); cel-go (`baseList.Add`, which needs a
///   `traits.Lister`) reports no such overload, as the engine does. Skipped
///   only when the engine's error is exactly that one and cel-rust returns
///   a value.
/// - `x in map` where `x` cannot be a map key (a list, a map, `null`, only
///   reachable through `dyn`): cel-rust 0.15.0 has no `@in` overload for it
///   and fails with `NoSuchOverload`. The engine answers `false`, as cel-go
///   does (`baseMap.Contains` returns `Find`'s `found`, which misses) and as
///   the spec's parametric signature `A in map(A, B) -> bool` (cel-spec
///   `doc/langdef.md`, "Standard definitions", `@in`) and its conformance
///   data read a value that is no key type (`tests/simple/testdata/
///   comparisons.textproto`, `nan_not_in_map`: `dyn(0.0/0.0) in {1: 'a',
///   2u: 'b'}` is `false`). cel-cpp sides with cel-rust (it registers `@in`
///   on maps for bool, int, uint, string and double keys only), so this one
///   is a choice between the reference implementations; the engine keeps
///   cel-go's. Skipped only when cel-rust's error is that missing `@in`
///   overload on (list | map | null, map) and the engine returns a value.
fn diverges_by_design(mine: &Result<String, String>, theirs: &Result<String, TheirError>) -> bool {
    match (mine, theirs) {
        (Err(detail), Ok(_)) => detail == "no overload for `+` on list and map",
        (Ok(_), Err(TheirError::Execution(cel::ExecutionError::NoSuchOverload(e)))) => {
            e.function() == "@in"
                && matches!(
                    e.argument_types(),
                    [key, map] if map == "map" && matches!(key.as_str(), "list" | "map" | "null_type")
                )
        }
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn prop_subset_agrees_with_cel_rust(src in expr()) {
        if let Some(mine) = ours_detailed(&src) {
            let other = theirs_detailed(&src);
            if !diverges_by_design(&mine, &other) {
                prop_assert_eq!(mine.map_err(|_| ()), other.map_err(|_| ()), "{}", src);
            }
        }
    }
}

/// The known divergences stay what they are: cel-rust still differs (a
/// cel-rust fix makes this fail, and the skip is removed), the engine still
/// answers as cel-go does, and nothing else is skipped.
#[test]
fn known_divergences_are_exactly_these() {
    // A mixed list's element is `dyn` to the checker, which refuses
    // `[1] + {'k': 1}` itself.
    for (src, engine) in [
        ("[1] + [{'k': 1}, 1][0]", Err(())),
        ("([1, 2] + [3] + [{'k': 1, 'j': 2}, 1][0])", Err(())),
        ("[1, 2] in [{'k': 1}, 1][0]", Ok("bool:false".to_string())),
        (
            "([1, 2, 3].map(x, x + 0) in [{'k': 1, 'j': 2}, 1][0])",
            Ok("bool:false".to_string()),
        ),
        ("{'k': 1} in [{'k': 1}, 1][0]", Ok("bool:false".to_string())),
        ("null in [{'k': 1}, 1][0]", Ok("bool:false".to_string())),
        ("!([1] in [{'k': 1}, 1][0])", Ok("bool:true".to_string())),
    ] {
        let mine = ours_detailed(src).expect("compiles");
        let other = theirs_detailed(src);
        assert_eq!(mine.clone().map_err(|_| ()), engine, "{src}");
        assert!(
            diverges_by_design(&mine, &other),
            "{src}: cel-rust now agrees: drop the skip"
        );
    }
    // `list + list`, the other `+` errors and membership of a key type
    // (or of a non-key type in a list) are still compared.
    for src in [
        "[1] + [[2], 1][0]",
        "[{'k': 1}, 1][0] + [1]",
        "[1] + [1, 'a'][0]",
        "[1, 'a'][0] + [1]",
        "'k' in [{'k': 1}, 1][0]",
        "1.5 in [{'k': 1}, 1][0]",
        "true in [{'k': 1}, 1][0]",
        "[1] in [[1], 1]",
        "null in [1, 'a']",
    ] {
        let mine = ours_detailed(src).expect("compiles");
        let other = theirs_detailed(src);
        assert!(!diverges_by_design(&mine, &other), "{src}");
        assert_eq!(mine.map_err(|_| ()), other.map_err(|_| ()), "{src}");
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
        // A negative double is out of uint range, even one that truncates
        // to 0 (the generator's `uint(-(0.5))`, 4.7.1); -0.0 is zero.
        "uint(-(0.5))",
        "uint(-0.5)",
        "uint(-1.5)",
        "uint(-(0.0))",
        "uint(0.5)",
        "uint(-1)",
        "int(-(0.5))",
        "int(9223372036854775807.0)",
        "int(-9223372036854775808.0)",
        "uint(18446744073709551615.0)",
        "uint(6.022e23)",
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
