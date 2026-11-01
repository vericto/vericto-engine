// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Values of the CEL subset, and the operators on them.
//!
//! [`Const`] is an owned value (literals, `vars:` constants, folded
//! `timestamp()`/`duration()` calls): it lives in the compiled policy, which
//! is shared across threads. [`Value`] is what an evaluation handles: it
//! borrows the facts, the context and the constants instead of copying them,
//! so evaluating a policy allocates only for the lists and strings it builds.
//!
//! Semantics follow cel-spec: integer overflow, division by zero and
//! out-of-range conversions are errors; `==` is heterogeneous (values of
//! different types are unequal, except numbers, which compare by value);
//! ordering is defined for numbers (across int, uint and double), strings,
//! bools, timestamps and durations.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::time::Ts;

/// An owned constant.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Const {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(f64),
    Str(String),
    Timestamp(Ts),
    /// Nanoseconds.
    Duration(i64),
    List(Vec<Const>),
    Map(BTreeMap<String, Const>),
}

/// Why an evaluation could not produce a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FaultKind {
    /// The value exists but is not known here (absent field, unbound
    /// parameter, truncated fact list, non-constant SQL expression).
    Unknown,
    /// A genuine evaluation error (type mismatch, overflow, no such key).
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fault {
    pub(crate) kind: FaultKind,
    pub(crate) detail: String,
}

impl Fault {
    pub(crate) fn unknown(detail: impl Into<String>) -> Self {
        Fault {
            kind: FaultKind::Unknown,
            detail: detail.into(),
        }
    }

    pub(crate) fn error(detail: impl Into<String>) -> Self {
        Fault {
            kind: FaultKind::Error,
            detail: detail.into(),
        }
    }

    /// Of two faults, the one to report: an unknown wins over an error (the
    /// value may exist; cel-spec merges unknowns ahead of errors too).
    pub(crate) fn merge(self, other: Fault) -> Fault {
        match (&self.kind, &other.kind) {
            (FaultKind::Error, FaultKind::Unknown) => other,
            _ => self,
        }
    }
}

pub(crate) type R<'a> = Result<Value<'a>, Fault>;

/// A runtime value. Lists and maps either borrow (facts, context,
/// constants) or own an `Rc` built during evaluation.
#[derive(Debug, Clone)]
pub(crate) enum Value<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(f64),
    Str(&'a str),
    OwnedStr(Rc<str>),
    Timestamp(Ts),
    Duration(i64),
    StrList(&'a [String]),
    ConstList(&'a [Const]),
    List(Rc<Vec<Value<'a>>>),
    StrMap(&'a BTreeMap<String, String>),
    ConstMap(&'a BTreeMap<String, Const>),
    Map(Rc<Vec<(Value<'a>, Value<'a>)>>),
}

impl<'a> Value<'a> {
    pub(crate) fn from_const(c: &'a Const) -> Value<'a> {
        match c {
            Const::Null => Value::Null,
            Const::Bool(b) => Value::Bool(*b),
            Const::Int(i) => Value::Int(*i),
            Const::Uint(u) => Value::Uint(*u),
            Const::Double(d) => Value::Double(*d),
            Const::Str(s) => Value::Str(s),
            Const::Timestamp(t) => Value::Timestamp(*t),
            Const::Duration(d) => Value::Duration(*d),
            Const::List(l) => Value::ConstList(l),
            Const::Map(m) => Value::ConstMap(m),
        }
    }

    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Uint(_) => "uint",
            Value::Double(_) => "double",
            Value::Str(_) | Value::OwnedStr(_) => "string",
            Value::Timestamp(_) => "timestamp",
            Value::Duration(_) => "duration",
            Value::StrList(_) | Value::ConstList(_) | Value::List(_) => "list",
            Value::StrMap(_) | Value::ConstMap(_) | Value::Map(_) => "map",
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            Value::OwnedStr(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Result<bool, Fault> {
        match self {
            Value::Bool(b) => Ok(*b),
            other => Err(Fault::error(format!(
                "expected bool, got {}",
                other.type_name()
            ))),
        }
    }

    /// The elements of a list, materialised (small lists only: facts are
    /// capped at 1024 entries).
    pub(crate) fn list_items(&self) -> Option<Vec<Value<'a>>> {
        match self {
            Value::StrList(l) => Some(l.iter().map(|s| Value::Str(s)).collect()),
            Value::ConstList(l) => Some(l.iter().map(Value::from_const).collect()),
            Value::List(l) => Some(l.as_ref().clone()),
            _ => None,
        }
    }

    pub(crate) fn list_len(&self) -> Option<usize> {
        match self {
            Value::StrList(l) => Some(l.len()),
            Value::ConstList(l) => Some(l.len()),
            Value::List(l) => Some(l.len()),
            _ => None,
        }
    }

    pub(crate) fn list_get(&self, i: usize) -> Option<Value<'a>> {
        match self {
            Value::StrList(l) => l.get(i).map(|s| Value::Str(s)),
            Value::ConstList(l) => l.get(i).map(Value::from_const),
            Value::List(l) => l.get(i).cloned(),
            _ => None,
        }
    }

    pub(crate) fn is_map(&self) -> bool {
        matches!(self, Value::StrMap(_) | Value::ConstMap(_) | Value::Map(_))
    }

    /// The keys of a map, in a deterministic order (sorted maps; literal
    /// maps in source order).
    pub(crate) fn map_keys(&self) -> Option<Vec<Value<'a>>> {
        match self {
            Value::StrMap(m) => Some(m.keys().map(|k| Value::Str(k)).collect()),
            Value::ConstMap(m) => Some(m.keys().map(|k| Value::Str(k)).collect()),
            Value::Map(m) => Some(m.iter().map(|(k, _)| k.clone()).collect()),
            _ => None,
        }
    }

    pub(crate) fn map_len(&self) -> Option<usize> {
        match self {
            Value::StrMap(m) => Some(m.len()),
            Value::ConstMap(m) => Some(m.len()),
            Value::Map(m) => Some(m.len()),
            _ => None,
        }
    }

    /// `map[key]`: `Ok(None)` when the key is absent.
    pub(crate) fn map_get(&self, key: &Value<'a>) -> Result<Option<Value<'a>>, Fault> {
        match self {
            Value::StrMap(m) => Ok(key
                .as_str()
                .and_then(|k| m.get(k))
                .map(|v| Value::Str(v.as_str()))),
            Value::ConstMap(m) => Ok(key.as_str().and_then(|k| m.get(k)).map(Value::from_const)),
            Value::Map(m) => {
                for (k, v) in m.iter() {
                    if equals(k, key) {
                        return Ok(Some(v.clone()));
                    }
                }
                Ok(None)
            }
            other => Err(Fault::error(format!(
                "cannot index a {} by key",
                other.type_name()
            ))),
        }
    }
}

/// A number as one of CEL's three numeric types.
#[derive(Clone, Copy)]
enum Num {
    I(i64),
    U(u64),
    D(f64),
}

fn num(v: &Value<'_>) -> Option<Num> {
    match v {
        Value::Int(i) => Some(Num::I(*i)),
        Value::Uint(u) => Some(Num::U(*u)),
        Value::Double(d) => Some(Num::D(*d)),
        _ => None,
    }
}

/// Numeric comparison across int, uint and double, exactly (no rounding of
/// large integers through f64). `None` when a NaN is involved.
fn cmp_num(a: Num, b: Num) -> Option<Ordering> {
    match (a, b) {
        (Num::I(x), Num::I(y)) => Some(x.cmp(&y)),
        (Num::U(x), Num::U(y)) => Some(x.cmp(&y)),
        (Num::I(x), Num::U(y)) => Some(if x < 0 {
            Ordering::Less
        } else {
            (x as u64).cmp(&y)
        }),
        (Num::U(_), Num::I(_)) => cmp_num(b, a).map(Ordering::reverse),
        (Num::D(x), Num::D(y)) => x.partial_cmp(&y),
        (Num::D(x), Num::I(y)) => cmp_double_i128(x, i128::from(y)),
        (Num::D(x), Num::U(y)) => cmp_double_i128(x, i128::from(y)),
        (Num::I(_) | Num::U(_), Num::D(_)) => cmp_num(b, a).map(Ordering::reverse),
    }
}

fn cmp_double_i128(x: f64, y: i128) -> Option<Ordering> {
    if x.is_nan() {
        return None;
    }
    // Every i64/u64 fits in i128; compare the integral part exactly.
    if x >= 1.8e19 {
        return Some(Ordering::Greater);
    }
    if x <= -1.0e19 {
        return Some(Ordering::Less);
    }
    let t = x.trunc();
    let ti = t as i128;
    match ti.cmp(&y) {
        Ordering::Equal => {
            let frac = x - t;
            Some(if frac > 0.0 {
                Ordering::Greater
            } else if frac < 0.0 {
                Ordering::Less
            } else {
                Ordering::Equal
            })
        }
        o => Some(o),
    }
}

/// `a == b` with cel-spec heterogeneous equality.
pub(crate) fn equals(a: &Value<'_>, b: &Value<'_>) -> bool {
    if let (Some(x), Some(y)) = (num(a), num(b)) {
        return cmp_num(x, y) == Some(Ordering::Equal);
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Timestamp(x), Value::Timestamp(y)) => x == y,
        (Value::Duration(x), Value::Duration(y)) => x == y,
        _ => {
            if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
                return x == y;
            }
            if let (Some(n), Some(m)) = (a.list_len(), b.list_len()) {
                return n == m
                    && (0..n).all(|i| match (a.list_get(i), b.list_get(i)) {
                        (Some(x), Some(y)) => equals(&x, &y),
                        _ => false,
                    });
            }
            if a.is_map() && b.is_map() {
                let (Some(ka), Some(n)) = (a.map_keys(), b.map_len()) else {
                    return false;
                };
                return ka.len() == n
                    && ka.iter().all(|k| match (a.map_get(k), b.map_get(k)) {
                        (Ok(Some(x)), Ok(Some(y))) => equals(&x, &y),
                        _ => false,
                    });
            }
            false
        }
    }
}

/// `a < b` and friends: the ordering, or an error for types without one.
pub(crate) fn compare(a: &Value<'_>, b: &Value<'_>) -> Result<Ordering, Fault> {
    if let (Some(x), Some(y)) = (num(a), num(b)) {
        return cmp_num(x, y).ok_or_else(|| Fault::error("comparison with NaN"));
    }
    match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => Ok(x.cmp(y)),
        (Value::Timestamp(x), Value::Timestamp(y)) => Ok(x.cmp(y)),
        (Value::Duration(x), Value::Duration(y)) => Ok(x.cmp(y)),
        _ => match (a.as_str(), b.as_str()) {
            (Some(x), Some(y)) => Ok(x.cmp(y)),
            _ => Err(Fault::error(format!(
                "no ordering between {} and {}",
                a.type_name(),
                b.type_name()
            ))),
        },
    }
}

/// `x in container`.
pub(crate) fn contains(container: &Value<'_>, x: &Value<'_>) -> Result<bool, Fault> {
    if let Some(n) = container.list_len() {
        return Ok((0..n).any(|i| container.list_get(i).is_some_and(|e| equals(&e, x))));
    }
    if container.is_map() {
        return Ok(container.map_get(x)?.is_some());
    }
    Err(Fault::error(format!(
        "`in` needs a list or a map, got {}",
        container.type_name()
    )))
}

fn overflow() -> Fault {
    Fault::error("integer overflow")
}

pub(crate) fn add<'a>(a: &Value<'a>, b: &Value<'a>) -> R<'a> {
    Ok(match (a, b) {
        (Value::Int(x), Value::Int(y)) => Value::Int(x.checked_add(*y).ok_or_else(overflow)?),
        (Value::Uint(x), Value::Uint(y)) => Value::Uint(x.checked_add(*y).ok_or_else(overflow)?),
        (Value::Double(x), Value::Double(y)) => Value::Double(x + y),
        (Value::Timestamp(t), Value::Duration(d)) | (Value::Duration(d), Value::Timestamp(t)) => {
            Value::Timestamp(t.plus_nanos(*d).ok_or_else(overflow)?)
        }
        (Value::Duration(x), Value::Duration(y)) => {
            Value::Duration(x.checked_add(*y).ok_or_else(overflow)?)
        }
        _ => {
            if let (Some(x), Some(y)) = (a.as_str(), b.as_str()) {
                let mut s = String::with_capacity(x.len() + y.len());
                s.push_str(x);
                s.push_str(y);
                return Ok(Value::OwnedStr(Rc::from(s)));
            }
            if let (Some(mut x), Some(y)) = (a.list_items(), b.list_items()) {
                x.extend(y);
                return Ok(Value::List(Rc::new(x)));
            }
            return Err(no_overload("+", a, b));
        }
    })
}

pub(crate) fn sub<'a>(a: &Value<'a>, b: &Value<'a>) -> R<'a> {
    Ok(match (a, b) {
        (Value::Int(x), Value::Int(y)) => Value::Int(x.checked_sub(*y).ok_or_else(overflow)?),
        (Value::Uint(x), Value::Uint(y)) => Value::Uint(x.checked_sub(*y).ok_or_else(overflow)?),
        (Value::Double(x), Value::Double(y)) => Value::Double(x - y),
        (Value::Timestamp(t), Value::Duration(d)) => Value::Timestamp(
            t.plus_nanos(d.checked_neg().ok_or_else(overflow)?)
                .ok_or_else(overflow)?,
        ),
        (Value::Timestamp(x), Value::Timestamp(y)) => {
            Value::Duration(x.nanos_since(y).ok_or_else(overflow)?)
        }
        (Value::Duration(x), Value::Duration(y)) => {
            Value::Duration(x.checked_sub(*y).ok_or_else(overflow)?)
        }
        _ => return Err(no_overload("-", a, b)),
    })
}

pub(crate) fn mul<'a>(a: &Value<'a>, b: &Value<'a>) -> R<'a> {
    Ok(match (a, b) {
        (Value::Int(x), Value::Int(y)) => Value::Int(x.checked_mul(*y).ok_or_else(overflow)?),
        (Value::Uint(x), Value::Uint(y)) => Value::Uint(x.checked_mul(*y).ok_or_else(overflow)?),
        (Value::Double(x), Value::Double(y)) => Value::Double(x * y),
        _ => return Err(no_overload("*", a, b)),
    })
}

pub(crate) fn div<'a>(a: &Value<'a>, b: &Value<'a>) -> R<'a> {
    Ok(match (a, b) {
        (Value::Int(_), Value::Int(0)) | (Value::Uint(_), Value::Uint(0)) => {
            return Err(Fault::error("division by zero"));
        }
        (Value::Int(x), Value::Int(y)) => Value::Int(x.checked_div(*y).ok_or_else(overflow)?),
        (Value::Uint(x), Value::Uint(y)) => Value::Uint(x / y),
        (Value::Double(x), Value::Double(y)) => Value::Double(x / y),
        _ => return Err(no_overload("/", a, b)),
    })
}

pub(crate) fn rem<'a>(a: &Value<'a>, b: &Value<'a>) -> R<'a> {
    Ok(match (a, b) {
        (Value::Int(_), Value::Int(0)) | (Value::Uint(_), Value::Uint(0)) => {
            return Err(Fault::error("modulus by zero"));
        }
        (Value::Int(x), Value::Int(y)) => Value::Int(x.checked_rem(*y).ok_or_else(overflow)?),
        (Value::Uint(x), Value::Uint(y)) => Value::Uint(x % y),
        _ => return Err(no_overload("%", a, b)),
    })
}

pub(crate) fn neg<'a>(a: &Value<'a>) -> R<'a> {
    Ok(match a {
        Value::Int(x) => Value::Int(x.checked_neg().ok_or_else(overflow)?),
        Value::Double(x) => Value::Double(-x),
        Value::Duration(x) => Value::Duration(x.checked_neg().ok_or_else(overflow)?),
        other => {
            return Err(Fault::error(format!(
                "no overload for unary `-` on {}",
                other.type_name()
            )));
        }
    })
}

fn no_overload(op: &str, a: &Value<'_>, b: &Value<'_>) -> Fault {
    Fault::error(format!(
        "no overload for `{op}` on {} and {}",
        a.type_name(),
        b.type_name()
    ))
}

// ---------------------------------------------------------------------------
// Conversions (cel-spec "Standard definitions")

pub(crate) fn to_int<'a>(v: &Value<'a>) -> R<'a> {
    let range = || Fault::error("int() argument out of range");
    Ok(Value::Int(match v {
        Value::Int(i) => *i,
        Value::Uint(u) => i64::try_from(*u).map_err(|_| range())?,
        Value::Double(d) => {
            // cel-spec: truncation toward zero; out of range (or NaN) is an
            // error. 2^63 itself is out of range.
            if !(d.is_finite() && *d > -9.223_372_036_854_776e18 && *d < 9.223_372_036_854_776e18) {
                return Err(range());
            }
            *d as i64
        }
        Value::Timestamp(t) => t.secs,
        other => match other.as_str() {
            Some(s) => s
                .parse::<i64>()
                .map_err(|_| Fault::error(format!("int() cannot parse {s:?}")))?,
            None => {
                return Err(Fault::error(format!(
                    "no overload for int() on {}",
                    other.type_name()
                )));
            }
        },
    }))
}

pub(crate) fn to_uint<'a>(v: &Value<'a>) -> R<'a> {
    let range = || Fault::error("uint() argument out of range");
    Ok(Value::Uint(match v {
        Value::Uint(u) => *u,
        Value::Int(i) => u64::try_from(*i).map_err(|_| range())?,
        Value::Double(d) => {
            // The range is checked before truncation: [0, 2^64), so a
            // negative double (even -0.5, which would truncate to 0) is out
            // of range, while -0.0 compares equal to 0 and converts to 0u.
            // NaN fails every comparison. This is what cel-go
            // (`doubleToUint64Checked`), cel-cpp (`CheckedDoubleToUint64`)
            // and cel-rust (`uint_from_double`) do; 4.4.0 to 4.7.0 returned
            // 0u for a double in (-1, 0).
            if !(*d >= 0.0 && *d < 1.844_674_407_370_955_2e19) {
                return Err(range());
            }
            *d as u64
        }
        other => match other.as_str() {
            Some(s) => s
                .parse::<u64>()
                .map_err(|_| Fault::error(format!("uint() cannot parse {s:?}")))?,
            None => {
                return Err(Fault::error(format!(
                    "no overload for uint() on {}",
                    other.type_name()
                )));
            }
        },
    }))
}

pub(crate) fn to_double<'a>(v: &Value<'a>) -> R<'a> {
    Ok(Value::Double(match v {
        Value::Double(d) => *d,
        Value::Int(i) => *i as f64,
        Value::Uint(u) => *u as f64,
        other => match other.as_str() {
            Some(s) => s
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|_| !s.trim().is_empty())
                .ok_or_else(|| Fault::error(format!("double() cannot parse {s:?}")))?,
            None => {
                return Err(Fault::error(format!(
                    "no overload for double() on {}",
                    other.type_name()
                )));
            }
        },
    }))
}

pub(crate) fn to_string<'a>(v: &Value<'a>) -> R<'a> {
    let s = match v {
        Value::Str(s) => return Ok(Value::Str(s)),
        Value::OwnedStr(s) => return Ok(Value::OwnedStr(s.clone())),
        Value::Int(i) => i.to_string(),
        Value::Uint(u) => u.to_string(),
        Value::Double(d) => format_double(*d),
        Value::Bool(b) => b.to_string(),
        Value::Timestamp(t) => t.to_rfc3339(),
        Value::Duration(d) => super::time::format_duration(*d),
        other => {
            return Err(Fault::error(format!(
                "no overload for string() on {}",
                other.type_name()
            )));
        }
    };
    Ok(Value::OwnedStr(Rc::from(s)))
}

/// `string(double)`: the shortest representation that reads back the same
/// value, as Go's `strconv.FormatFloat(d, 'g', -1, 64)` style that cel-go and
/// cel-rust print (`1.5`, `100`, `1e+21`).
pub(crate) fn format_double(d: f64) -> String {
    if d.is_nan() {
        return "NaN".into();
    }
    if d.is_infinite() {
        return if d > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    let s = format!("{d}");
    // Rust prints integral doubles without a fraction (`100`), as CEL does.
    s
}

pub(crate) fn to_bool<'a>(v: &Value<'a>) -> R<'a> {
    match v {
        Value::Bool(b) => Ok(Value::Bool(*b)),
        other => match other.as_str() {
            Some("true" | "TRUE" | "True" | "t" | "1") => Ok(Value::Bool(true)),
            Some("false" | "FALSE" | "False" | "f" | "0") => Ok(Value::Bool(false)),
            Some(s) => Err(Fault::error(format!("bool() cannot parse {s:?}"))),
            None => Err(Fault::error(format!(
                "no overload for bool() on {}",
                other.type_name()
            ))),
        },
    }
}

/// `size()`: Unicode code points of a string, elements of a list or map.
pub(crate) fn size<'a>(v: &Value<'a>) -> R<'a> {
    if let Some(s) = v.as_str() {
        return Ok(Value::Int(s.chars().count() as i64));
    }
    if let Some(n) = v.list_len().or_else(|| v.map_len()) {
        return Ok(Value::Int(n as i64));
    }
    Err(Fault::error(format!(
        "no overload for size() on {}",
        v.type_name()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heterogeneous_numeric_equality_is_exact() {
        assert!(equals(&Value::Int(1), &Value::Double(1.0)));
        assert!(equals(&Value::Uint(3), &Value::Int(3)));
        assert!(!equals(&Value::Int(-1), &Value::Uint(u64::MAX)));
        // 2^53 + 1 is not representable as f64: the comparison stays exact.
        assert!(!equals(
            &Value::Int((1 << 53) + 1),
            &Value::Double((1u64 << 53) as f64)
        ));
        assert!(!equals(&Value::Str("1"), &Value::Int(1)));
        assert!(!equals(&Value::Double(f64::NAN), &Value::Double(f64::NAN)));
    }

    #[test]
    fn ordering_and_errors() {
        assert_eq!(
            compare(&Value::Int(1), &Value::Double(1.5)).unwrap(),
            Ordering::Less
        );
        assert!(compare(&Value::Str("a"), &Value::Int(1)).is_err());
        assert!(add(&Value::Int(i64::MAX), &Value::Int(1)).is_err());
        assert!(div(&Value::Int(1), &Value::Int(0)).is_err());
        assert!(div(&Value::Int(i64::MIN), &Value::Int(-1)).is_err());
        assert!(rem(&Value::Int(1), &Value::Int(0)).is_err());
        assert!(add(&Value::Int(1), &Value::Double(1.0)).is_err());
        assert!(to_int(&Value::Double(9.3e18)).is_err());
        assert!(to_int(&Value::Double(f64::NAN)).is_err());
        assert_eq!(to_int(&Value::Double(-1.9)).unwrap().type_name(), "int");
        assert!(to_uint(&Value::Int(-1)).is_err());
    }

    fn int_of(v: Value<'_>) -> Option<i64> {
        match to_int(&v) {
            Ok(Value::Int(i)) => Some(i),
            Ok(other) => panic!("int() returned {}", other.type_name()),
            Err(_) => None,
        }
    }

    fn uint_of(v: Value<'_>) -> Option<u64> {
        match to_uint(&v) {
            Ok(Value::Uint(u)) => Some(u),
            Ok(other) => panic!("uint() returned {}", other.type_name()),
            Err(_) => None,
        }
    }

    /// `uint(double)`: [0, 2^64), range checked before truncation (cel-go
    /// `doubleToUint64Checked`, cel-cpp `CheckedDoubleToUint64`, cel-rust
    /// `uint_from_double`).
    #[test]
    fn uint_of_double_edges() {
        const TWO_TO_64: f64 = 18_446_744_073_709_551_616.0;
        // A negative double is out of range, even one that truncates to 0.
        for d in [-0.5, -0.1, -f64::MIN_POSITIVE, -1.0, -1.5, -1e300] {
            assert_eq!(uint_of(Value::Double(d)), None, "uint({d:?})");
        }
        // -0.0 is zero, not negative.
        assert_eq!(uint_of(Value::Double(-0.0)), Some(0));
        assert_eq!(uint_of(Value::Double(0.0)), Some(0));
        assert_eq!(uint_of(Value::Double(0.5)), Some(0));
        assert_eq!(uint_of(Value::Double(1.9)), Some(1));
        assert_eq!(uint_of(Value::Double(25.5)), Some(25));
        // The largest double below 2^64 converts; 2^64 itself does not.
        let below = f64::from_bits(TWO_TO_64.to_bits() - 1);
        assert_eq!(uint_of(Value::Double(below)), Some(below as u64));
        assert_eq!(uint_of(Value::Double(TWO_TO_64)), None);
        assert_eq!(uint_of(Value::Double(6.022e23)), None);
        for d in [f64::NAN, -f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(uint_of(Value::Double(d)), None, "uint({d:?})");
        }
        assert_eq!(uint_of(Value::Int(-1)), None);
        assert_eq!(uint_of(Value::Int(i64::MAX)), Some(i64::MAX as u64));
    }

    /// `int(double)`: (-2^63, 2^63), both ends excluded, truncation toward
    /// zero (cel-spec conversions `double_int_min_range`,
    /// `double_int_max_range`, `double_truncate_neg`).
    #[test]
    fn int_of_double_edges() {
        const TWO_TO_63: f64 = 9_223_372_036_854_775_808.0;
        assert_eq!(int_of(Value::Double(-0.0)), Some(0));
        assert_eq!(int_of(Value::Double(-0.5)), Some(0));
        assert_eq!(int_of(Value::Double(-7.9)), Some(-7));
        assert_eq!(int_of(Value::Double(-3.5)), Some(-3));
        assert_eq!(int_of(Value::Double(11.5)), Some(11));
        assert_eq!(int_of(Value::Double(TWO_TO_63)), None);
        assert_eq!(int_of(Value::Double(-TWO_TO_63)), None);
        let below = f64::from_bits(TWO_TO_63.to_bits() - 1);
        assert_eq!(int_of(Value::Double(below)), Some(below as i64));
        assert_eq!(int_of(Value::Double(-below)), Some(-below as i64));
        assert_eq!(int_of(Value::Double(1e99)), None);
        for d in [f64::NAN, -f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(int_of(Value::Double(d)), None, "int({d:?})");
        }
        assert_eq!(int_of(Value::Uint(i64::MAX as u64)), Some(i64::MAX));
        assert_eq!(int_of(Value::Uint(i64::MAX as u64 + 1)), None);
    }

    /// `double()` of an int or a uint is total; of a double, the identity
    /// (NaN, infinities and -0.0 kept as they are).
    #[test]
    fn double_conversion_edges() {
        let d = |v: Value<'_>| match to_double(&v) {
            Ok(Value::Double(d)) => d,
            other => panic!("double() returned {other:?}"),
        };
        assert_eq!(d(Value::Int(i64::MIN)), -9_223_372_036_854_775_808.0);
        assert_eq!(d(Value::Uint(u64::MAX)), 18_446_744_073_709_551_616.0);
        assert!(d(Value::Double(f64::NAN)).is_nan());
        assert_eq!(d(Value::Double(f64::INFINITY)), f64::INFINITY);
        assert_eq!(d(Value::Double(f64::NEG_INFINITY)), f64::NEG_INFINITY);
        assert!(d(Value::Double(-0.0)).is_sign_negative());
    }

    #[test]
    fn size_counts_code_points() {
        let Value::Int(n) = size(&Value::Str("héllo")).unwrap() else {
            panic!()
        };
        assert_eq!(n, 5);
    }
}
