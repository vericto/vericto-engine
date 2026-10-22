// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! The interpreter: runs a checked expression over one statement's facts
//! and the host's context. A pure function of its inputs: no clock, no I/O,
//! no randomness, no global state.
//!
//! Absent fields and unknown facts are faults, not values: `&&` and `||`
//! absorb them when the other side decides (`false && x` is false), as are
//! `all`/`exists` when one element decides, exactly as cel-spec's
//! commutative logical operators; otherwise the fault reaches the policy,
//! whose `on_unknown` decides.

use std::rc::Rc;

use super::compile::{Field, Func, Node};
use super::glob::{cidr_contains, glob};
use super::syntax::{BinOp, Macro};
use super::time::{self, Local, Ts, TzSpec};
use super::value::{self as v, Fault, R, Value};
use crate::policy::context::EvalContext;
use crate::policy::facts::{FactList, FactVal, Facts, LimitFact};

/// What an evaluation reads.
pub(crate) struct Activation<'a> {
    pub(crate) ctx: &'a EvalContext,
    pub(crate) facts: Option<&'a Facts>,
    pub(crate) dialect: &'static str,
    /// `time.*` derived once per statement.
    pub(crate) now: Option<Ts>,
    pub(crate) local: Option<Local>,
    pub(crate) date: Option<String>,
}

impl<'a> Activation<'a> {
    pub(crate) fn new(
        ctx: &'a EvalContext,
        facts: Option<&'a Facts>,
        dialect: &'static str,
    ) -> Self {
        let now = ctx.time.as_ref().and_then(|t| Ts::from_secs(t.now_unix));
        let local = match (now, ctx.time.as_ref()) {
            (Some(n), Some(t)) => Some(time::local(n, t.utc_offset_secs)),
            _ => None,
        };
        let date = local.map(|l| format!("{:04}-{:02}-{:02}", l.year, l.month, l.day));
        Activation {
            ctx,
            facts,
            dialect,
            now,
            local,
            date,
        }
    }
}

/// Runs `node` with `slots` comprehension variables.
pub(crate) fn run<'a>(node: &'a Node, act: &'a Activation<'a>, slots: usize) -> R<'a> {
    let mut vars: Vec<Option<Value<'a>>> = vec![None; slots];
    eval(node, act, &mut vars)
}

fn absent(path: &str) -> Fault {
    Fault::unknown(format!("{path} is absent here"))
}

fn facts<'a>(act: &Activation<'a>) -> Result<&'a Facts, Fault> {
    act.facts
        .ok_or_else(|| Fault::unknown("the statement facts were not extracted"))
}

fn list<'a>(l: &'a FactList, path: &str) -> R<'a> {
    match l {
        FactList::Known(v) => Ok(Value::StrList(v)),
        FactList::Unknown(why) => Err(Fault::unknown(format!("{path} is not known: {why}"))),
    }
}

fn field<'a>(f: Field, act: &'a Activation<'a>) -> R<'a> {
    use Field::*;
    let ctx = act.ctx;
    let p = ctx.principal.as_ref();
    let path = || f.path();
    Ok(match f {
        PrincipalType => Value::Str(ctx.principal_type().as_str()),
        PrincipalId => Value::Str(p.map(|p| p.id.as_str()).ok_or_else(|| absent(&path()))?),
        PrincipalOwner => Value::Str(
            p.and_then(|p| p.owner.as_deref())
                .ok_or_else(|| absent(&path()))?,
        ),
        PrincipalTrust => Value::Int(ctx.trust().level()),
        PrincipalVia => Value::Str(
            p.and_then(|p| p.via.as_deref())
                .ok_or_else(|| absent(&path()))?,
        ),
        PrincipalAttrs => match p {
            Some(p) => Value::StrMap(&p.attrs),
            None => Value::Map(Rc::new(Vec::new())),
        },
        PrincipalGroups => match p {
            Some(p) => Value::StrList(&p.groups),
            None => Value::List(Rc::new(Vec::new())),
        },
        PrincipalEndUser => Value::StrMap(
            p.and_then(|p| p.end_user.as_ref())
                .ok_or_else(|| absent(&path()))?,
        ),
        StmtOp => Value::Str(facts(act)?.op),
        StmtKind => Value::Str(&facts(act)?.kind),
        StmtTables => list(&facts(act)?.tables, "stmt.tables")?,
        StmtTablesWritten => list(&facts(act)?.tables_written, "stmt.tables_written")?,
        StmtColumnsRead => list(&facts(act)?.columns_read, "stmt.columns_read")?,
        StmtColumnsWritten => list(&facts(act)?.columns_written, "stmt.columns_written")?,
        StmtFunctions => list(&facts(act)?.functions, "stmt.functions")?,
        StmtHasWhere => Value::Bool(facts(act)?.has_where),
        StmtWhereAlwaysTrue => Value::Bool(facts(act)?.where_always_true),
        StmtLimit => match &facts(act)?.limit {
            LimitFact::Int(i) => Value::Int(*i),
            LimitFact::Absent => return Err(absent("stmt.limit")),
            LimitFact::Unknown(why) => return Err(Fault::unknown(format!("stmt.limit: {why}"))),
        },
        StmtHasReturning => Value::Bool(facts(act)?.has_returning),
        StmtInsertRows => Value::Int(
            facts(act)?
                .insert_rows
                .ok_or_else(|| absent("stmt.insert_rows"))?,
        ),
        StmtTruncated => Value::Bool(facts(act)?.truncated),
        DbId | DbName | DbEnv => {
            let db = ctx.db.as_ref().ok_or_else(|| absent(&path()))?;
            let v = match f {
                DbId => db.id.as_deref(),
                DbName => db.name.as_deref(),
                _ => db.env.as_deref(),
            };
            Value::Str(v.ok_or_else(|| absent(&path()))?)
        }
        DbTags => Value::StrList(&ctx.db.as_ref().ok_or_else(|| absent(&path()))?.tags),
        DbDialect => Value::Str(act.dialect),
        TimeNow => Value::Timestamp(act.now.ok_or_else(|| absent(&path()))?),
        TimeHour | TimeMinute | TimeWeekday => {
            let l = act.local.ok_or_else(|| absent(&path()))?;
            Value::Int(match f {
                TimeHour => i64::from(l.minute_of_day / 60),
                TimeMinute => i64::from(l.minute_of_day % 60),
                // ISO 8601: 1 = Monday … 7 = Sunday.
                _ => i64::from(l.weekday + 1),
            })
        }
        TimeDate => Value::Str(act.date.as_deref().ok_or_else(|| absent(&path()))?),
        TimeTz => Value::Str(&ctx.time.as_ref().ok_or_else(|| absent(&path()))?.tz),
        SessionTenant | SessionApplicationName | SessionClientIp | SessionListener => {
            let s = ctx.session.as_ref().ok_or_else(|| absent(&path()))?;
            let v = match f {
                SessionTenant => s.tenant.as_deref(),
                SessionApplicationName => s.application_name.as_deref(),
                SessionClientIp => s.client_ip.as_deref(),
                _ => s.listener.as_deref(),
            };
            Value::Str(v.ok_or_else(|| absent(&path()))?)
        }
        TicketId => Value::Str(&ctx.ticket.as_ref().ok_or_else(|| absent(&path()))?.id),
        TicketSource => Value::Str(
            ctx.ticket
                .as_ref()
                .and_then(|t| t.source.as_deref())
                .ok_or_else(|| absent(&path()))?,
        ),
        TicketVerified => Value::Bool(ctx.ticket.as_ref().ok_or_else(|| absent(&path()))?.verified),
    })
}

fn has_field(f: Field, act: &Activation<'_>) -> Result<bool, Fault> {
    use Field::*;
    let ctx = act.ctx;
    let p = ctx.principal.as_ref();
    Ok(match f {
        PrincipalType | PrincipalTrust | PrincipalAttrs | PrincipalGroups => true,
        PrincipalId => p.is_some(),
        PrincipalOwner => p.is_some_and(|p| p.owner.is_some()),
        PrincipalVia => p.is_some_and(|p| p.via.is_some()),
        PrincipalEndUser => p.is_some_and(|p| p.end_user.is_some()),
        StmtLimit => !matches!(facts(act)?.limit, LimitFact::Absent),
        StmtInsertRows => facts(act)?.insert_rows.is_some(),
        f if f.is_stmt() => true,
        DbDialect => true,
        DbId => ctx.db.as_ref().is_some_and(|d| d.id.is_some()),
        DbName => ctx.db.as_ref().is_some_and(|d| d.name.is_some()),
        DbEnv => ctx.db.as_ref().is_some_and(|d| d.env.is_some()),
        DbTags => ctx.db.is_some(),
        TimeNow | TimeHour | TimeMinute | TimeWeekday | TimeDate | TimeTz => act.now.is_some(),
        SessionTenant => ctx.session.as_ref().is_some_and(|s| s.tenant.is_some()),
        SessionApplicationName => ctx
            .session
            .as_ref()
            .is_some_and(|s| s.application_name.is_some()),
        SessionClientIp => ctx.session.as_ref().is_some_and(|s| s.client_ip.is_some()),
        SessionListener => ctx.session.as_ref().is_some_and(|s| s.listener.is_some()),
        TicketId | TicketVerified => ctx.ticket.is_some(),
        TicketSource => ctx.ticket.as_ref().is_some_and(|t| t.source.is_some()),
        _ => false,
    })
}

/// A SQL literal as a CEL value; a parameter or an expression is UNKNOWN.
fn sql_value<'a>(fv: &FactVal, col: &str, as_time: bool) -> R<'a> {
    Ok(match fv {
        FactVal::Int(i) => Value::Int(*i),
        FactVal::Double(d) => Value::Double(*d),
        FactVal::Bool(b) => Value::Bool(*b),
        FactVal::Null => Value::Null,
        FactVal::Str(s) => {
            if as_time {
                if let Some(t) = time::parse_timestamp(s, true) {
                    return Ok(Value::Timestamp(t));
                }
            }
            Value::OwnedStr(Rc::from(s.as_str()))
        }
        FactVal::Param(n) => {
            return Err(Fault::unknown(if *n > 0 {
                format!("a value of {col} is the parameter ${n}, bound at execution")
            } else {
                format!("a value of {col} is a parameter, bound at execution")
            }));
        }
        FactVal::Expr => {
            return Err(Fault::unknown(format!(
                "a value of {col} is an expression, not a literal"
            )));
        }
    })
}

fn sql_values<'a>(vals: Result<Vec<FactVal>, String>, col: &str) -> R<'a> {
    let vals = vals.map_err(Fault::unknown)?;
    let mut out = Vec::with_capacity(vals.len());
    for fv in &vals {
        out.push(sql_value(fv, col, false)?);
    }
    Ok(Value::List(Rc::new(out)))
}

/// The tightest bound, or UNKNOWN when any bound is not a literal or they
/// cannot be ordered.
fn tightest<'a>(vals: Result<Vec<FactVal>, String>, col: &str, lower: bool) -> R<'a> {
    let vals = vals.map_err(Fault::unknown)?;
    let mut best: Option<Value<'a>> = None;
    for fv in &vals {
        let x = sql_value(fv, col, true)?;
        best = Some(match best {
            None => x,
            Some(b) => {
                let o = v::compare(&x, &b).map_err(|_| {
                    Fault::unknown(format!("the bounds of {col} cannot be compared"))
                })?;
                let take = if lower { o.is_gt() } else { o.is_lt() };
                if take { x } else { b }
            }
        });
    }
    best.ok_or_else(|| {
        Fault::unknown(format!(
            "{col} has no {} bound in the top-level WHERE",
            if lower { "lower" } else { "upper" }
        ))
    })
}

/// A glob against a fact list; a fact without a schema (unknown default)
/// also matches on the pattern's table part.
fn list_glob(l: &FactList, pattern: &str, path: &str, f: &Facts) -> Result<bool, Fault> {
    let FactList::Known(items) = l else {
        return Err(list(l, path)
            .err()
            .unwrap_or_else(|| Fault::unknown(path.to_string())));
    };
    let pattern = f.fold_arg(pattern);
    let table_part = pattern.rsplit_once('.').map(|(_, t)| t.to_string());
    Ok(items.iter().any(|t| {
        glob(t, &pattern)
            || (!t.contains('.') && table_part.as_deref().is_some_and(|tp| glob(t, tp)))
    }))
}

fn str_arg<'x>(v: &'x Value<'_>, what: &str) -> Result<&'x str, Fault> {
    v.as_str()
        .ok_or_else(|| Fault::error(format!("{what} needs a string, got {}", v.type_name())))
}

fn call<'a>(f: Func, args: Vec<Value<'a>>, act: &'a Activation<'a>) -> R<'a> {
    let a0 = || {
        args.first()
            .cloned()
            .ok_or_else(|| Fault::error("missing argument"))
    };
    match f {
        Func::Size => v::size(&a0()?),
        Func::Int => v::to_int(&a0()?),
        Func::Uint => v::to_uint(&a0()?),
        Func::Double => v::to_double(&a0()?),
        Func::String => v::to_string(&a0()?),
        Func::Bool => v::to_bool(&a0()?),
        Func::Dyn => a0(),
        Func::Contains | Func::StartsWith | Func::EndsWith => {
            let s = str_arg(&args[0], "the method")?;
            let t = str_arg(&args[1], "the method")?;
            Ok(Value::Bool(match f {
                Func::Contains => s.contains(t),
                Func::StartsWith => s.starts_with(t),
                _ => s.ends_with(t),
            }))
        }
        Func::Glob => Ok(Value::Bool(glob(
            str_arg(&args[0], "glob")?,
            str_arg(&args[1], "glob")?,
        ))),
        Func::CidrContains => {
            let c = str_arg(&args[0], "cidr_contains")?;
            let ip = str_arg(&args[1], "cidr_contains")?;
            cidr_contains(c, ip).map(Value::Bool).ok_or_else(|| {
                Fault::error(format!("`{c}` / `{ip}` is not a CIDR and an IP address"))
            })
        }
        Func::StmtValues
        | Func::StmtFilterValues
        | Func::StmtHasFilter
        | Func::StmtLowerBound
        | Func::StmtUpperBound
        | Func::StmtReads
        | Func::StmtWrites
        | Func::StmtTouches => {
            let facts = facts(act)?;
            let arg = str_arg(&args[0], "the stmt helper")?;
            match f {
                Func::StmtValues => sql_values(facts.values(arg), arg),
                Func::StmtFilterValues => sql_values(facts.filter_values(arg), arg),
                Func::StmtHasFilter => facts
                    .has_filter(arg)
                    .map(Value::Bool)
                    .map_err(Fault::unknown),
                Func::StmtLowerBound => tightest(facts.bounds(arg, true), arg, true),
                Func::StmtUpperBound => tightest(facts.bounds(arg, false), arg, false),
                Func::StmtReads => {
                    // Read side: every table referenced (a write target is
                    // also read when its rows are matched).
                    list_glob(&facts.tables, arg, "stmt.tables", facts).map(Value::Bool)
                }
                Func::StmtWrites => {
                    list_glob(&facts.tables_written, arg, "stmt.tables_written", facts)
                        .map(Value::Bool)
                }
                _ => list_glob(&facts.tables, arg, "stmt.tables", facts).map(Value::Bool),
            }
        }
    }
}

fn eval<'a>(node: &'a Node, act: &'a Activation<'a>, vars: &mut Vec<Option<Value<'a>>>) -> R<'a> {
    match node {
        Node::Const(c) => Ok(Value::from_const(c)),
        Node::Field(f) => field(*f, act),
        Node::Var(slot) => vars[*slot]
            .clone()
            .ok_or_else(|| Fault::error("comprehension variable out of scope")),
        Node::Select(m, key) => {
            let m = eval(m, act, vars)?;
            if !m.is_map() {
                return Err(Fault::error(format!(
                    "cannot select `.{key}` on a {}",
                    m.type_name()
                )));
            }
            m.map_get(&Value::Str(key))?
                .ok_or_else(|| Fault::error(format!("no such key: {key}")))
        }
        Node::HasField(f) => has_field(*f, act).map(Value::Bool),
        Node::HasKey(m, key) => {
            let m = eval(m, act, vars)?;
            if !m.is_map() {
                return Err(Fault::error(format!(
                    "has() needs a map, got {}",
                    m.type_name()
                )));
            }
            Ok(Value::Bool(m.map_get(&Value::Str(key))?.is_some()))
        }
        Node::Index(c, i) => {
            let c = eval(c, act, vars)?;
            let i = eval(i, act, vars)?;
            if c.is_map() {
                return c.map_get(&i)?.ok_or_else(|| Fault::error("no such key"));
            }
            let idx = match i {
                Value::Int(n) => usize::try_from(n).ok(),
                Value::Uint(n) => usize::try_from(n).ok(),
                other => {
                    return Err(Fault::error(format!(
                        "list index must be an int, got {}",
                        other.type_name()
                    )));
                }
            };
            idx.and_then(|n| c.list_get(n))
                .ok_or_else(|| Fault::error("list index out of range"))
        }
        Node::Not(x) => Ok(Value::Bool(!eval(x, act, vars)?.as_bool()?)),
        Node::Neg(x) => v::neg(&eval(x, act, vars)?),
        Node::And(a, b) | Node::Or(a, b) => {
            let is_and = matches!(node, Node::And(..));
            // The value that decides: false for &&, true for ||.
            let decides = !is_and;
            let left = eval(a, act, vars).and_then(|x| x.as_bool());
            if left == Ok(decides) {
                return Ok(Value::Bool(decides));
            }
            let right = eval(b, act, vars).and_then(|x| x.as_bool());
            if right == Ok(decides) {
                return Ok(Value::Bool(decides));
            }
            match (left, right) {
                (Ok(_), Ok(_)) => Ok(Value::Bool(!decides)),
                (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(e),
                (Err(e1), Err(e2)) => Err(e1.merge(e2)),
            }
        }
        Node::Bin(op, a, b) => {
            let x = eval(a, act, vars)?;
            let y = eval(b, act, vars)?;
            match op {
                BinOp::Eq => Ok(Value::Bool(v::equals(&x, &y))),
                BinOp::Ne => Ok(Value::Bool(!v::equals(&x, &y))),
                BinOp::Lt => Ok(Value::Bool(v::compare(&x, &y)?.is_lt())),
                BinOp::Le => Ok(Value::Bool(v::compare(&x, &y)?.is_le())),
                BinOp::Gt => Ok(Value::Bool(v::compare(&x, &y)?.is_gt())),
                BinOp::Ge => Ok(Value::Bool(v::compare(&x, &y)?.is_ge())),
                BinOp::In => Ok(Value::Bool(v::contains(&y, &x)?)),
                BinOp::Add => v::add(&x, &y),
                BinOp::Sub => v::sub(&x, &y),
                BinOp::Mul => v::mul(&x, &y),
                BinOp::Div => v::div(&x, &y),
                BinOp::Rem => v::rem(&x, &y),
                BinOp::And | BinOp::Or => unreachable!("lowered to And/Or"),
            }
        }
        Node::Cond(c, a, b) => {
            if eval(c, act, vars)?.as_bool()? {
                eval(a, act, vars)
            } else {
                eval(b, act, vars)
            }
        }
        Node::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(it, act, vars)?);
            }
            Ok(Value::List(Rc::new(out)))
        }
        Node::Map(entries) => {
            let mut out: Vec<(Value<'a>, Value<'a>)> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let k = eval(k, act, vars)?;
                let val = eval(val, act, vars)?;
                if out.iter().any(|(e, _)| v::equals(e, &k)) {
                    return Err(Fault::error("duplicate key in a map literal"));
                }
                out.push((k, val));
            }
            Ok(Value::Map(Rc::new(out)))
        }
        Node::Call(f, args) => {
            let mut vals = Vec::with_capacity(args.len());
            for a in args {
                vals.push(eval(a, act, vars)?);
            }
            call(*f, vals, act)
        }
        Node::Matches(s, re) => {
            let s = eval(s, act, vars)?;
            let s = str_arg(&s, "matches")?;
            Ok(Value::Bool(re.is_match(s)))
        }
        Node::InWindow(ts, spec, tz) => {
            let ts = match eval(ts, act, vars)? {
                Value::Timestamp(t) => t,
                other => {
                    return Err(Fault::error(format!(
                        "in_window needs a timestamp, got {}",
                        other.type_name()
                    )));
                }
            };
            let offset = match tz {
                TzSpec::Fixed(o) => *o,
                TzSpec::Named(name) => {
                    let t = act.ctx.time.as_ref().ok_or_else(|| absent("time.tz"))?;
                    // The host's offset holds at time.now only.
                    if &t.tz != name || Some(ts) != act.now {
                        return Err(Fault::unknown(format!(
                            "the offset of `{name}` is known only for time.now in the workspace time zone ({})",
                            t.tz
                        )));
                    }
                    t.utc_offset_secs
                }
            };
            Ok(Value::Bool(spec.contains(time::local(ts, offset))))
        }
        Node::Comp {
            mac,
            range,
            slot,
            pred,
            body,
        } => {
            let r = eval(range, act, vars)?;
            let items = if r.is_map() {
                r.map_keys()
            } else {
                r.list_items()
            }
            .ok_or_else(|| Fault::error(format!("cannot range over a {}", r.type_name())))?;
            comprehension(
                *mac,
                items,
                *slot,
                pred.as_deref(),
                body.as_deref(),
                act,
                vars,
            )
        }
    }
}

fn comprehension<'a>(
    mac: Macro,
    items: Vec<Value<'a>>,
    slot: usize,
    pred: Option<&'a Node>,
    body: Option<&'a Node>,
    act: &'a Activation<'a>,
    vars: &mut Vec<Option<Value<'a>>>,
) -> R<'a> {
    let saved = vars[slot].take();
    let test = |x: &Value<'a>, vars: &mut Vec<Option<Value<'a>>>| -> Result<bool, Fault> {
        vars[slot] = Some(x.clone());
        let p = pred.expect("this macro has a predicate");
        eval(p, act, vars)?.as_bool()
    };
    let result = match mac {
        Macro::All | Macro::Exists => {
            // The value that decides: false for all, true for exists.
            let decides = mac == Macro::Exists;
            let mut fault: Option<Fault> = None;
            let mut decided = false;
            for x in &items {
                match test(x, vars) {
                    Ok(b) if b == decides => {
                        decided = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => fault = Some(fault.map_or(e.clone(), |f| f.merge(e))),
                }
            }
            if decided {
                Ok(Value::Bool(decides))
            } else if let Some(f) = fault {
                Err(f)
            } else {
                Ok(Value::Bool(!decides))
            }
        }
        Macro::ExistsOne => {
            let mut n = 0usize;
            let mut res = Ok(());
            for x in &items {
                match test(x, vars) {
                    Ok(true) => n += 1,
                    Ok(false) => {}
                    Err(e) => {
                        res = Err(e);
                        break;
                    }
                }
            }
            res.map(|()| Value::Bool(n == 1))
        }
        Macro::Filter => {
            let mut out = Vec::new();
            let mut res = Ok(());
            for x in &items {
                match test(x, vars) {
                    Ok(true) => out.push(x.clone()),
                    Ok(false) => {}
                    Err(e) => {
                        res = Err(e);
                        break;
                    }
                }
            }
            res.map(|()| Value::List(Rc::new(out)))
        }
        Macro::Map | Macro::MapFilter => {
            let mut out = Vec::new();
            let mut res = Ok(());
            for x in &items {
                if mac == Macro::MapFilter {
                    match test(x, vars) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(e) => {
                            res = Err(e);
                            break;
                        }
                    }
                }
                vars[slot] = Some(x.clone());
                match eval(body.expect("map has a body"), act, vars) {
                    Ok(y) => out.push(y),
                    Err(e) => {
                        res = Err(e);
                        break;
                    }
                }
            }
            res.map(|()| Value::List(Rc::new(out)))
        }
    };
    vars[slot] = saved;
    result
}
