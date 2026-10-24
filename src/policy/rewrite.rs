// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `rewrite_limit` (design "Business policy rules" §8.1; runtime controls
//! §5.5, VERICTO-102): bound the rows a top-level `SELECT` returns by adding
//! or clamping its **outer** `LIMIT`, on the VERICTO-085 rewrite machinery.
//!
//! - No `LIMIT` (or `LIMIT ALL` / `LIMIT NULL`): add `LIMIT n` to the outer
//!   query; a set operation gets one `LIMIT` on its outer node.
//! - A literal `LIMIT m` with `m > n`: set it to `n`. `m <= n`: nothing to do.
//! - Postgres `LIMIT $k`: `LIMIT LEAST($k::bigint, n)`. The cast keeps the
//!   type Postgres infers for `$k` (`bigint`, as for a bare `LIMIT $k`), so
//!   the parameter numbering and the client's binding are unchanged. Any
//!   other expression: `LIMIT LEAST(<expr>, n)`.
//! - MySQL `LIMIT ?` (or `LIMIT a, ?`): a placeholder must stay a
//!   placeholder, and its value is only known at execution: UNKNOWN, and the
//!   policy's `on_unknown` decides (the proxy checks the bound value in
//!   Phase 2).
//! - `OFFSET` is kept: the result is the first `n` rows of the original
//!   under the same `ORDER BY`. Subqueries and CTEs are untouched.
//! - Skipped, as VERICTO-102 skips them (they return at most one row, or are
//!   not reads): a `SELECT` without `FROM` that calls no function and has
//!   no subquery (`SELECT 1`), an aggregate-only projection without
//!   `GROUP BY`, `SELECT … INTO`, a data-modifying CTE, `EXPLAIN`, cursors,
//!   `COPY`.
//!
//! **Failure blocks.** The rewritten text is only returned after the checks
//! VERICTO-085 runs on its own rewrites: Postgres deparses the tree, parses
//! the text back, and requires the same bind parameters and a stable
//! deparse; MySQL prints through [`crate::sensitive::mysql::Prepared`]
//! (fidelity of the unmodified text, re-parse to the same tree, the same
//! `?` in the same order). Anything else, and `FETCH … WITH TIES` (which
//! cannot be bounded exactly), is a failure: the caller blocks.
//!
//! Nothing here runs unless a `rewrite_limit` policy was violated.

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{self, LimitOption, Node, SelectStmt, SetOperation};
use sqlparser::ast::{
    Expr, GroupByExpr, LimitClause, Query, Select, SelectItem, SetExpr, Statement, Value,
};

use crate::parser::{Dialect, ParsedQuery, SourceAst};

/// Largest `rewrite_limit` a policy may set (the checker's static bound).
pub const MAX_REWRITE_LIMIT: u64 = 1_000_000;

/// What the rewrite did to one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StatementLimit {
    /// Out of scope, or already bounded by `n` or less: nothing to do.
    Unchanged,
    /// The outer LIMIT was added or lowered. `ordered`: the outer query has
    /// an `ORDER BY` (without one, the rows kept are an arbitrary subset).
    Bounded { ordered: bool },
    /// The bound depends on a value only known at execution.
    Unknown(String),
    /// The statement cannot be bounded: the caller blocks.
    Failed(String),
}

/// The rewrite of a whole input: one entry per requested statement, and the
/// text to execute when at least one was bounded.
#[derive(Debug, Clone)]
pub(crate) struct LimitRewrite {
    pub(crate) statements: Vec<(usize, StatementLimit)>,
    pub(crate) sql: Option<String>,
}

/// Rewrites `parsed` (whose text is `sql`, when the host has it) so that
/// each statement of `caps` (`(index, n)`, at most one per index) returns at
/// most `n` rows. A failure to render or verify the text turns every
/// bounded statement into [`StatementLimit::Failed`].
pub(crate) fn rewrite(
    parsed: &ParsedQuery,
    sql: Option<&str>,
    caps: &[(usize, u64)],
) -> LimitRewrite {
    let fail_all = |why: &str| LimitRewrite {
        statements: caps
            .iter()
            .map(|(i, _)| (*i, StatementLimit::Failed(why.to_string())))
            .collect(),
        sql: None,
    };
    if parsed.mysql.is_some() {
        return fail_all(
            "MySQL may read this text in more than one way: the LIMIT cannot be rewritten safely",
        );
    }
    match &parsed.ast {
        SourceAst::Pg(tree) => pg(tree, caps),
        SourceAst::Sql {
            dialect: Dialect::Mysql,
            ..
        } => match sql {
            Some(text) => mysql(text, caps),
            None => fail_all("the statement text is not available for the MySQL rewrite"),
        },
        SourceAst::Sql { dialect, .. } => LimitRewrite {
            statements: caps
                .iter()
                .map(|(i, _)| {
                    (
                        *i,
                        StatementLimit::Unknown(format!(
                            "no LIMIT rewrite for {} yet (Postgres and MySQL only)",
                            dialect.as_str()
                        )),
                    )
                })
                .collect(),
            sql: None,
        },
        SourceAst::None | SourceAst::Classified { .. } => fail_all("the statement was not read"),
    }
}

/// Re-reads `sql` (a VERICTO-085 mask rewrite) in `dialect`, so the LIMIT is
/// applied on top of the mask. `None` when it does not parse.
pub(crate) fn reparse(sql: &str, dialect: Dialect) -> Option<ParsedQuery> {
    crate::parser::parser_for(dialect).parse(sql).ok()
}

// ---------------------------------------------------------------------------
// Shared helpers

/// Aggregates that return one row without `GROUP BY` (both dialects). A
/// projection made only of these calls is skipped.
const AGGREGATES: &[&str] = &[
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "bool_and",
    "bool_or",
    "every",
    "bit_and",
    "bit_or",
    "bit_xor",
    "string_agg",
    "array_agg",
    "json_agg",
    "jsonb_agg",
    "json_object_agg",
    "jsonb_object_agg",
    "json_arrayagg",
    "json_objectagg",
    "group_concat",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "std",
    "variance",
    "var_pop",
    "var_samp",
];

fn is_aggregate(name: &str) -> bool {
    AGGREGATES.iter().any(|a| a.eq_ignore_ascii_case(name))
}

// ---------------------------------------------------------------------------
// Postgres (pg_query)

/// `$n` numbers of every bind parameter, sorted (repetitions kept).
fn params(tree: &protobuf::ParseResult) -> Vec<i32> {
    let mut n: Vec<i32> = tree
        .nodes()
        .into_iter()
        .filter_map(|(node, ..)| match node {
            pg_query::NodeRef::ParamRef(p) => Some(p.number),
            _ => None,
        })
        .collect();
    n.sort_unstable();
    n
}

/// Whether a node contains a function call or a subquery anywhere inside it.
fn calls_or_queries(nodes: &[Node]) -> bool {
    fn walk(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::Object(m) => {
                m.contains_key("FuncCall") || m.contains_key("SubLink") || m.values().any(walk)
            }
            serde_json::Value::Array(a) => a.iter().any(walk),
            _ => false,
        }
    }
    // Serialization of the protobuf cannot fail; if it ever did, do not skip.
    nodes
        .iter()
        .any(|n| serde_json::to_value(n).map_or(true, |v| walk(&v)))
}

fn pg_func_name(f: &protobuf::FuncCall) -> Option<&str> {
    match f.funcname.last().and_then(|n| n.node.as_ref()) {
        Some(NodeEnum::String(s)) => Some(s.sval.as_str()),
        _ => None,
    }
}

/// Every projected expression is a plain aggregate call (no window).
fn pg_aggregate_only(s: &SelectStmt) -> bool {
    !s.target_list.is_empty()
        && s.target_list.iter().all(|t| {
            let Some(NodeEnum::ResTarget(rt)) = t.node.as_ref() else {
                return false;
            };
            match rt.val.as_deref().and_then(|v| v.node.as_ref()) {
                Some(NodeEnum::FuncCall(f)) => {
                    f.over.is_none() && pg_func_name(f).is_some_and(is_aggregate)
                }
                _ => false,
            }
        })
}

fn pg_modifying_cte(s: &SelectStmt) -> bool {
    s.with_clause.as_ref().is_some_and(|w| {
        w.ctes.iter().any(|c| match c.node.as_ref() {
            Some(NodeEnum::CommonTableExpr(cte)) => !matches!(
                cte.ctequery.as_deref().and_then(|q| q.node.as_ref()),
                Some(NodeEnum::SelectStmt(_))
            ),
            _ => true,
        })
    })
}

/// Why this top-level SELECT is out of scope, if it is.
fn pg_skipped(s: &SelectStmt) -> bool {
    if s.into_clause.is_some() || pg_modifying_cte(s) {
        return true;
    }
    let simple = s.op == SetOperation::SetopNone as i32 || s.op == SetOperation::Undefined as i32;
    if !simple {
        return false;
    }
    // `VALUES (…), (…)` and `SELECT <constants>`: their row count is in the text.
    if s.from_clause.is_empty() && (!s.values_lists.is_empty() || !calls_or_queries(&s.target_list))
    {
        return true;
    }
    s.group_clause.is_empty() && s.window_clause.is_empty() && pg_aggregate_only(s)
}

/// A node parsed from `SELECT 1 LIMIT <limit>`.
fn pg_limit_template(limit: &str) -> Option<Node> {
    let tree = pg_query::parse(&format!("SELECT 1 LIMIT {limit}")).ok()?;
    let raw = tree.protobuf.stmts.into_iter().next()?;
    match raw.stmt?.node? {
        NodeEnum::SelectStmt(s) => s.limit_count.map(|b| *b),
        _ => None,
    }
}

/// Replaces the first `$1` (or the first NULL constant) inside `node` with `orig`.
fn pg_splice(node: &mut Node, orig: &Node) -> bool {
    match node.node.as_mut() {
        Some(NodeEnum::ParamRef(_)) => {
            *node = orig.clone();
            true
        }
        Some(NodeEnum::AConst(c)) if c.isnull => {
            *node = orig.clone();
            true
        }
        Some(NodeEnum::TypeCast(tc)) => tc.arg.as_deref_mut().is_some_and(|a| pg_splice(a, orig)),
        Some(NodeEnum::MinMaxExpr(m)) => m.args.iter_mut().any(|a| pg_splice(a, orig)),
        _ => false,
    }
}

/// `LEAST(<orig>, n)`: `$k` keeps its inferred type through a bigint cast.
fn pg_least(orig: &Node, n: u64) -> Option<Node> {
    let param = matches!(orig.node, Some(NodeEnum::ParamRef(_)));
    let mut t = pg_limit_template(&if param {
        format!("LEAST(CAST($1 AS bigint), {n})")
    } else {
        format!("LEAST(NULL, {n})")
    })?;
    pg_splice(&mut t, orig).then_some(t)
}

fn pg_int(n: &Node) -> Option<i64> {
    match n.node.as_ref() {
        Some(NodeEnum::AConst(c)) => match &c.val {
            Some(protobuf::a_const::Val::Ival(i)) => Some(i64::from(i.ival)),
            _ => None,
        },
        _ => None,
    }
}

/// Bounds one top-level SELECT in place.
fn pg_bound(s: &mut SelectStmt, n: u64) -> StatementLimit {
    if pg_skipped(s) {
        return StatementLimit::Unchanged;
    }
    if s.limit_option == LimitOption::WithTies as i32 {
        return StatementLimit::Failed(
            "FETCH … WITH TIES may return more rows than its count: use FETCH FIRST n ROWS ONLY or LIMIT"
                .into(),
        );
    }
    let ordered = !s.sort_clause.is_empty();
    let lit = || pg_limit_template(&n.to_string());
    let new = match s.limit_count.as_deref() {
        None => lit(),
        Some(cur) => match cur.node.as_ref() {
            Some(NodeEnum::AConst(c)) if c.isnull => lit(),
            Some(NodeEnum::AConst(c)) => match &c.val {
                Some(protobuf::a_const::Val::Ival(i)) => {
                    if i64::from(i.ival) <= n as i64 {
                        return StatementLimit::Unchanged;
                    }
                    lit()
                }
                Some(protobuf::a_const::Val::Fval(f)) => match f.fval.parse::<f64>() {
                    Ok(v) if v.is_finite() && v <= n as f64 => return StatementLimit::Unchanged,
                    Ok(v) if v.is_finite() => lit(),
                    _ => pg_least(cur, n),
                },
                // A string or boolean constant: Postgres rejects or casts it;
                // LEAST keeps whatever it does and bounds the result.
                _ => pg_least(cur, n),
            },
            // `LEAST(…, m)` with a literal `m <= n`: already bounded (a text
            // this rewrite produced).
            Some(NodeEnum::MinMaxExpr(mm))
                if mm.op == protobuf::MinMaxOp::IsLeast as i32
                    && mm
                        .args
                        .iter()
                        .any(|a| pg_int(a).is_some_and(|m| m <= n as i64)) =>
            {
                return StatementLimit::Unchanged;
            }
            _ => pg_least(cur, n),
        },
    };
    match new {
        Some(node) => {
            s.limit_count = Some(Box::new(node));
            // `LIMIT`/`FETCH FIRST … ROWS ONLY` (no LIMIT reads `Default`).
            s.limit_option = LimitOption::Count as i32;
            StatementLimit::Bounded { ordered }
        }
        None => StatementLimit::Failed("the LIMIT expression could not be built".into()),
    }
}

fn pg(tree: &protobuf::ParseResult, caps: &[(usize, u64)]) -> LimitRewrite {
    let mut tree = tree.clone();
    let mut statements = Vec::with_capacity(caps.len());
    // Facts index the statements that have a node (facts::pg::shapes).
    let mut index = 0usize;
    for raw in tree.stmts.iter_mut() {
        let Some(node) = raw.stmt.as_deref_mut().and_then(|n| n.node.as_mut()) else {
            continue;
        };
        if let Some((_, n)) = caps.iter().find(|(i, _)| *i == index) {
            let r = match node {
                NodeEnum::SelectStmt(s) => pg_bound(s, *n),
                _ => StatementLimit::Unchanged,
            };
            statements.push((index, r));
        }
        index += 1;
    }
    for (i, _) in caps {
        if !statements.iter().any(|(j, _)| j == i) {
            statements.push((*i, StatementLimit::Failed("no such statement".into())));
        }
    }
    let bounded = statements
        .iter()
        .any(|(_, r)| matches!(r, StatementLimit::Bounded { .. }));
    if !bounded {
        return LimitRewrite {
            statements,
            sql: None,
        };
    }
    match pg_render(&tree) {
        Ok(sql) => LimitRewrite {
            statements,
            sql: Some(sql),
        },
        Err(why) => LimitRewrite {
            statements: fail_bounded(statements, &why),
            sql: None,
        },
    }
}

/// Deparse, then verify: the text parses back, with the same bind
/// parameters, and deparses to itself.
fn pg_render(tree: &protobuf::ParseResult) -> Result<String, String> {
    let sql = pg_query::deparse(tree).map_err(|e| format!("rewrite failed ({e})"))?;
    let again = pg_query::parse(&sql)
        .map_err(|e| format!("the rewritten text does not parse back ({e})"))?;
    if params(&again.protobuf) != params(tree) {
        return Err("the rewrite changed the bind parameters".into());
    }
    if again.protobuf.stmts.len() != tree.stmts.len() {
        return Err("the rewrite changed the number of statements".into());
    }
    let stable = pg_query::deparse(&again.protobuf)
        .map_err(|e| format!("the rewritten text does not deparse ({e})"))?;
    if stable != sql {
        return Err("the rewritten text does not read back as the rewritten query".into());
    }
    Ok(sql)
}

fn fail_bounded(
    statements: Vec<(usize, StatementLimit)>,
    why: &str,
) -> Vec<(usize, StatementLimit)> {
    statements
        .into_iter()
        .map(|(i, r)| match r {
            StatementLimit::Bounded { .. } => (i, StatementLimit::Failed(why.to_string())),
            other => (i, other),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// MySQL (sqlparser, printed and checked by sensitive::mysql)

fn sql_name_last(name: &sqlparser::ast::ObjectName) -> Option<String> {
    name.0
        .last()
        .and_then(|p| p.as_ident())
        .map(|i| i.value.clone())
}

fn sql_calls_or_queries(items: &[SelectItem]) -> bool {
    use sqlparser::ast::Visit;
    struct Finder(bool);
    impl sqlparser::ast::Visitor for Finder {
        type Break = ();
        fn pre_visit_expr(&mut self, e: &Expr) -> std::ops::ControlFlow<()> {
            if matches!(
                e,
                Expr::Function(_)
                    | Expr::Subquery(_)
                    | Expr::Exists { .. }
                    | Expr::InSubquery { .. }
            ) {
                self.0 = true;
                return std::ops::ControlFlow::Break(());
            }
            std::ops::ControlFlow::Continue(())
        }
    }
    let mut f = Finder(false);
    for item in items {
        if item.visit(&mut f).is_break() {
            break;
        }
    }
    f.0
}

fn sql_aggregate_only(sel: &Select) -> bool {
    !sel.projection.is_empty()
        && sel.projection.iter().all(|item| {
            let e = match item {
                SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => e,
                _ => return false,
            };
            matches!(e, Expr::Function(f)
                if f.over.is_none() && sql_name_last(&f.name).is_some_and(|n| is_aggregate(&n)))
        })
}

fn sql_skipped(q: &Query) -> bool {
    if q.with.as_ref().is_some_and(|w| {
        w.cte_tables.iter().any(|c| {
            !matches!(
                c.query.body.as_ref(),
                SetExpr::Select(_)
                    | SetExpr::Query(_)
                    | SetExpr::SetOperation { .. }
                    | SetExpr::Values(_)
            )
        })
    }) {
        return true;
    }
    match q.body.as_ref() {
        SetExpr::Select(sel) => {
            if sel.into.is_some() {
                return true;
            }
            if sel.from.is_empty() && !sql_calls_or_queries(&sel.projection) {
                return true;
            }
            let no_group = matches!(&sel.group_by, GroupByExpr::Expressions(v, _) if v.is_empty());
            no_group && sel.named_window.is_empty() && sql_aggregate_only(sel)
        }
        SetExpr::Values(_) => true,
        _ => false,
    }
}

fn number(n: u64) -> Expr {
    Expr::Value(Value::Number(n.to_string(), false).with_empty_span())
}

/// The literal row count of a MySQL LIMIT argument.
enum MyLimit {
    Literal(u64),
    Placeholder,
    Other,
}

fn my_limit(e: &Expr) -> MyLimit {
    match e {
        Expr::Value(v) => match &v.value {
            Value::Number(s, _) => s.parse::<u64>().map_or(MyLimit::Other, MyLimit::Literal),
            Value::Placeholder(_) => MyLimit::Placeholder,
            _ => MyLimit::Other,
        },
        _ => MyLimit::Other,
    }
}

fn my_bound(q: &mut Query, n: u64) -> StatementLimit {
    if sql_skipped(q) {
        return StatementLimit::Unchanged;
    }
    if q.fetch.is_some() {
        return StatementLimit::Failed("MySQL has no FETCH clause".into());
    }
    let ordered = q.order_by.is_some();
    let slot: &mut Expr = match &mut q.limit_clause {
        None => {
            q.limit_clause = Some(LimitClause::LimitOffset {
                limit: Some(number(n)),
                offset: None,
                limit_by: Vec::new(),
            });
            return StatementLimit::Bounded { ordered };
        }
        Some(LimitClause::LimitOffset { limit: None, .. }) => {
            if let Some(LimitClause::LimitOffset { limit, .. }) = &mut q.limit_clause {
                *limit = Some(number(n));
            }
            return StatementLimit::Bounded { ordered };
        }
        Some(LimitClause::LimitOffset { limit: Some(e), .. }) => e,
        Some(LimitClause::OffsetCommaLimit { limit, .. }) => limit,
    };
    match my_limit(slot) {
        MyLimit::Literal(m) if m <= n => StatementLimit::Unchanged,
        MyLimit::Literal(_) => {
            *slot = number(n);
            StatementLimit::Bounded { ordered }
        }
        MyLimit::Placeholder => StatementLimit::Unknown(
            "the LIMIT is a bind parameter: its value is only known at execution".into(),
        ),
        MyLimit::Other => StatementLimit::Failed("the MySQL LIMIT is not a literal".into()),
    }
}

fn mysql(text: &str, caps: &[(usize, u64)]) -> LimitRewrite {
    let all = |r: StatementLimit| LimitRewrite {
        statements: caps.iter().map(|(i, _)| (*i, r.clone())).collect(),
        sql: None,
    };
    let mut prepared = match crate::sensitive::mysql::prepare(text) {
        Ok(p) => p,
        Err(e) => {
            return all(StatementLimit::Failed(format!(
                "the MySQL text cannot be read the way MySQL reads it ({})",
                e.0
            )));
        }
    };
    let mut statements = std::mem::take(&mut prepared.statements);
    let original = statements.clone();
    let mut out = Vec::with_capacity(caps.len());
    for (i, n) in caps {
        let r = match statements.get_mut(*i) {
            Some(Statement::Query(q)) => my_bound(q, *n),
            Some(_) => StatementLimit::Unchanged,
            None => StatementLimit::Failed("no such statement".into()),
        };
        out.push((*i, r));
    }
    if !out
        .iter()
        .any(|(_, r)| matches!(r, StatementLimit::Bounded { .. }))
    {
        return LimitRewrite {
            statements: out,
            sql: None,
        };
    }
    let rendered = prepared
        .check_original(&original)
        .and_then(|()| prepared.render(&statements))
        .map_err(|why| format!("the MySQL text cannot be reproduced faithfully ({why})"));
    match rendered {
        Ok(sql) => LimitRewrite {
            statements: out,
            sql: Some(sql),
        },
        Err(why) => LimitRewrite {
            statements: fail_bounded(out, &why),
            sql: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(sql: &str, dialect: Dialect, n: u64) -> (StatementLimit, Option<String>) {
        let parsed = crate::parser::parser_for(dialect)
            .parse(sql)
            .expect("parses");
        let r = rewrite(&parsed, Some(sql), &[(0, n)]);
        (r.statements[0].1.clone(), r.sql)
    }

    fn pg_sql(sql: &str, n: u64) -> String {
        match rw(sql, Dialect::Postgres, n) {
            (StatementLimit::Bounded { .. }, Some(s)) => s,
            other => panic!("{sql}: {other:?}"),
        }
    }

    fn my_sql(sql: &str, n: u64) -> String {
        match rw(sql, Dialect::Mysql, n) {
            (StatementLimit::Bounded { .. }, Some(s)) => s,
            other => panic!("{sql}: {other:?}"),
        }
    }

    #[test]
    fn postgres_adds_or_clamps_the_outer_limit() {
        assert_eq!(
            pg_sql("SELECT id FROM t", 100),
            "SELECT id FROM t LIMIT 100"
        );
        assert_eq!(
            pg_sql("SELECT id FROM t LIMIT 5000", 100),
            "SELECT id FROM t LIMIT 100"
        );
        assert_eq!(
            pg_sql("SELECT id FROM t LIMIT ALL", 100),
            "SELECT id FROM t LIMIT 100"
        );
        assert_eq!(
            pg_sql("SELECT id FROM t ORDER BY id OFFSET 20", 100),
            "SELECT id FROM t ORDER BY id LIMIT 100 OFFSET 20"
        );
        assert_eq!(
            pg_sql("SELECT id FROM t WHERE a = $2 LIMIT $1", 100),
            "SELECT id FROM t WHERE a = $2 LIMIT LEAST($1::bigint, 100)"
        );
        assert_eq!(
            pg_sql("SELECT id FROM t LIMIT 10 + $1", 100),
            "SELECT id FROM t LIMIT LEAST(10 + $1, 100)"
        );
        assert_eq!(
            pg_sql("SELECT id FROM t FETCH FIRST 500 ROWS ONLY", 100),
            "SELECT id FROM t LIMIT 100"
        );
        assert_eq!(
            pg_sql("SELECT a FROM t UNION SELECT a FROM u", 10),
            "SELECT a FROM t UNION SELECT a FROM u LIMIT 10"
        );
        assert_eq!(
            pg_sql(
                "(SELECT a FROM t LIMIT 5000) UNION ALL (SELECT a FROM u)",
                10
            ),
            "(SELECT a FROM t LIMIT 5000) UNION ALL SELECT a FROM u LIMIT 10"
        );
        assert_eq!(
            pg_sql("WITH x AS (SELECT a FROM t) SELECT a FROM x", 10),
            "WITH x AS (SELECT a FROM t) SELECT a FROM x LIMIT 10"
        );
        assert_eq!(
            pg_sql(
                "SELECT a FROM (SELECT a FROM t) s WHERE a IN (SELECT b FROM u)",
                10
            ),
            "SELECT a FROM (SELECT a FROM t) s WHERE a IN (SELECT b FROM u) LIMIT 10"
        );
        assert_eq!(
            pg_sql("SELECT generate_series(1, 100000)", 10),
            "SELECT generate_series(1, 100000) LIMIT 10"
        );
    }

    #[test]
    fn postgres_leaves_bounded_and_out_of_scope_statements() {
        for sql in [
            "SELECT id FROM t LIMIT 10",
            "SELECT id FROM t FETCH FIRST 3 ROWS ONLY",
            "SELECT 1",
            "SELECT $1::int",
            "VALUES (1), (2)",
            "SELECT count(*) FROM t",
            "SELECT count(*), max(a) FROM t WHERE b = 1",
            "SELECT * INTO t2 FROM t",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            "EXPLAIN SELECT * FROM t",
            "INSERT INTO t SELECT * FROM u",
        ] {
            assert_eq!(
                rw(sql, Dialect::Postgres, 100),
                (StatementLimit::Unchanged, None),
                "{sql}"
            );
        }
        // GROUP BY or a window: many rows, bounded.
        assert_eq!(
            pg_sql("SELECT a, count(*) FROM t GROUP BY a", 10),
            "SELECT a, count(*) FROM t GROUP BY a LIMIT 10"
        );
        assert_eq!(
            pg_sql("SELECT count(*) OVER () FROM t", 10),
            "SELECT count(*) OVER () FROM t LIMIT 10"
        );
    }

    #[test]
    fn postgres_with_ties_fails() {
        let (r, sql) = rw(
            "SELECT a FROM t ORDER BY a FETCH FIRST 500 ROWS WITH TIES",
            Dialect::Postgres,
            10,
        );
        assert!(
            matches!(r, StatementLimit::Failed(ref w) if w.contains("WITH TIES")),
            "{r:?}"
        );
        assert!(sql.is_none());
    }

    #[test]
    fn postgres_only_the_requested_statements() {
        let sql = "SELECT a FROM t; SELECT b FROM u";
        let parsed = crate::parser::parser_for(Dialect::Postgres)
            .parse(sql)
            .unwrap();
        let r = rewrite(&parsed, Some(sql), &[(1, 7)]);
        assert_eq!(
            r.statements,
            vec![(1, StatementLimit::Bounded { ordered: false })]
        );
        assert_eq!(
            r.sql.as_deref(),
            Some("SELECT a FROM t; SELECT b FROM u LIMIT 7")
        );
    }

    #[test]
    fn mysql_adds_or_clamps_and_keeps_placeholders() {
        assert_eq!(
            my_sql("SELECT id FROM t", 100),
            "SELECT id FROM t LIMIT 100"
        );
        assert_eq!(
            my_sql("select id from t limit 5000", 100),
            "SELECT id FROM t LIMIT 100"
        );
        assert_eq!(
            my_sql("SELECT id FROM t LIMIT 20, 5000", 100),
            "SELECT id FROM t LIMIT 20, 100"
        );
        assert_eq!(
            my_sql("SELECT id FROM t LIMIT 5000 OFFSET 20", 100),
            "SELECT id FROM t LIMIT 100 OFFSET 20"
        );
        assert_eq!(
            my_sql("SELECT id FROM t WHERE a = ? AND b = ?", 100),
            "SELECT id FROM t WHERE a = ? AND b = ? LIMIT 100"
        );
        assert_eq!(
            my_sql("SELECT id FROM t LIMIT ?, 5000", 100),
            "SELECT id FROM t LIMIT ?, 100"
        );
        assert_eq!(
            my_sql("SELECT a FROM t UNION SELECT a FROM u", 10),
            "SELECT a FROM t UNION SELECT a FROM u LIMIT 10"
        );
        assert_eq!(
            my_sql("WITH x AS (SELECT a FROM t) SELECT a FROM x ORDER BY a", 10),
            "WITH x AS (SELECT a FROM t) SELECT a FROM x ORDER BY a LIMIT 10"
        );
        for sql in ["SELECT id FROM t LIMIT ?", "SELECT id FROM t LIMIT 5, ?"] {
            assert!(
                matches!(rw(sql, Dialect::Mysql, 10).0, StatementLimit::Unknown(_)),
                "{sql}"
            );
        }
        for sql in [
            "SELECT id FROM t LIMIT 10",
            "SELECT 1",
            "SELECT count(*) FROM t",
            "SELECT id INTO @x FROM t",
        ] {
            assert_eq!(
                rw(sql, Dialect::Mysql, 100),
                (StatementLimit::Unchanged, None),
                "{sql}"
            );
        }
    }

    #[test]
    fn mysql_unfaithful_text_fails() {
        // A SELECT modifier sqlparser does not know cannot be put back.
        let (r, _) = rw("SELECT SQL_NO_CACHE id FROM t", Dialect::Mysql, 10);
        assert!(matches!(r, StatementLimit::Failed(_)), "{r:?}");
    }

    #[test]
    fn other_dialects_are_unknown() {
        let (r, _) = rw("SELECT id FROM t", Dialect::Sqlite, 10);
        assert!(
            matches!(r, StatementLimit::Unknown(ref w) if w.contains("sqlite")),
            "{r:?}"
        );
    }
}
