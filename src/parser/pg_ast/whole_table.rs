// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Whole-table predicates on the PostgreSQL path: the libpg_query counterpart
//! of `parser::walk::whole_table` (see it for the forms and what stays a real
//! filter). A `DELETE` / `UPDATE` whose `WHERE` keeps every row of its own
//! target is read as always-true (VERICTO-003 / 030 / 042, since 5.1.0).
//!
//! libpg_query has already folded unquoted identifiers to lower case and kept
//! quoted ones as written, so names compare exactly. `ONLY` (`inh = false`)
//! must match on both sides: `FROM ONLY t` leaves out the child tables that
//! `DELETE FROM t` reaches.

use std::collections::HashSet;

use pg_query::NodeEnum;
use pg_query::protobuf::{
    BoolExprType, BoolTestType, Node, NullTestType, RangeVar, SelectStmt, SetOperation, SubLinkType,
};

use super::{column_ref_path, truth};
use crate::parser::Truth;

/// Whether `node`, the `WHERE` of a statement writing `target` (with no
/// `USING` / `FROM` / `WITH`), holds for every row of it.
pub(super) fn covers_every_row(node: &NodeEnum, target: &RangeVar) -> bool {
    match node {
        NodeEnum::BoolExpr(b) => match BoolExprType::try_from(b.boolop) {
            Ok(BoolExprType::AndExpr) => {
                let mut ops = Vec::new();
                operands(node, BoolExprType::AndExpr, &mut ops);
                ops.iter().all(|o| operand_covers(o, target))
            }
            Ok(BoolExprType::OrExpr) => {
                let mut ops = Vec::new();
                operands(node, BoolExprType::OrExpr, &mut ops);
                complementary_tests(&ops) || ops.iter().any(|o| operand_covers(o, target))
            }
            _ => false,
        },
        NodeEnum::SubLink(link) => membership(link, target),
        _ => false,
    }
}

fn operand_covers(node: &NodeEnum, target: &RangeVar) -> bool {
    truth(node) == Truth::True || covers_every_row(node, target)
}

/// The operands of a chain of `op` (libpg_query keeps `a OR (b OR c)` nested).
fn operands<'a>(node: &'a NodeEnum, op: BoolExprType, out: &mut Vec<&'a NodeEnum>) {
    match node {
        NodeEnum::BoolExpr(b) if BoolExprType::try_from(b.boolop) == Ok(op) => {
            for arg in b.args.iter().filter_map(|n| n.node.as_ref()) {
                operands(arg, op, out);
            }
        }
        other => out.push(other),
    }
}

/// `c IN (SELECT c FROM target)`, `c = ANY (SELECT c FROM target)`,
/// `EXISTS (SELECT … FROM target)`.
fn membership(link: &pg_query::protobuf::SubLink, target: &RangeVar) -> bool {
    let Some(NodeEnum::SelectStmt(select)) =
        link.subselect.as_deref().and_then(|n| n.node.as_ref())
    else {
        return false;
    };
    let Some(inner) = unfiltered_scan(select, target) else {
        return false;
    };
    match SubLinkType::try_from(link.sub_link_type) {
        Ok(SubLinkType::ExistsSublink) => select.target_list.iter().all(|t| {
            matches!(
                res_target_value(t),
                Some(NodeEnum::AConst(_) | NodeEnum::ColumnRef(_))
            )
        }),
        Ok(SubLinkType::AnySublink) => {
            // `IN` carries no operator name, `= ANY` carries `=`.
            let eq = match link.oper_name.as_slice() {
                [] => true,
                [n] => matches!(n.node.as_ref(), Some(NodeEnum::String(s)) if s.sval == "="),
                _ => false,
            };
            let [item] = select.target_list.as_slice() else {
                return false;
            };
            let outer = link.testexpr.as_deref().and_then(|n| column_of(n, target));
            let inner = res_target_value(item).and_then(|v| match v {
                NodeEnum::ColumnRef(c) => column_name(c, inner),
                _ => None,
            });
            eq && outer.is_some() && outer == inner
        }
        _ => false,
    }
}

/// The value of a `ResTarget` projection item.
fn res_target_value(node: &Node) -> Option<&NodeEnum> {
    match node.node.as_ref()? {
        NodeEnum::ResTarget(t) => t.val.as_deref()?.node.as_ref(),
        _ => None,
    }
}

/// The subquery's one table when it reads every row of `target` and nothing
/// else (no `WHERE`, grouping, window, `LIMIT` / `OFFSET`, lock, set
/// operation, CTE, `INTO`, `DISTINCT ON`, `VALUES`, join).
fn unfiltered_scan<'s>(select: &'s SelectStmt, target: &RangeVar) -> Option<&'s RangeVar> {
    let SelectStmt {
        distinct_clause,
        into_clause,
        target_list: _,
        from_clause,
        where_clause,
        group_clause,
        group_distinct: _,
        having_clause,
        window_clause,
        values_lists,
        sort_clause: _,
        limit_offset,
        limit_count,
        limit_option: _,
        locking_clause,
        with_clause,
        op,
        all: _,
        larg,
        rarg,
    } = select;
    // Plain `DISTINCT` is one empty node; `DISTINCT ON (…)` lists expressions.
    let plain_distinct = match distinct_clause.as_slice() {
        [] => true,
        [only] => only.node.is_none(),
        _ => false,
    };
    if !plain_distinct
        || into_clause.is_some()
        || where_clause.is_some()
        || !group_clause.is_empty()
        || having_clause.is_some()
        || !window_clause.is_empty()
        || !values_lists.is_empty()
        || limit_offset.is_some()
        || limit_count.is_some()
        || !locking_clause.is_empty()
        || with_clause.is_some()
        || SetOperation::try_from(*op) != Ok(SetOperation::SetopNone)
        || larg.is_some()
        || rarg.is_some()
    {
        return None;
    }
    let [from] = from_clause.as_slice() else {
        return None;
    };
    // A sample is a `RangeTableSample`, a join a `JoinExpr`: not a `RangeVar`.
    let Some(NodeEnum::RangeVar(inner)) = from.node.as_ref() else {
        return None;
    };
    (inner.catalogname == target.catalogname
        && inner.schemaname == target.schemaname
        && inner.relname == target.relname
        && inner.inh == target.inh)
        .then_some(inner)
}

/// The visible name of a relation: its alias, else its table name.
fn visible_name(rel: &RangeVar) -> &str {
    rel.alias
        .as_ref()
        .map_or(rel.relname.as_str(), |a| a.aliasname.as_str())
}

/// The column a `ColumnRef` names in `rel`: `c`, or `q.c` with `q` its
/// visible name.
fn column_name(col: &pg_query::protobuf::ColumnRef, rel: &RangeVar) -> Option<String> {
    let path = column_ref_path(col);
    let parts: Vec<&str> = path.split('.').collect();
    match parts.as_slice() {
        [c] if !c.is_empty() && col.fields.len() == 1 => Some((*c).to_string()),
        [q, c] if col.fields.len() == 2 && *q == visible_name(rel) => Some((*c).to_string()),
        _ => None,
    }
}

fn column_of(node: &Node, rel: &RangeVar) -> Option<String> {
    match node.node.as_ref()? {
        NodeEnum::ColumnRef(c) => column_name(c, rel),
        _ => None,
    }
}

/// `x IS NULL OR … OR x IS NOT NULL` on the same column, or an
/// `IS [NOT] TRUE / FALSE / UNKNOWN` pair. Linear in the number of operands.
fn complementary_tests(ops: &[&NodeEnum]) -> bool {
    let mut seen: HashSet<(u8, bool, String)> = HashSet::new();
    for op in ops {
        let (test, negated, arg) = match op {
            NodeEnum::NullTest(t) if !t.argisrow => match NullTestType::try_from(t.nulltesttype) {
                Ok(NullTestType::IsNull) => (0, false, t.arg.as_deref()),
                Ok(NullTestType::IsNotNull) => (0, true, t.arg.as_deref()),
                _ => continue,
            },
            NodeEnum::BooleanTest(t) => match BoolTestType::try_from(t.booltesttype) {
                Ok(BoolTestType::IsTrue) => (1, false, t.arg.as_deref()),
                Ok(BoolTestType::IsNotTrue) => (1, true, t.arg.as_deref()),
                Ok(BoolTestType::IsFalse) => (2, false, t.arg.as_deref()),
                Ok(BoolTestType::IsNotFalse) => (2, true, t.arg.as_deref()),
                Ok(BoolTestType::IsUnknown) => (3, false, t.arg.as_deref()),
                Ok(BoolTestType::IsNotUnknown) => (3, true, t.arg.as_deref()),
                _ => continue,
            },
            _ => continue,
        };
        let Some(NodeEnum::ColumnRef(col)) = arg.and_then(|a| a.node.as_ref()) else {
            continue;
        };
        let path = column_ref_path(col);
        if path.is_empty() || path.split('.').count() != col.fields.len() {
            continue; // `t.*` or anything that is not a plain column path
        }
        if seen.contains(&(test, !negated, path.clone())) {
            return true;
        }
        seen.insert((test, negated, path));
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::parser::{Dialect, WherePresence, parser_for};

    fn presence(sql: &str) -> WherePresence {
        let p = parser_for(Dialect::Postgres).parse(sql).expect(sql);
        p.statements[0].where_presence
    }

    #[test]
    fn whole_table_forms_are_always_true() {
        for sql in [
            "DELETE FROM users WHERE id IN (SELECT id FROM users)",
            "DELETE FROM users WHERE id = ANY (SELECT id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT DISTINCT id FROM users)",
            "DELETE FROM users WHERE users.id IN (SELECT users.id FROM users)",
            "DELETE FROM users u WHERE u.id IN (SELECT x.id FROM users x)",
            "DELETE FROM users WHERE ID IN (SELECT id FROM USERS)",
            "DELETE FROM app.users WHERE id IN (SELECT id FROM app.users)",
            "DELETE FROM ONLY users WHERE id IN (SELECT id FROM ONLY users)",
            "DELETE FROM users WHERE EXISTS (SELECT 1 FROM users)",
            "DELETE FROM users WHERE EXISTS (SELECT * FROM users)",
            "DELETE FROM users WHERE email IS NOT NULL OR email IS NULL",
            "DELETE FROM users WHERE email IS NULL OR status = 'x' OR email IS NOT NULL",
            "DELETE FROM users WHERE (a IS NULL OR (b = 1 OR a IS NOT NULL))",
            "DELETE FROM users WHERE flag IS TRUE OR flag IS NOT TRUE",
            "DELETE FROM users WHERE flag IS UNKNOWN OR flag IS NOT UNKNOWN",
            "DELETE FROM users WHERE 1 = 1 AND id IN (SELECT id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users) OR id = 7",
            "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM users)",
            "UPDATE users SET a = 1 WHERE a IS NULL OR a IS NOT NULL",
        ] {
            assert_eq!(presence(sql), WherePresence::AlwaysTrue, "{sql}");
        }
    }

    #[test]
    fn real_filters_stay_present() {
        for sql in [
            "DELETE FROM users WHERE id IN (SELECT id FROM users WHERE banned)",
            "DELETE FROM users WHERE id IN (SELECT user_id FROM orders)",
            "DELETE FROM users WHERE id IN (SELECT id FROM orders)",
            "DELETE FROM users WHERE id IN (SELECT manager_id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM archive.users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM \"Users\")",
            "DELETE FROM users WHERE id IN (SELECT id FROM ONLY users)",
            "DELETE FROM users WHERE id NOT IN (SELECT id FROM users)",
            "DELETE FROM users WHERE id <> ALL (SELECT id FROM users)",
            "DELETE FROM users WHERE id > ANY (SELECT id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users GROUP BY id HAVING count(*) > 1)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users GROUP BY id)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users UNION SELECT 1)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users LIMIT 10)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users OFFSET 1)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users FOR UPDATE SKIP LOCKED)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users TABLESAMPLE SYSTEM (10))",
            "DELETE FROM users WHERE id IN (SELECT DISTINCT ON (email) id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT u.id FROM users u JOIN bans b ON b.id = u.id)",
            "DELETE FROM users WHERE id IN (SELECT max(id) FROM users)",
            "DELETE FROM users WHERE id IN (WITH x AS (SELECT 1) SELECT id FROM users)",
            "DELETE FROM users u WHERE id IN (SELECT u.id FROM users)",
            "DELETE FROM users u WHERE id IN (SELECT id FROM users x WHERE x.id = u.id)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users) AND status = 'x'",
            "DELETE FROM users WHERE NOT EXISTS (SELECT 1 FROM users)",
            "DELETE FROM users WHERE EXISTS (SELECT 1 FROM orders)",
            "DELETE FROM users WHERE EXISTS (SELECT generate_series(1, 0) FROM users)",
            "DELETE FROM users WHERE EXISTS (SELECT 1 FROM users x WHERE x.id = 1)",
            "DELETE FROM users WHERE a IS NULL OR b IS NOT NULL",
            "DELETE FROM users WHERE a IS NULL OR a IS NULL",
            "DELETE FROM users WHERE (a IS NULL OR a IS NOT NULL) AND b = 1",
            "DELETE FROM users WHERE a IS NULL AND a IS NOT NULL",
            "DELETE FROM users WHERE flag IS TRUE OR flag IS FALSE",
            "DELETE FROM users WHERE \"A\" IS NULL OR a IS NOT NULL",
            "DELETE FROM users USING bans WHERE users.id IN (SELECT id FROM users)",
            "UPDATE users SET a = 1 FROM bans WHERE users.id IN (SELECT id FROM users)",
            "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM users WHERE a = 0)",
        ] {
            assert_eq!(presence(sql), WherePresence::Present, "{sql}");
        }
    }

    /// Inside a CTE, or under the statement's own `WITH`, a CTE can shadow
    /// the table name: not decided.
    #[test]
    fn dml_with_a_with_clause_is_not_decided() {
        for sql in [
            "WITH users AS (SELECT 1 AS id) DELETE FROM users WHERE id IN (SELECT id FROM users)",
            "WITH d AS (DELETE FROM users WHERE id IN (SELECT id FROM users) RETURNING id) \
             SELECT count(*) FROM d",
        ] {
            let p = parser_for(Dialect::Postgres).parse(sql).unwrap();
            assert!(
                p.statements
                    .iter()
                    .all(|s| s.where_presence != WherePresence::AlwaysTrue),
                "{sql}: {:?}",
                p.statements
            );
        }
    }
}
