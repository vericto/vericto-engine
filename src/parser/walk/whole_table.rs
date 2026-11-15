// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Whole-table predicates on the sqlparser path: a `DELETE` / `UPDATE`
//! `WHERE` that reads like a filter but keeps every row of the target, proven
//! from the statement alone (VERICTO-003 / 030 / 042, since 5.1.0).
//!
//! The constant tautologies (`1=1`, `WHERE true`) and the column
//! self-comparison `id = id` are [`super::truth`]'s. This adds the forms whose
//! proof needs the statement's own target table, so they cannot live in a
//! context-free predicate:
//!
//! - `c IN (SELECT c FROM <target>)` and `c = ANY (SELECT c FROM <target>)`:
//!   every row is a member of its own table's unfiltered column. Like
//!   `id = id`, a NULL `c` is not matched; like `id = id`, the construct has no
//!   use other than neutralising the `WHERE`, so it is reported the same way.
//! - `EXISTS (SELECT … FROM <target>)`: true for every row, since a row of the
//!   target exists whenever there is one to delete.
//! - `x IS NULL OR x IS NOT NULL` (and the `IS [NOT] TRUE / FALSE / UNKNOWN`
//!   pairs) on the same column: `IS` tests are two-valued, so one of the pair
//!   holds for every row.
//! - `AND` of operands that each hold for every row, `OR` with any.
//!
//! What stays a real filter: a subquery with its own `WHERE`, `HAVING`,
//! `GROUP BY`, `LIMIT` / `TOP` / `FETCH`, a join, a set operation, a CTE, a
//! sample, a partition or time-travel clause; a different table or schema; a
//! different column; a correlated reference; `NOT IN` / `NOT EXISTS`; a
//! statement with `USING` / `FROM` sources or several targets; a DML nested in
//! a CTE (an enclosing `WITH` can shadow the table name). Identifiers compare
//! case-insensitively only when neither is quoted, and exactly on MySQL,
//! whose table names can be case-sensitive.

use std::collections::HashSet;

use sqlparser::ast::{
    BinaryOperator, Delete, Distinct, Expr, FromTable, GroupByExpr, Ident, ObjectName,
    ObjectNamePart, Query, Select, SelectFlavor, SelectItem, SetExpr, TableFactor, TableWithJoins,
    Update,
};

use super::{truth, unwrap_nested};
use crate::parser::{Dialect, Truth};

/// The one table a `DELETE` / `UPDATE` writes when it reads no other source.
pub(super) struct Target<'a> {
    name: &'a ObjectName,
    alias: Option<&'a Ident>,
}

/// `DELETE FROM t [AS a] WHERE …` with no table list, no `USING`.
pub(super) fn delete_target(d: &Delete) -> Option<Target<'_>> {
    if !d.tables.is_empty() || d.using.is_some() {
        return None;
    }
    let (FromTable::WithFromKeyword(from) | FromTable::WithoutKeyword(from)) = &d.from;
    match from.as_slice() {
        [twj] => plain_table(twj).map(|(name, alias)| Target { name, alias }),
        _ => None,
    }
}

/// `UPDATE t [AS a] SET … WHERE …` with no `FROM`.
pub(super) fn update_target(u: &Update) -> Option<Target<'_>> {
    if u.from.is_some() {
        return None;
    }
    plain_table(&u.table).map(|(name, alias)| Target { name, alias })
}

/// A plain named table with no join, no arguments, no sample, no partition
/// selection and no time travel: every row of the table, nothing else.
fn plain_table(twj: &TableWithJoins) -> Option<(&ObjectName, Option<&Ident>)> {
    if !twj.joins.is_empty() {
        return None;
    }
    // Destructured field by field: a field a sqlparser upgrade adds fails to
    // compile until it is classified as a filter or not.
    match &twj.relation {
        TableFactor::Table {
            name,
            alias,
            args,
            with_hints: _,
            version,
            with_ordinality: _,
            partitions,
            json_path,
            sample,
            index_hints: _,
        } if args.is_none()
            && version.is_none()
            && partitions.is_empty()
            && json_path.is_none()
            && sample.is_none() =>
        {
            Some((name, alias.as_ref().map(|a| &a.name)))
        }
        _ => None,
    }
}

/// Whether `expr`, the `WHERE` of a statement writing `target`, holds for
/// every row of it (see the module documentation).
pub(super) fn covers_every_row(expr: &Expr, target: &Target<'_>, dialect: Dialect) -> bool {
    let expr = unwrap_nested(expr);
    match expr {
        Expr::BinaryOp {
            op: BinaryOperator::And,
            ..
        } => {
            let mut ops = Vec::new();
            operands(expr, &BinaryOperator::And, &mut ops);
            ops.iter().all(|o| operand_covers(o, target, dialect))
        }
        Expr::BinaryOp {
            op: BinaryOperator::Or,
            ..
        } => {
            let mut ops = Vec::new();
            operands(expr, &BinaryOperator::Or, &mut ops);
            complementary_tests(&ops, dialect)
                || ops.iter().any(|o| operand_covers(o, target, dialect))
        }
        _ => membership(expr, target, dialect),
    }
}

/// One operand of an `AND` / `OR`: a constant tautology, or a whole-table form.
fn operand_covers(expr: &Expr, target: &Target<'_>, dialect: Dialect) -> bool {
    truth(expr, dialect) == Truth::True || covers_every_row(expr, target, dialect)
}

/// The operands of a chain of `op`, through parentheses.
fn operands<'a>(expr: &'a Expr, op: &BinaryOperator, out: &mut Vec<&'a Expr>) {
    match unwrap_nested(expr) {
        Expr::BinaryOp { left, op: o, right } if o == op => {
            operands(left, op, out);
            operands(right, op, out);
        }
        other => out.push(other),
    }
}

/// `c IN (SELECT c FROM target)`, `c = ANY (SELECT c FROM target)`,
/// `EXISTS (SELECT … FROM target)`.
fn membership(expr: &Expr, target: &Target<'_>, dialect: Dialect) -> bool {
    match expr {
        Expr::InSubquery {
            expr,
            subquery,
            negated: false,
        } => self_membership(expr, subquery, target, dialect),
        Expr::AnyOp {
            left,
            compare_op: BinaryOperator::Eq,
            right,
            ..
        } => match unwrap_nested(right) {
            Expr::Subquery(q) => self_membership(left, q, target, dialect),
            _ => false,
        },
        Expr::Exists {
            subquery,
            negated: false,
        } => unfiltered_scan(subquery, target, dialect).is_some_and(|(select, _)| {
            select.projection.iter().all(|item| match item {
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => true,
                SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => {
                    // A literal or a column: one output row per table row. A
                    // function could be a set-returning one with no rows.
                    matches!(
                        unwrap_nested(e),
                        Expr::Value(_) | Expr::Identifier(_) | Expr::CompoundIdentifier(_)
                    )
                }
                SelectItem::ExprWithAliases { .. } => false,
            })
        }),
        _ => false,
    }
}

/// `c IN (SELECT c FROM target)`: the left column of the target, the
/// subquery's one projected column the same column of the same table.
fn self_membership(left: &Expr, q: &Query, target: &Target<'_>, dialect: Dialect) -> bool {
    let Some(outer) = column(left, |qual| {
        names_relation(qual, target.name, target.alias, dialect)
    }) else {
        return false;
    };
    let Some((select, inner_alias)) = unfiltered_scan(q, target, dialect) else {
        return false;
    };
    let [item] = select.projection.as_slice() else {
        return false;
    };
    let inner_expr = match item {
        SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => e,
        _ => return false,
    };
    column(inner_expr, |qual| {
        names_relation(qual, target.name, inner_alias, dialect)
    })
    .is_some_and(|inner| same_ident(outer, inner, dialect))
}

/// The subquery when it reads every row of `target` and nothing else: one
/// SELECT over the same plain table, with no clause that drops rows. Returns
/// it with the inner table's alias.
fn unfiltered_scan<'q>(
    q: &'q Query,
    target: &Target<'_>,
    dialect: Dialect,
) -> Option<(&'q Select, Option<&'q Ident>)> {
    let Query {
        with,
        body,
        order_by: _,
        limit_clause,
        fetch,
        locks,
        for_clause,
        settings,
        format_clause,
        pipe_operators,
    } = q;
    // A CTE can shadow the table name; a lock clause can skip locked rows.
    if with.is_some()
        || limit_clause.is_some()
        || fetch.is_some()
        || !locks.is_empty()
        || for_clause.is_some()
        || settings.is_some()
        || format_clause.is_some()
        || !pipe_operators.is_empty()
    {
        return None;
    }
    let SetExpr::Select(select) = body.as_ref() else {
        return None;
    };
    let Select {
        select_token: _,
        optimizer_hints: _,
        distinct,
        select_modifiers: _,
        top,
        top_before_distinct: _,
        projection: _,
        exclude,
        into,
        from,
        lateral_views,
        prewhere,
        selection,
        connect_by,
        group_by,
        cluster_by,
        distribute_by,
        sort_by,
        having,
        named_window,
        qualify,
        window_before_qualify: _,
        value_table_mode,
        flavor,
    } = select.as_ref();
    let no_grouping =
        matches!(group_by, GroupByExpr::Expressions(e, m) if e.is_empty() && m.is_empty());
    if !matches!(distinct, None | Some(Distinct::All | Distinct::Distinct))
        || top.is_some()
        || exclude.is_some()
        || into.is_some()
        || !lateral_views.is_empty()
        || prewhere.is_some()
        || selection.is_some()
        || !connect_by.is_empty()
        || !no_grouping
        || !cluster_by.is_empty()
        || !distribute_by.is_empty()
        || !sort_by.is_empty()
        || having.is_some()
        || !named_window.is_empty()
        || qualify.is_some()
        || value_table_mode.is_some()
        || !matches!(flavor, SelectFlavor::Standard)
    {
        return None;
    }
    let [twj] = from.as_slice() else {
        return None;
    };
    let (name, alias) = plain_table(twj)?;
    same_object_name(name, target.name, dialect).then_some((select, alias))
}

/// The column a reference names, unqualified or qualified by `qualifier_ok`.
fn column(expr: &Expr, qualifier_ok: impl Fn(&Ident) -> bool) -> Option<&Ident> {
    match unwrap_nested(expr) {
        Expr::Identifier(c) => Some(c),
        Expr::CompoundIdentifier(parts) => match parts.as_slice() {
            [q, c] if qualifier_ok(q) => Some(c),
            _ => None,
        },
        _ => None,
    }
}

/// Whether `qualifier` names the relation `name AS alias`: the alias when it
/// has one (the table name is then hidden), otherwise the table's own name.
fn names_relation(
    qualifier: &Ident,
    name: &ObjectName,
    alias: Option<&Ident>,
    dialect: Dialect,
) -> bool {
    match alias {
        Some(a) => same_ident(qualifier, a, dialect),
        None => match name.0.last() {
            Some(ObjectNamePart::Identifier(t)) => same_ident(qualifier, t, dialect),
            _ => false,
        },
    }
}

fn same_object_name(a: &ObjectName, b: &ObjectName, dialect: Dialect) -> bool {
    a.0.len() == b.0.len()
        && a.0.iter().zip(&b.0).all(|pair| match pair {
            (ObjectNamePart::Identifier(x), ObjectNamePart::Identifier(y)) => {
                same_ident(x, y, dialect)
            }
            _ => false,
        })
}

/// Two identifiers that certainly name the same object. Unquoted: equal up to
/// ASCII case, except on MySQL, where table names can be case-sensitive (the
/// server's `lower_case_table_names`), so they must be equal exactly. Quoted:
/// equal exactly. One quoted and one not: undecided, so not the same.
fn same_ident(a: &Ident, b: &Ident, dialect: Dialect) -> bool {
    match (a.quote_style, b.quote_style) {
        (None, None) if dialect == Dialect::Mysql => a.value == b.value,
        (None, None) => a.value.eq_ignore_ascii_case(&b.value),
        (Some(_), Some(_)) => a.value == b.value,
        _ => false,
    }
}

/// `x IS NULL OR … OR x IS NOT NULL` on the same column, or one of the
/// `IS [NOT] TRUE / FALSE / UNKNOWN` pairs: `IS` tests are never NULL, so one
/// side of a pair holds for every row. Linear in the number of operands.
fn complementary_tests(ops: &[&Expr], dialect: Dialect) -> bool {
    // (test, negated, column path)
    let mut seen: HashSet<(u8, bool, String)> = HashSet::new();
    for op in ops {
        let (test, negated, arg) = match op {
            Expr::IsNull(a) => (0, false, a),
            Expr::IsNotNull(a) => (0, true, a),
            Expr::IsTrue(a) => (1, false, a),
            Expr::IsNotTrue(a) => (1, true, a),
            Expr::IsFalse(a) => (2, false, a),
            Expr::IsNotFalse(a) => (2, true, a),
            Expr::IsUnknown(a) => (3, false, a),
            Expr::IsNotUnknown(a) => (3, true, a),
            _ => continue,
        };
        let Some(path) = column_key(arg, dialect) else {
            continue;
        };
        if seen.contains(&(test, !negated, path.clone())) {
            return true;
        }
        seen.insert((test, negated, path));
    }
    false
}

/// A column reference as a comparison key: unquoted parts folded to lower
/// case (exact on MySQL), quoted parts kept exactly and marked as quoted.
fn column_key(expr: &Expr, dialect: Dialect) -> Option<String> {
    let parts: &[Ident] = match unwrap_nested(expr) {
        Expr::Identifier(id) => std::slice::from_ref(id),
        Expr::CompoundIdentifier(ids) => ids,
        _ => return None,
    };
    let mut key = String::new();
    for p in parts {
        key.push('\u{1}');
        match p.quote_style {
            Some(_) => {
                key.push('"');
                key.push_str(&p.value);
            }
            None if dialect == Dialect::Mysql => key.push_str(&p.value),
            None => key.push_str(&p.value.to_ascii_lowercase()),
        }
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use crate::parser::{Dialect, WherePresence, parser_for};

    fn presence(sql: &str, d: Dialect) -> WherePresence {
        let p = parser_for(d).parse(sql).expect(sql);
        p.statements[0].where_presence
    }

    const DIALECTS: [Dialect; 5] = [
        Dialect::Mysql,
        Dialect::MsSql,
        Dialect::Oracle,
        Dialect::Snowflake,
        Dialect::Sqlite,
    ];

    #[test]
    fn whole_table_forms_are_always_true() {
        for sql in [
            "DELETE FROM users WHERE id IN (SELECT id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT DISTINCT id FROM users)",
            "DELETE FROM users WHERE users.id IN (SELECT users.id FROM users)",
            "DELETE FROM users u WHERE u.id IN (SELECT x.id FROM users x)",
            "DELETE FROM users WHERE (id IN (SELECT id FROM users))",
            "DELETE FROM app.users WHERE id IN (SELECT id FROM app.users)",
            "DELETE FROM users WHERE ID IN (SELECT id FROM users)",
            "DELETE FROM users WHERE EXISTS (SELECT 1 FROM users)",
            "DELETE FROM users WHERE EXISTS (SELECT * FROM users)",
            "DELETE FROM users WHERE email IS NOT NULL OR email IS NULL",
            "DELETE FROM users WHERE email IS NULL OR status = 'x' OR email IS NOT NULL",
            "DELETE FROM users WHERE (a IS NULL OR (b = 1 OR a IS NOT NULL))",
            "DELETE FROM users WHERE flag IS TRUE OR flag IS NOT TRUE",
            "DELETE FROM users WHERE 1 = 1 AND id IN (SELECT id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users) OR id = 7",
            "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM users)",
            "UPDATE users SET a = 1 WHERE a IS NULL OR a IS NOT NULL",
        ] {
            for d in DIALECTS {
                // MySQL: `ID` and `id` are the same column but compared exactly.
                if d == Dialect::Mysql && sql.contains(" ID ") {
                    continue;
                }
                assert_eq!(presence(sql, d), WherePresence::AlwaysTrue, "{d:?}: {sql}");
            }
        }
    }

    #[test]
    fn real_filters_stay_present() {
        for sql in [
            "DELETE FROM users WHERE id IN (SELECT id FROM users WHERE banned = 1)",
            "DELETE FROM users WHERE id IN (SELECT user_id FROM orders)",
            "DELETE FROM users WHERE id IN (SELECT id FROM orders)",
            "DELETE FROM users WHERE id IN (SELECT manager_id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM archive.users)",
            "DELETE FROM users WHERE id NOT IN (SELECT id FROM users)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users GROUP BY id HAVING COUNT(*) > 1)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users GROUP BY id)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users UNION SELECT 1)",
            "DELETE FROM users WHERE id IN (SELECT u.id FROM users u JOIN bans b ON b.id = u.id)",
            "DELETE FROM users WHERE id IN (SELECT MAX(id) FROM users)",
            "DELETE FROM users u WHERE id IN (SELECT u.id FROM users)",
            "DELETE FROM users u WHERE id IN (SELECT id FROM users x WHERE x.id = u.id)",
            "DELETE FROM users WHERE id IN (SELECT id FROM users) AND status = 'x'",
            "DELETE FROM users WHERE NOT EXISTS (SELECT 1 FROM users)",
            "DELETE FROM users WHERE EXISTS (SELECT 1 FROM orders)",
            "DELETE FROM users WHERE EXISTS (SELECT 1 FROM users x WHERE x.id = 1)",
            "DELETE FROM users WHERE a IS NULL OR b IS NOT NULL",
            "DELETE FROM users WHERE a IS NULL OR a IS NULL",
            "DELETE FROM users WHERE (a IS NULL OR a IS NOT NULL) AND b = 1",
            "DELETE FROM users WHERE a IS NULL AND a IS NOT NULL",
            "DELETE FROM users WHERE flag IS TRUE OR flag IS FALSE",
            "UPDATE users SET a = 1 WHERE id IN (SELECT id FROM users WHERE a = 0)",
        ] {
            for d in DIALECTS {
                assert_eq!(presence(sql, d), WherePresence::Present, "{d:?}: {sql}");
            }
        }
        // Quoted against unquoted: undecided, so a real filter.
        assert_eq!(
            presence(
                "DELETE FROM users WHERE id IN (SELECT id FROM \"Users\")",
                Dialect::Snowflake
            ),
            WherePresence::Present
        );
        // MySQL table names can be case-sensitive.
        assert_eq!(
            presence(
                "DELETE FROM users WHERE id IN (SELECT id FROM USERS)",
                Dialect::Mysql
            ),
            WherePresence::Present
        );
        // A second source: the rows written depend on it.
        assert_eq!(
            presence(
                "DELETE FROM users USING users, bans WHERE users.id IN (SELECT id FROM users)",
                Dialect::Mysql
            ),
            WherePresence::Present
        );
        assert_eq!(
            presence(
                "UPDATE users SET a = 1 FROM bans WHERE users.id IN (SELECT id FROM users)",
                Dialect::Snowflake
            ),
            WherePresence::Present
        );
        // LIMIT / TOP in the subquery bound it.
        assert_eq!(
            presence(
                "DELETE FROM users WHERE id IN (SELECT id FROM users LIMIT 10)",
                Dialect::Sqlite
            ),
            WherePresence::Present
        );
        assert_eq!(
            presence(
                "DELETE FROM users WHERE id IN (SELECT TOP 10 id FROM users)",
                Dialect::MsSql
            ),
            WherePresence::Present
        );
        // MySQL partition selection reads part of the table.
        assert_eq!(
            presence(
                "DELETE FROM users WHERE id IN (SELECT id FROM users PARTITION (p0))",
                Dialect::Mysql
            ),
            WherePresence::Present
        );
    }

    /// A DML nested in a CTE is not decided: an enclosing `WITH` can shadow the
    /// table name the subquery reads.
    #[test]
    fn nested_dml_is_not_decided() {
        let p = parser_for(Dialect::Sqlite)
            .parse(
                "WITH users AS (SELECT 1 AS id) \
                 DELETE FROM users WHERE id IN (SELECT id FROM users)",
            )
            .unwrap();
        assert!(
            p.statements
                .iter()
                .all(|s| s.where_presence != WherePresence::AlwaysTrue),
            "{:?}",
            p.statements
        );
    }
}
