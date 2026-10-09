//! Access analysis over the `sqlparser` AST (MySQL, Oracle, SQL Server): which
//! statements are analysed, allowed or denied outright. The analysis itself
//! is the VERICTO-085 walker run in access mode
//! ([`crate::sensitive::sql::access_walk`]).

use sqlparser::ast::{
    Expr, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr, Ident, ObjectName, Query,
    Select, SelectItem, SetExpr, Statement, Value,
};

use crate::access::session::{self, ModePiece, Setting};

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::parser::Dialect;
use crate::sensitive::Tags;
use crate::sensitive::sql::access_walk;

enum Class {
    /// Reads or writes tables: walked.
    Walk,
    /// Touches no table and cannot widen access.
    Allowed,
    /// DDL, or a statement that changes the identity or how names resolve.
    Denied(String),
}

/// Records every reference the statements make in `tags`.
pub(crate) fn collect(statements: &[Statement], tags: &Tags, dialect: Dialect) -> Result<()> {
    for s in statements {
        match classify(s, tags, 0, dialect)? {
            Class::Walk => {
                // The walker takes the tree mutably (it is the mask rewriter
                // too); the analysis never changes it, but works on a copy.
                let mut s = s.clone();
                access_walk(&mut s, tags, dialect)?;
            }
            Class::Allowed => {}
            Class::Denied(what) => tags.statement(&what),
        }
    }
    Ok(())
}

fn split(name: &ObjectName) -> (Option<String>, String) {
    let parts = &name.0;
    let table = parts.last().map(|i| i.value.clone()).unwrap_or_default();
    let schema = (parts.len() >= 2).then(|| parts[parts.len() - 2].value.clone());
    (schema, table)
}

/// Why `SET name = values` is denied under an allowlist, or `None` when it
/// is allowed: a session setting on the closed list with a literal value
/// (`sql_mode` and `standard_conforming_strings` with their value rules), or
/// a user variable (`@v`) set to a literal. Everything else is denied by
/// default.
fn set_denial(name: &ObjectName, values: &[&Expr]) -> Option<String> {
    let last = name
        .0
        .last()
        .map(|i| i.value.trim_start_matches('@').to_ascii_lowercase())
        .unwrap_or_default();
    match last.as_str() {
        "search_path" => return Some("SET search_path".into()),
        "role" => return Some("SET ROLE".into()),
        "session_authorization" => return Some("SET SESSION AUTHORIZATION".into()),
        _ => {}
    }
    let joined = name
        .0
        .iter()
        .map(|i| i.value.as_str())
        .collect::<Vec<_>>()
        .join(".");
    let computed = || Some("SET (computed value)".to_string());
    let Some(setting_name) = session::session_name(&joined) else {
        // `@v` (a user variable): harmless with a literal. `@@GLOBAL.x`,
        // `@@PERSIST.x`: server-wide. (`SET GLOBAL x` / `SET PERSIST x` do
        // not parse: a parse error, which blocks.)
        if joined.starts_with('@') && !joined.starts_with("@@") {
            return if values.iter().all(|v| literal_value(v)) {
                None
            } else {
                computed()
            };
        }
        return Some("SET GLOBAL".into());
    };
    match session::setting(setting_name) {
        Setting::Listed => {
            if values.iter().all(|v| literal_value(v)) {
                None
            } else {
                computed()
            }
        }
        Setting::StandardConformingStrings => match values {
            [Expr::Value(Value::SingleQuotedString(v))]
            | [Expr::Identifier(Ident { value: v, .. })]
                if session::scs_on(v) =>
            {
                None
            }
            [Expr::Value(Value::Boolean(true))] => None,
            [Expr::Value(Value::Number(n, _))] if n == "1" => None,
            _ => Some("SET standard_conforming_strings".into()),
        },
        Setting::SqlMode => match values {
            [v] if sql_mode_pieces(v).is_some_and(|p| session::sql_mode_ok(&p)) => None,
            _ => Some("SET sql_mode".into()),
        },
        Setting::Unlisted => Some(format!("SET {}", setting_name.to_ascii_lowercase())),
    }
}

/// A `sql_mode` value built only from string literals, the current mode
/// (`@@sql_mode`, `@@SESSION.sql_mode`) and `CONCAT(…)`, possibly nested.
fn sql_mode_pieces(e: &Expr) -> Option<Vec<ModePiece>> {
    let is_current = |parts: &[&str]| match parts {
        [one] => one.eq_ignore_ascii_case("@@sql_mode"),
        [scope, m] => {
            (scope.eq_ignore_ascii_case("@@SESSION") || scope.eq_ignore_ascii_case("@@LOCAL"))
                && m.eq_ignore_ascii_case("sql_mode")
        }
        _ => false,
    };
    match e {
        Expr::Value(Value::SingleQuotedString(s) | Value::DoubleQuotedString(s)) => {
            Some(vec![ModePiece::Literal(s.clone())])
        }
        Expr::Identifier(i)
            if i.quote_style.is_none() && i.value.eq_ignore_ascii_case("DEFAULT") =>
        {
            Some(vec![ModePiece::Literal(String::new())])
        }
        Expr::Identifier(i) if i.quote_style.is_none() && is_current(&[i.value.as_str()]) => {
            Some(vec![ModePiece::Current])
        }
        Expr::CompoundIdentifier(ids)
            if ids.iter().all(|i| i.quote_style.is_none())
                && is_current(&ids.iter().map(|i| i.value.as_str()).collect::<Vec<_>>()) =>
        {
            Some(vec![ModePiece::Current])
        }
        Expr::Nested(x) => sql_mode_pieces(x),
        Expr::Function(f)
            if f.name.0.len() == 1
                && f.name.0[0].value.eq_ignore_ascii_case("concat")
                && f.filter.is_none()
                && f.over.is_none()
                && f.within_group.is_empty()
                && matches!(f.parameters, FunctionArguments::None) =>
        {
            let FunctionArguments::List(list) = &f.args else {
                return None;
            };
            if list.duplicate_treatment.is_some() || !list.clauses.is_empty() {
                return None;
            }
            let mut out = Vec::new();
            for a in &list.args {
                match a {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(x)) => {
                        out.extend(sql_mode_pieces(x)?)
                    }
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn literal_value(e: &Expr) -> bool {
    use sqlparser::ast::UnaryOperator;
    match e {
        Expr::Value(_) | Expr::Identifier(_) => true,
        Expr::UnaryOp {
            op: UnaryOperator::Minus | UnaryOperator::Plus,
            expr,
        } => matches!(expr.as_ref(), Expr::Value(_)),
        _ => false,
    }
}

/// A MySQL `SHOW` that reads the catalogue: recorded as a read of the
/// `information_schema` table it is a view of, so only an entry naming that
/// schema allows it.
fn catalogue(tags: &Tags, table: &str) -> Result<Class> {
    tags.relation(Some("information_schema"), table);
    Ok(Class::Allowed)
}

/// `CALL f(…)` / `EXECUTE p(…)`: the arguments analysed as `SELECT <args>`.
fn arguments(tags: &Tags, dialect: Dialect, args: &[Expr]) -> Result<Class> {
    if args.is_empty() {
        return Ok(Class::Allowed);
    }
    let projection = args.iter().cloned().map(SelectItem::UnnamedExpr).collect();
    let select = Select {
        distinct: None,
        top: None,
        top_before_distinct: false,
        projection,
        into: None,
        from: Vec::new(),
        lateral_views: Vec::new(),
        prewhere: None,
        selection: None,
        group_by: GroupByExpr::Expressions(Vec::new(), Vec::new()),
        cluster_by: Vec::new(),
        distribute_by: Vec::new(),
        sort_by: Vec::new(),
        having: None,
        named_window: Vec::new(),
        qualify: None,
        window_before_qualify: false,
        value_table_mode: None,
        connect_by: None,
    };
    let mut stmt = Statement::Query(Box::new(Query {
        with: None,
        body: Box::new(SetExpr::Select(Box::new(select))),
        order_by: None,
        limit: None,
        limit_by: Vec::new(),
        offset: None,
        fetch: None,
        locks: Vec::new(),
        for_clause: None,
        settings: None,
        format_clause: None,
    }));
    access_walk(&mut stmt, tags, dialect)?;
    Ok(Class::Allowed)
}

fn classify(s: &Statement, tags: &Tags, depth: usize, dialect: Dialect) -> Result<Class> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    let denied = |w: &str| Ok(Class::Denied(w.to_string()));
    match s {
        Statement::Query(_)
        | Statement::Insert(_)
        | Statement::Update { .. }
        | Statement::Delete(_)
        | Statement::Merge { .. }
        | Statement::Copy { .. }
        | Statement::Declare { .. } => Ok(Class::Walk),
        // The statement inside is what runs (EXPLAIN ANALYZE executes it).
        Statement::Explain { statement, .. } | Statement::Prepare { statement, .. } => {
            match classify(statement, tags, depth + 1, dialect)? {
                Class::Allowed => Ok(Class::Allowed),
                other => Ok(other),
            }
        }
        // `DESCRIBE t`: the table's structure, i.e. every column.
        Statement::ExplainTable { table_name, .. } => {
            let (schema, table) = split(table_name);
            tags.relation(schema.as_deref(), &table);
            tags.of_table(schema.as_deref(), &table);
            Ok(Class::Allowed)
        }
        // A table lock can stall every other writer: it needs write.
        Statement::LockTables { tables } => {
            for t in tables {
                tags.write(None, &t.table.value, None);
            }
            Ok(Class::Allowed)
        }
        Statement::SetVariable {
            variables, value, ..
        } => {
            // sqlparser reads `SET a = 1, b = 2` as one variable whose values
            // are `1` and the expression `b = 2`: each later `name = value`
            // starts the next assignment. Every assignment must be allowed.
            if variables.iter().count() != 1 {
                return denied("SET (…)");
            }
            let mut assignments: Vec<(ObjectName, Vec<&Expr>)> = vec![(
                variables
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or(ObjectName(Vec::new())),
                Vec::new(),
            )];
            for e in value {
                match e {
                    Expr::BinaryOp {
                        left,
                        op: sqlparser::ast::BinaryOperator::Eq,
                        right,
                    } if matches!(
                        left.as_ref(),
                        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
                    ) =>
                    {
                        let name = match left.as_ref() {
                            Expr::Identifier(i) => ObjectName(vec![i.clone()]),
                            Expr::CompoundIdentifier(ids) => ObjectName(ids.clone()),
                            _ => unreachable!("matched above"),
                        };
                        assignments.push((name, vec![right]));
                    }
                    other => {
                        if let Some(last) = assignments.last_mut() {
                            last.1.push(other);
                        }
                    }
                }
            }
            for (name, values) in &assignments {
                if let Some(what) = set_denial(name, values) {
                    return Ok(Class::Denied(what));
                }
            }
            Ok(Class::Allowed)
        }
        Statement::SetRole { .. } => denied("SET ROLE"),
        Statement::Use(_) => denied("USE"),
        Statement::ShowTables { .. } => catalogue(tags, "TABLES"),
        Statement::ShowViews { .. } => catalogue(tags, "VIEWS"),
        Statement::ShowColumns { .. } => catalogue(tags, "COLUMNS"),
        Statement::ShowDatabases { .. } | Statement::ShowSchemas { .. } => {
            catalogue(tags, "SCHEMATA")
        }
        Statement::ShowCreate { .. } => catalogue(tags, "TABLES"),
        Statement::ShowFunctions { .. } => catalogue(tags, "ROUTINES"),
        // `SHOW <anything>` the parser does not model (MySQL `SHOW GRANTS`,
        // `SHOW PROCESSLIST`, `SHOW TABLE STATUS`, …): denied, except the
        // few that only describe the session or the server's settings.
        Statement::ShowVariable { variable } => {
            let words: Vec<String> = variable
                .iter()
                .map(|i| i.value.to_ascii_uppercase())
                .collect();
            let first = words.first().map(String::as_str).unwrap_or("");
            if matches!(
                first,
                "WARNINGS" | "ERRORS" | "COUNT" | "ENGINES" | "CHARSET" | "CHARACTER" | "SESSION"
            ) && !words.iter().any(|w| w == "GRANTS" || w == "PROCESSLIST")
            {
                Ok(Class::Allowed)
            } else {
                Ok(Class::Denied(format!("SHOW {}", words.join(" "))))
            }
        }
        Statement::ShowVariables { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowCollation { .. }
        | Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. }
        | Statement::SetNames { .. }
        | Statement::SetNamesDefault { .. }
        | Statement::SetTimeZone { .. }
        | Statement::SetTransaction { .. }
        | Statement::Deallocate { .. }
        | Statement::Fetch { .. }
        | Statement::Close { .. }
        | Statement::Discard { .. }
        | Statement::LISTEN { .. }
        | Statement::NOTIFY { .. }
        | Statement::UnlockTables => Ok(Class::Allowed),
        // Allowed, but the arguments are values the statement reads.
        Statement::Call(f) => arguments(tags, dialect, &[Expr::Function(f.clone())]),
        Statement::Execute {
            parameters, using, ..
        } => {
            let all: Vec<Expr> = parameters.iter().chain(using).cloned().collect();
            arguments(tags, dialect, &all)
        }
        Statement::CreateTable(ct) if ct.query.is_some() => denied("CREATE TABLE AS"),
        Statement::CreateTable(_) => denied("CREATE TABLE"),
        Statement::CreateView { .. } => denied("CREATE VIEW"),
        Statement::Drop { .. } => denied("DROP"),
        Statement::AlterTable { .. } => denied("ALTER TABLE"),
        Statement::Truncate { .. } => denied("TRUNCATE"),
        Statement::CreateIndex(_) => denied("CREATE INDEX"),
        Statement::Grant { .. } => denied("GRANT"),
        Statement::Revoke { .. } => denied("REVOKE"),
        Statement::CreateFunction { .. } => denied("CREATE FUNCTION"),
        Statement::CreateProcedure { .. } => denied("CREATE PROCEDURE"),
        Statement::Comment { .. } => denied("COMMENT"),
        other => Ok(Class::Denied(statement_name(other))),
    }
}

/// `CreateSchema` → `CREATE SCHEMA`, for statements without a dedicated name
/// above. Deny by default: any kind not known to be harmless is DDL.
fn statement_name(s: &Statement) -> String {
    let debug = format!("{s:?}");
    let variant = debug.split(['(', ' ', '{']).next().unwrap_or("STATEMENT");
    let mut out = String::new();
    let mut prev_upper = true;
    for c in variant.chars() {
        if c.is_ascii_uppercase() && !prev_upper && !out.is_empty() {
            out.push(' ');
        }
        prev_upper = c.is_ascii_uppercase();
        out.push(c.to_ascii_uppercase());
    }
    out
}
