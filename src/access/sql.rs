// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Access analysis over the `sqlparser` AST (MySQL, Oracle, SQL Server,
//! Snowflake, SQLite): which statements are analysed, allowed or denied
//! outright. The analysis itself is the VERICTO-085 walker run in access mode
//! ([`crate::sensitive::sql::access_walk`]).

use sqlparser::ast::{
    ContextModifier, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, Ident, ObjectName,
    Query, Select, SelectItem, Set, SetExpr, Statement, Value, ValueWithSpan,
};

use crate::access::session::{self, ModePiece, Setting};

use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::parser::Dialect;
use crate::sensitive::sql::access_walk;
use crate::sensitive::{Tags, name_part, name_parts};

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

/// Snowflake's text with its identifiers folded the way Snowflake stores
/// them, parsed again: unquoted names to upper case, and quoted ones too when
/// `fold_quoted` (`QUOTED_IDENTIFIERS_IGNORE_CASE = TRUE`). The fold is done
/// on the text, in place (ASCII upper-casing keeps every byte offset), over
/// the tokens Snowflake's tokenizer reads as words, so string literals,
/// comments and `$$` bodies are untouched. Keywords fold too, which changes
/// nothing. `None` when the text does not tokenize or the folded text does
/// not parse to as many statements: the caller denies.
pub(crate) fn fold_snowflake(sql: &str, fold_quoted: bool) -> Option<Vec<Statement>> {
    use sqlparser::dialect::SnowflakeDialect;
    use sqlparser::tokenizer::{Token, Tokenizer};
    let dialect = SnowflakeDialect {};
    let toks = Tokenizer::new(&dialect, sql)
        .with_unescape(false)
        .tokenize_with_location()
        .ok()?;
    let offs = crate::parser::byte_offsets(sql, &toks);
    let mut text = sql.as_bytes().to_vec();
    for (k, t) in toks.iter().enumerate() {
        let Token::Word(w) = &t.token else { continue };
        let fold = match w.quote_style {
            None => true,
            Some('"') => fold_quoted,
            Some(_) => false,
        };
        if fold {
            let end = offs.get(k + 1).copied().unwrap_or(sql.len());
            text[offs[k]..end].make_ascii_uppercase();
        }
    }
    let text = String::from_utf8(text).ok()?;
    let before = sqlparser::parser::Parser::parse_sql(&dialect, sql)
        .ok()?
        .len();
    let mut folded = sqlparser::parser::Parser::parse_sql(&dialect, &text).ok()?;
    // Read `ORDER BY ALL` as the parse did (temporary, see the function).
    crate::parser::resolve_snowflake_order_by_all(&mut folded);
    (folded.len() == before).then_some(folded)
}

/// A Snowflake `ALTER SESSION SET` parameter that only changes how values
/// are formatted, tagged or timed out: allowed under an allowlist. Anything
/// else, `QUOTED_IDENTIFIERS_IGNORE_CASE` first (it changes how every name
/// resolves), is denied.
fn snowflake_session_param_ok(name: &str) -> bool {
    const OK: &[&str] = &[
        "QUERY_TAG",
        "TIMEZONE",
        "DATE_INPUT_FORMAT",
        "DATE_OUTPUT_FORMAT",
        "TIME_INPUT_FORMAT",
        "TIME_OUTPUT_FORMAT",
        "TIMESTAMP_INPUT_FORMAT",
        "TIMESTAMP_OUTPUT_FORMAT",
        "TIMESTAMP_LTZ_OUTPUT_FORMAT",
        "TIMESTAMP_NTZ_OUTPUT_FORMAT",
        "TIMESTAMP_TZ_OUTPUT_FORMAT",
        "TIMESTAMP_TYPE_MAPPING",
        "WEEK_START",
        "WEEK_OF_YEAR_POLICY",
        "STATEMENT_TIMEOUT_IN_SECONDS",
        "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS",
        "LOCK_TIMEOUT",
        "ABORT_DETACHED_QUERY",
        "AUTOCOMMIT",
        "BINARY_OUTPUT_FORMAT",
        "BINARY_INPUT_FORMAT",
        "GEOGRAPHY_OUTPUT_FORMAT",
        "JSON_INDENT",
        "ROWS_PER_RESULTSET",
        "USE_CACHED_RESULT",
        "CLIENT_SESSION_KEEP_ALIVE",
    ];
    OK.iter().any(|p| p.eq_ignore_ascii_case(name))
}

fn split(name: &ObjectName, dialect: Dialect) -> (Option<String>, String) {
    if dialect == Dialect::Snowflake {
        return crate::sensitive::sql::split_name_snowflake(name);
    }
    let parts = name_parts(name);
    let table = parts.last().map(|p| p.to_string()).unwrap_or_default();
    // SQL Server's `db..t`: an empty schema is the default one.
    let schema = (parts.len() >= 2)
        .then(|| parts[parts.len() - 2])
        .filter(|s| !s.is_empty())
        .map(str::to_string);
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
        .map(|p| name_part(p).trim_start_matches('@').to_ascii_lowercase())
        .unwrap_or_default();
    match last.as_str() {
        "search_path" => return Some("SET search_path".into()),
        "role" => return Some("SET ROLE".into()),
        "session_authorization" => return Some("SET SESSION AUTHORIZATION".into()),
        _ => {}
    }
    let joined = name_parts(name).join(".");
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
            [
                Expr::Value(ValueWithSpan {
                    value: Value::SingleQuotedString(v),
                    ..
                }),
            ]
            | [Expr::Identifier(Ident { value: v, .. })]
                if session::scs_on(v) =>
            {
                None
            }
            [
                Expr::Value(ValueWithSpan {
                    value: Value::Boolean(true),
                    ..
                }),
            ] => None,
            [
                Expr::Value(ValueWithSpan {
                    value: Value::Number(n, _),
                    ..
                }),
            ] if n == "1" => None,
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
        Expr::Value(ValueWithSpan {
            value: Value::SingleQuotedString(s) | Value::DoubleQuotedString(s),
            ..
        }) => Some(vec![ModePiece::Literal(s.clone())]),
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
                && name_part(&f.name.0[0]).eq_ignore_ascii_case("concat")
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
fn catalogue(tags: &Tags, table: &str, dialect: Dialect) -> Result<Class> {
    // Snowflake compares folded names: its catalogue is spelled as stored.
    if dialect == Dialect::Snowflake {
        tags.relation(Some("INFORMATION_SCHEMA"), table);
    } else {
        tags.relation(Some("information_schema"), table);
    }
    Ok(Class::Allowed)
}

/// `CALL f(…)`: the arguments analysed as `SELECT <args>`.
fn arguments(tags: &Tags, dialect: Dialect, args: &[Expr]) -> Result<Class> {
    if args.is_empty() {
        return Ok(Class::Allowed);
    }
    let projection = args.iter().cloned().map(SelectItem::UnnamedExpr).collect();
    let select = Select {
        select_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
        optimizer_hints: Vec::new(),
        distinct: None,
        select_modifiers: None,
        top: None,
        top_before_distinct: false,
        projection,
        exclude: None,
        into: None,
        from: Vec::new(),
        lateral_views: Vec::new(),
        prewhere: None,
        selection: None,
        connect_by: Vec::new(),
        group_by: sqlparser::ast::GroupByExpr::Expressions(Vec::new(), Vec::new()),
        cluster_by: Vec::new(),
        distribute_by: Vec::new(),
        sort_by: Vec::new(),
        having: None,
        named_window: Vec::new(),
        qualify: None,
        window_before_qualify: false,
        value_table_mode: None,
        flavor: sqlparser::ast::SelectFlavor::Standard,
    };
    let mut stmt = Statement::Query(Box::new(Query {
        with: None,
        body: Box::new(SetExpr::Select(Box::new(select))),
        order_by: None,
        limit_clause: None,
        fetch: None,
        locks: Vec::new(),
        for_clause: None,
        settings: None,
        format_clause: None,
        pipe_operators: Vec::new(),
    }));
    access_walk(&mut stmt, tags, dialect)?;
    Ok(Class::Allowed)
}

/// `SET …`, one statement kind since sqlparser 0.56 (`SetVariable`,
/// `SetRole`, `SetNames`, `SetTimeZone`, `SetTransaction` before). Every
/// assignment must be allowed.
fn set_class(set: &Set) -> Result<Class> {
    let denied = |w: &str| Ok(Class::Denied(w.to_string()));
    let assignments: Vec<(ObjectName, Vec<&Expr>)> = match set {
        // `SET GLOBAL x = …` is server-wide (it did not parse before: a
        // parse error, which blocks).
        Set::SingleAssignment {
            scope: Some(ContextModifier::Global),
            ..
        } => return denied("SET GLOBAL"),
        Set::SingleAssignment {
            variable, values, ..
        } => {
            // sqlparser may still read `SET a = 1, b = 2` as one variable
            // whose values are `1` and the expression `b = 2`: each later
            // `name = value` starts the next assignment.
            let mut out: Vec<(ObjectName, Vec<&Expr>)> = vec![(variable.clone(), Vec::new())];
            for e in values {
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
                            Expr::Identifier(i) => ObjectName::from(i.clone()),
                            Expr::CompoundIdentifier(ids) => ObjectName::from(ids.clone()),
                            _ => unreachable!("matched above"),
                        };
                        out.push((name, vec![right.as_ref()]));
                    }
                    other => {
                        if let Some(last) = out.last_mut() {
                            last.1.push(other);
                        }
                    }
                }
            }
            out
        }
        // MySQL's `SET a = 1, b = 2` as separate assignments.
        Set::MultipleAssignments { assignments } => {
            if assignments
                .iter()
                .any(|a| matches!(a.scope, Some(ContextModifier::Global)))
            {
                return denied("SET GLOBAL");
            }
            assignments
                .iter()
                .map(|a| (a.name.clone(), vec![&a.value]))
                .collect()
        }
        Set::ParenthesizedAssignments { .. } => return denied("SET (…)"),
        Set::SetRole { .. } => return denied("SET ROLE"),
        Set::SetSessionAuthorization(_) => return denied("SET SESSION AUTHORIZATION"),
        // Character set, time zone and transaction characteristics: allowed,
        // as before.
        Set::SetNames { .. }
        | Set::SetNamesDefault { .. }
        | Set::SetTimeZone { .. }
        | Set::SetTransaction { .. } => return Ok(Class::Allowed),
        // SQL Server session options (`SET NOCOUNT ON`, `SET IDENTITY_INSERT
        // t ON`, …), which sqlparser 0.52 rejected: denied, as
        // anything not on the closed list.
        Set::SetSessionParam(p) => return Ok(Class::Denied(format!("SET {p}"))),
    };
    for (name, values) in &assignments {
        if let Some(what) = set_denial(name, values) {
            return Ok(Class::Denied(what));
        }
    }
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
        Statement::Explain { statement, .. } => {
            match classify(statement, tags, depth + 1, dialect)? {
                Class::Allowed => Ok(Class::Allowed),
                other => Ok(other),
            }
        }
        // `DESCRIBE t`: the table's structure, i.e. every column.
        Statement::ExplainTable { table_name, .. } => {
            let (schema, table) = split(table_name, dialect);
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
        Statement::Set(set) => set_class(set),
        // SQLite: the structure reads (`PRAGMA table_info(t)`: every column
        // of `t`) and the connection settings drivers send are allowed; every
        // other pragma is denied as DDL.
        Statement::Pragma { name, value, .. } if dialect == Dialect::Sqlite => {
            use crate::parser::sqlite::{PragmaAccess, pragma_access};
            match pragma_access(name, value.as_ref().map(|v| &v.value)) {
                PragmaAccess::ReadsTable(t) => {
                    let (schema, table) = split(&t, dialect);
                    tags.relation(schema.as_deref(), &table);
                    tags.of_table(schema.as_deref(), &table);
                    Ok(Class::Allowed)
                }
                PragmaAccess::Allowed => Ok(Class::Allowed),
                PragmaAccess::Denied(what) => Ok(Class::Denied(what)),
            }
        }
        Statement::Use(_) => denied("USE"),
        // A block of statements (Snowflake scripting; on every other dialect
        // it is a parse error): its control flow is not analysed.
        Statement::StartTransaction {
            statements,
            exception,
            ..
        } if !statements.is_empty() || exception.is_some() => denied("BEGIN … END block"),
        // Snowflake.
        Statement::AlterSession {
            set: true,
            session_params,
        } => match session_params
            .options
            .iter()
            .find(|o| !snowflake_session_param_ok(&o.option_name))
        {
            None => Ok(Class::Allowed),
            Some(o) => Ok(Class::Denied(format!(
                "ALTER SESSION SET {}",
                o.option_name.to_ascii_uppercase()
            ))),
        },
        Statement::AlterSession { set: false, .. } => denied("ALTER SESSION UNSET"),
        Statement::CopyIntoSnowflake { .. } => denied("COPY INTO"),
        Statement::CreateStage { .. } => denied("CREATE STAGE"),
        Statement::Put { .. } => denied("PUT"),
        Statement::List { .. } => denied("LIST"),
        Statement::Remove { .. } => denied("REMOVE"),
        Statement::CreateWarehouse(_) => denied("CREATE WAREHOUSE"),
        Statement::ShowTables { .. } => catalogue(tags, "TABLES", dialect),
        Statement::ShowViews { .. } => catalogue(tags, "VIEWS", dialect),
        Statement::ShowColumns { .. } => catalogue(tags, "COLUMNS", dialect),
        Statement::ShowDatabases { .. } | Statement::ShowSchemas { .. } => {
            catalogue(tags, "SCHEMATA", dialect)
        }
        Statement::ShowCreate { .. } => catalogue(tags, "TABLES", dialect),
        Statement::ShowFunctions { .. } => catalogue(tags, "ROUTINES", dialect),
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
        // Their own statement kinds in newer sqlparser (`ShowVariable`
        // before): decided as before.
        Statement::ShowProcessList { .. } => denied("SHOW PROCESSLIST"),
        Statement::ShowCharset { .. } => Ok(Class::Allowed),
        Statement::ShowVariables { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowCollation { .. }
        | Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. }
        | Statement::Fetch { .. }
        | Statement::Close { .. }
        | Statement::Discard { .. }
        | Statement::LISTEN { .. }
        | Statement::NOTIFY { .. }
        | Statement::UnlockTables => Ok(Class::Allowed),
        // Allowed, but the arguments are values the statement reads.
        Statement::Call(f) => arguments(tags, dialect, &[Expr::Function(f.clone())]),
        // SQL-level prepared statements: `EXECUTE s` runs whatever `s` was
        // bound to in this session (MySQL `PREPARE s FROM @sql`: text the
        // engine never sees), so no EXECUTE can be judged; the three are
        // denied together. On SQL Server `EXEC` parses as this too, and is
        // denied for the same reason (`EXEC sp_executesql @sql`, `EXEC (@sql)`).
        // Protocol-level prepared statements (COM_STMT_PREPARE) are
        // unaffected: the host evaluates the statement text when it is
        // prepared.
        Statement::Prepare { .. } => denied("PREPARE"),
        Statement::Execute { .. } => denied("EXECUTE"),
        Statement::Deallocate { .. } => denied("DEALLOCATE"),
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
