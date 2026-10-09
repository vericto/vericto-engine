//! Access analysis over the `pg_query` AST (Postgres): which statements are
//! analysed, allowed or denied outright. The analysis itself is the
//! VERICTO-085 walker run in access mode ([`crate::sensitive::pg::access_walk`]).

use pg_query::protobuf::node::Node as NodeEnum;
use pg_query::protobuf::{self, ObjectType};

use crate::access::session;
use crate::error::{MAX_AST_DEPTH, ProxyError, Result};
use crate::sensitive::Tags;
use crate::sensitive::pg::access_walk;

/// What a statement is, for an agent identity.
enum Class {
    /// Reads or writes tables: walked.
    Walk,
    /// Touches no table and cannot widen access (transaction control,
    /// settings, cursors, prepared-statement plumbing).
    Allowed,
    /// `CALL f(…)` / `EXECUTE p(…)`: allowed, but the arguments are values
    /// the statement reads (`CALL f((SELECT email FROM customers))`).
    Arguments,
    /// DDL, or a statement that changes the identity or how names resolve.
    Denied(String),
}

/// Records every reference the statements make in `tags`.
pub(crate) fn collect(tree: &protobuf::ParseResult, tags: &Tags) -> Result<()> {
    // The walker takes the tree mutably (it is the mask rewriter too); the
    // analysis never changes it, but works on a copy all the same.
    let mut tree = tree.clone();
    for raw in tree.stmts.iter_mut() {
        if let Some(node) = raw.stmt.as_deref_mut().and_then(|n| n.node.as_mut()) {
            statement(node, tags)?;
        }
    }
    Ok(())
}

fn statement(node: &mut NodeEnum, tags: &Tags) -> Result<()> {
    match classify(node, 0)? {
        Class::Walk => {
            if let NodeEnum::LockStmt(l) = node {
                // A table lock can stall every other writer: it needs write.
                for r in &l.relations {
                    if let Some(NodeEnum::RangeVar(rv)) = r.node.as_ref() {
                        let schema = (!rv.schemaname.is_empty()).then_some(rv.schemaname.as_str());
                        tags.write(schema, &rv.relname, None);
                    }
                }
                return Ok(());
            }
            access_walk(node, tags)
        }
        Class::Allowed => Ok(()),
        Class::Arguments => {
            // Analysed as `SELECT <arguments>`: the same walk, same scope.
            let args: Vec<protobuf::Node> = match node {
                NodeEnum::CallStmt(c) => c
                    .funccall
                    .as_ref()
                    .map(|f| {
                        vec![protobuf::Node {
                            node: Some(NodeEnum::FuncCall(f.clone())),
                        }]
                    })
                    .unwrap_or_default(),
                NodeEnum::ExecuteStmt(e) => e.params.clone(),
                _ => Vec::new(),
            };
            let target_list = args
                .into_iter()
                .map(|a| protobuf::Node {
                    node: Some(NodeEnum::ResTarget(Box::new(protobuf::ResTarget {
                        val: Some(Box::new(a)),
                        ..Default::default()
                    }))),
                })
                .collect();
            let mut select = NodeEnum::SelectStmt(Box::new(protobuf::SelectStmt {
                target_list,
                ..Default::default()
            }));
            access_walk(&mut select, tags)
        }
        Class::Denied(what) => {
            tags.statement(&what);
            Ok(())
        }
    }
}

fn inner(n: Option<&protobuf::Node>, depth: usize) -> Result<Class> {
    match n.and_then(|n| n.node.as_ref()) {
        Some(n) => classify(n, depth + 1),
        None => Ok(Class::Allowed),
    }
}

fn classify(node: &NodeEnum, depth: usize) -> Result<Class> {
    if depth > MAX_AST_DEPTH {
        return Err(ProxyError::AstTooDeep);
    }
    let denied = |s: &str| Ok(Class::Denied(s.to_string()));
    match node {
        NodeEnum::SelectStmt(s) if s.into_clause.is_some() => denied("SELECT INTO"),
        NodeEnum::SelectStmt(_)
        | NodeEnum::InsertStmt(_)
        | NodeEnum::UpdateStmt(_)
        | NodeEnum::DeleteStmt(_)
        | NodeEnum::MergeStmt(_)
        | NodeEnum::CopyStmt(_)
        | NodeEnum::LockStmt(_) => Ok(Class::Walk),
        // The statement inside is what runs (EXPLAIN ANALYZE executes it).
        NodeEnum::ExplainStmt(e) => match inner(e.query.as_deref(), depth)? {
            Class::Allowed => Ok(Class::Walk),
            other => Ok(other),
        },
        NodeEnum::DeclareCursorStmt(d) => match inner(d.query.as_deref(), depth)? {
            Class::Allowed => Ok(Class::Walk),
            other => Ok(other),
        },
        NodeEnum::PrepareStmt(p) => match inner(p.query.as_deref(), depth)? {
            Class::Allowed => Ok(Class::Walk),
            other => Ok(other),
        },
        NodeEnum::VariableSetStmt(v) => Ok(variable_set(v)),
        NodeEnum::TransactionStmt(_)
        | NodeEnum::VariableShowStmt(_)
        | NodeEnum::DeallocateStmt(_)
        | NodeEnum::ClosePortalStmt(_)
        | NodeEnum::FetchStmt(_)
        | NodeEnum::ListenStmt(_)
        | NodeEnum::UnlistenStmt(_)
        | NodeEnum::NotifyStmt(_)
        | NodeEnum::DiscardStmt(_) => Ok(Class::Allowed),
        NodeEnum::CallStmt(_) | NodeEnum::ExecuteStmt(_) => Ok(Class::Arguments),
        NodeEnum::CreateTableAsStmt(c) => {
            if c.objtype == ObjectType::ObjectMatview as i32 {
                denied("CREATE MATERIALIZED VIEW")
            } else if c.is_select_into {
                denied("SELECT INTO")
            } else {
                denied("CREATE TABLE AS")
            }
        }
        NodeEnum::ViewStmt(_) => denied("CREATE VIEW"),
        NodeEnum::CreateStmt(_) => denied("CREATE TABLE"),
        NodeEnum::DropStmt(_) => denied("DROP"),
        NodeEnum::AlterTableStmt(_) => denied("ALTER TABLE"),
        NodeEnum::TruncateStmt(_) => denied("TRUNCATE"),
        NodeEnum::IndexStmt(_) => denied("CREATE INDEX"),
        NodeEnum::GrantStmt(g) => denied(if g.is_grant { "GRANT" } else { "REVOKE" }),
        NodeEnum::GrantRoleStmt(g) => denied(if g.is_grant { "GRANT" } else { "REVOKE" }),
        NodeEnum::DoStmt(_) => denied("DO"),
        NodeEnum::CreateFunctionStmt(_) => denied("CREATE FUNCTION"),
        NodeEnum::CommentStmt(_) => denied("COMMENT"),
        NodeEnum::VacuumStmt(v) => denied(if v.is_vacuumcmd { "VACUUM" } else { "ANALYZE" }),
        NodeEnum::AlterSystemStmt(_) => denied("ALTER SYSTEM"),
        NodeEnum::RenameStmt(_) => denied("ALTER … RENAME"),
        other => Ok(Class::Denied(statement_name(other))),
    }
}

/// `SET` / `RESET` under an allowlist. Who the session is and where
/// unqualified names resolve are what the allowlist is written against, so
/// those are denied; otherwise only the closed list of session settings
/// (`crate::access::session`) is allowed — deny by default, since an
/// unlisted setting can be dangerous (`session_replication_role` disables
/// triggers and foreign keys, `default_transaction_read_only = off`, …).
fn variable_set(v: &protobuf::VariableSetStmt) -> Class {
    use protobuf::VariableSetKind as K;
    let name = v.name.to_ascii_lowercase();
    match name.as_str() {
        "role" => return Class::Denied("SET ROLE".into()),
        "session_authorization" => return Class::Denied("SET SESSION AUTHORIZATION".into()),
        "search_path" => return Class::Denied("SET search_path".into()),
        // `SET [SESSION|LOCAL] TRANSACTION …`, `SET SESSION CHARACTERISTICS
        // AS TRANSACTION …`, and their GUC forms.
        "transaction" | "session characteristics" | "transaction_isolation" => {
            return Class::Allowed;
        }
        _ => {}
    }
    // `RESET ALL` returns every setting to the session's defaults (the
    // login identity's, not the agent's choice).
    if v.kind == K::VarResetAll as i32 {
        return Class::Allowed;
    }
    match session::setting(&name) {
        session::Setting::Listed => Class::Allowed,
        session::Setting::StandardConformingStrings => {
            let on = v.kind != K::VarSetValue as i32
                || match v.args.first().and_then(|a| a.node.as_ref()) {
                    Some(NodeEnum::AConst(c)) => match c.val.as_ref() {
                        Some(protobuf::a_const::Val::Sval(s)) => session::scs_on(&s.sval),
                        Some(protobuf::a_const::Val::Ival(i)) => i.ival == 1,
                        Some(protobuf::a_const::Val::Boolval(b)) => b.boolval,
                        _ => false,
                    },
                    _ => false,
                };
            if on {
                Class::Allowed
            } else {
                Class::Denied("SET standard_conforming_strings".into())
            }
        }
        _ => Class::Denied(format!("SET {name}")),
    }
}

/// `CreateSchemaStmt` → `CREATE SCHEMA`, for statements without a dedicated
/// name above. Deny by default: any kind not known to be harmless is DDL.
fn statement_name(node: &NodeEnum) -> String {
    let debug = format!("{node:?}");
    let variant = debug.split(['(', ' ', '{']).next().unwrap_or("STATEMENT");
    let variant = variant.strip_suffix("Stmt").unwrap_or(variant);
    let mut out = String::new();
    for (i, c) in variant.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push(' ');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}
