//! Rule evaluators against the normalized AST.
//!
//! Each built-in rule is a deterministic predicate on the detected statements.
//! Custom rules are defined in YAML and compiled to predicates on the same nodes.

use serde::Deserialize;

use crate::parser::{
    AlterTableKind, DropObjectKind, ParsedQuery, StatementInfo, StatementKind, WherePresence,
};
use crate::rules::engine::{Rule, RuleType};

/// A violation detected by a rule.
pub struct Violation {
    pub rule_id: String,
    pub rule_code: String,
    pub ast_node_path: String,
    pub estimated_rows_affected: Option<i64>,
    pub suggested_safe_query: Option<String>,
}

/// Evaluates a rule against the parsed query. Returns `Some(Violation)` if triggered.
pub fn evaluate_rule(rule: &Rule, parsed: &ParsedQuery) -> Option<Violation> {
    match rule.rule_type {
        RuleType::Standard => evaluate_builtin(rule, parsed),
        RuleType::Custom => evaluate_custom(rule, parsed),
    }
}

/// Dispatches the built-in rule code to its predicate.
fn evaluate_builtin(rule: &Rule, parsed: &ParsedQuery) -> Option<Violation> {
    let stmts = &parsed.statements;
    match rule.code.as_str() {

        // ── CRITICAL rules ─────────────────────────────────────────────────

        // VERICTO-001: DELETE without WHERE clause.
        "VERICTO-001" => find(stmts, |s| {
            s.kind == StatementKind::Delete && s.where_presence == WherePresence::Absent
        })
        .map(|s| violation(rule, s, suggest_delete(s))),

        // VERICTO-003: DELETE with a trivially-true WHERE (1=1, true).
        "VERICTO-003" => find(stmts, |s| {
            s.kind == StatementKind::Delete && s.where_presence == WherePresence::AlwaysTrue
        })
        .map(|s| violation(rule, s, suggest_delete(s))),

        // VERICTO-010: DROP TABLE / DROP DATABASE. Excludes DROP INDEX (own rule
        // VERICTO-013) and DROP SCHEMA (own rule VERICTO-012) so the two no longer
        // co-match on the same statement (ENG-010). DROP DATABASE is included
        // here now that the PostgreSQL path emits DropObjectKind::Database
        // (ENG-004); on MySQL it already arrived as a generic DropStmt.
        "VERICTO-010" => find(stmts, |s| {
            s.kind == StatementKind::Drop
                && !matches!(
                    s.drop_object,
                    Some(DropObjectKind::Index) | Some(DropObjectKind::Schema)
                )
        })
        .map(|s| violation(rule, s, Some(suggest_migration()))),

        // VERICTO-011: TRUNCATE TABLE.
        "VERICTO-011" => find(stmts, |s| s.kind == StatementKind::Truncate)
            .map(|s| violation(rule, s, suggest_truncate(s))),

        // VERICTO-012: DROP SCHEMA specifically.
        "VERICTO-012" => find(stmts, |s| {
            s.kind == StatementKind::Drop
                && matches!(s.drop_object, Some(DropObjectKind::Schema))
        })
        .map(|s| violation(rule, s, Some(suggest_migration()))),

        // VERICTO-030: UPDATE without WHERE — alias targeting 'primary tables'.
        // Identical predicate to VERICTO-042; separate code allows independent
        // configuration per workspace (e.g. different severity or scope).
        "VERICTO-030" => find(stmts, |s| {
            s.kind == StatementKind::Update && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_update(s))),

        // VERICTO-042: UPDATE without WHERE clause (includes always-true WHERE).
        "VERICTO-042" => find(stmts, |s| {
            s.kind == StatementKind::Update && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_update(s))),

        // ── HIGH rules ─────────────────────────────────────────────────────

        // VERICTO-002: DELETE with LIMIT 0 (MySQL/SQLite). A LIMIT of 0 deletes
        // zero rows, but it is syntactically indistinguishable from a
        // misconfigured attempt to scope a DELETE.
        "VERICTO-002" => find(stmts, |s| {
            s.kind == StatementKind::Delete && s.delete_limit == Some(0)
        })
        .map(|s| {
            let mut v = violation(rule, s, suggest_delete(s));
            v.ast_node_path = "DeleteStmt > LimitCount = 0".to_string();
            v
        }),

        // VERICTO-013: DROP INDEX without IF EXISTS. Without IF EXISTS the
        // statement will error if the index is missing, potentially breaking
        // scripts. With IF EXISTS it is idempotent.
        "VERICTO-013" => find(stmts, |s| {
            s.kind == StatementKind::Drop
                && matches!(s.drop_object, Some(DropObjectKind::Index))
                && !s.drop_index_if_exists
        })
        .map(|s| {
            let mut v = violation(rule, s, Some("DROP INDEX IF EXISTS <index_name>".to_string()));
            v.ast_node_path = "DropStmt > ObjectType = INDEX (no IF EXISTS)".to_string();
            v
        }),

        // VERICTO-015: ALTER TABLE DROP COLUMN — irreversible schema change.
        "VERICTO-015" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::DropColumn))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Use soft-delete (nullable column) or a versioned migration tool".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > AlterTableCmd.subtype = DROP_COLUMN".to_string();
            v
        }),

        // VERICTO-016: ALTER TABLE RENAME — renames a table or column, breaking
        // any code that references the old name.
        "VERICTO-016" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::Rename))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Use a versioned migration tool and update all code references first".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > Rename".to_string();
            v
        }),

        // VERICTO-017: ALTER TABLE DROP CONSTRAINT — removes a FK/PK/CHECK and
        // silently allows future data to violate the dropped invariant.
        "VERICTO-017" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::DropConstraint))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Drop constraints only via a reviewed, versioned migration".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > DropConstraint".to_string();
            v
        }),

        // VERICTO-018: ALTER TABLE ALTER COLUMN TYPE — rewrites the table and can
        // be a lossy/blocking cast on a large relation.
        "VERICTO-018" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::AlterColumnType))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Use an additive migration (new column + backfill + swap)".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > AlterColumnType".to_string();
            v
        }),

        // VERICTO-019: ALTER TABLE DISABLE TRIGGER / DISABLE ROW LEVEL SECURITY —
        // disables a data-integrity or access-control protection.
        "VERICTO-019" => find(stmts, |s| {
            s.kind == StatementKind::AlterTable
                && matches!(s.alter_table_kind, Some(AlterTableKind::DisableTrigger))
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Keep triggers / RLS enabled; scope the operation instead".to_string()),
            );
            v.ast_node_path = "AlterTableStmt > DisableTrigger".to_string();
            v
        }),

        // ── Dangerous statement types (ENG-007) ────────────────────────────

        // VERICTO-080: COPY … TO/FROM PROGRAM — executes a shell command on the
        // database host. Remote code execution / data-exfiltration channel.
        "VERICTO-080" => find(stmts, |s| {
            s.kind == StatementKind::Copy && s.copy_is_program
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("Use client-side \\copy or COPY … TO STDOUT, never PROGRAM".to_string()),
            );
            v.ast_node_path = "CopyStmt > PROGRAM".to_string();
            v
        }),

        // VERICTO-081: DO $$ … $$ anonymous code block — runs an arbitrary
        // PL/pgSQL body that can perform any hidden DML/DDL.
        "VERICTO-081" => find(stmts, |s| s.kind == StatementKind::DoBlock)
            .map(|s| {
                let mut v = violation(
                    rule,
                    s,
                    Some("Replace the anonymous DO block with explicit, reviewable statements".to_string()),
                );
                v.ast_node_path = "DoStmt".to_string();
                v
            }),

        // VERICTO-082: GRANT / REVOKE — privilege escalation or accidental lockout.
        "VERICTO-082" => find(stmts, |s| s.kind == StatementKind::Grant)
            .map(|s| {
                let mut v = violation(
                    rule,
                    s,
                    Some("Manage privileges through your access-control / IaC pipeline".to_string()),
                );
                v.ast_node_path = "GrantStmt".to_string();
                v
            }),

        // VERICTO-083: MERGE — can mass-mutate the target table like an
        // UPDATE/DELETE with no effective WHERE.
        "VERICTO-083" => find(stmts, |s| s.kind == StatementKind::Merge)
            .map(|s| {
                let mut v = violation(
                    rule,
                    s,
                    Some("Scope the MERGE join so it cannot match the whole table".to_string()),
                );
                v.ast_node_path = "MergeStmt".to_string();
                v
            }),

        // VERICTO-084: CREATE TABLE AS SELECT … / SELECT … INTO — bulk data copy
        // that can duplicate an entire table (and any sensitive data in it).
        "VERICTO-084" => find(stmts, |s| s.kind == StatementKind::CreateTableAs)
            .map(|s| {
                let mut v = violation(
                    rule,
                    s,
                    Some("Add a WHERE/LIMIT to the source SELECT, or use a reviewed migration".to_string()),
                );
                v.ast_node_path = "CreateTableAsStmt".to_string();
                v
            }),

        // VERICTO-031: UPDATE without WHERE nested inside a CTE.
        "VERICTO-031" => find(stmts, |s| {
            s.kind == StatementKind::Update
                && s.is_nested
                && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_update(s))),

        // VERICTO-033: DELETE without WHERE in a subquery or CTE.
        "VERICTO-033" => find(stmts, |s| {
            s.kind == StatementKind::Delete
                && s.is_nested
                && s.where_presence != WherePresence::Present
        })
        .map(|s| violation(rule, s, suggest_delete(s))),

        // VERICTO-040: INSERT INTO … SELECT without a WHERE filter on the SELECT.
        // This copies every row from the source, which can be accidental.
        "VERICTO-040" => find(stmts, |s| {
            s.kind == StatementKind::Insert && s.insert_has_select
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some(format!(
                    "INSERT INTO {} SELECT ... WHERE <condition> LIMIT N",
                    s.relation.as_deref().unwrap_or("{table}")
                )),
            );
            v.ast_node_path = "InsertStmt > source = SelectStmt (no WHERE)".to_string();
            v
        }),

        // VERICTO-070: Use of SLEEP() or PG_SLEEP() — indicates intentional delays,
        // usually for DoS or timing-based SQL injection probing.
        "VERICTO-070" => find(stmts, |s| {
            s.kind == StatementKind::FunctionCall
        })
        .map(|s| {
            let fname = s.function_name.as_deref().unwrap_or("sleep");
            let mut v = violation(rule, s, None);
            v.ast_node_path = format!("FunctionCall > {fname}()");
            v
        }),

        // ── MEDIUM rules ───────────────────────────────────────────────────

        // VERICTO-050: SELECT without LIMIT. Without table-size statistics in the
        // proxy we cannot distinguish large from small tables, so we flag all
        // unbounded SELECTs with MEDIUM severity (log-only by default).
        //
        // Scoped to the top-level (client-visible) SELECT: a bounded outer query
        // (`SELECT … FROM (subquery) LIMIT 10`) caps the rows returned, so we do
        // not flag every inner scan for "missing" a LIMIT it cannot carry. Inner
        // selects are still recorded (ENG-005) for VERICTO-051/090.
        "VERICTO-050" => find(stmts, |s| {
            s.kind == StatementKind::Select && !s.is_nested && !s.select_has_limit
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("SELECT ... WHERE <condition> LIMIT 1000".to_string()),
            );
            v.ast_node_path = "SelectStmt > LimitCount = NULL".to_string();
            v
        }),

        // VERICTO-051: SELECT * without any WHERE clause.
        "VERICTO-051" => find(stmts, |s| {
            s.kind == StatementKind::Select
                && s.select_is_star
                && s.where_presence == WherePresence::Absent
        })
        .map(|s| {
            let mut v = violation(
                rule,
                s,
                Some("SELECT col1, col2 FROM ... WHERE <condition>".to_string()),
            );
            v.ast_node_path = "SelectStmt > TargetEntry = STAR & WhereClause = NULL".to_string();
            v
        }),

        // VERICTO-060: INSERT without explicit column list. Relies on table
        // column order, which breaks on schema changes.
        "VERICTO-060" => find(stmts, |s| {
            s.kind == StatementKind::Insert && !s.insert_has_columns
        })
        .map(|s| {
            let rel = s.relation.as_deref().unwrap_or("{table}");
            let mut v = violation(
                rule,
                s,
                Some(format!("INSERT INTO {rel} (col1, col2) VALUES ($1, $2)")),
            );
            v.ast_node_path = "InsertStmt > Cols = NULL".to_string();
            v
        }),

        // VERICTO-061: INSERT … VALUES with more than 10,000 row tuples.
        "VERICTO-061" => find(stmts, |s| {
            s.kind == StatementKind::Insert
                && s.insert_row_count.map(|n| n > 10_000).unwrap_or(false)
        })
        .map(|s| {
            let count = s.insert_row_count.unwrap_or(0);
            let mut v = violation(
                rule,
                s,
                Some("Split the batch into chunks of ≤1,000 rows with COPY or multiple INSERT statements".to_string()),
            );
            v.ast_node_path = format!("InsertStmt > ValuesList count = {count}");
            v
        }),

        // ── SQL injection ─────────────────────────────────────────────────

        // VERICTO-090: SQL injection tautology — OR branch in WHERE is always true
        // (e.g. `WHERE id = $1 OR 1=1`, `WHERE name = 'x' OR 'a'='a'`).
        //
        // Zero-false-positive guarantee: no well-behaved LLM has a legitimate
        // reason to include `OR 1=1` or any OR branch with a literal tautology.
        // This pattern is exclusively a SQL injection bypass technique.
        //
        // Covers SELECT, DELETE, and UPDATE WHERE clauses.
        "VERICTO-090" => find(stmts, |s| {
            matches!(
                s.kind,
                StatementKind::Select | StatementKind::Delete | StatementKind::Update
            ) && s.has_or_tautology
        })
        .map(|s| {
            let stmt_name = match s.kind {
                StatementKind::Select => "SelectStmt",
                StatementKind::Delete => "DeleteStmt",
                StatementKind::Update => "UpdateStmt",
                _ => "Stmt",
            };
            let suggestion = match s.kind {
                StatementKind::Select => "SELECT ... WHERE id = $1  -- use parameterized queries",
                StatementKind::Delete => "DELETE FROM {table} WHERE id = $1",
                _                     => "UPDATE {table} SET col = $1 WHERE id = $2",
            };
            let mut v = violation(rule, s, Some(suggestion.to_string()));
            v.ast_node_path = format!(
                "{stmt_name} > WhereClause > BoolExpr(OR) > always_true_branch"
            );
            v
        }),

        // Unknown or not-yet-implemented built-in codes: pass through.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Custom rule evaluator (YAML-defined)
// ---------------------------------------------------------------------------

/// A YAML-defined custom rule, matching the schema documented at
/// `/docs/custom-rules`:
///
/// ```yaml
/// rule: block-select-star        # optional label
/// node_type: SelectStmt          # required — AST node to capture
/// message: "..."                 # optional human message
/// condition:                     # optional — predicates on the node
///   target_list: "*"
/// ```
///
/// Predicates live under `condition:`. We deserialize `condition` as a raw
/// `serde_yaml::Value` so we can distinguish `where_clause: null` (key present,
/// value null → "no WHERE clause") from the key being absent — an important
/// signal that a typed `Option<T>` would collapse into `None` either way.
///
/// Supported predicates: `relation`, `where_clause: null`, `where_always_true`,
/// `target_list`, `has_limit`, `func_name`, `object_type`, `alter_kind`.
#[derive(Debug, Deserialize)]
struct CustomRuleSpec {
    #[allow(dead_code)]
    rule: Option<String>,
    node_type: String,
    #[allow(dead_code)]
    message: Option<String>,
    #[serde(default)]
    condition: serde_yaml::Value,
}

fn evaluate_custom(rule: &Rule, parsed: &ParsedQuery) -> Option<Violation> {
    let yaml = rule.ast_condition_yaml.as_ref()?;
    let spec: CustomRuleSpec = serde_yaml::from_str(yaml).ok()?;

    let target_kind = match spec.node_type.as_str() {
        "DeleteStmt" => StatementKind::Delete,
        "UpdateStmt" => StatementKind::Update,
        "DropStmt" => StatementKind::Drop,
        "TruncateStmt" => StatementKind::Truncate,
        "InsertStmt" => StatementKind::Insert,
        "SelectStmt" => StatementKind::Select,
        "AlterTableStmt" => StatementKind::AlterTable,
        "FuncCall" => StatementKind::FunctionCall,
        _ => return None,
    };

    let cond = &spec.condition;
    // A node_type with no `condition:` block fires for every matching node
    // (e.g. `node_type: DropStmt` blocks any DROP).
    let cond_get = |key: &str| cond.get(serde_yaml::Value::from(key));

    // `where_clause: null` — the key must be PRESENT (its value is null). serde's
    // `.get()` returns Some(Value::Null) when present-with-null, None when absent.
    let where_clause_present = cond_get("where_clause").is_some();

    find(&parsed.statements, |s| {
        if s.kind != target_kind {
            return false;
        }
        // relation: <table> → scope the rule to a single table (dialect-normalized,
        // case-insensitive; a schema-qualified name matches on its final segment).
        if let Some(rel) = cond_get("relation").and_then(|v| v.as_str()) {
            match &s.relation {
                Some(actual) if relation_matches(actual, rel) => {}
                _ => return false,
            }
        }
        // alter_kind: <kind> → restrict AlterTableStmt to one command subtype
        // (drop_column | rename | drop_constraint | alter_column_type | disable_trigger).
        if let Some(kind) = cond_get("alter_kind").and_then(|v| v.as_str()) {
            if !alter_kind_matches(s.alter_table_kind, kind) {
                return false;
            }
        }
        // where_clause: null → require the statement to have NO WHERE clause.
        if where_clause_present && s.where_presence == WherePresence::Present {
            return false;
        }
        // where_always_true: true → require a trivially-true predicate (OR 1=1, …).
        if cond_get("where_always_true").and_then(|v| v.as_bool()) == Some(true)
            && !s.has_or_tautology
        {
            return false;
        }
        // target_list: "*" → require SELECT * (any other value never matches).
        if let Some(target) = cond_get("target_list").and_then(|v| v.as_str()) {
            if target != "*" || !s.select_is_star {
                return false;
            }
        }
        // has_limit: false/true → match statements with/without a LIMIT.
        if let Some(want_limit) = cond_get("has_limit").and_then(|v| v.as_bool()) {
            if s.select_has_limit != want_limit {
                return false;
            }
        }
        // func_name: "sleep" → match a called function by name (case-insensitive).
        if let Some(fname) = cond_get("func_name").and_then(|v| v.as_str()) {
            match &s.function_name {
                Some(actual) if actual.eq_ignore_ascii_case(fname) => {}
                _ => return false,
            }
        }
        // object_type: "table"|"schema"|"index"|"database" → scope a DROP.
        if let Some(obj) = cond_get("object_type").and_then(|v| v.as_str()) {
            if !drop_object_matches(s.drop_object, obj) {
                return false;
            }
        }
        true
    })
    .map(|s| violation(rule, s, None))
}

/// Matches a statement's DROP object kind against a user-supplied string
/// (case-insensitive): "table" | "database" | "schema" | "index".
fn drop_object_matches(actual: Option<DropObjectKind>, expected: &str) -> bool {
    let Some(actual) = actual else { return false };
    let expected = expected.to_ascii_lowercase();
    matches!(
        (actual, expected.as_str()),
        (DropObjectKind::Table, "table")
            | (DropObjectKind::Database, "database")
            | (DropObjectKind::Schema, "schema")
            | (DropObjectKind::Index, "index")
    )
}

/// Matches an ALTER TABLE subtype against a user-supplied string
/// (case-insensitive): "drop_column" | "rename" | "drop_constraint" |
/// "alter_column_type" | "disable_trigger".
fn alter_kind_matches(actual: Option<AlterTableKind>, expected: &str) -> bool {
    let Some(actual) = actual else { return false };
    let expected = expected.to_ascii_lowercase();
    matches!(
        (actual, expected.as_str()),
        (AlterTableKind::DropColumn, "drop_column")
            | (AlterTableKind::Rename, "rename")
            | (AlterTableKind::DropConstraint, "drop_constraint")
            | (AlterTableKind::AlterColumnType, "alter_column_type")
            | (AlterTableKind::DisableTrigger, "disable_trigger")
    )
}

/// Compares two relation names, dialect-normalized: strips schema qualifier and
/// quotes, then case-insensitive. `public.payments` matches `payments`.
fn relation_matches(actual: &str, expected: &str) -> bool {
    let normalize = |s: &str| {
        s.rsplit('.')
            .next()
            .unwrap_or(s)
            .trim_matches('"')
            .trim_matches('`')
            .to_ascii_lowercase()
    };
    normalize(actual) == normalize(expected)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find<F>(stmts: &[StatementInfo], pred: F) -> Option<&StatementInfo>
where
    F: Fn(&StatementInfo) -> bool,
{
    stmts.iter().find(|s| pred(s))
}

fn violation(rule: &Rule, stmt: &StatementInfo, suggestion: Option<String>) -> Violation {
    Violation {
        rule_id: rule.rule_id.clone(),
        rule_code: rule.code.clone(),
        ast_node_path: stmt.ast_node_path.clone(),
        estimated_rows_affected: None,
        suggested_safe_query: suggestion,
    }
}

fn rel_or_placeholder(stmt: &StatementInfo) -> String {
    stmt.relation
        .clone()
        .unwrap_or_else(|| "{table}".to_string())
}

fn suggest_delete(stmt: &StatementInfo) -> Option<String> {
    Some(format!(
        "DELETE FROM {} WHERE id = $1",
        rel_or_placeholder(stmt)
    ))
}

fn suggest_update(stmt: &StatementInfo) -> Option<String> {
    Some(format!(
        "UPDATE {} SET {{col}} = $1 WHERE id = $2",
        rel_or_placeholder(stmt)
    ))
}

fn suggest_truncate(stmt: &StatementInfo) -> Option<String> {
    Some(format!(
        "DELETE FROM {} WHERE created_at < NOW() - INTERVAL '90 days'",
        rel_or_placeholder(stmt)
    ))
}

fn suggest_migration() -> String {
    "Use a versioned migration tool (Flyway, Prisma Migrate, Alembic, Rails migrations)".to_string()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parser_for, Dialect, ParsedQuery};
    use crate::rules::engine::{EnforcementPolicy, Rule, RuleType, Severity};

    fn parse(sql: &str, dialect: Dialect) -> ParsedQuery {
        parser_for(dialect).parse(sql).expect("must parse")
    }

    fn make_rule(code: &str) -> Rule {
        let severity = Severity::Critical;
        Rule {
            rule_id: code.to_string(),
            code: code.to_string(),
            severity,
            // Derive the built-in action from the default policy so test rules
            // stay consistent with the severity→action mapping (R13).
            default_action: EnforcementPolicy::default().action_for(severity),
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        }
    }

    // ── VERICTO-001 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_001_blocks_delete_without_where() {
        let p = parse("DELETE FROM users", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-001"), &p).is_some());
    }

    #[test]
    fn vetro_001_allows_delete_with_where() {
        let p = parse("DELETE FROM users WHERE id = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-001"), &p).is_none());
    }

    // ── VERICTO-003 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_003_blocks_delete_where_always_true() {
        let p = parse("DELETE FROM users WHERE 1 = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-003"), &p).is_some());
    }

    // ── VERICTO-010 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_010_blocks_drop_table() {
        let p = parse("DROP TABLE users", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-010"), &p).is_some());
    }

    #[test]
    fn vetro_010_blocks_drop_database() {
        // sqlparser represents DROP DATABASE under the generic DropStmt
        let p = parse("DROP TABLE prod", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-010"), &p).is_some());
    }

    // ── VERICTO-011 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_011_blocks_truncate() {
        let p = parse("TRUNCATE TABLE orders", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-011"), &p).is_some());
    }

    // ── VERICTO-012 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_012_blocks_drop_schema() {
        let p = parse("DROP SCHEMA analytics CASCADE", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-012"), &p).is_some());
    }

    // ── VERICTO-013 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_013_blocks_drop_index_without_if_exists() {
        let p = parse("DROP INDEX idx_users_email", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-013"), &p).is_some());
    }

    #[test]
    fn vetro_013_allows_drop_index_with_if_exists() {
        let p = parse("DROP INDEX IF EXISTS idx_users_email", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-013"), &p).is_none());
    }

    // ── VERICTO-015 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_015_blocks_alter_table_drop_column() {
        let p = parse("ALTER TABLE users DROP COLUMN email", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-015"), &p).is_some());
    }

    // ── VERICTO-016 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_016_blocks_alter_table_rename() {
        let p = parse("ALTER TABLE users RENAME TO accounts", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-016"), &p).is_some());
    }

    // ── VERICTO-030 / VERICTO-042 ──────────────────────────────────────────────
    #[test]
    fn vetro_042_blocks_update_without_where() {
        let p = parse("UPDATE products SET price = 0", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-042"), &p).is_some());
        assert!(evaluate_rule(&make_rule("VERICTO-030"), &p).is_some());
    }

    #[test]
    fn vetro_042_allows_update_with_where() {
        let p = parse(
            "UPDATE products SET price = 0 WHERE id = 1",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-042"), &p).is_none());
    }

    // ── VERICTO-031 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_031_blocks_update_in_cte_without_where() {
        let sql = "WITH x AS (UPDATE sessions SET status = 'expired' RETURNING id) SELECT * FROM x";
        let p = parse(sql, Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-031"), &p).is_some());
    }

    // ── VERICTO-060 ──────────────────────────────────────────────────────────
    #[test]
    fn vetro_060_blocks_insert_without_columns() {
        let p = parse("INSERT INTO users VALUES (1, 'a')", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-060"), &p).is_some());
    }

    #[test]
    fn vetro_060_allows_insert_with_columns() {
        let p = parse(
            "INSERT INTO users (id, name) VALUES (1, 'a')",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-060"), &p).is_none());
    }

    // ── VERICTO-090: SQL injection tautology ─────────────────────────────────

    #[test]
    fn vetro_090_blocks_select_with_or_one_equals_one() {
        let p = parse("SELECT * FROM users WHERE id = 1 OR 1=1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_blocks_select_with_or_string_tautology() {
        let p = parse(
            "SELECT * FROM users WHERE name = 'x' OR 'a'='a'",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_blocks_delete_with_or_true() {
        let p = parse(
            "DELETE FROM sessions WHERE user_id = $1 OR 1=1",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_blocks_update_with_or_tautology() {
        let p = parse(
            "UPDATE users SET role = 'admin' WHERE id = 1 OR 1=1",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_some());
    }

    #[test]
    fn vetro_090_allows_select_with_legitimate_or() {
        // Legitimate: OR with two real conditions, neither always-true
        let p = parse(
            "SELECT * FROM products WHERE category = 'A' OR category = 'B'",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_none());
    }

    #[test]
    fn vetro_090_allows_select_without_where() {
        let p = parse("SELECT * FROM config", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_none());
    }

    #[test]
    fn vetro_090_allows_select_with_normal_where() {
        let p = parse(
            "SELECT * FROM users WHERE id = $1 AND status = 'active'",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_none());
    }

    #[test]
    fn vetro_090_blocks_deeply_nested_or_tautology() {
        // Tautology buried inside AND: `a AND (b OR 1=1)` — still caught
        let p = parse(
            "SELECT * FROM users WHERE status = 'active' AND (role = 'user' OR 1=1)",
            Dialect::Postgres,
        );
        assert!(evaluate_rule(&make_rule("VERICTO-090"), &p).is_some());
    }

    // ── VERICTO-050 / VERICTO-051: SELECT limit & star (Postgres path) ─────────

    #[test]
    fn vetro_050_allows_select_with_limit() {
        // Regression: `SELECT 1 LIMIT 1` was blocked because the pg_query
        // path never populated select_has_limit. It must now pass.
        let p = parse("SELECT 1 LIMIT 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-050"), &p).is_none());
    }

    #[test]
    fn vetro_050_allows_parameterized_select_with_where_and_limit() {
        // Regression lock for the vetro-regression suite case
        // (tests/proxy/allow-safe-queries.spec.ts): a parameterized SELECT with
        // explicit columns, a WHERE, and a LIMIT must NOT be flagged by
        // VERICTO-050. This mirrors the exact query the proxy receives over the
        // extended protocol ($1 is parsed as a ParamRef by pg_query).
        let p = parse(
            "SELECT user_id, email FROM users WHERE email = $1 LIMIT 1",
            Dialect::Postgres,
        );
        assert!(
            evaluate_rule(&make_rule("VERICTO-050"), &p).is_none(),
            "SELECT with explicit LIMIT must not trigger VERICTO-050"
        );
    }

    #[test]
    fn vetro_050_flags_select_without_limit() {
        let p = parse("SELECT id FROM users WHERE id = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-050"), &p).is_some());
    }

    #[test]
    fn vetro_051_flags_select_star_without_where() {
        let p = parse("SELECT * FROM users", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-051"), &p).is_some());
    }

    #[test]
    fn vetro_051_allows_select_star_with_where() {
        let p = parse("SELECT * FROM users WHERE id = 1", Dialect::Postgres);
        assert!(evaluate_rule(&make_rule("VERICTO-051"), &p).is_none());
    }

    // ── Custom rules (ast_condition_yaml) ────────────────────────────────────
    // These mirror the six "practical examples" documented at /docs/custom-rules,
    // using the exact YAML schema published there: a required `node_type`, an
    // optional `condition:` block, and the predicates where_clause/
    // where_always_true/target_list/has_limit/func_name/object_type.
    fn make_custom_rule(yaml: &str) -> Rule {
        Rule {
            rule_id: "CUSTOM-1".to_string(),
            code: "CUSTOM-1".to_string(),
            severity: Severity::High,
            default_action: EnforcementPolicy::default().action_for(Severity::High),
            rule_type: RuleType::Custom,
            ast_condition_yaml: Some(yaml.to_string()),
        }
    }

    // Example 1: block SELECT * (target_list: "*").
    #[test]
    fn custom_target_list_star_matches_select_star() {
        let rule = make_custom_rule(
            "rule: block-select-star\nnode_type: SelectStmt\ncondition:\n  target_list: \"*\"",
        );
        assert!(evaluate_rule(&rule, &parse("SELECT * FROM payments", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("SELECT id, email FROM payments", Dialect::Postgres)).is_none());
    }

    // Example 2: block UPDATE with no WHERE (where_clause: null).
    #[test]
    fn custom_where_clause_null_matches_update_without_where() {
        let rule = make_custom_rule(
            "rule: block-update-no-where\nnode_type: UpdateStmt\ncondition:\n  where_clause: null",
        );
        assert!(evaluate_rule(&rule, &parse("UPDATE users SET status = 'blocked'", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("UPDATE users SET status = 'blocked' WHERE id = 1", Dialect::Postgres)).is_none());
    }

    // Example 3: detect SQL-injection tautology (where_always_true: true).
    #[test]
    fn custom_where_always_true_matches_tautology() {
        let rule = make_custom_rule(
            "rule: block-or-tautology\nnode_type: DeleteStmt\ncondition:\n  where_always_true: true",
        );
        assert!(evaluate_rule(&rule, &parse("DELETE FROM users WHERE id = 1 OR 1 = 1", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("DELETE FROM users WHERE id = 1", Dialect::Postgres)).is_none());
    }

    // Example 4: block SLEEP/PG_SLEEP calls (node_type: FuncCall, func_name).
    #[test]
    fn custom_func_name_matches_sleep_case_insensitive() {
        let rule = make_custom_rule(
            "rule: block-sleep-calls\nnode_type: FuncCall\ncondition:\n  func_name: pg_sleep",
        );
        assert!(evaluate_rule(&rule, &parse("SELECT PG_SLEEP(10)", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("SELECT id FROM users", Dialect::Postgres)).is_none());
    }

    // Example 5: require LIMIT on SELECT (has_limit: false).
    #[test]
    fn custom_has_limit_false_matches_unbounded_select() {
        let rule = make_custom_rule(
            "rule: require-limit\nnode_type: SelectStmt\ncondition:\n  has_limit: false",
        );
        assert!(evaluate_rule(&rule, &parse("SELECT id FROM users", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("SELECT id FROM users LIMIT 100", Dialect::Postgres)).is_none());
    }

    // Example 6: block any DROP (node_type with no condition block).
    #[test]
    fn custom_no_condition_matches_any_drop() {
        let rule = make_custom_rule("rule: block-all-drops\nnode_type: DropStmt");
        assert!(evaluate_rule(&rule, &parse("DROP TABLE users", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("DROP INDEX idx_users_email", Dialect::Postgres)).is_some());
    }

    // object_type scopes a DROP to a single kind.
    #[test]
    fn custom_object_type_scopes_drop() {
        let rule = make_custom_rule(
            "node_type: DropStmt\ncondition:\n  object_type: index",
        );
        assert!(evaluate_rule(&rule, &parse("DROP INDEX idx_users_email", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("DROP TABLE users", Dialect::Postgres)).is_none());
    }

    // relation scopes a rule to a single table (case-insensitive, schema-agnostic).
    #[test]
    fn custom_relation_scopes_to_one_table() {
        let rule = make_custom_rule(
            "node_type: DeleteStmt\ncondition:\n  relation: payments\n  where_clause: null",
        );
        assert!(evaluate_rule(&rule, &parse("DELETE FROM payments", Dialect::Postgres)).is_some());
        // Schema-qualified name still matches on its final segment.
        assert!(evaluate_rule(&rule, &parse("DELETE FROM public.payments", Dialect::Postgres)).is_some());
        // A different table is left alone.
        assert!(evaluate_rule(&rule, &parse("DELETE FROM users", Dialect::Postgres)).is_none());
    }

    // alter_kind restricts an ALTER TABLE rule to one command subtype.
    #[test]
    fn custom_alter_kind_scopes_alter_table() {
        let rule = make_custom_rule(
            "node_type: AlterTableStmt\ncondition:\n  alter_kind: drop_column",
        );
        assert!(evaluate_rule(&rule, &parse("ALTER TABLE users DROP COLUMN email", Dialect::Postgres)).is_some());
        // A RENAME is a different subtype → no match.
        assert!(evaluate_rule(&rule, &parse("ALTER TABLE users RENAME TO accounts", Dialect::Postgres)).is_none());
    }

    // Without alter_kind, an AlterTableStmt rule fires for any ALTER subtype.
    #[test]
    fn custom_alter_table_no_kind_matches_any() {
        let rule = make_custom_rule("node_type: AlterTableStmt");
        assert!(evaluate_rule(&rule, &parse("ALTER TABLE users DROP COLUMN email", Dialect::Postgres)).is_some());
        assert!(evaluate_rule(&rule, &parse("ALTER TABLE users RENAME TO accounts", Dialect::Postgres)).is_some());
    }

    #[test]
    fn custom_unknown_node_type_never_matches() {
        let rule = make_custom_rule("node_type: BogusStmt");
        assert!(evaluate_rule(&rule, &parse("DELETE FROM users", Dialect::Postgres)).is_none());
    }
}
