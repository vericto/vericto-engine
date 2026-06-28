# vetro-engine

> Deterministic SQL AST evaluation engine — the open core of [Vetro](https://vetro.dev).

[![CI](https://github.com/donkan168/vetro-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/donkan168/vetro-engine/actions/workflows/ci.yml)
[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

`vetro-engine` parses every SQL query into its full Abstract Syntax Tree using
[pg_query](https://github.com/pganalyze/pg_query.rs) (PostgreSQL's own internal
parser) and [sqlparser-rs](https://github.com/sqlparser-rs/sqlparser-rs), then
evaluates it against a ruleset **deterministically** — same input always produces
the same result, no ML, no thresholds, no false positives.

This crate is consumed by:
- **[vetro-proxy](https://github.com/donkan168/vetro-proxy)** — TCP wire-protocol proxy deployed in customer infrastructure
- **vetro-eval** (private) — HTTP evaluation sidecar used by the Vetro SaaS API

---

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vetro-engine = { git = "https://github.com/donkan168/vetro-engine", tag = "v2.1.0" }
```

### Quick example

```rust
use vetro_engine::{
    evaluate, Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity,
};

let rules = vec![Rule {
    rule_id: "r1".into(),
    code: "VETRO-001".into(),          // DELETE without WHERE
    severity: Severity::Critical,
    default_action: EnforcementAction::Block,
    rule_type: RuleType::Standard,
    ast_condition_yaml: None,
}];

// The host injects the workspace enforcement policy; `default()` maps
// Critical/High → Block, Medium → Flag, Low/Informational → Monitor.
let policy = EnforcementPolicy::default();
let outcome = evaluate("DELETE FROM users", Dialect::Postgres, &rules, &policy);
assert_eq!(outcome.decision, Decision::Block);
assert_eq!(outcome.rule_code.as_deref(), Some("VETRO-001"));
assert_eq!(outcome.ast_node_path.as_deref(), Some("DeleteStmt > WhereClause = NULL"));
```

### Evaluate with a full ruleset

```rust
use vetro_engine::{evaluate, Dialect, EnforcementPolicy};
use vetro_engine::rules::engine::{Decision, Rule};

fn is_safe(sql: &str, rules: &[Rule], policy: &EnforcementPolicy) -> bool {
    evaluate(sql, Dialect::Postgres, rules, policy).decision == Decision::Allow
}
```

---

## Supported dialects

| Dialect    | Parser backend                     |
|------------|------------------------------------|
| PostgreSQL | `pg_query` 5.1 (libpg_query 16)     |
| MySQL      | `sqlparser-rs`                     |
| SQL Server | `sqlparser-rs`                     |
| Oracle     | `sqlparser-rs`                     |

---

## Standard rules (VETRO-*)

Standard rules are identified by code and evaluated by built-in Rust logic — no
YAML required. The complete catalogue is below, grouped by severity. Each rule
is a deterministic predicate over the parsed AST in
[`src/rules/evaluator.rs`](src/rules/evaluator.rs); severity drives the default
enforcement action via the policy (Critical/High → Block, Medium → Flag,
Low/Informational → Monitor).

> Dialect notes: PostgreSQL is parsed with `libpg_query`; MySQL/Oracle/MSSQL
> with `sqlparser-rs`. Differences are called out per rule.

### Critical

| Code | Name | What it detects |
|---|---|---|
| VETRO-001 | DELETE without WHERE | A `DELETE` with no `WHERE` — removes every row of the table. |
| VETRO-003 | DELETE with always-true WHERE | A `DELETE` whose `WHERE` is trivially true (`1=1`, `id = id`, `NOT FALSE`, `WHERE 1`) — semantically WHERE-less. |
| VETRO-010 | DROP TABLE / DATABASE | `DROP TABLE` or `DROP DATABASE` — irreversible loss of a relation/database. Excludes `INDEX` (VETRO-013) and `SCHEMA` (VETRO-012). |
| VETRO-011 | TRUNCATE TABLE | `TRUNCATE` — empties a table, non-transactional/unfiltered by design. |
| VETRO-012 | DROP SCHEMA | `DROP SCHEMA` — drops a whole namespace and everything in it. |
| VETRO-030 | UPDATE without WHERE (primary tables) | An `UPDATE` with no effective `WHERE`. Same predicate as VETRO-042; separate code so a workspace can scope/severity it independently. |
| VETRO-042 | UPDATE without WHERE | An `UPDATE` with no `WHERE` (or an always-true one) — rewrites every row. |
| VETRO-080 | COPY … TO/FROM PROGRAM | `COPY … PROGRAM '…'` runs a shell command on the database host — remote code execution / data-exfiltration channel. (PostgreSQL.) |
| VETRO-081 | DO anonymous code block | `DO $$ … $$` runs an arbitrary PL/pgSQL body that can hide any DML/DDL; opaque to the SQL parser. (PostgreSQL.) |
| VETRO-090 | OR tautology in WHERE (SQL injection) | A `WHERE` with a trivially-true `OR` branch (`… OR 1=1`) — the canonical injection bypass. Covers SELECT/DELETE/UPDATE at any depth. |

### High

| Code | Name | What it detects |
|---|---|---|
| VETRO-002 | DELETE with LIMIT 0 | A `DELETE … LIMIT 0` — deletes nothing, usually a misconfigured scope. (MySQL/SQLite; no `DELETE … LIMIT` syntax on PostgreSQL.) |
| VETRO-013 | DROP INDEX without IF EXISTS | `DROP INDEX` lacking `IF EXISTS` — errors if the index is missing, breaking scripts. |
| VETRO-015 | ALTER TABLE DROP COLUMN | Drops a column — irreversible data loss. |
| VETRO-016 | ALTER TABLE RENAME | Renames a table or column — breaks any code referencing the old name. |
| VETRO-017 | ALTER TABLE DROP CONSTRAINT | Drops a FK/PK/CHECK (or `DROP PRIMARY KEY`) — silently removes a data-integrity invariant. |
| VETRO-018 | ALTER TABLE ALTER COLUMN TYPE | Changes a column type — table rewrite, potentially lossy/blocking cast. |
| VETRO-019 | ALTER TABLE DISABLE TRIGGER / RLS | `DISABLE TRIGGER` or `DISABLE ROW LEVEL SECURITY` — disables a protection. |
| VETRO-031 | UPDATE in CTE without WHERE | A data-modifying CTE (`WITH x AS (UPDATE … )`) whose `UPDATE` has no WHERE. |
| VETRO-033 | DELETE in subquery/CTE without WHERE | A nested `DELETE` with no WHERE inside a subquery or CTE. |
| VETRO-040 | INSERT INTO … SELECT without filter | `INSERT … SELECT` whose source has no filter — copies every source row. |
| VETRO-070 | SLEEP() / PG_SLEEP() | A sleep-family call (`sleep`, `pg_sleep`, `pg_sleep_for`, `pg_sleep_until`) anywhere in the query — DoS / time-based blind injection probing. |
| VETRO-082 | GRANT / REVOKE | A `GRANT` or `REVOKE` — privilege escalation or accidental lockout. |
| VETRO-083 | MERGE | `MERGE INTO …` — can mass-mutate the target like an UPDATE/DELETE with no effective WHERE. |
| VETRO-084 | CREATE TABLE AS SELECT | `CREATE TABLE … AS SELECT …` / `SELECT … INTO` — bulk data copy that can duplicate a whole table. |

### Medium

| Code | Name | What it detects |
|---|---|---|
| VETRO-050 | SELECT without LIMIT | A top-level `SELECT` with no `LIMIT`/`FETCH`/`TOP` — unbounded read. Scoped to the client-visible query, not inner subqueries. |
| VETRO-051 | SELECT * without WHERE | `SELECT *` with no `WHERE` — unfiltered full-column scan; detected at any nesting depth. |
| VETRO-061 | INSERT batch > 10k rows | `INSERT … VALUES` with more than 10,000 row tuples — oversized batch. |

### Low

| Code | Name | What it detects |
|---|---|---|
| VETRO-060 | INSERT without explicit columns | `INSERT` with no explicit column list — relies on column order, breaks on schema change. |

The host application owns the rule *catalogue* (which codes are active, with
what severity/action per workspace); the engine owns the *detection logic*. The
proxy's built-in fallback catalogue
([`vetro-proxy/src/tcp/evaluator.rs`](https://github.com/donkan168/vetro-proxy))
mirrors this table verbatim.

## Custom rules (YAML)

You can define domain-specific rules using YAML AST conditions. The condition
supports these fields: `node_type` (required — `DeleteStmt`, `UpdateStmt`,
`DropStmt`, `TruncateStmt`, `InsertStmt`, `SelectStmt`, or `AlterTableStmt`),
`relation` (optional — matches the target table, case-insensitive, ignoring
schema qualifier and quoting), and `where_null` (optional — when `true`, only
matches statements with no WHERE clause):

```rust
use vetro_engine::rules::engine::{EnforcementAction, Rule, RuleType, Severity};

let custom = Rule {
    rule_id: "custom-1".into(),
    code: "CUSTOM-001".into(),
    severity: Severity::High,
    default_action: EnforcementAction::Block,
    rule_type: RuleType::Custom,
    ast_condition_yaml: Some(r#"
rule: block_orders_delete
node_type: DeleteStmt
relation: orders
where_null: true
"#.into()),
};
```

---

## Architecture

```
vetro-engine/
├── src/
│   ├── lib.rs          ← public API + evaluate() convenience fn
│   ├── error.rs        ← ProxyError, Result
│   ├── parser/
│   │   ├── mod.rs      ← SqlParser trait, parser_for(), Dialect enum
│   │   ├── postgres.rs ← pg_query backend
│   │   ├── mysql.rs    ← sqlparser-rs backend
│   │   ├── oracle.rs   ← sqlparser-rs backend
│   │   ├── mssql.rs    ← sqlparser-rs backend
│   │   ├── pg_ast.rs   ← pg_query AST normalization
│   │   └── walk.rs     ← AST traversal helpers
│   └── rules/
│       ├── mod.rs
│       ├── engine.rs    ← Rule, RuleEngine, Decision, EnforcementPolicy, EvaluationOutcome
│       ├── evaluator.rs ← per-rule evaluation logic (VETRO-* codes)
│       └── properties.rs ← property-based tests (test-only)
└── tests/               ← integration tests (audit regression, README↔code sync)
```

---

## License

Elastic License 2.0 — source-available, community PRs welcome, no managed-service
resale. See [LICENSE](LICENSE).

For a managed-service license contact [hola@vetro.dev](mailto:hola@vetro.dev).
