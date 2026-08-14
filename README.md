# vericto-engine

> Deterministic SQL AST evaluation engine — the open core of [Vericto](https://vericto.com).

[![CI](https://github.com/vericto/vericto-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/vericto/vericto-engine/actions/workflows/ci.yml)
[![License: ELv2](https://img.shields.io/badge/license-Elastic--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

`vericto-engine` parses every SQL query into its full Abstract Syntax Tree using
[pg_query](https://github.com/pganalyze/pg_query.rs) (PostgreSQL's own internal
parser) and [sqlparser-rs](https://github.com/sqlparser-rs/sqlparser-rs), then
evaluates it against a ruleset **deterministically** — same input always produces
the same result, no ML, no thresholds, no false positives.

This crate is consumed by:
- **[vericto-proxy](https://github.com/vericto/vericto-proxy)** — TCP wire-protocol proxy deployed in customer infrastructure
- **vericto-eval** (private) — HTTP evaluation sidecar used by the Vericto SaaS API

---

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vericto-engine = { git = "https://github.com/vericto/vericto-engine", tag = "v3.5.1" }
```

### Quick example

```rust
use vericto_engine::{
    evaluate, Decision, Dialect, EnforcementAction, EnforcementPolicy, Rule, RuleType, Severity,
};

let rules = vec![Rule {
    rule_id: "r1".into(),
    code: "VERICTO-001".into(),          // DELETE without WHERE
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
assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-001"));
assert_eq!(outcome.ast_node_path.as_deref(), Some("DeleteStmt > WhereClause = NULL"));
```

### Evaluate with a full ruleset

```rust
use vericto_engine::{evaluate, Dialect, EnforcementPolicy};
use vericto_engine::rules::engine::{Decision, Rule};

fn is_safe(sql: &str, rules: &[Rule], policy: &EnforcementPolicy) -> bool {
    evaluate(sql, Dialect::Postgres, rules, policy).decision == Decision::Allow
}
```

A query may violate several rules at once; the outcome reports the one with the
highest severity. When several share the top severity, the one with the lowest
`code` wins. The order of the `rules` slice never affects the result, so you do
not need to sort it — the same query and ruleset always report the same
violation.

### Every violation, not only the winner

The flat fields carry one violation because that is what the hosts need: a wire
proxy builds a single native protocol error, and an audit row has one
`rule_id_triggered`. `outcome.violations` carries the full set alongside it.

```rust
let outcome = evaluate(sql, Dialect::Postgres, &rules, &policy);

// The verdict — derived from the winner alone.
if outcome.decision == Decision::Block { /* reject */ }

// Everything the query is guilty of, worst first.
for v in &outcome.violations {
    println!("{} {:?} → {:?}  {}", v.rule_code, v.severity, v.action, v.ast_node_path);
}
```

Guarantees, each pinned by a property test:

- `violations[0]` **is** the winner reported in the flat fields.
- Ordered severity descending, then rule code ascending — never by the order you
  passed the rules in.
- `decision` and `action` come from the winner **alone**. A longer list can never
  change whether a query is blocked, so the field is safe to ignore.
- Contains exactly the rules that fire when each is evaluated on its own — nothing
  dropped, nothing invented.
- Empty exactly when no rule matched. A parse error also reports an empty set:
  nothing was evaluated, so there is no violation to report.

Each entry carries its **own** resolved `severity` and `action`, so a caller
rendering the set does not re-derive them and cannot disagree with the decision.
Note that a per-class cap can make a lower-severity violation resolve to a
*stronger* action than the winner — `schema_migration_cap: Monitor` softens a
Critical `DROP TABLE` while a High `DELETE` still blocks. The winner is chosen by
severity, not by action.

Before this field, a host that wanted the full set had to call `evaluate()` once
per rule, re-parsing the SQL every time: measured at roughly **20× the cost** on a
28-rule catalogue. Collecting them costs nothing measurable, because the evaluator
already ran every rule and simply discarded the rest.

---

## Supported dialects

| Dialect    | Parser backend                       |
|------------|--------------------------------------|
| PostgreSQL | `pg_query` 6.2 (libpg_query, PG 17)  |
| MySQL      | `sqlparser-rs` 0.52                  |
| SQL Server | `sqlparser-rs` 0.52                  |
| Oracle     | `sqlparser-rs` 0.52                  |

---

## Standard rules (VERICTO-*)

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
| VERICTO-001 | DELETE without WHERE | A `DELETE` with no `WHERE` — removes every row of the table. |
| VERICTO-003 | DELETE with always-true WHERE | A `DELETE` whose `WHERE` is trivially true (`1=1`, `id = id`, `NOT FALSE`, `WHERE 1`, `1 IN (1,2)`, `1 BETWEEN 0 AND 2`, `'x' LIKE '%'`) — semantically WHERE-less. See [what counts as always-true](#what-counts-as-always-true). |
| VERICTO-010 | DROP TABLE / DATABASE | `DROP TABLE` or `DROP DATABASE` — irreversible loss of a relation/database. Excludes `INDEX` (VERICTO-013) and `SCHEMA` (VERICTO-012). |
| VERICTO-011 | TRUNCATE TABLE | `TRUNCATE` — empties a table, non-transactional/unfiltered by design. |
| VERICTO-012 | DROP SCHEMA | `DROP SCHEMA` — drops a whole namespace and everything in it. |
| VERICTO-030 | UPDATE without WHERE (primary tables) | An `UPDATE` with no effective `WHERE`. Same predicate as VERICTO-042; separate code so a workspace can scope/severity it independently. |
| VERICTO-042 | UPDATE without WHERE | An `UPDATE` with no `WHERE` (or an always-true one) — rewrites every row. |
| VERICTO-080 | COPY … TO/FROM PROGRAM | `COPY … PROGRAM '…'` runs a shell command on the database host — remote code execution / data-exfiltration channel. (PostgreSQL.) |
| VERICTO-081 | DO anonymous code block | `DO $$ … $$` runs an arbitrary PL/pgSQL body that can hide any DML/DDL; opaque to the SQL parser. (PostgreSQL.) |
| VERICTO-090 | OR tautology in WHERE (SQL injection) | A `WHERE` with a trivially-true `OR` branch (`… OR 1=1`) — the canonical injection bypass. Covers SELECT/DELETE/UPDATE at any depth. |

### High

| Code | Name | What it detects |
|---|---|---|
| VERICTO-002 | DELETE with LIMIT 0 | A `DELETE … LIMIT 0` — deletes nothing, usually a misconfigured scope. (MySQL/SQLite; no `DELETE … LIMIT` syntax on PostgreSQL.) |
| VERICTO-013 | DROP INDEX without IF EXISTS | `DROP INDEX` lacking `IF EXISTS` — errors if the index is missing, breaking scripts. |
| VERICTO-015 | ALTER TABLE DROP COLUMN | Drops a column — irreversible data loss. |
| VERICTO-016 | ALTER TABLE RENAME | Renames a table or column — breaks any code referencing the old name. |
| VERICTO-017 | ALTER TABLE DROP CONSTRAINT | Drops a FK/PK/CHECK (or `DROP PRIMARY KEY`) — silently removes a data-integrity invariant. |
| VERICTO-018 | ALTER TABLE ALTER COLUMN TYPE | Changes a column type — table rewrite, potentially lossy/blocking cast. |
| VERICTO-019 | ALTER TABLE DISABLE TRIGGER / RLS | `DISABLE TRIGGER` or `DISABLE ROW LEVEL SECURITY` — disables a protection. |
| VERICTO-031 | UPDATE in CTE without WHERE | A data-modifying CTE (`WITH x AS (UPDATE … )`) whose `UPDATE` has no WHERE. |
| VERICTO-033 | DELETE in subquery/CTE without WHERE | A nested `DELETE` with no WHERE inside a subquery or CTE. |
| VERICTO-040 | INSERT INTO … SELECT without filter | `INSERT … SELECT` whose source has no filter — copies every source row. |
| VERICTO-070 | SLEEP() / PG_SLEEP() | A sleep-family call (`sleep`, `pg_sleep`, `pg_sleep_for`, `pg_sleep_until`) anywhere in the query — DoS / time-based blind injection probing. |
| VERICTO-082 | GRANT / REVOKE | A `GRANT` or `REVOKE` — privilege escalation or accidental lockout. |
| VERICTO-083 | MERGE | `MERGE INTO …` — can mass-mutate the target like an UPDATE/DELETE with no effective WHERE. |
| VERICTO-084 | CREATE TABLE AS SELECT | `CREATE TABLE … AS SELECT …` / `SELECT … INTO` — bulk data copy that can duplicate a whole table. |

### Medium

| Code | Name | What it detects |
|---|---|---|
| VERICTO-050 | SELECT without LIMIT | A top-level `SELECT` with no `LIMIT`/`FETCH`/`TOP` — unbounded read. Scoped to the client-visible query, not inner subqueries. |
| VERICTO-051 | SELECT * without WHERE | `SELECT *` with no `WHERE` — unfiltered full-column scan; detected at any nesting depth. |
| VERICTO-061 | INSERT batch > 10k rows | `INSERT … VALUES` with more than 10,000 row tuples — oversized batch. |

### Low

| Code | Name | What it detects |
|---|---|---|
| VERICTO-060 | INSERT without explicit columns | `INSERT` with no explicit column list — relies on column order, breaks on schema change. |

The host application owns the rule *catalogue* (which codes are active, with
what severity/action per workspace); the engine owns the *detection logic*. The
proxy's built-in fallback catalogue
([`vericto-proxy/src/tcp/evaluator.rs`](https://github.com/vericto/vericto-proxy))
mirrors this table verbatim.

## What counts as always-true

Several rules turn on whether a `WHERE` clause actually filters anything.
VERICTO-003/030/042 treat an always-true `WHERE` as WHERE-less, VERICTO-090 looks
for one as an `OR` branch, and VERICTO-040 asks whether an `INSERT … SELECT`
source is bounded. All four share one predicate, so what it recognises is worth
stating precisely.

**A predicate qualifies only when every operand is a literal.** Its truth value
then cannot depend on the row, so it filters nothing:

| Form | Example |
|---|---|
| boolean / truthy literal | `WHERE TRUE`, `WHERE 1` |
| constant comparison | `1=1`, `2 > 1`, `'a'='a'` |
| constant `IN` list | `1 IN (1, 2)` |
| constant `BETWEEN` | `1 BETWEEN 0 AND 2` |
| constant `LIKE '%'` | `'x' LIKE '%'` |
| `NOT <always-false>` | `NOT FALSE`, `NOT 1=2` |
| `AND` of always-true, `OR` with any always-true | `1=1 AND 2>1` |

Plus one deliberate exception: the column self-comparison `id = id`, the canonical
trick for neutralising a `WHERE`, which has no legitimate use.

### What does not count, and why

A predicate that references a column is a real filter, even when it reads like a
tautology. SQL's three-valued logic is the reason — these drop every row where the
column is `NULL`:

```sql
WHERE id IS NOT NULL   -- filters: NULL rows are excluded
WHERE name LIKE '%'    -- filters: NULL names are excluded
WHERE id IN (1, 2)     -- filters, obviously
```

Reporting those would be a false positive on rules that reject live traffic, so
they are correct behaviour rather than gaps.

Two further cases are **deliberate false negatives**, since over-reporting is the
dangerous direction for a blocking rule:

- **`NOT IN` is never treated as the negation of `IN`.** With a `NULL` in the list
  the predicate evaluates to `NULL`, not true: `1 NOT IN (2, NULL)` matches *no*
  rows. Only the positive form is decided.
- **A `NULL` anywhere in an `IN` list disqualifies it**, so `1 IN (1, NULL)` is not
  reported even though it does match every row.

Semantic tautologies over columns (`WHERE id = 1 OR id > 0`) are out of scope:
deciding them needs the column's domain, which a deterministic parser cannot know.

## Rule classes and per-channel caps

Every built-in code carries a static [`RuleClass`](src/rules/engine.rs) — the
*kind* of risk it represents, independent of the channel it is evaluated on:

| Class | Codes | What it covers |
|---|---|---|
| `SchemaMigration` | 010–019 | DROP TABLE/DATABASE/SCHEMA, TRUNCATE, ALTER TABLE, DROP INDEX. Destructive against a live database, but normal in a versioned migration. |
| `DataMutation` | 001, 002, 003, 030, 031, 033, 040, 042, 083, 084 | Data mutation without adequate scope. Dangerous on *any* channel — a WHERE-less DELETE is never intended, even in a migration. |
| `Security` | 070, 080, 081, 082, 090 | Injection tautologies, `COPY … PROGRAM`, `DO` blocks, GRANT/REVOKE, sleep-based probing. |
| `Performance` | 050, 051, 060, 061 | Best-practice / performance hints. Advisory. |

Custom rules and any unrecognized code classify as `DataMutation` — the
conservative default, since that class is never softened by a cap.

The class exists so a host can modulate the resulting *action* per channel
without the detection logic ever knowing about the channel.
`EnforcementPolicy::schema_migration_cap` is the only cap today:

```rust
use vericto_engine::{EnforcementAction, EnforcementPolicy};

// A CI channel: migration DDL reports instead of blocking, because a versioned
// migration legitimately contains DROP/ALTER/TRUNCATE. Everything else keeps
// the full policy in force.
let ci = EnforcementPolicy {
    schema_migration_cap: Some(EnforcementAction::Flag),
    ..EnforcementPolicy::default()
};
```

Under that policy `DROP TABLE users` resolves to `Flag` while
`DELETE FROM users` still resolves to `Block`. The cap is applied as
`action.min(cap)` — a **ceiling, never a floor**, so it can only ever *lower* an
action and can never make a channel more aggressive than the base policy. Left
as `None` (the default) it has no effect at all, which is also how older
serialized policies that predate the field deserialize.

## Custom rules (YAML)

You can define domain-specific rules using YAML AST conditions. A rule has a
required `node_type` and an optional `condition:` block of predicates (omit it
to fire for every node of that type):

- `node_type` (required): `DeleteStmt`, `UpdateStmt`, `DropStmt`,
  `TruncateStmt`, `InsertStmt`, `SelectStmt`, `AlterTableStmt`, or `FuncCall`.

Predicates under `condition:`:

| Predicate | Applies to | Meaning |
|---|---|---|
| `relation: <table>` | any | Scope to a table (case-insensitive, schema-agnostic) |
| `where_clause: null` | DELETE/UPDATE/SELECT | No WHERE clause |
| `where_always_true: true` | DELETE/UPDATE/SELECT | WHERE that matches every row: trivially true (`1=1`, `true`, `1 IN (1,2)`) or with an always-true OR branch (`id = 5 OR 1=1`). See [what counts as always-true](#what-counts-as-always-true) |
| `target_list: "*"` | SELECT | `SELECT *` |
| `has_limit: false` | SELECT | No LIMIT |
| `func_name: <name>` | FuncCall | Any function by name, case-insensitive and schema-agnostic (`pg_catalog.pg_sleep` matches `pg_sleep`) — e.g. `pg_read_file`, `dblink`, `lo_export` |
| `object_type: <kind>` | DropStmt | `table`/`database`/`schema`/`index` |
| `alter_kind: <kind>` | AlterTableStmt | `drop_column`/`rename`/`drop_constraint`/`alter_column_type`/`disable_trigger` |

```rust
use vericto_engine::rules::engine::{EnforcementAction, Rule, RuleType, Severity};

let custom = Rule {
    rule_id: "custom-1".into(),
    code: "CUSTOM-001".into(),
    severity: Severity::High,
    default_action: EnforcementAction::Block,
    rule_type: RuleType::Custom,
    ast_condition_yaml: Some(r#"
rule: block_orders_delete
node_type: DeleteStmt
condition:
  relation: orders
  where_clause: null
"#.into()),
};
```

---

## Architecture

```
vericto-engine/
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
│       ├── evaluator.rs ← per-rule evaluation logic (VERICTO-* codes)
│       └── properties.rs ← property-based tests (test-only)
└── tests/               ← integration tests (audit regression, README↔code sync)
```

---

## License

Elastic License 2.0 — source-available, community PRs welcome, no managed-service
resale. See [LICENSE](LICENSE).

For a managed-service license contact [hola@vericto.com](mailto:hola@vericto.com).
