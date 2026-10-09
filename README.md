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
vericto-engine = { git = "https://github.com/vericto/vericto-engine", tag = "v3.8.0" }
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
| VERICTO-086 | SQL text MySQL and the engine would read differently | MySQL text the engine cannot resolve to one statement with certainty, because of differences between MySQL's and the engine's reading of comments and string escapes. Every rule is evaluated on the statement MySQL executes (comments read by MySQL's rules, string literals under both string-escape modes, the strictest outcome kept); this blocks what that cannot settle. Not enabled through the rules slice, not a parse error: always blocks (flags under `monitor_mode`). (MySQL.) |
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
| VERICTO-085 | Read of a sensitive column | A query projects (or copies elsewhere) a column the host tagged as sensitive. Driven by `EnforcementPolicy::sensitive_columns`, not by the rules slice; High for `block`/`mask`, Medium for `flag`. See [Sensitive columns](#sensitive-columns-vericto-085). |
| VERICTO-087 | Access outside the agent's allowlist | The identity making the call (an API key, or the database user of a proxy session) references a table, column or write target its allowlist does not grant, or runs DDL. Every reference counts, predicates included. Driven by `EnforcementPolicy::access_policy`, not by the rules slice; blocks under `mode = enforce`, flags under `observe`. See [Agent access allowlists](#agent-access-allowlists-vericto-087). |

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
| `Security` | 070, 080, 081, 082, 085, 086, 087, 090 | Injection tautologies, `COPY … PROGRAM`, `DO` blocks, GRANT/REVOKE, sleep-based probing, reads of sensitive columns, MySQL text read differently, access outside an agent's allowlist. |
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

## Sensitive columns (VERICTO-085)

The rules above protect the database from the query. Sensitive-column protection
protects the data from whoever sent it: an agent that runs
`SELECT email, card FROM customers` breaks nothing, and still puts personal data
into an LLM's context. The host tags columns and gives each a policy; the engine
decides, on the AST alone, whether the query **reads** one.

```rust
use vericto_engine::{
    evaluate, Decision, Dialect, EnforcementPolicy, MaskStyle, SensitiveColumn, SensitivePolicy,
};

let policy = EnforcementPolicy {
    sensitive_columns: vec![SensitiveColumn {
        schema: None, // any schema
        table: "customers".into(),
        column: "email".into(),
        policy: SensitivePolicy::Mask,
        mask_style: MaskStyle::Email,
    }],
    ..EnforcementPolicy::default()
};

let outcome = evaluate("SELECT id, email FROM customers WHERE id = $1", Dialect::Postgres, &[], &policy);
assert_eq!(outcome.decision, Decision::Flag);
assert_eq!(outcome.rule_code.as_deref(), Some("VERICTO-085"));
// Execute this instead of the original:
assert_eq!(
    outcome.rewritten_query.as_deref(),
    Some(r"SELECT id, regexp_replace(email::text, '^(.)[^@]*(@.*)?$', E'\\1***\\2') AS email FROM customers WHERE id = $1")
);
assert_eq!(outcome.sensitive_columns[0].column, "email"); // for the audit trail
```

A tag is JSON-serializable as
`{"schema": "public", "table": "customers", "column": "email", "policy": "mask", "mask_style": "email"}`
(`schema` and `mask_style` optional). An unknown `policy` deserializes as `block`
and an unknown `mask_style` as `full`, so a value this engine does not know never
weakens the protection. With no tags the rule does not run at all — the only cost
is an `is_empty()` — and every outcome is exactly what it was before.

### What counts as a read

A column is read when it is a source of a **projected** expression: the select
list the client receives (every arm of a `UNION`), `RETURNING`, `COPY … TO`,
`DECLARE … CURSOR`, `PREPARE`. Derivation follows aliases, expressions, functions,
aggregates, casts, `CASE`, scalar subqueries, derived tables and CTEs (nested,
recursive and data-modifying). Using a column only to filter, join, group or order
— `WHERE`, `JOIN … ON`, `GROUP BY`, `HAVING`, `ORDER BY`, aggregate `FILTER`,
`OVER`, `EXISTS` — is not a read: nothing of it is projected.

Two things are deliberately treated as reads:

- **`*`, `t.*`, whole-row references** (`to_jsonb(c)`, `row_to_json(c)`,
  `SELECT c FROM customers c`) and `COPY table TO` touch **every** tagged column
  of the table. The engine has no schema, so it cannot tell which columns `*`
  expands to.
- **Copies** — `INSERT … SELECT`, `CREATE TABLE … AS`, `SELECT … INTO`,
  `CREATE VIEW`, `UPDATE … SET x = <tagged>`, `MERGE` — because they move the value
  somewhere untagged that the next query reads freely. Writing a tagged column
  into itself (`SET email = lower(email)`) is not a copy.

Names resolve conservatively: an unqualified table matches a tag in any schema, a
tag without a schema matches every schema, an unqualified column resolves against
every relation in scope, and identifiers compare case-insensitively. A false
positive is a blocked query with a clear message; a false negative is a leak.

### Decision

| Strictest policy read | Decision | `rewritten_query` |
|---|---|---|
| `flag` | `Flag` | `None` |
| `mask`, rewritten (Postgres, MySQL) | `Flag` — forward the **rewritten** query, record it | `Some(sql)` |
| `mask` that cannot be applied | `Block` | `None` |
| `block` | `Block` | `None` |

Strictness is `block > mask > flag`. A mask cannot be applied to `*` / whole-row /
`COPY table TO` (nothing to name — the message says to list the columns), to a
copy (masking would change stored data), on MySQL to a statement the engine
cannot print back faithfully (see below), or on Oracle and SQL Server (no rewrite
yet; blocking is the fail-safe direction). The column
verdict is a **floor** over the rules: the final decision is the stricter of the
two, and VERICTO-085 takes the flat fields only when it is the stricter one.
`monitor_mode` turns a column block into a flag and never applies a mask (the
would-be rewrite is in `suggested_safe_query`). With a `block` or `mask` tag
configured, a parse error always blocks
([`EnforcementPolicy::effective_parse_error`](src/rules/engine.rs)): a query the
engine cannot read cannot be shown not to read a tagged column.

### Mask rewrite (Postgres)

Each projected expression that derives from a masked column is replaced and
aliased to its original output name, and the statement is regenerated with
`pg_query`'s deparser (`$n` parameters are kept; comments and formatting are not,
so audit the original too). If anything about the rewrite fails, the query is
**blocked** — the unmasked query is never returned as approved.

| Style | Expression |
|---|---|
| `full` | `'[redacted]'::text` |
| `last4` | `'****' \|\| right(col::text, 4)` |
| `email` | `regexp_replace(col::text, '^(.)[^@]*(@.*)?$', '\1***\2')` |
| `hash` | `encode(sha256(convert_to(col::text, 'UTF8')), 'hex')` |

The tag's style applies only when the projected value **is** the column (a bare
reference, possibly through CTEs and subqueries). Any computed value —
`substring(card, 1, 4)`, `lower(email)`, `string_agg(…)` — is masked `full`:
applying `last4` to a caller-chosen substring would hand out any four characters.
A computed value masked `full` keeps the expression and discards its value,
`concat('[redacted]'::text, left((expr)::text, 0))`, so its `$n` parameters stay
in place and an aggregate still returns one row. A masked column becomes `text`. `ORDER BY` / `GROUP BY` items that referred to a
masked output keep sorting and grouping by the original value.

`tests/mask_equivalence.rs` runs every rewrite against a real Postgres and checks
that unmasked columns are identical row for row and masked ones match their style
(set `VERICTO_EQUIV_PSQL` to a `psql` command line).

### Mask rewrite (MySQL)

The same rewrite on MySQL — and on MariaDB and Aurora MySQL, which use the same
dialect — printed back from the sqlparser tree. The masks use only functions that
MySQL 5.7, 8.0, Aurora MySQL 2/3 and MariaDB all have, and return exactly what the
Postgres masks return for the same text (NULL stays NULL except under `full`):

| Style | Expression (`x` = `(CONVERT((col) USING utf8mb4) COLLATE utf8mb4_bin)`) |
|---|---|
| `full` | `'[redacted]'` (a computed value: `CONCAT('[redacted]', COALESCE(LEFT(x, 0), ''))`) |
| `last4` | `CONCAT('****', RIGHT(x, 4))` |
| `email` | `CASE WHEN CHAR_LENGTH(x) = 0 THEN x WHEN LOCATE('@', x, 2) > 0 THEN CONCAT(LEFT(x, 1), '***', SUBSTRING(x, LOCATE('@', x, 2))) ELSE CONCAT(LEFT(x, 1), '***') END` |
| `hash` | `SHA2(x, 256)` |

`x` gives the same characters and UTF-8 bytes whatever the column's or the
connection's charset, and its explicit collation lets the masked value be
`UNION`ed, compared or concatenated with a column of any collation
(`CAST(col AS CHAR)` raises "Illegal mix of collations" there). A replaced
projection keeps MySQL's output name: the column name as written, or an
unaliased expression's own text.

MySQL binds `?` by position. The engine numbers the client's `?` before parsing
and only forwards a rewrite whose `?` are all there, once each, in the same order
(`LIMIT ?, ?` keeps its comma form). It also checks that the unmodified statement
prints back to the client's own tokens — string literals verbatim, so the result
does not depend on the server's string-escape mode — and that the rewrite parses back to
itself. When any check fails, the query is **blocked**. Statements that block
instead of rewriting: optimizer hints, the SELECT modifiers sqlparser does not
know, bit literals, a `GROUP BY` / `HAVING` / `ORDER BY` expression naming a masked
alias, and everything sqlparser 0.52 does not parse (index hints, `LOCK IN SHARE
MODE`, `WITH ROLLUP`, `INTO OUTFILE`, …).

MySQL text that sqlparser would read differently from MySQL, because of how
MySQL reads comments and string escapes, cannot be analysed for sensitive columns
and resolves like a parse error (blocked under a `block` or `mask` tag). A quote
inside a string literal should be doubled rather than backslash-escaped.

`tests/mysql_mask_equivalence.rs` runs every rewrite against real MySQL servers,
over the text and the binary protocol (prepared statements with bound `?`), on
utf8mb4 tables with a non-default collation and a latin1 table, and compares the
masked values with the Postgres ones (set `VERICTO_EQUIV_MYSQL` to a JSON
connection object or array, with the `mysql2` Node driver on `NODE_PATH`).

## Agent access allowlists (VERICTO-087)

Sensitive-column tags are a denylist that applies to every caller. An agent
needs the opposite: an **allowlist** for its own identity, deny by default, so a
prompt-injected agent cannot reach a table, a column or a write it was not given.
The host selects the policy of the identity making the call — the API key on the
Runtime API, MCP and CLI; the database user of the session on the TCP proxy — and
passes it in `EnforcementPolicy::access_policy`.

```rust
use vericto_engine::{evaluate, AccessPolicy, Decision, Dialect, EnforcementPolicy};

let agent: AccessPolicy = serde_json::from_str(r#"{
    "mode": "enforce",
    "entries": [
        { "table": "orders",    "columns": "*",            "access": "read" },
        { "table": "customers", "columns": ["id", "name"], "access": "read" }
    ]
}"#).unwrap();
let policy = EnforcementPolicy { access_policy: Some(agent), ..EnforcementPolicy::default() };

let ok = evaluate("SELECT c.name, o.total FROM customers c JOIN orders o ON o.customer_id = c.id",
                  Dialect::Postgres, &[], &policy);
assert_eq!(ok.decision, Decision::Allow);

// A predicate on a column that is not granted lets the agent probe it: denied.
let probe = evaluate("SELECT id FROM customers WHERE email LIKE 'a%'", Dialect::Postgres, &[], &policy);
assert_eq!(probe.decision, Decision::Block);
assert_eq!(probe.rule_code.as_deref(), Some("VERICTO-087"));
assert_eq!(probe.ast_node_path.as_deref(), Some("AccessPolicy > customers.email (read)"));
assert_eq!(probe.access_denied[0].column.as_deref(), Some("email")); // for the audit trail
```

An entry is `{"schema": null, "table": "orders", "columns": "*" | ["id", …], "access": "read" | "read_write"}`
(`schema` optional = any schema). The policy is `{"mode": "observe" | "enforce", "ddl": "deny", "entries": [ … ]}`.
Absent or unknown values fail safe: `mode` → `enforce`, `access` → `read`,
`columns` other than `"*"` never widen to every column. The TCP proxy receives one
policy per database user ([`AccessPolicyMap`](src/access/mod.rs), with an optional
`"*"` default) and picks the session's with `for_user`. With `access_policy: None`
the analysis does not run at all and every outcome is exactly what it was before.

### What counts as access

Stricter than VERICTO-085, which counts projections: **every reference counts** —
the select list, `WHERE`, `JOIN … ON`/`USING`, `GROUP BY`, `HAVING`, `ORDER BY`,
windows, aggregate `FILTER`/`ORDER BY`, `LIMIT`, subqueries anywhere (including
`EXISTS`), CTEs, every arm of a set operation, `RETURNING`, upserts and `MERGE` —
because a predicate lets an agent probe a value it may not read. Every table in
`FROM` counts even when no column of it is named (`SELECT count(*) FROM t`).

- `*`, `t.*`, whole-row references, `COPY t TO`, `TABLE t` and MySQL `DESCRIBE t`
  need the table's entry to have `"columns": "*"`.
- **Writes need `read_write`**: `INSERT` (each listed column; no column list means
  every column), `UPDATE … SET` (each assigned column), `DELETE` and `REPLACE` (every
  column: a removed row loses all of them), `MERGE`, `COPY … FROM`, `LOCK`.
- **DDL is always denied**, and so are the statements that change who the session
  is or where unqualified names resolve (`SET ROLE`, `SET SESSION AUTHORIZATION`,
  `SET search_path`, `USE`). A statement kind not known to be harmless is denied;
  transaction control, settings, cursors, `PREPARE`/`EXECUTE` and `CALL` are allowed
  (functions are out of scope).
- **The catalogue** (`information_schema`, `pg_catalog`, `mysql`,
  `performance_schema`, `sys`) is denied unless an entry names that schema
  explicitly; an unqualified `pg_*` relation is `pg_catalog`'s, and MySQL `SHOW
  TABLES`/`COLUMNS`/`DATABASES`/`CREATE …` read `information_schema`.
- **Names resolve conservatively.** An unqualified column resolves against every
  relation in scope (subqueries see the outer ones) and must be allowed in all of
  them — otherwise it is denied and the message says to qualify it. An unqualified
  table matches an entry without a schema, or `public` (Postgres) / `dbo` (SQL
  Server). A qualifier that names nothing in scope is taken as a table.
- **`SET` is deny by default** under a policy: an unlisted setting can be
  dangerous even with a literal value (`session_replication_role`,
  `foreign_key_checks`, `unique_checks`, `sql_log_bin`,
  `default_transaction_read_only`, `check_function_bodies`). Allowed, with
  literal values only (no subquery, no function call): transaction control and
  characteristics (`BEGIN`, `START TRANSACTION`, `COMMIT`, `ROLLBACK`, savepoints,
  `SET [SESSION|LOCAL] TRANSACTION …`, `transaction_isolation`/`tx_isolation`),
  `SET NAMES`, `SET CHARACTER SET`, `character_set_results/client/connection`,
  `collation_connection`, `client_encoding`, `autocommit`, the time zone,
  `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`,
  `idle_session_timeout`, `wait_timeout`, `interactive_timeout`,
  `net_read_timeout`, `net_write_timeout`, `max_execution_time`,
  `sql_select_limit`, `sql_auto_is_null`, `session_track_*`, `application_name`,
  `DateStyle`, `IntervalStyle`, `extra_float_digits`, `work_mem`,
  `maintenance_work_mem`, `temp_buffers`, `bytea_output`,
  `standard_conforming_strings = on` (not `off`: it changes how escapes are read),
  `RESET ALL`, and user variables (`@v`) set to a literal. A multi-assignment `SET`
  is allowed only if every assignment is. **`sql_mode`** is allowed only as a
  value built from string literals, `@@sql_mode` and `CONCAT(…)` (Rails'
  `CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO')`),
  where no comma-separated mode is `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`,
  `ANSI`, `PIPES_AS_CONCAT` or a combination mode implying them (`ORACLE`,
  `MSSQL`, `DB2`, `POSTGRESQL`, `MAXDB`); those change how MySQL lexes the next
  statements. `SET GLOBAL`/`PERSIST`, `SET ROLE`, `SET SESSION AUTHORIZATION`,
  `SET search_path`, `set_config` and `USE` are denied.
- With an enforced policy, a parse error blocks
  ([`effective_parse_error_for`](src/rules/engine.rs)), except for the session
  statements above, which sqlparser 0.52 sometimes rejects (Django's `SET SESSION
  TRANSACTION ISOLATION LEVEL …`, `SET CHARACTER SET …`): they are matched on the
  normalized text, one statement only, with the same value rules, and keep the
  host's parse-error choice. Hosts that parse themselves call
  `policy.effective_parse_error_for(sql, dialect)` instead of
  `effective_parse_error()`. On MySQL the analysis runs on the statement MySQL
  executes (the 3.7.0 lexical normalization), every reading.

**Expected behaviour: an unqualified column inside a subquery counts against the
outer tables too.** SQL resolves `customer_id` in
`SELECT count(*) FROM customers WHERE id IN (SELECT customer_id FROM orders)` to
`orders` only if `orders` has that column, and the engine has no schema to know
it: if it does not, the name is the outer `customers.customer_id`, which the
agent could use to probe a column it was not granted. So the column must be
allowed in `customers` as well, and the query is denied with
`… (read): \`customer_id\` is unqualified and may belong to several tables;
qualify the column`. **Fix: qualify the column** —
`SELECT count(*) FROM customers c WHERE c.id IN (SELECT o.customer_id FROM orders o)`
is allowed.

### Precedence with sensitive columns

1. A `block` tag always wins (VERICTO-085 keeps the flat fields).
2. Not allowed → VERICTO-087: `Block` under `enforce`, `Flag` under `observe`.
3. Allowed and tagged `mask` → the VERICTO-085 rewrite.
4. Otherwise allowed (a `flag` tag still flags).

A denial clears any rewrite (a refused query is never forwarded, masked or not);
under `observe` an allowed mask keeps its rewrite. `monitor_mode` turns a denial
into a flag. `EvaluationOutcome::access_denied` lists every denied reference
(`{"schema", "table", "column", "needed": "read" | "write" | "ddl"}`), also in
`observe` mode.

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
│   ├── access/         ← VERICTO-087: agent allowlists — policy types, statement classes, verdict (runs the sensitive/ walkers in access mode)
│   ├── sensitive/      ← VERICTO-085: sensitive-column derivation + mask rewrite (pg.rs, sql.rs, mysql.rs)
│   │   ├── mod.rs      ← tags, scopes, lineage, verdict
│   │   ├── pg.rs       ← pg_query walker + rewrite
│   │   └── sql.rs      ← sqlparser walker (MySQL/Oracle/MSSQL)
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

Copyright 2026 Vericto S.A.S. Elastic License 2.0 — source-available, community PRs
welcome, no managed-service resale. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

For a managed-service license contact [enterprise@vericto.com](mailto:enterprise@vericto.com).
