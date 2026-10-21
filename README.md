# vericto-engine

> Deterministic SQL AST evaluation engine — the source-available core of [Vericto](https://vericto.com).

[![CI](https://github.com/vericto/vericto-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/vericto/vericto-engine/actions/workflows/ci.yml)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue.svg)](LICENSING.md)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

`vericto-engine` parses each SQL query into its full Abstract Syntax Tree using
[pg_query](https://github.com/pganalyze/pg_query.rs) (PostgreSQL's own internal
parser) and [sqlparser-rs](https://github.com/sqlparser-rs/sqlparser-rs), then
evaluates it against a ruleset **deterministically** — the same input always
produces the same result, with no ML and no thresholds.

Deterministic is not the same as free of false positives. Every false positive
found so far has been fixed with a regression test that pins it, for example
VERICTO-010 on `DROP VIEW` / `DROP FUNCTION`, VERICTO-040 on a filtered
`INSERT … SELECT` and VERICTO-050 on a `UNION … LIMIT` (see the
[CHANGELOG](CHANGELOG.md)). To trial a ruleset against real traffic before it
blocks, set `monitor_mode` on the `EnforcementPolicy`: a rule match that would
block is reported as a `Flag` instead (a parse error still follows the host's
`parse_error` setting).

This crate is consumed by:
- **[vericto-proxy](https://github.com/vericto/vericto-proxy)** — TCP wire-protocol proxy deployed in customer infrastructure
- **vericto-eval** (private) — HTTP evaluation sidecar used by the Vericto SaaS API

---

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
vericto-engine = { git = "https://github.com/vericto/vericto-engine", tag = "v4.4.0" }
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

A query (or a script of several statements) may violate several rules at once.
Each violation's action is resolved through the policy on its own, and the
decision is the **strongest** of those actions (Block > Flag > Monitor), never
weaker than any single violation's. The outcome reports the violation that holds
it: among those with the same action, the highest severity, then the lowest
`code`. The order of the `rules` slice never affects the result, so you do not
need to sort it — the same query and ruleset always report the same violation.

Before 4.2.0 the winner was the highest severity, and its action became the
decision. Under a CI policy (`schema_migration_cap: Some(Flag)`) the script
`DROP TABLE a; UPDATE accounts SET balance = 0;` therefore reported the capped
DROP (VERICTO-010, Flag) and passed, although its WHERE-less UPDATE
(VERICTO-030) blocks. Since 4.2.0 it blocks with VERICTO-030.

### The standard ruleset and versions

A host with no ruleset of its own — before its first rule sync, after a failed
one, or checking files offline — evaluates with `standard_rules()`: every
built-in rule of the [catalogue](#standard-rules-vericto-) at its default
severity, ready to pass to `evaluate`. `STANDARD_RULES` is the same table as
`StandardRule` entries, with each rule's `code`, `severity`, `class` (as
`RuleClass::for_code`), the `default_action` the default policy maps that
severity to, and `engine_driven` for VERICTO-085, 086 and 087, which the policy
drives and the rules slice neither enables nor disables. A test keeps the table
equal to the catalogue below.

`ENGINE_VERSION` is this crate's version (`"4.4.0"`) and
`STANDARD_RULESET_VERSION` is `standard@<engine version>` (`"standard@4.4.0"`):
a built-in rule's predicate lives in the engine, so what the standard ruleset
detects changes with the engine version. Print them with a verdict to say what
it was evaluated with.

```rust
use vericto_engine::{
    evaluate, standard_rules, Dialect, EnforcementPolicy, STANDARD_RULESET_VERSION,
};

let outcome = evaluate(sql, Dialect::Postgres, &standard_rules(), &EnforcementPolicy::default());
println!("{:?} ({STANDARD_RULESET_VERSION})", outcome.decision);
```

### Every violation, not only the winner

The flat fields carry one violation because that is what the hosts need: a wire
proxy builds a single native protocol error, and an audit row has one
`rule_id_triggered`. `outcome.violations` carries the full set alongside it.

```rust
let outcome = evaluate(sql, Dialect::Postgres, &rules, &policy);

// The verdict — the winner's action, the strongest of the set.
if outcome.decision == Decision::Block { /* reject */ }

// Everything the query is guilty of, strongest action first.
for v in &outcome.violations {
    println!("{} {:?} → {:?}  {}", v.rule_code, v.severity, v.action, v.ast_node_path);
}
```

Guarantees, each pinned by a property test:

- `violations[0]` **is** the winner reported in the flat fields.
- Ordered by resolved action descending (Block, Flag, Monitor), then severity
  descending, then rule code ascending — never by the order you passed the rules
  in. VERICTO-085 and VERICTO-087 take their place in the same order.
- `decision` and `action` are the winner's, and the winner holds the strongest
  action of the list: no entry resolves to an action stronger than the decision,
  so a host that reads only the flat fields acts on the strictest violation.
- Contains exactly the rules that fire when each is evaluated on its own — nothing
  dropped, nothing invented.
- Empty exactly when no rule matched. A parse error also reports an empty set:
  nothing was evaluated, so there is no violation to report.

Each entry carries its **own** resolved `severity` and `action`, so a caller
rendering the set does not re-derive them and cannot disagree with the decision.
A per-class cap can make a lower-severity violation resolve to a *stronger*
action than a higher-severity one — `schema_migration_cap: Monitor` softens a
Critical `DROP TABLE` while a High `INSERT … SELECT` still blocks. The winner is
chosen by action first, so the High block is the winner and the decision, and the
capped DROP follows it in the list.

Before this field, a host that wanted the full set had to call `evaluate()` once
per rule, re-parsing the SQL every time: measured at roughly **20× the cost** on a
28-rule catalogue. Collecting them costs nothing measurable, because the evaluator
already ran every rule and simply discarded the rest.

---

## Supported dialects

| Dialect    | Parser backend                       | Parse errors (default) |
|------------|--------------------------------------|------------------------|
| PostgreSQL | `pg_query` 6.2 (libpg_query, PG 17)  | host's `parse_error` (fail-open: flag) |
| MySQL      | `sqlparser-rs` 0.63                  | host's `parse_error` (fail-open: flag) |
| SQL Server | `sqlparser-rs` 0.63                  | host's `parse_error` (fail-open: flag) |
| Oracle     | `sqlparser-rs` 0.63                  | host's `parse_error` (fail-open: flag) |
| Snowflake  | `sqlparser-rs` 0.63 (`SnowflakeDialect`) + keyword pre-classifier and allowlist | host's `parse_error` (fail-open: flag); see [Snowflake](#snowflake) |
| SQLite     | `sqlparser-rs` 0.63 (`SQLiteDialect`) + `PRAGMA` grammar, keyword pre-classifier and allowlist | host's `parse_error` (fail-open: flag); see [SQLite](#sqlite) |

`Dialect::parse_dialect` accepts `postgres`/`postgresql`, `mysql`, `oracle`,
`mssql`/`sqlserver`/`tsql`, `snowflake` and `sqlite`/`sqlite3`.

Every parse-error outcome says why the text did not parse:
`EvaluationOutcome::parse_error_kind()` is `Some(ParseErrorKind::UnknownStatement)`
for a statement kind the parser does not know or the engine does not analyse (a
gap worth adding to a corpus), `Some(ParseErrorKind::Syntax)` for a known kind
whose text the parser rejects, `Some(ParseErrorKind::TooComplex)` for nesting past
the limits, and `None` for every outcome that is not a parse error
(`ParseErrorKind::as_str`: `unknown_statement`, `syntax`, `too_complex`).
PostgreSQL's parser reports every failure as a syntax error.

---

## Standard rules (VERICTO-*)

Standard rules are identified by code and evaluated by built-in Rust logic — no
YAML required. The complete catalogue is below, grouped by severity. Each rule
is a deterministic predicate over the parsed AST in
[`src/rules/evaluator.rs`](src/rules/evaluator.rs); severity drives the default
enforcement action via the policy (Critical/High → Block, Medium → Flag,
Low/Informational → Monitor).

> Dialect notes: PostgreSQL is parsed with `libpg_query`; MySQL/Oracle/MSSQL/
> Snowflake/SQLite with `sqlparser-rs`. Differences are called out per rule; how
> each rule applies on Snowflake is in [Snowflake](#snowflake), and on SQLite in
> [SQLite](#sqlite).

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
| VERICTO-091 | Stage unload or file transfer | `COPY INTO @stage \| @~ \| 's3://…' \| 'azure://…' \| 'gcs://…'` (an unload), `GET @stage`, `PUT … @stage` — data or files leave through a stage or an external location. Security; never softened by a channel cap. (Snowflake.) |
| VERICTO-092 | External stage or integration | `CREATE`/`ALTER STAGE` with `URL =` or inline `CREDENTIALS`, `CREATE STORAGE \| EXTERNAL ACCESS \| API INTEGRATION`, `CREATE EXTERNAL FUNCTION`, an egress `CREATE NETWORK RULE` — a path out of the account. Security. (Snowflake.) |
| VERICTO-093 | Share to another account | `GRANT … TO SHARE`, `CREATE SHARE`, `ALTER SHARE … ADD \| SET ACCOUNTS`, `CREATE LISTING` — data leaves the account. `GRANT … TO SHARE` is also a GRANT (VERICTO-082). Security. (Snowflake.) |
| VERICTO-100 | SQLite extension loading or file functions | `load_extension()` (native code), `fts3_tokenizer()` (a tokenizer registered by raw pointer), and the sqlite3 shell's `readfile()`, `writefile()`, `edit()` (the file system), in any clause, a quoted function name too. Security. (SQLite.) |

### High

| Code | Name | What it detects |
|---|---|---|
| VERICTO-002 | DELETE with LIMIT 0 | A `DELETE … LIMIT 0` — deletes nothing, usually a misconfigured scope. (MySQL/SQLite; no `DELETE … LIMIT` syntax on PostgreSQL.) |
| VERICTO-013 | DROP INDEX without IF EXISTS | `DROP INDEX` lacking `IF EXISTS` — errors if the index is missing, breaking scripts. |
| VERICTO-015 | ALTER TABLE DROP COLUMN | Drops a column — irreversible data loss. |
| VERICTO-016 | ALTER TABLE RENAME | Renames a table or column — breaks any code referencing the old name. |
| VERICTO-017 | ALTER TABLE DROP CONSTRAINT | Drops a FK/PK/CHECK (or `DROP PRIMARY KEY`) — silently removes a data-integrity invariant. |
| VERICTO-018 | ALTER TABLE ALTER COLUMN TYPE | Changes a column type — table rewrite, potentially lossy/blocking cast. |
| VERICTO-019 | ALTER TABLE DISABLE TRIGGER / RLS | `DISABLE TRIGGER` or `DISABLE ROW LEVEL SECURITY` — disables a protection; `DROP TRIGGER` removes it for good. |
| VERICTO-031 | UPDATE in CTE without WHERE | A data-modifying CTE (`WITH x AS (UPDATE … )`) whose `UPDATE` has no WHERE. |
| VERICTO-033 | DELETE in subquery/CTE without WHERE | A nested `DELETE` with no WHERE inside a subquery or CTE. |
| VERICTO-040 | INSERT INTO … SELECT without filter | `INSERT … SELECT` whose source has no filter — copies every source row. |
| VERICTO-070 | SLEEP() / PG_SLEEP() | A sleep-family call (`sleep`, `pg_sleep`, `pg_sleep_for`, `pg_sleep_until`, Snowflake's `system$wait`) anywhere in the query — DoS / time-based blind injection probing. SQLite has no sleep: there, a `randomblob(N)` / `zeroblob(N)` with a constant `N` of 10,000,000 bytes or more (`randomblob(500000000/2)`), in any clause SQLite evaluates (`WHERE … IS NULL`, `CASE`, `IN (…)`, subqueries, CTEs, `ORDER BY` / `GROUP BY` / `HAVING`, `UPDATE … SET`, `INSERT … VALUES`, `RETURNING`, trigger bodies and their `WHEN`). |
| VERICTO-082 | GRANT / REVOKE | A `GRANT` or `REVOKE` — privilege escalation or accidental lockout. |
| VERICTO-083 | MERGE | `MERGE INTO …` — can mass-mutate the target like an UPDATE/DELETE with no effective WHERE. |
| VERICTO-084 | CREATE TABLE AS SELECT | `CREATE TABLE … AS SELECT …` / `SELECT … INTO` — bulk data copy that can duplicate a whole table. |
| VERICTO-085 | Read of a sensitive column | A query projects (or copies elsewhere) a column the host tagged as sensitive. Driven by `EnforcementPolicy::sensitive_columns`, not by the rules slice; High for `block`/`mask`, Medium for `flag`. See [Sensitive columns](#sensitive-columns-vericto-085). |
| VERICTO-094 | Recovery reduced | `DATA_RETENTION_TIME_IN_DAYS = 0` (table, schema, database, account), `ALTER ACCOUNT`, `CREATE OR REPLACE TABLE \| SCHEMA \| DATABASE` (drops an existing object of that name), `INSERT OVERWRITE` (replaces every row), `UNDROP` (can shadow a newer object). SchemaMigration: a CI channel's `schema_migration_cap` softens it like DROP TABLE. (Snowflake.) |
| VERICTO-095 | Warehouse cost | `CREATE`/`ALTER WAREHOUSE` setting `WAREHOUSE_SIZE`, a cluster count, a type, a scaling policy, query acceleration or a never-suspend `AUTO_SUSPEND` (`0`/`NULL`); `ALTER RESOURCE MONITOR`. A warehouse created with the defaults is not reported. Performance. (Snowflake.) |
| VERICTO-096 | Code that runs later | `CREATE TASK \| STREAM \| PIPE \| PROCEDURE \| FUNCTION \| ALERT` (`OR REPLACE`/`OR ALTER` too), `ALTER TASK … RESUME \| MODIFY AS`, `EXECUTE TASK \| ALERT …` — embedded statements run later, outside any check. Security. (Snowflake.) |
| VERICTO-097 | Role switch | `USE ROLE r` (the evidence names an administrative role: `ACCOUNTADMIN`, `SECURITYADMIN`, `SYSADMIN`, `USERADMIN`, `ORGADMIN`), `USE SECONDARY ROLES ALL \| <roles>`. `USE SECONDARY ROLES NONE` only narrows privileges and is not reported. Security. (Snowflake.) |
| VERICTO-098 | SQLite ATTACH DATABASE | `ATTACH [DATABASE] <file> AS <name>` — opens, or creates, another database file on the connection: arbitrary file access or creation, reads and writes across databases (`':memory:'` too). `DETACH` is not reported. Security. (SQLite.) |
| VERICTO-099 | SQLite safety PRAGMA | A `PRAGMA` write that turns a safety off: `writable_schema` (any value), `trusted_schema = ON`, `foreign_keys = OFF`, `ignore_check_constraints = ON`, `journal_mode = OFF`, `synchronous = OFF`, `cell_size_check = OFF`, `query_only = OFF`, `schema_version = n`, `temp_store_directory` / `data_store_directory`. Reads (`PRAGMA table_info(t)`) and other settings are not reported. SchemaMigration: a CI channel's `schema_migration_cap` softens it (`PRAGMA foreign_keys = OFF` is the standard step of a SQLite table rebuild in migrations). (SQLite.) |
| VERICTO-101 | SQLite VACUUM INTO | `VACUUM [schema] INTO <file>` — a full copy of the database written to a path. Plain `VACUUM` is not reported. Security. (SQLite.) |
| VERICTO-087 | Access outside the agent's allowlist | The identity making the call (an API key, or the database user of a proxy session) references a table, column or write target its allowlist does not grant, or runs DDL. Every reference counts, predicates included. Driven by `EnforcementPolicy::access_policy`, not by the rules slice; blocks under `mode = enforce`, flags under `observe`. See [Agent access allowlists](#agent-access-allowlists-vericto-087). |

### Medium

| Code | Name | What it detects |
|---|---|---|
| VERICTO-050 | SELECT without LIMIT | A top-level `SELECT` with no `LIMIT`/`FETCH`/`TOP` — unbounded read. Scoped to the client-visible query, not inner subqueries. |
| VERICTO-051 | SELECT * without WHERE | `SELECT *` with no `WHERE` — unfiltered full-column scan; detected at any nesting depth. |
| VERICTO-061 | INSERT batch > 10k rows | `INSERT … VALUES` with more than 10,000 row tuples — oversized batch; also `COPY … FROM` a file on the database server (`FROM STDIN` is not reported). |

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
| constant comparison | `1=1`, `2 > 1`, `-1 < 0`, `'a'='a'` |
| constant `IN` list | `1 IN (1, 2)` |
| constant `BETWEEN` | `1 BETWEEN 0 AND 2` |
| constant `LIKE '%'` | `'x' LIKE '%'` |
| `NOT <always-false>` | `NOT FALSE`, `NOT 1=2` |
| `AND` of always-true, `OR` with any always-true | `1=1 AND 2>1` |

Plus one deliberate exception: the column self-comparison `id = id`, the canonical
trick for neutralising a `WHERE`, which has no legitimate use.

**SQLite** reads a text value as a number in a boolean context (its numeric
prefix: `'1abc'` is 1), so on SQLite a string literal with a non-zero numeric
prefix is always-true too (`WHERE '1abc'`, `OR '1'`), and so is a double-quoted
name spelling one (`WHERE "1"`), which SQLite reads as a string when no column
has that name.

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

Constant predicates are read with the same three-valued logic: a predicate is
always-true only when it is *provably* true, and what the engine cannot decide
stays undecided through `NOT`:

```sql
WHERE NULL = NULL          -- NULL, not true: matches no row
WHERE NOT (NULL = 1)       -- NOT of NULL is NULL
WHERE NOT ('a' < 'b')      -- string order depends on the collation
WHERE 'a' <> 'A'           -- equal under case-insensitive collations
WHERE NOT (1 = '1')        -- how a number and a string compare is the dialect's call
WHERE ? = ?                -- bind parameters are values the engine does not see
```

Two string literals are decided equal when they are identical, and different
only when both are plain ASCII letters and digits that differ beyond case
(`'a' <> 'b'`).

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
| `SchemaMigration` | 010–019, 094, 099 | DROP TABLE/DATABASE/SCHEMA, TRUNCATE, ALTER TABLE, DROP INDEX, DROP TRIGGER, Snowflake recovery reduced, SQLite safety pragmas. Destructive against a live database, but normal in a versioned migration. |
| `DataMutation` | 001, 002, 003, 030, 031, 033, 040, 042, 083, 084 | Data mutation without adequate scope. Dangerous on *any* channel — a WHERE-less DELETE is never intended, even in a migration. |
| `Security` | 070, 080, 081, 082, 085, 086, 087, 090, 091–093, 096–098, 100, 101 | Injection tautologies, `COPY … PROGRAM`, `DO` blocks, GRANT/REVOKE, sleep-based probing, reads of sensitive columns, MySQL text read differently, access outside an agent's allowlist, Snowflake unloads, external access, shares, persistent code and role switches, SQLite `ATTACH`, native-code functions and `VACUUM INTO`. |
| `Performance` | 050, 051, 060, 061, 095 | Best-practice / performance hints, Snowflake warehouse cost. Advisory. |

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
two, and VERICTO-085 takes the flat fields only when it ranks first in the
shared order (action, then severity, then code): a `mask` (High, Flag) next to a
Medium rule that flags is the winner, a Critical rule that blocks keeps them.
`monitor_mode` turns a column block into a flag and never applies a mask (the
would-be rewrite is in `suggested_safe_query`). With a `block` or `mask` tag
configured, a parse error blocks
([`EnforcementPolicy::effective_parse_error_for`](src/rules/engine.rs)): a query the
engine cannot read cannot be shown not to read a tagged column. The exception
is the closed list of session statements drivers send on connect (see the
`SET` list under agent access allowlists): they read no column and keep the
host's parse-error choice.

### Mask rewrite (Postgres)

Each projected expression that derives from a masked column is replaced and
aliased to its original output name, and the statement is regenerated with
`pg_query`'s deparser (`$n` parameters are kept; comments and formatting are not,
so audit the original too). If anything about the rewrite fails, the query is
**blocked** — the unmasked query is never returned as approved.

| Style | Expression |
|---|---|
| `full` | `'[redacted]'::text` |
| `last4` | `CASE WHEN char_length(col::text) <= 8 THEN '[redacted]'::text ELSE '****' \|\| right(col::text, 4) END` |
| `email` | `regexp_replace(col::text, '^(.)[^@]*(@.*)?$', '\1***\2')` |
| `hash` | `encode(sha256(convert_to(col::text, 'UTF8')), 'hex')` |

The tag's style applies only when the projected value **is** the column (a bare
reference, possibly through CTEs and subqueries). Any computed value —
`substring(card, 1, 4)`, `lower(email)`, `string_agg(…)` — is masked `full`:
applying `last4` to a caller-chosen substring would hand out any four characters.
`last4` reveals the last four characters only of a value longer than 8 characters
(counted in characters, not bytes); a shorter one, where four characters are half
of it or more, renders `'[redacted]'`, as under `full`. NULL stays NULL. Its
length test names the value twice, so it applies to a bare column only: `last4`
reached through a scalar subquery, which would run twice, renders
`'[redacted]'::text || left((expr)::text, 0)`, redacted whatever its length, NULL
staying NULL and its `$n` kept once.
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
| `last4` | `CASE WHEN CHAR_LENGTH(x) <= 8 THEN '[redacted]' ELSE CONCAT('****', RIGHT(x, 4)) END` (through a scalar subquery: `CONCAT('[redacted]', LEFT(x, 0))`) |
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

### Mask rewrite (Snowflake)

Printed back from the sqlparser tree, as on MySQL, with the same three checks:
the unmodified statement must print back to the client's own tokens (keyword and
unquoted-identifier case, and an inserted `AS`, are the only differences
allowed; string literals and quoted names compare verbatim), the rewrite must
parse back to itself, and its bind parameters (`?`, `:1`, `:name`) must be the
client's, in the client's order. Any failure **blocks**. The masks return what
the Postgres masks return for the same text (NULL stays NULL except under
`full`):

| Style | Expression (`x` = `TO_VARCHAR(col)`) |
|---|---|
| `full` | `'[redacted]'` (a computed value or one holding a bind parameter: `CONCAT('[redacted]', COALESCE(LEFT(x, 0), ''))`) |
| `last4` | `CASE WHEN LENGTH(x) <= 8 THEN '[redacted]' ELSE CONCAT('****', RIGHT(x, 4)) END` (through a scalar subquery: `CONCAT('[redacted]', LEFT(x, 0))`) |
| `email` | `CASE WHEN LENGTH(x) = 0 THEN x WHEN CHARINDEX('@', x, 2) > 0 THEN CONCAT(LEFT(x, 1), '***', SUBSTR(x, CHARINDEX('@', x, 2))) ELSE CONCAT(LEFT(x, 1), '***') END` |
| `hash` | `SHA2(x, 256)` |

`email` is written without `REGEXP_REPLACE`: a regular expression that fails to
match (a newline, an escape read differently) returns the value unmasked, and
this form cannot. A masked projection keeps the client's column name: an alias
is kept as written, and a bare column is aliased with its own identifier (`email`
is still `EMAIL`, `"Email"` still `Email`). An unaliased expression over a masked
column has a name Snowflake derives from its text, so it **blocks**: alias it.
A `VARIANT` path (`v:email`) masks the whole projected value, and `FLATTEN`
output derived from a masked column is masked `full`. Also blocked: `ORDER BY`,
`GROUP BY`, `HAVING` or `QUALIFY` naming a masked output (or its position), and
`ORDER BY ALL` when any output is masked.
When a Snowflake masking policy already protects the column, the rewrite runs on
top of it: harmless, but the client sees the engine's mask of the policy's
output.

The rewrites are pinned by golden outputs (`tests/snowflake.rs`); there is no
Snowflake emulator, so an equivalence run against a real account, like the
Postgres and MySQL ones, is not part of this repository's CI.

### Mask rewrite (SQLite)

Printed back from the sqlparser tree, with Snowflake's checks (the unmodified
statement prints back to the client's tokens, the rewrite parses back to itself,
the bind parameters `?`, `?NNN`, `:name`, `@name`, `$name` are the client's, in
order) and one more: **a statement holding a double-quoted name is not
rewritten** (it blocks). SQLite reads `"x"` as a string literal when no column
`x` is in scope (its double-quoted-string fallback), and without a schema the
engine cannot rule that out; `[x]` and `` `x` `` are always names. Block and flag
tags count `"x"` as a column reference, the conservative direction. Hosts that
open the database should also turn the fallback off
(`SQLITE_DBCONFIG_DQS_DML = 0`). The masks use core functions only:

| Style | Expression (`x` = `CAST(col AS TEXT)`) |
|---|---|
| `full` | `'[redacted]'` (a computed value or one holding a bind parameter: `'[redacted]' \|\| coalesce(substr(x, 1, 0), '')`) |
| `last4` | `CASE WHEN length(x) <= 8 THEN '[redacted]' ELSE '****' \|\| substr(x, -4) END` (through a scalar subquery: `'[redacted]' \|\| substr(x, 1, 0)`) |
| `email` | `CASE WHEN length(x) = 0 THEN x WHEN instr(substr(x, 2), '@') > 0 THEN substr(x, 1, 1) \|\| '***' \|\| substr(x, instr(substr(x, 2), '@') + 1) ELSE substr(x, 1, 1) \|\| '***' END` |
| `hash` | **blocks**: core SQLite has no SHA-256 (it is a loadable extension). Tag the column `block`, or mask it `full`, `last4` or `email`. |

They return what the Postgres masks return for the same text (NULL stays NULL
except under `full`). Output names are kept as on Snowflake (an alias as written,
a bare column aliased with its own identifier); an unaliased expression over a
masked column, and `ORDER BY`, `GROUP BY` or `HAVING` naming a masked output (or
its position), **block**. `tests/sqlite_mask_equivalence.rs` runs every mask
through the `sqlite3` command-line shell when one is on `PATH` and compares the
values with the Postgres forms' expected outputs.

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
(`schema` optional = the default schema, see *Names* below). The policy is `{"mode": "observe" | "enforce", "ddl": "deny", "entries": [ … ]}`.
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
  every column), `UPDATE … SET` (each assigned column), `DELETE` (the table, any
  column list; its `WHERE` still needs read), `REPLACE` (every column), `MERGE`,
  `COPY … FROM`, `LOCK`, and row locks: `SELECT … FOR UPDATE / NO KEY UPDATE /
  SHARE / KEY SHARE` needs `read_write` on each locked table (the `OF` tables, or
  every table of the `FROM`).
- **DDL is always denied**, and so are the statements that change who the session
  is or where unqualified names resolve (`SET ROLE`, `SET SESSION AUTHORIZATION`,
  `SET search_path`, `USE`). A statement kind not known to be harmless is denied;
  transaction control, settings, cursors and `CALL` are allowed (functions are out
  of scope).
- **SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` are denied** (`needed: ddl`), on
  every dialect (SQL Server's `EXEC` included): `EXECUTE p` runs whatever `p` was
  bound to earlier in the session, or to text the engine never sees (MySQL
  `PREPARE s FROM @sql`), so no `EXECUTE` can be judged. MySQL's
  `PREPARE s FROM '…'` does not parse and blocks as a parse error under an
  enforced policy. Protocol-level prepared statements (Postgres Parse/Bind,
  MySQL `COM_STMT_PREPARE`) are unaffected: the host evaluates the statement text
  when it is prepared.
- **The catalogue** (`information_schema`, `pg_catalog`, `mysql`,
  `performance_schema`, `sys`) is denied unless an entry names that schema
  explicitly; an unqualified `pg_*` relation is `pg_catalog`'s, and MySQL `SHOW
  TABLES`/`COLUMNS`/`DATABASES`/`CREATE …` read `information_schema`.
- **Names resolve conservatively.** An unqualified column resolves against every
  relation in scope (subqueries see the outer ones) and must be allowed in all of
  them — otherwise it is denied and the message says to qualify it. A qualifier
  that names nothing in scope is taken as a table.
- **An entry without a schema is the table in the default schema only**:
  `public` on Postgres and `dbo` on SQL Server (qualified or not in the query);
  on MySQL (the session's database) and Oracle (the user's schema), which the
  engine cannot see, the unqualified name only. The host can name the default
  schema in `AccessPolicy::default_schema` (never the customer): on MySQL the
  connection's database, so a name qualified with it (Prisma's
  `` `db`.`User` ``, compared exactly) matches entries without a schema; on
  Postgres and SQL Server it replaces `public` / `dbo`. A table of the same name
  in any other schema — on MySQL, a name qualified with any other database —
  needs an entry naming that schema.
  An entry naming a schema matches that schema, and the unqualified name where
  the default schema is known to be it (`public`, `dbo`). An empty `schema` is no
  schema.
- **Snowflake names are three-part** (`database.schema.table`). An entry may
  name its `database` (alias `database_name`); the host names the connection's
  current database and schema in `AccessPolicy::default_database` and
  `default_schema`, as stored (`CURRENT_DATABASE()`, `CURRENT_SCHEMA()`). An
  entry without a database is the table in the default database; with neither
  known, only names written without a database match it. `db..t` is
  `db.PUBLIC.t`. `INFORMATION_SCHEMA` (in every database) and the shared
  `SNOWFLAKE` database (`ACCOUNT_USAGE`, …) are the catalogue: denied unless an
  entry names them. A stage (`@stage`, `@~`, `@%t`) is data: reading staged
  files needs an entry whose `table` is the stage (`"@raw_stage"`). Dynamic
  names (`IDENTIFIER(…)`, `TABLE($var)`) and table functions that may read
  anything (`RESULT_SCAN`, `INFORMATION_SCHEMA.QUERY_HISTORY()`, user table
  functions) are denied; `FLATTEN`, `SPLIT_TO_TABLE`, `STRTOK_SPLIT_TO_TABLE`
  and `GENERATOR` read only their arguments. `COPY INTO`, `PUT`, `LIST`,
  `CREATE STAGE`, `CREATE WAREHOUSE`, scripting blocks and every statement only
  the pre-classifier recognised are denied outright; `ALTER SESSION SET` is
  allowed for formatting, tagging and timeout parameters only
  (`QUOTED_IDENTIFIERS_IGNORE_CASE`, which changes how names resolve, is denied).
- **SQLite.** Names compare ASCII case-insensitively, quoted or not (`"x"`,
  `` `x` `` and `[x]` are accepted in queries and entries). The default schema is
  `main` (the host may set another in `default_schema`); `temp` and attached
  databases are other schemas. `sqlite_master`/`sqlite_schema` and the
  table-valued functions (`pragma_table_info('t')`, `dbstat`) are relations like
  any other: only an entry naming them allows them (`json_each` and `json_tree`
  read only their arguments). `PRAGMA table_info | table_xinfo | index_list |
  foreign_key_list(<t>)` reads every column of `<t>`; the connection settings
  drivers send (`foreign_keys = ON`, `busy_timeout`, `journal_mode = WAL |
  DELETE | TRUNCATE | PERSIST`, `synchronous = NORMAL | FULL | EXTRA`,
  `cache_size`, `temp_store`, `defer_foreign_keys`, `recursive_triggers`,
  `case_sensitive_like`) are allowed; every other `PRAGMA`, `ATTACH`, `DETACH`,
  `VACUUM`, `REINDEX` and `ANALYZE` are denied as DDL.
- **Identifier case follows the dialect.** Snowflake is Postgres's mirror image:
  unquoted names fold to **upper** case and quoted names compare exactly, in the
  query and in the entry alike (an entry `orders` is `ORDERS`; `"orders"` is a
  different table). Under `QUOTED_IDENTIFIERS_IGNORE_CASE = TRUE` quoted names
  fold too: the host says which in `AccessPolicy::quoted_identifiers_ignore_case`
  (`true`/`false`); when it does not, both readings are checked and a reference
  either one denies is denied.
  Postgres: unquoted names fold to lower
  case and quoted names compare exactly, in the query and in the entry alike —
  an entry `Customers` is `customers`; a case-sensitive name is sent quoted,
  `"Customers"` (an embedded `"` doubled), in `schema`, `table` or a column.
  MySQL: table and database names compare exactly (the conservative reading of
  `lower_case_table_names=0`; `information_schema`'s names case-insensitively, as
  MySQL compares them), column names case-insensitively; backticks around an
  entry's name are accepted. SQL Server and Oracle: ASCII case-insensitive, as
  before (SQL Server's default collations are; on Oracle a quoted mixed-case name
  compares more loosely than Oracle does).
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
- With an enforced policy (or a `block`/`mask` tag), a parse error blocks
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

The flat fields follow the shared order (action, then severity, then code): a
`block` tag and an `enforce` denial both block at High, and VERICTO-085 is the
lower code; under `observe` a denial (High, Flag) ranks ahead of a `flag` tag
(Medium, Flag).

A denial clears any rewrite (a refused query is never forwarded, masked or not);
under `observe` an allowed mask keeps its rewrite. `monitor_mode` turns a denial
into a flag. `EvaluationOutcome::access_denied` lists every denied reference
(`{"schema", "table", "column", "needed": "read" | "write" | "ddl"}`), also in
`observe` mode.

## Snowflake

Snowflake is parsed with sqlparser's `SnowflakeDialect` and walked by the same
sqlparser walker as MySQL, Oracle and SQL Server, which records the Snowflake
statement kinds for the rules: `COPY INTO` (table ← stage is a load, stage ←
query an unload), `CREATE`/`DROP STAGE`, `PUT`, `LIST`, `USE`, `EXECUTE
IMMEDIATE`, scripting blocks (`BEGIN … END`), time travel (`AT`/`BEFORE`),
semi-structured paths (`:`, `[]`, `FLATTEN`), `QUALIFY`, `MERGE`, `GRANT … TO
SHARE`, warehouses, three-part names and `IDENTIFIER()`.

**Parse errors.** A Snowflake statement the engine cannot read resolves like
on every dialect: flagged by default (`parse_error: allow_report`), blocked
under `parse_error: block`, and **always blocked under a `block`/`mask` tag or
an enforced agent allowlist** (VERICTO-087). `monitor_mode` and
`schema_migration_cap` do not change a parse error, as everywhere.

**The pre-classifier.** When (and only when) sqlparser rejects a single
statement, its leading keywords are matched against the known-dangerous kinds:
`UNDROP`, `GET`/`PUT`, `GRANT`/`REVOKE` forms sqlparser does not read, `CREATE
[OR REPLACE | OR ALTER] TASK | STREAM | PIPE | PROCEDURE | FUNCTION | ALERT |
SHARE | LISTING | … INTEGRATION | NETWORK RULE | STAGE | WAREHOUSE`, `ALTER
WAREHOUSE | RESOURCE MONITOR | ACCOUNT | SHARE | STAGE | TASK`, `ALTER TABLE …
DROP ROW ACCESS POLICY | UNSET MASKING POLICY`, `DATA_RETENTION_TIME_IN_DAYS =
0`, `DROP DYNAMIC | ICEBERG | EXTERNAL TABLE`, `CLONE`, `DECLARE … BEGIN … END`.
A match becomes a finding of the rule that names it, so the report says what
the statement is. A pre-classified statement, a scripting block and `EXECUTE
IMMEDIATE` are **unread code**: the outcome is the stricter of the findings and
the parse-error outcome, so recognising one never makes it more lenient than a
parse error (under a protective tag or an enforced allowlist: a block).

**The allowlist.** A short list of legitimate Snowflake statements sqlparser
0.63 rejects is analysed with **no finding**, as the same statements are on the
dialects whose parser reads them (`COMMENT ON`, `ALTER VIEW`, `DESCRIBE` match
no rule on PostgreSQL), so no SchemaMigration-class flag either: that class
belongs to the rules that report specific DDL (DROP, TRUNCATE, ALTER … DROP
COLUMN, …), none of which these are. Each entry is an anchored pattern over the
whole statement: its head keywords, names and literal values, nothing more; a
statement with anything else, a second statement, or a `$$` body anywhere but
a comment value is not on it. Under an agent allowlist they are still denied as
DDL. The entries, with an example each, are documented on
`parser::snowflake::allowlisted`:

| Entry | Example |
|---|---|
| `COMMENT [IF EXISTS] ON <object> <name> IS '…' \| $$…$$` | `COMMENT ON TABLE orders IS $$One row per order$$` |
| `ALTER [MATERIALIZED] VIEW <name> SET\|UNSET SECURE`, `SET COMMENT = '…'`, `UNSET COMMENT` | `ALTER VIEW v SET SECURE` |
| `ALTER DYNAMIC TABLE <name> SET TARGET_LAG\|WAREHOUSE\|COMMENT = …`, `REFRESH`, `SUSPEND`, `RESUME` | `ALTER DYNAMIC TABLE dt SET TARGET_LAG = '2 hours'` |
| `ALTER TABLE <name> ALTER\|MODIFY [COLUMN] <col> COMMENT …` / `UNSET COMMENT` | `ALTER TABLE orders ALTER "STATUS" COMMENT $$Order status$$` |
| `ALTER TABLE <name> SET COMMENT\|CHANGE_TRACKING\|DEFAULT_DDL_COLLATION = …`, `UNSET COMMENT` | `ALTER TABLE t SET CHANGE_TRACKING = TRUE` |
| `ALTER TABLE <name> ADD [COLUMN] [IF NOT EXISTS] <col> <type> [, …]` (types only) | `ALTER TABLE t ADD COLUMN IF NOT EXISTS a2 NUMBER(38, 2)` |
| `ALTER TABLE <name> ADD ROW ACCESS POLICY <p> ON (<cols>)` | `ALTER TABLE t ADD ROW ACCESS POLICY rap ON (region)` |
| `ALTER TABLE <name> ALTER\|MODIFY [COLUMN] <col> SET MASKING POLICY <p> [USING (…)]` (no `FORCE`) | `ALTER TABLE t MODIFY COLUMN email SET MASKING POLICY m` |
| `ALTER WAREHOUSE <name> SUSPEND \| RESUME [IF SUSPENDED] \| ABORT ALL QUERIES` | `ALTER WAREHOUSE wh RESUME IF SUSPENDED` |
| `ALTER TASK <name> SUSPEND`; `ALTER STAGE <name> REFRESH [SUBPATH = '…']` | `ALTER TASK t SUSPEND` |
| `CREATE [TRANSIENT\|TEMPORARY] TABLE <name> (<columns>)` (names, types, `AUTOINCREMENT`, `NOT NULL`) | `CREATE TABLE x (y INT AUTOINCREMENT START 10)` |
| `CREATE SEQUENCE …`, `CREATE TAG …`, `CREATE STAGE <name>` with format/copy options only (no `OR REPLACE`) | `CREATE STAGE s FILE_FORMAT = f` |
| `DESC[RIBE] <object> <name>` (not users, shares, integrations, secrets), `DESCRIBE TABLE <name> TYPE = …` | `DESC EXTERNAL TABLE ext` |
| `SHOW …` (words, names and `'…'` only), `UNSET <var>` | `SHOW TERSE TABLES IN ACCOUNT LIKE 'ORD%'` |
| `COPY INTO <table> [<option> = <value>]…` (the table's own stage) | `COPY INTO orders FILE_FORMAT = (TYPE = CSV)` |

**The standard rules on Snowflake** (design §4.2; `tests/snowflake.rs` holds the
matrix):

- **Direct** (same predicate): 001, 003, 010, 011, 012, 013, 015, 016 (`ALTER
  TABLE … SWAP WITH` counts as a rename), 017, 018, 030, 040, 042, 051, 060, 061,
  083, 090.
- **Variants**: 019 (`DROP ROW ACCESS POLICY`, `UNSET MASKING POLICY`), 050
  (`TOP n`, a fixed-size `SAMPLE (n ROWS)` and `RESULT_SCAN` bound a read; a
  percentage sample does not), 070 (`system$wait`), 080 (no `PROGRAM` form; the
  exfiltration path is the unload, VERICTO-091), 081 (`EXECUTE IMMEDIATE`,
  scripting blocks), 082 (`GRANT ROLE`, `GRANT OWNERSHIP`, `GRANT … TO SHARE`),
  084 (CTAS, and `CLONE` of a table, schema or database; `CREATE TABLE … LIKE`
  copies no rows and is not reported), 085 (the Snowflake mask rewrite above),
  087 (Snowflake identifier semantics above).
- **Not applicable** (the construct does not exist; the rule stays in the
  catalogue and never fires on Snowflake): 002 (no `DELETE … LIMIT`), 031 and
  033 (no data-modifying CTEs), 086 (MySQL's lexical ambiguity).

The Snowflake rules VERICTO-091 to VERICTO-097 are in the tables above; they read
only what the Snowflake walker and pre-classifier record, so they never fire on
another dialect. `tests/snowflake_corpus.rs` pins how the engine reads a corpus
of public Snowflake SQL (rendered dbt models and the DDL around them, the
statements dbt-snowflake sends, sqlglot's Snowflake tests) and prints its parse
and recognition rates (parsed, pre-classified or allowlisted).

## SQLite

SQLite is a library inside the application, not a server: there is no wire
protocol and so no proxy. The host evaluates each statement before the
application runs it — the Runtime API and the driver wrappers that call it, the
CLI on migrations, MCP for agents. It is parsed with sqlparser's `SQLiteDialect`
and walked by the shared sqlparser walker, which records the SQLite statement
kinds for the rules: `ATTACH`, `PRAGMA` (reads and writes), `VACUUM`,
`CREATE TABLE … AS SELECT` (VERICTO-084), and a trigger's body, whose statements
run on every matching write and are walked like any other (a `CREATE TRIGGER …
BEGIN DELETE FROM log; END` is a WHERE-less DELETE). UPSERT (`ON CONFLICT`),
`INSERT OR REPLACE`, `REPLACE INTO`, `RETURNING`, `WITH RECURSIVE`, window and
JSON functions read as on the other dialects.

**Before a text is a parse error** (only when sqlparser 0.63 rejects it):

- `INDEXED BY <index>` and `NOT INDEXED` after a table name, query-planner hints
  that change no result, are read through: the statement is analysed without
  them (a mask rewrite of such a statement blocks, since the printed text would
  not be the client's);
- a `PRAGMA` with a keyword or a name as its value (`PRAGMA foreign_keys = OFF`,
  `PRAGMA journal_mode = WAL`, `PRAGMA table_info(users)`, `PRAGMA cache_size =
  -2000`) is read with SQLite's own grammar (`PRAGMA [schema.]name [= value |
  (value)]`);
- `DETACH [DATABASE] <name>` and `REINDEX [[<schema>.]<name>]` are analysed with
  no finding (the allowlist, `parser::sqlite::allowlisted`);
- the pre-classifier turns `VACUUM [schema] INTO …`, the `ATTACH` forms sqlparser
  does not read (`… KEY '…'`) and a safety pragma outside the grammar into
  findings of the rule that names them. Unless its pattern covers the whole
  statement, such a statement is **unread code**: the outcome is the stricter of
  the findings and the parse-error outcome.

Everything else resolves like on every dialect: flagged by default, blocked
under `parse_error: block`, a `block`/`mask` tag or an enforced allowlist
(`SELECT … WHERE a IS NOT b`, an expression sqlparser does not read, is one).

**Native code anywhere.** VERICTO-100 reads the tokens of the whole text, so a
`load_extension(…)` in `INSERT … VALUES`, `UPDATE … SET` or a quoted function
name (`"load_extension"(…)`) is found where the walker visits no expression; a
name in a string literal or a comment is not.

**The standard rules on SQLite** (design §4.2; `tests/sqlite.rs` holds the
matrix):

- **Direct** (same predicate): 001, 002 (`DELETE … LIMIT`, in builds with
  `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`), 010, 013, 015, 016, 019 (`DROP TRIGGER`;
  SQLite has no `DISABLE TRIGGER` or row-level security), 030, 040, 042, 050,
  051, 060, 061 (`INSERT` batches; no `COPY`), 084 (`CREATE TABLE … AS SELECT`).
- **Variants**: 003 and 090 (SQLite truthiness, see [what counts as
  always-true](#what-counts-as-always-true)), 070 (`randomblob(N)` /
  `zeroblob(N)` with a huge constant `N`, wherever SQLite evaluates it; a bind
  parameter or a computed `N` is not read), 085 (the SQLite mask rewrite above),
  087 (SQLite names above).
- **Not applicable** (the construct does not exist, or SQLite rejects it; the rule
  stays in the catalogue and never fires on SQLite): 011 (`TRUNCATE`), 012 (`DROP
  SCHEMA`; `DETACH` destroys nothing), 017 and 018 (no `DROP CONSTRAINT`, no
  `ALTER COLUMN`), 031 and 033 (no data-modifying CTEs), 080, 081, 082 and 083
  (no `COPY`, `DO`, `GRANT`/`REVOKE` or `MERGE`), 086 (MySQL's lexical
  ambiguity).

The SQLite rules VERICTO-098 to VERICTO-101 are in the tables above; they read
only what the SQLite walker and pre-classifier record, so they never fire on
another dialect. `tests/sqlite_corpus.rs` pins how the engine reads a corpus of
SQLite statements written for it (the DDL, DML and pragmas ORMs and migration
tools send, UPSERT, `WITH RECURSIVE`, window and JSON functions, transactions,
and the dangerous statements) and prints its parse and recognition rates.

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

## Business policies (CEL)

Since 4.4.0, a custom rule can also be a **business policy**: who runs the
statement (the *principal*), what it does (its facts: tables, columns, the
values it assigns, the values its `WHERE` pins), and the declared context
(database, time, ticket, session), combined in a [CEL](https://github.com/google/cel-spec)
expression inside the same YAML. It resolves to `allow`, `monitor`, `flag`,
`block` or `require_approval`.

```yaml
rule: refund-cap
applies_to: { ops: [insert, update], tables: ["public.refunds"], principal_types: [agent, human] }
vars: { limit: 200 }
min_trust: medium
deny_if: stmt.values("public.refunds.amount").exists(v, double(v) > double(vars.limit))
on_unknown: block
action: block
message: "Refunds above {{vars.limit}} need approval"
tests:
  - { name: small passes, sql: "INSERT INTO refunds (amount) VALUES (150)", principal: { type: agent }, expect: allow }
  - { name: large blocks, sql: "INSERT INTO refunds (amount) VALUES (950)", principal: { type: agent }, expect: block }
```

**Backward compatible.** A document is a policy only when it carries one of
`when`, `deny_if`, `require`, `action`, `applies_to`, `min_trust`, `exempt`,
`modes`, `vars`, `on_unknown`. Every other custom rule — including one with keys
this engine already ignored, such as `severity:` or `metadata:` — evaluates
exactly as before. `evaluate()` is unchanged for every document; policies run
only through `evaluate_with_context()` with a compiled `PolicySet`, which the
host gates behind its own flag:

```rust
use vericto_engine::policy::{EvalContext, PolicySet, Principal, PrincipalType, Trust};
use vericto_engine::{evaluate_with_context, Dialect, EnforcementPolicy};

let policies = PolicySet::compile(&rules); // once, at rule sync
let ctx = EvalContext::new()
    .with_principal(Principal::new("agent-support-bot", PrincipalType::Agent, Trust::Medium));
let outcome = evaluate_with_context(sql, Dialect::Postgres, &rules, &EnforcementPolicy::default(), &policies, &ctx);
// outcome.policy_hits, outcome.unknowns, outcome.approval_required
```

### Keys

| Key | Meaning |
|---|---|
| `applies_to` | `ops` (`select`, `insert`, `update`, `delete`, `merge`, `ddl`, `copy`, `call`, `set`, `other`), `tables` (globs), `principal_types`, `databases` (id or name). A cheap index evaluated before any CEL |
| `modes` | `proxy`, `runtime_api`, `mcp`, `ci`; default all |
| `node_type` / `condition` | Today's predicates; they AND with the CEL |
| `vars` | Named constants (`vars.limit`) |
| `min_trust` | `weak`, `medium` or `strong`: below it, `on_insufficient_trust` (`block` by default, or `flag`) |
| `when` | CEL guard |
| `deny_if` / `require` | CEL: a violation when `deny_if` is true or `require` is false (at most one; neither: every match is a violation) |
| `on_unknown` | `block` (default for `block`/`require_approval`), `flag` (default otherwise), `skip` (only with an explicit `modes:` list) |
| `action` | `allow`, `monitor`, `flag`, `block`, `require_approval` |
| `approval` | `approvers` (`roles`, `groups`), `quorum`, `request_timeout`, `grant_ttl`, `fallback_for` (`service`/`pipeline`/`tool` → `block` or `flag`: they never wait for a human) |
| `exempt` | `{ rule_classes: [schema_migration, performance], cap: flag }`: caps those rule classes for this principal. Needs `min_trust: strong`; Security and DataMutation can never be exempted |
| `mode` | `enforce` (default) or `monitor` (blocks become flags) |
| `message`, `tests`, `rule`, `code`, `severity`, `metadata` | Text (`{{vars.x}}` is substituted), fixtures, labels |

`rewrite_limit`, `inject_predicate`, `limits`, `budget`, `deny_after` and
`params` are refused by this version (later milestones and phases).

### The context

| Field | Type | From |
|---|---|---|
| `principal.type`, `.id`, `.owner`, `.via` | string | The host's identity mapping; `unknown` when unmatched |
| `principal.trust` | int (`WEAK` 1, `MEDIUM` 2, `STRONG` 3) | The signal that identified it |
| `principal.attrs`, `.groups`, `.end_user` | map, list, map | Mapping config, IdP groups, a service's asserted end user |
| `stmt.op`, `.kind` | string | The statement |
| `stmt.tables`, `.tables_written`, `.columns_read`, `.columns_written`, `.functions` | list(string) | `schema.table[.column]`, default schema applied (as VERICTO-087 reads names) |
| `stmt.has_where`, `.where_always_true`, `.has_returning`, `.truncated` | bool | |
| `stmt.limit`, `.insert_rows` | int (optional) | Literal outer `LIMIT`/`FETCH`/`TOP`; `VALUES` rows |
| `db.id`, `.name`, `.env`, `.tags`, `.dialect` | string, list | The database record |
| `time.now`, `.hour`, `.minute`, `.weekday` (1 = Monday), `.date`, `.tz` | timestamp, int, string | The host's clock in the workspace time zone. **The engine reads no clock** |
| `session.tenant`, `.application_name`, `.client_ip`, `.listener` | string | The proxy session (weak signals: they tighten, never loosen) |
| `ticket.id`, `.source`, `.verified` | string, bool | Declared by the session or the caller |

Helpers: `stmt.values(col)`, `stmt.filter_values(col)`, `stmt.has_filter(col)`,
`stmt.lower_bound(col)`, `stmt.upper_bound(col)`, `stmt.reads(glob)`,
`stmt.writes(glob)`, `stmt.touches(glob)`, `glob(s, pattern)`,
`cidr_contains(cidr, ip)`, `in_window(ts, "Mon-Fri 09:00-18:00", tz)` (UTC, a
fixed offset, or the workspace zone the host passed), plus the CEL standard
subset (`size`, `in`, `contains`, `startsWith`, `endsWith`, `matches` with a
literal pattern compiled once, `int`/`uint`/`double`/`string`/`bool`,
`timestamp`/`duration` of literals, `has`, `all`, `exists`, `exists_one`,
`map`, `filter`). There is no `now()`, no randomness and no I/O.

### Unknown, deterministic, conservative

A field absent in a mode (`session.tenant` over MCP), a parameter (`$2`), a
value that is an expression, a column the walk cannot resolve to one table, a
fact list over 1,024 entries: each is **UNKNOWN**, and `on_unknown` decides —
never a guess. `&&`, `||`, `all` and `exists` absorb an UNKNOWN when the other
side decides, as in CEL. A policy that does not compile fails closed in its
`applies_to` scope. A statement that does not parse blocks when an enforced
blocking policy may apply to the principal (session boilerplate excepted).

Precedence: VERICTO-086, then a 085 block, an 087 denial, a policy block, a
policy requiring approval, then flags and monitors — a policy finding joins
`violations` after every other finding of the same action. A required approval
is a `Block` decision plus `approval_required`, so a host that does not know
approvals blocks.

### Authoring

`policy::check_policy(yaml)` returns errors with their key and offset (with
suggestions for typos), warnings, the fields the policy reads and, per mode,
whether it is decidable there. `policy::run_policy_tests(yaml, dialect)` runs
its `tests:` fixtures. `policy::statement_facts(sql, dialect, default_schema)`
shows what a policy sees in a statement.

The CEL is Vericto's own interpreter of a CEL subset (same grammar and
semantics), checked against [cel-rust](https://github.com/cel-rust/cel-rust)
on generated expressions in the test suite. Static bounds: 2 KiB per
expression, 256 nodes, comprehension nesting 2, `matches` patterns of 256
bytes, a worst-case cost estimate, 200 policies per set.

### Cost

Measured by `cargo bench --bench policy` (statements under 2 KiB, added over
`evaluate` with the standard ruleset; the bench fails when a cell is over its
budget): an empty set adds nothing measurable; policies out of scope for the
principal ≤ 1 µs; three typical policies ≤ 15 µs; fifty applicable policies
≤ 50 µs.

---

## Architecture

```
vericto-engine/
├── src/
│   ├── lib.rs          ← public API + evaluate() convenience fn
│   ├── error.rs        ← ProxyError, Result
│   ├── policy/         ← business policies: context, facts (pg.rs, sql.rs), CEL subset (cel/), spec, set, check
│   ├── access/         ← VERICTO-087: agent allowlists — policy types, statement classes, verdict (runs the sensitive/ walkers in access mode)
│   ├── sensitive/      ← VERICTO-085: sensitive-column derivation + mask rewrite (pg.rs, sql.rs, mysql.rs, snowflake.rs)
│   │   ├── mod.rs      ← tags, scopes, lineage, verdict
│   │   ├── pg.rs       ← pg_query walker + rewrite
│   │   ├── sql.rs      ← sqlparser walker (MySQL/Oracle/MSSQL/Snowflake)
│   │   └── snowflake.rs ← Snowflake mask expressions + print-back checks
│   ├── parser/
│   │   ├── mod.rs      ← SqlParser trait, parser_for(), Dialect enum
│   │   ├── postgres.rs ← pg_query backend
│   │   ├── mysql.rs    ← sqlparser-rs backend
│   │   ├── oracle.rs   ← sqlparser-rs backend
│   │   ├── mssql.rs    ← sqlparser-rs backend
│   │   ├── snowflake.rs ← sqlparser-rs backend + keyword pre-classifier
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

Copyright 2026 Vericto S.A.S. Source-available under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE)
(SPDX `FSL-1.1-ALv2`) since 4.3.0: use, modify and redistribute it for any
purpose other than a Competing Use, and each version becomes Apache-2.0 two
years after it is released. Versions 4.2.0 and earlier remain under the Elastic
License 2.0. [LICENSING.md](LICENSING.md) answers the common questions; see
also [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md). Community PRs welcome.

For a commercial license contact [enterprise@vericto.com](mailto:enterprise@vericto.com).
