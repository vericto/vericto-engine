# Changelog

All notable changes to `vericto-engine` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.5.0] — 2026-10-23

**`rewrite_limit`: bounded reads as a business policy** (design "Business
policy rules" §8.1; implementation plan, milestone M5; the same semantics as
the runtime-controls VERICTO-102 bound). Nothing changes for anyone who does
not use it: `evaluate()` is unchanged for every input, the corpus goldens are
unchanged byte for byte, and without a `rewrite_limit` policy
`evaluate_with_context()` runs exactly the 4.4.0 code (one emptiness check).

### Added

- **`action: { rewrite_limit: n }`** (1 to 1,000,000; SELECT only:
  `applies_to.ops` is `[select]` or left out; default `on_unknown: flag`).
  A violated policy adds the outer `LIMIT n`, or lowers a larger literal
  `LIMIT`/`FETCH FIRST`/MySQL `LIMIT a, m`; `OFFSET` is kept; a set operation
  gets one outer `LIMIT`; subqueries and CTEs are untouched. Postgres
  `LIMIT $k` (or any expression) becomes `LIMIT LEAST($k::bigint, n)`, which
  keeps the parameter's number and inferred type. MySQL `LIMIT ?` is UNKNOWN
  (`on_unknown` decides). Out of scope, as VERICTO-102: `SELECT 1`, `VALUES`,
  aggregate-only projections without `GROUP BY`, `SELECT … INTO`,
  data-modifying CTEs, `EXPLAIN`. Postgres and MySQL; other dialects are
  UNKNOWN.
- Built on the VERICTO-085 machinery and run last (§4.6 step 6): on top of a
  mask when both apply; deparse (Postgres) or the MySQL renderer, then the
  text must parse back with the same bind parameters; **failure blocks**
  (`FETCH … WITH TIES` too). An applied rewrite is a `monitor` finding of the
  policy with `rewritten_query` set; `monitor_mode`, `mode: monitor` and a
  statement that blocks anyway apply nothing and report the would-be text as
  the finding's `suggested_safe_query`.
- `PolicyAction::RewriteLimit`; `PolicyOutcome::Rewritten` and
  `PolicyOutcome::RewriteFailed`; `policy::MAX_REWRITE_LIMIT`.
- `policy::POLICY_LANGUAGE` (`"cel/1"`) and `policy::POLICY_FEATURES`
  (`["rewrite_limit"]`), for hosts to announce, so a control plane can
  withhold `rewrite_limit` documents from older engines (which refuse them and
  fail closed in their scope).
- Fixtures: `expect: rewrite` and an optional `expect_sql:` (the exact text to
  execute); reasons `REWRITTEN` and `REWRITE_FAILED`; `FixtureResult` gains
  `rewritten_query`.
- The checker validates the bound and the SELECT-only scope, and warns when a
  `rewrite_limit` policy reads `stmt.limit` (not needed, and it makes
  `LIMIT $1` UNKNOWN instead of rewriting it).
- Tests: `tests/policy_rewrite.rs` (semantics, composition with the mask,
  monitor modes, failures, fixtures, a property over generated SELECTs:
  total, idempotent, binds kept) and `tests/limit_equivalence.rs` (against
  real Postgres and MySQL: the rewritten query returns the first `n` rows of
  the original under the same `ORDER BY`, across LIMIT/OFFSET, FETCH FIRST,
  MySQL `LIMIT a, b`, UNION/INTERSECT/EXCEPT, CTEs, recursive CTEs,
  subqueries, GROUP BY, DISTINCT, windows, FOR UPDATE and bind parameters,
  plus mask + LIMIT); the fuzz target `policy` also runs the rewrite.

### Changed

- The checker no longer refuses `rewrite_limit` ("not available in this engine
  version"); `inject_predicate` still is (Phase 2).

## [4.4.0] — 2026-10-21

**Business policies (Phase 1, engine core).** A custom rule can now be a
principal-aware policy written in CEL inside the same YAML (design "Business
policy rules", Confluence VTO 7798785; implementation plan, milestone M1).
Nothing changes for anyone who does not use them: `evaluate()` is unchanged
for every input, today's custom rules (including those with keys the engine
already ignored) are not policies, and the outcome of the new entry point with
an empty policy set is exactly `evaluate()`'s. The corpus goldens are
unchanged byte for byte.

### Added

- **`evaluate_with_context(sql, dialect, rules, policy, &PolicySet, &EvalContext)`**
  and `RuleEngine::evaluate_with_context`: the rules, VERICTO-085, VERICTO-087,
  then the business policies of a `PolicySet` (compiled once with
  `PolicySet::compile(&rules)`) against the declared context.
- **`policy` module.** `EvalContext` (principal, database, time, ticket,
  session, host mode, default schema; JSON-deserializable), `Principal` with
  `PrincipalType` and `Trust` (weak 1, medium 2, strong 3), `PolicySet`,
  `PolicyHit` / `PolicyOutcome`, `ApprovalRequirement`, `UnknownField`.
- **Policy documents**: `applies_to` (ops, table globs, principal types,
  databases), `modes`, `vars`, `min_trust` / `on_insufficient_trust`, `when`,
  `deny_if` / `require`, `on_unknown` (`block`, `flag`, `skip`), `action`
  (`allow`, `monitor`, `flag`, `block`, `require_approval`), `approval` (with
  `fallback_for`: services, pipelines and tools never wait for a human),
  `exempt` (caps `schema_migration` / `performance` violations, needs
  `min_trust: strong`; Security and DataMutation can never be exempted),
  `mode: monitor`, `message` with `{{vars.x}}`, `tests:`. `node_type` /
  `condition` keep working and AND with the CEL.
- **Statement facts** on both parser front ends (pg_query; sqlparser for
  MySQL, SQL Server, Oracle, Snowflake and SQLite): tables, tables written,
  columns read and written (the VERICTO-087 walk), op, kind, values assigned
  (INSERT VALUES, UPDATE SET, upserts), the top-level conjunctive `=`/`IN`
  pins and range bounds of the `WHERE`, the outer LIMIT/FETCH/TOP, RETURNING,
  VALUES rows, called functions. Conservative: what cannot be known is
  UNKNOWN. `policy::statement_facts()` shows them.
- **A CEL subset** with its own checker (types against the fixed schema,
  allowed identifiers and functions, suggestions for typos, static bounds:
  2 KiB, 256 nodes, comprehension nesting 2, 256-byte `matches` patterns
  compiled once, a worst-case cost estimate, 200 policies per set) and
  interpreter (UNKNOWN absorbed by `&&`/`||`/`all`/`exists` as in CEL; no
  clock: `time.*` comes from the host).
- **Decision resolution** (design §4.6): a policy finding joins `violations`
  with its own action, after every rule, 085 and 087 finding of the same action;
  `require_approval` is `Block` plus `approval_required`; `monitor_mode` and
  `mode: monitor` never block; a policy that does not compile fails closed in
  its scope; a statement that does not parse blocks under an enforced blocking
  policy that may apply (session boilerplate excepted).
- `EvaluationOutcome` gains `policy_hits`, `approval_required` and `unknowns`
  (always empty without policies).
- **Authoring**: `policy::check_policy()` (errors with key and offset,
  warnings, the fields read, per-mode decidability) and
  `policy::run_policy_tests()` (the `tests:` fixtures).
- **Benchmark and gate**: `cargo bench --bench policy` measures an empty set,
  10 out-of-scope policies, 3 typical and 50 applicable policies, and fails
  when a cell is over its budget (ratio ≤ 1.05; ≤ 1, 15 and 50 µs added). CI
  runs it.
- **Fuzzing**: a second cargo-fuzz target, `policy` (an arbitrary expression
  and statement through the checker, the compiler and the evaluation); the
  weekly workflow runs both targets.

### Changed

- `regex` is a new dependency (policy `matches` patterns). `cel` (=0.15.0) and
  `criterion` are new dev-dependencies (the conformance oracle and the bench).
- `rules::evaluator` splits the custom-rule matching into `node_kind` and
  `condition_matches` (shared with the policy guard); behaviour is unchanged.

## [4.3.0] — 2026-10-18

**A new license, and no code change.** From this version on, vericto-engine is
licensed under the Functional Source License, Version 1.1, ALv2 Future License
(SPDX `FSL-1.1-ALv2`) instead of the Elastic License 2.0. **All previously
released versions, 4.2.0 and earlier, remain under the Elastic License 2.0.**
The engine evaluates exactly as 4.2.0 did: same rules, same decisions. Only
`ENGINE_VERSION` and `STANDARD_RULESET_VERSION` move to `4.3.0` and
`standard@4.3.0`.

### Changed

- **License: FSL-1.1-ALv2, which becomes Apache-2.0 after two years.** `LICENSE`
  is the FSL-1.1-ALv2 text from fsl.software, unmodified, with
  "Copyright 2026 Vericto S.A.S." in its notice. It lets you use, copy, modify
  and redistribute the engine for any purpose other than a Competing Use: a
  commercial product or service that substitutes for the engine, or for a
  Vericto product that uses it, or that offers substantially similar
  functionality. Internal use, including in production at a company,
  non-commercial education and research, and professional services for a
  licensee are permitted purposes. Each version is also licensed under the
  Apache License 2.0 from the second anniversary of the date it is made
  available, irrevocably. Compared with the Elastic License 2.0, the FSL also
  covers self-managed competing products (ELv2 only restricted hosted and
  managed services) and drops the license-key clause, which this code never
  used.
- `Cargo.toml` declares `license = "FSL-1.1-ALv2"` (the SPDX identifier), and so
  does the fuzz crate. The crate description says FSL-1.1-ALv2.
- `NOTICE` states the copyright, the license, the Apache-2.0 future license and
  that versions up to 4.2.0 stay under the Elastic License 2.0, and lists the
  third-party SQL in the Snowflake test corpus.
- **New `LICENSING.md`**: which versions are under which license, and a short
  FAQ (what is allowed, what a Competing Use is, when a version becomes
  Apache-2.0, commercial licenses). **New `TRADEMARKS.md`**: the license grants
  no right to the Vericto name or logo, and what you may do without asking.
- Every Rust source file, and the test helper `tests/support/mysql_runner.cjs`,
  starts with `SPDX-FileCopyrightText` and `SPDX-License-Identifier` lines (the
  REUSE convention). The third-party test fixtures keep their own notices.
- README (badge and License section), crate documentation and CONTRIBUTING
  name the new license. CONTRIBUTING explains that CLA 1.0, which names the
  Elastic License 2.0, also covers later and other licenses.
- `deny.toml`: `Elastic-2.0` is no longer an allowed dependency license, and
  `FSL-1.1-ALv2` is allowed for this crate only, so a dependency under a
  source-available license still fails `cargo deny check`.

### Documentation

- **The CLA check runs in GitHub Actions** instead of cla-assistant.io, whose
  webhook failed on every delivery on 2026-10-17 and 2026-10-18 and left pull
  requests without a status. `.github/workflows/cla.yml` (CLA Assistant Lite,
  pinned by commit SHA) reports the `CLA` check. The agreement is unchanged
  (ICLA v1.0, now also in `CLA.md`). Contributors sign it by commenting
  `I have read the CLA Document and I hereby sign the CLA` on their pull
  request, and `recheck` reruns the check. Signatures are kept on the
  `cla-signatures` branch. The workflow never checks out pull request code.
  No code change.

## [4.2.0] — 2026-10-18

A security fix and a small additive API. **This release can block scripts that
4.1.3 let through.** When a policy softened a high-severity violation (a CI
channel's `schema_migration_cap`, or a host's severity mapping), 4.1.3 could let
that violation decide for the whole evaluation and pass a script that also held
a violation that blocks. 4.2.0 blocks those scripts. Nothing that 4.1.3 blocked
is allowed now, and an evaluation whose violations all resolve to the same action
gets the same decision and the same reported rule as before. The API additions
change no existing signature.

### Fixed

- **The decision could be weaker than one of the violations.** The engine chose
  the winning violation by severity first, then by the lowest code, and only then
  used that violation's resolved action as the decision. When a policy resolved
  the higher-ranked violation to a weaker action, that weaker action decided.
  Under a CI policy (`schema_migration_cap = Some(Flag)`), the script
  `DROP TABLE a; UPDATE accounts SET balance = 0;` reported the DROP
  (VERICTO-010, Critical, capped to Flag) ahead of the UPDATE without WHERE
  (VERICTO-030, also Critical, which blocks). The whole evaluation was a Flag, and
  the file passed the check. The same happened to any evaluation where a
  higher-ranked rule resolved to a weaker action, for example a capped DROP ahead
  of a High `INSERT … SELECT` with no filter (VERICTO-040), or a host policy that
  maps Critical to Flag. The CLI offline-mode spike found it. Online checks were
  exposed wherever a whole script is evaluated as one unit.
  Since 4.2.0 the decision is the strongest resolved action across all
  violations (Block, then Flag, then Monitor), so it is never weaker than any
  single violation's action. The reported winner is the violation that holds that
  action: among those with the same action, the highest severity wins, then the
  lowest rule code, so the result stays deterministic and never depends on the
  order of the `rules` slice. The script above now blocks with VERICTO-030.
  Without the cap it still blocks with VERICTO-010, as before. `monitor_mode`
  still turns every block into a flag.
  One comparator now governs every place a winner is chosen:
  - the order of `EvaluationOutcome::violations` (action, then severity, then
    code; `violations[0]` is still the winner);
  - the place VERICTO-085 (sensitive columns) and VERICTO-087 (agent allowlists)
    take in that list, and whether they take the flat fields;
  - the reading kept when MySQL may read the text in several ways (VERICTO-086
    alternatives);
  - the parse-error floor for Snowflake and SQLite code the engine does not read.
  **Reporting changes, no change to what is blocked:**
  - when the engine-driven codes share an action with a rule, they now rank by
    severity like any rule. A `mask` tag (VERICTO-085, High, Flag) next to
    VERICTO-050 (Medium, Flag) now reports VERICTO-085 as the winner. The
    decision is still Flag, and the rewrite is still forwarded.
  - an `observe` allowlist denial (VERICTO-087, High, Flag) now outranks a `flag`
    tag (VERICTO-085, Medium, Flag).
  - in the golden corpora, two MySQL ORM lines under the `tags` policy changed
    their winner from VERICTO-050 to VERICTO-085, for that reason. The Snowflake
    and SQLite corpora are unchanged.
  A new property test checks that the decision equals the maximum of each
  violation's resolved action, for any order of the rules (Property 11). The
  ordering property (Property 10) now checks action, then severity, then code.
  The regression tests run on all six dialects.

### Added

- **`standard_rules()` and `STANDARD_RULES`: the standard ruleset.** These hold
  all 42 built-in rules at their default severity. `standard_rules()` returns a
  `Vec<Rule>` that you can pass to `evaluate`. Each `StandardRule` entry in
  `STANDARD_RULES` holds the rule's code, severity, `RuleClass` and default
  action. Its `engine_driven` field marks VERICTO-085, 086 and 087, which the
  policy drives. A host with no ruleset of its own can use this table instead of
  keeping a copy: the proxy uses one when its rule sync fails, and the CLI's
  offline mode needs one. `tests/rule_catalogue_sync.rs` keeps it equal to the
  README catalogue (codes and severities), to the README's class table, and to
  the evaluator.
- **`ENGINE_VERSION` and `STANDARD_RULESET_VERSION`.** `ENGINE_VERSION` is the
  crate version (`"4.2.0"`). `STANDARD_RULESET_VERSION` is
  `standard@<engine version>` (`"standard@4.2.0"`). Hosts can print them with a
  verdict to record what it was evaluated with.

## [4.1.3] — 2026-10-18

Four evaluation fixes, found by the tests that pin them (the walker coverage
suite added before this release, whose four findings were `#[ignore]`d failing
tests and now pass). Three of them **narrow what is reported and blocked**:
fewer false positives, nothing that was a real tautology stops being one. The
fourth (negative literals) goes the other way on purpose: MySQL, Oracle, SQL
Server, SQLite and Snowflake now detect `-1 < 0`-style tautologies that only
PostgreSQL detected, so a query those five dialects allowed can now be blocked
there. No API change, no new rule, and the rule catalogue is unchanged.

### Fixed

- **A comparison with NULL was a tautology.** Both walkers compared a `NULL`
  literal like any value, so `DELETE … WHERE NULL = NULL`, `WHERE NULL <> 1` and
  `WHERE NOT (NULL = 1)` tripped VERICTO-003 (Critical, blocking) on every
  dialect, and the same forms as an `OR` branch tripped VERICTO-090, although
  under SQL's three-valued logic a comparison with NULL is UNKNOWN and such a
  `DELETE` removes no row. The constant comparison now lives once, in
  `parser::mod`, shared by both walkers, and returns true, false or unknown; a
  NULL operand is unknown, and so is its `NOT`. VERICTO-030/042 (the `UPDATE`
  forms) and VERICTO-040 read the same predicate and are narrowed the same way.
  `x = NULL` was never a tautology and still is not.
- **`NOT` of a comparison the engine cannot decide was a tautology.** A string
  ordering depends on the collation, so the engine left `'a' < 'b'` undecided,
  and then read "undecided" as "false": `NOT ('a' < 'b')` and `NOT ('b' > 'a')`
  tripped VERICTO-003 on every dialect, although one of the two matches no row
  under any collation. Undecided now stays undecided through `NOT`, and only a
  provably true predicate is reported. The same reading closes three neighbouring
  cases of the same kind: string equality a collation can decide either way
  (`'a' <> 'A'` and `NOT ('a' = 'A')`; case- and accent-insensitive collations
  are the MySQL and SQL Server defaults, and Snowflake's can also ignore
  punctuation and surrounding spaces), literals of different kinds
  (`NOT (1 = '1')`, true on PostgreSQL and MySQL), and, on the sqlparser
  dialects only, bind parameters, which were compared by their text (`? = ?`)
  where PostgreSQL never did. Identical string literals (`'a' = 'a'`, the
  classic `' OR 'a'='a` injection) and distinct plain ones (`'a' <> 'b'`) are
  still decided and still blocked.
- **Negative literals were decided on PostgreSQL only.** libpg_query folds `-1`
  into one constant; sqlparser reads it as a unary minus, which the other
  walker did not accept as a literal. `DELETE … WHERE -1 < 0` tripped
  VERICTO-003, and `… OR -1 < 0` VERICTO-090, on PostgreSQL and on none of the
  other five dialects. Both walkers now fold the sign through one shared helper,
  so the comparison, `IN`, `BETWEEN` and bare-literal forms (`WHERE -1`) are
  decided alike everywhere. **This widens detection** on MySQL, Oracle, SQL
  Server, SQLite and Snowflake: such a `DELETE` was allowed there and is now
  blocked, as it already was on PostgreSQL.
- **Snowflake's `ORDER BY ALL` was read as a column named `ALL`.** sqlparser
  0.63's Snowflake dialect does not parse `ORDER BY ALL` (fixed upstream in
  apache/datafusion-sqlparser-rs#2502, not yet released), so the VERICTO-085
  mask rewrite never saw it: `SELECT note FROM customers ORDER BY ALL` over a
  masked `note` was forwarded with the masked values (no disclosure) in the
  order of the masked values, which the same check refuses for `ORDER BY note`
  and `ORDER BY 1`. Under a VERICTO-087 allowlist the phantom column was denied,
  so an identity granted `customers.id` could not run
  `SELECT id FROM customers ORDER BY ALL` (fail-safe, a false positive). The
  engine now reads an ORDER BY that is exactly one bare, unquoted `ALL` (any
  case, with its direction and `NULLS` order) as ordering by every output, in
  one place shared by the sensitive and access walkers: the mask rewrite is
  refused when any output is masked, with the same reason as `ORDER BY 1`, and
  an allowlist sees no reference beyond the outputs. A quoted `"ALL"` is still
  a column, as is `all_col`. Snowflake only: no other dialect Vericto supports
  has `ORDER BY ALL`. The workaround is temporary and is to be removed when the
  engine moves to a sqlparser release that contains #2502 (expected 0.64); its
  tests stay as the regression check for that upgrade.

The golden corpora (MySQL ORM, Snowflake, SQLite) pass unchanged: no outcome
in them differs from 4.1.2.

### Documentation

- **The README and the crate docs said the engine has "no false positives".**
  Determinism means the same input always gets the same result; it does not
  mean a rule never matches a legitimate query, and this changelog records
  several that did (VERICTO-010 on non-table `DROP`s, VERICTO-040 on a filtered
  `INSERT … SELECT`, VERICTO-050 on a bounded `UNION`). The intro now says what
  is verifiable: deterministic, no ML, no thresholds, every false positive found
  fixed with a regression test, and `monitor_mode` to trial a ruleset without
  blocking.
- **"Open core" is now "source-available".** The README tagline, the crate docs
  and the `Cargo.toml` description called the engine the open core of Vericto.
  It is licensed under the Elastic License 2.0, which is source-available, not
  an open-source license.

## [4.1.2] — 2026-10-17

### Fixed

- **The `last4` mask returned short values in clear.** It rendered
  `'****' || right(x, 4)`, and `right(x, 4)` of a value of four characters or
  fewer is the whole value: a PIN, a short code, a one-character value or
  `''` under a `last4` tag came back unmasked (`'1234'` as `'****1234'`), and a
  value of five to eight characters came back half or more (`'12345678'` as
  `'****5678'`), while the column was reported as masked. Every dialect that
  rewrites masks was affected (PostgreSQL, MySQL and its variants, Snowflake,
  SQLite), for every query that projects a `last4` column, directly or through
  aliases, CTEs, derived tables and scalar subqueries. `last4` now renders
  exactly what `full` renders (`'[redacted]'`) for a value of 8 characters or
  fewer, counted in characters (`char_length`, MySQL's `CHAR_LENGTH`, `length`
  on Snowflake and SQLite), never bytes, so `'ñandú12'` (7 characters, 9 bytes)
  is redacted; longer values keep `'****'` and their last four characters. The
  threshold is a fixed rule of the style, not configuration. NULL stays NULL, as
  before. The length test names the value twice, which is safe for a column
  but not for a scalar subquery: run twice, a volatile one could pass the test
  with one row and give out the tail of another, and on MySQL a repeated `?`
  would shift the client's bindings. `last4` over anything but a bare column is
  therefore redacted whatever its length (`'[redacted]'`, NULL staying NULL),
  with the expression and each of its bind parameters kept once, in order and in
  the same context, so prepared statements bind as before. Computed values and
  aggregates were already masked `full` and are unchanged. This narrows what a
  `last4` mask reveals; it does not change which queries are allowed, flagged
  or blocked, nor the reported rule, severity or columns. Hosts that compare
  rewritten text (golden files, caches keyed on the rewrite) see the new mask
  expression for every `last4` column.

## [4.1.1] — 2026-10-15

### Fixed

- **VERICTO-070 on SQLite missed a wrapped `randomblob(N)` / `zeroblob(N)`.**
  The sqlparser walker looked for calls only in the projection, the `WHERE`
  root, call arguments and `AND`/`OR`/`NOT`/parentheses, so `SELECT 1 WHERE
  randomblob(100000000) IS NOT NULL`, `IS NULL`, `CASE WHEN …`, `IN (…)`,
  `BETWEEN`, `LIKE`, `CAST`, a subquery under `IN` / `EXISTS`, `ORDER BY`,
  `GROUP BY`, `HAVING`, `LIMIT` / `OFFSET`, `JOIN … ON`, a window or `FILTER`
  clause, `INSERT … VALUES`, `ON CONFLICT … DO UPDATE`, `UPDATE … SET`, `UPDATE …
  FROM`, `RETURNING` and a trigger's `WHEN` were allowed (4.1.0 already walked
  trigger bodies, with the same blind spots inside them). On SQLite the walker
  now visits every expression a statement evaluates, through sqlparser's
  derived traversal (the `visitor` feature of `sqlparser`, which adds
  `sqlparser_derive` to the build), so a clause or an expression kind it does
  not name is still read. The threshold and the constant-only reading are
  unchanged: `N` ≥ 10,000,000 as a number literal or constant arithmetic; a
  bind parameter or a computed `N` is not a probe.
- **The other rules on SQLite see the same expressions**: a `SELECT *`
  subquery under `IN` / `EXISTS` is a nested SELECT for VERICTO-051, a
  `sleep()` an application defines is VERICTO-070 wherever it is, and a custom
  rule's `func_name:` matches a call in any clause (`CURRENT_TIMESTAMP`, which
  sqlparser reads as a call, is now recorded too).
- Unchanged on the other dialects: PostgreSQL has its own walker, and MySQL,
  Oracle, SQL Server and Snowflake walk exactly what they walked in 4.1.0
  (3,654 SQL strings from the engine, proxy and eval sources × 7 policies:
  identical outcomes). Extending the complete walk to them changes verdicts
  (`SELECT 1 WHERE sleep(5) IS NULL` on MySQL), so it is left to a minor
  release.

## [4.1.0] — 2026-10-14

SQLite becomes a dialect: `Dialect::Sqlite` (`"sqlite"`, also `"sqlite3"`),
parsed with sqlparser's `SQLiteDialect`, with four SQLite rules, SQLite readings
of five standard rules, SQLite identifier semantics for agent allowlists, a
SQLite mask rewrite, and, for the statements sqlparser 0.63 does not read, a
`PRAGMA` grammar, a planner-hint read-through, a keyword pre-classifier and an
allowlist. SQLite is a library inside the application, so there is no wire
protocol and no proxy: hosts evaluate through the Runtime API and its driver
wrappers, the CLI and MCP. A minor release: every API change is additive (the
`#[non_exhaustive]` types of 4.0.0 take the new variants and fields).

**Nothing changes for the other dialects**: the verdicts of every SQL string in
the test suites and fixtures of the engine (4.1.0's included), the proxy and the
sidecar — 3,479 statements — were compared with 4.0.0 on PostgreSQL, MySQL,
Oracle, SQL Server and Snowflake under seven policies (default, `parse_error:
block`, `monitor_mode`, a CI `schema_migration_cap`, block/mask/flag tags, an
enforced allowlist, an observed allowlist with tags): 121,765 outcomes, compared
field by field, and none differs. No sqlparser type is part of the public API.

### Added

- **`Dialect::Sqlite`** and `parser::sqlite::SqliteParser`. The shared sqlparser
  walker records the SQLite statement kinds the rules need: `ATTACH`, `PRAGMA`
  (reads and writes), `VACUUM`, `CREATE TABLE … AS SELECT` (VERICTO-084), and a
  trigger's body (`CREATE TRIGGER … BEGIN … END`), whose statements run on every
  matching write and are walked as nested statements (`DELETE FROM log` inside
  a trigger is VERICTO-001). UPSERT (`ON CONFLICT`), `INSERT OR REPLACE`,
  `REPLACE INTO`, `RETURNING`, `WITH RECURSIVE`, window and JSON functions, every
  quoting style (`"x"`, `` `x` ``, `[x]`) and placeholder (`?`, `?NNN`, `:name`,
  `@name`, `$name`) read as on the other dialects. `parser::walk::not_analysed`
  analyses `VACUUM` / `VACUUM <schema>` on SQLite; every other kind added since
  sqlparser 0.52 is still a parse error.
- **Before a SQLite text is a parse error** (only when the parse fails): the
  planner hints `INDEXED BY <index>` / `NOT INDEXED` after a table name, and the
  `IF NOT EXISTS` of `CREATE TRIGGER`, are read through (the statement is read
  without them, the client's text is kept); a `PRAGMA` whose value is a keyword
  or a name (`PRAGMA foreign_keys = OFF`, `PRAGMA table_info(users)`, `PRAGMA
  cache_size = -2000`) is read with SQLite's grammar; an **allowlist** analyses
  `DETACH [DATABASE] <name>`, `REINDEX [[schema.]name]` and `CREATE [TEMP]
  VIRTUAL TABLE … USING fts3 | fts4 | fts5 | rtree | rtree_i32 | geopoly(…)`
  (names, literals and `name = literal` options only) with no finding; and a
  **pre-classifier** turns `VACUUM … INTO`, the `ATTACH` forms sqlparser does not
  read, a safety pragma outside the grammar and a native-code call into findings.
  A statement only recognised by its keywords is unread code: its outcome is the
  stricter of the findings and the parse-error one.
- **VERICTO-098 — SQLite ATTACH DATABASE** (High, Security): `ATTACH [DATABASE]
  <file> AS <name>` opens, or creates, another database file on the connection.
  `DETACH` is not reported.
- **VERICTO-099 — SQLite safety PRAGMA** (High, SchemaMigration): a `PRAGMA`
  write that turns a safety off — `writable_schema` (any value), `trusted_schema
  = ON`, `foreign_keys = OFF`, `ignore_check_constraints = ON`, `journal_mode =
  OFF`, `synchronous = OFF`, `cell_size_check = OFF`, `query_only = OFF`,
  `schema_version = n`, `temp_store_directory` / `data_store_directory`. Reads
  and other settings are not reported. SchemaMigration, so a CI channel's
  `schema_migration_cap` softens it: `PRAGMA foreign_keys = OFF` is the standard
  step of a SQLite table rebuild in Prisma, Drizzle, Django and Alembic
  migrations.
- **VERICTO-100 — SQLite extension loading or file functions** (Critical,
  Security): `load_extension()`, `fts3_tokenizer()`, and the sqlite3 shell's
  `readfile()`, `writefile()`, `edit()`, `fsdir()` and `zipfile()`. Read from the
  tokens of the whole text, so a call in `INSERT … VALUES`, `UPDATE … SET`,
  `ORDER BY` or under a quoted name is found; one in a string or a comment is
  not.
- **VERICTO-101 — SQLite VACUUM INTO** (High, Security): `VACUUM [schema] INTO
  <file>`, a full copy of the database written to a path. Plain `VACUUM` is not
  reported.
- **The standard rules on SQLite** (design §4.2): direct — 001, 002, 010, 013,
  015, 016, 019 (`DROP TRIGGER`), 030, 040, 042, 050, 051, 060, 061, 084;
  variants — 003 and 090 (SQLite truthiness: a string literal with a non-zero
  numeric prefix, `WHERE '1abc'`, and a double-quoted name spelling one, is
  always-true), 070 (no sleep on SQLite: `randomblob(N)` / `zeroblob(N)` with a
  constant `N` ≥ 10,000,000, the time-based probe), 085, 087; not applicable,
  never fire on SQLite — 011, 012, 017, 018, 031, 033, 080, 081, 082, 083, 086.
  The new codes read only what the SQLite walker and pre-classifier record, so
  they never fire on another dialect, and like every code they fire only once
  the host's catalogue lists them.
- **VERICTO-087 on SQLite**: names compare ASCII case-insensitively, quoted or
  not (entries accept `"x"`, `` `x` `` and `[x]`); the default schema is `main`
  (or the host's `default_schema`), `temp` and attached databases are other
  schemas; `sqlite_master` and the table-valued functions (`pragma_table_info`,
  `dbstat`) need an entry naming them (`json_each` / `json_tree` read only their
  arguments); `PRAGMA table_info | table_xinfo | index_list |
  foreign_key_list(<t>)` reads every column of `<t>`; the connection settings
  drivers send (`foreign_keys = ON`, `busy_timeout`, `journal_mode = WAL |
  DELETE | TRUNCATE | PERSIST`, `synchronous = NORMAL | FULL | EXTRA`,
  `cache_size`, `temp_store`, `defer_foreign_keys`, `recursive_triggers`,
  `case_sensitive_like`) are allowed; every other `PRAGMA`, `ATTACH`, `DETACH`,
  `VACUUM`, `REINDEX` and `ANALYZE` are denied as DDL.
- **VERICTO-085 on SQLite**: a mask rewrite printed from the tree with core
  functions only (`full`, `last4` with `substr(…, -4)`, `email` with
  `instr`/`substr`), forwarded only when the unmodified statement prints back to
  the client's tokens, the rewrite reparses to itself and the bind parameters
  are the client's. **`hash` blocks on SQLite** (core SQLite has no SHA-256;
  design open question Q7, resolved the conservative way). **A statement holding
  a double-quoted name is not rewritten** (it blocks): SQLite reads `"x"` as a
  string literal when no column `x` exists (DQS), which the engine cannot rule
  out without a schema; block and flag tags count `"x"` as the column. As on
  Snowflake, output names are kept and `ORDER BY` / `GROUP BY` / `HAVING` over a
  masked output, or an unaliased expression over a masked column, block.
- **`ParseErrorKind`** (`UnknownStatement`, `Syntax`, `TooComplex`; serialized
  `unknown_statement`, `syntax`, `too_complex`; `#[non_exhaustive]`) and
  `EvaluationOutcome::parse_error_kind()`, which tells a statement kind the
  engine does not read (a corpus gap) from invalid SQL, for telemetry (design
  §4.6). `None` for every outcome that is not a parse error. Also
  `ParseErrorKind::classify` for a parse-error message.
- `parser::SqliteRisk` (`#[non_exhaustive]`) and `StatementInfo::sqlite`.
- Tests: `tests/sqlite.rs` (what the walker reads, the rules × SQLite matrix,
  every SQLite rule's positive and negative cases and catalogue examples, rule
  classes, parse errors and their kind, the parse-error floor, anchored
  fallbacks, VERICTO-087 names, VERICTO-085 golden rewrites and refusals);
  `tests/sqlite_corpus.rs` with a golden file over 171 SQLite statements written
  for this repository (ORM and migration-tool DDL and DML, UPSERT, `WITH
  RECURSIVE`, window, JSON and FTS5 queries, pragmas, transactions, maintenance,
  and the dangerous statements, which all block), each checked with sqlite3
  3.51: the engine recognises 100% (sqlparser alone 84.8%);
  `tests/sqlite_mask_equivalence.rs`, which runs every SQLite mask through the
  `sqlite3` shell (when one is on `PATH` or in `VERICTO_SQLITE3`) and compares the
  values with the Postgres masks'. The 003/090 tautology suite, the nesting guard
  and the property P9 also run on SQLite; the fuzz target covers Snowflake and
  SQLite and the Snowflake and SQLite codes.

### Changed

- `SourceAst::Classified` (crate-private) carries its dialect; the README rule
  classes table lists the Snowflake and SQLite codes.

### Notes for hosts

- The control plane seeds VERICTO-098 to VERICTO-101 (dialect `sqlite`); until
  the catalogue lists them, an `ATTACH` or a `load_extension()` is not reported.
- The proxy never sees SQLite (no wire protocol); its built-in fallback catalogue
  needs no SQLite code. Hosts that `match` on `Dialect` already have a wildcard
  arm (`#[non_exhaustive]` since 4.0.0).
- Unparseable SQLite text follows the host's `parse_error`, as on every dialect.
  A host that wants SQLite fail-closed by default (design §4.6, open question
  Q10) serves `parse_error: block` for SQLite databases.
- The version-pinned snippets in README.md and src/lib.rs are now v4.1.0.

## [4.0.0] — 2026-10-13

A major release: Snowflake becomes a dialect, and the public types that grow
release after release become `#[non_exhaustive]`, so a future dialect, statement
kind or policy field is no longer a breaking change (see **Migrating from 3.x**
below). 3.10.0 was never tagged; its changes are this release.

Snowflake: `Dialect::Snowflake` (`"snowflake"`), parsed with sqlparser's
`SnowflakeDialect`, with seven Snowflake rules, Snowflake identifier semantics for
agent allowlists, a Snowflake mask rewrite, and, for the statements sqlparser
0.63 does not read, a keyword pre-classifier (dangerous kinds become findings)
and an allowlist (legitimate forms are analysed with no finding). **Nothing
changes for the other dialects**: every verdict of the SQL in the test suites
and fixtures of the engine, the proxy and the sidecar was compared with 3.9.0
on PostgreSQL, MySQL, Oracle and SQL Server under seven policies (41,216
verdicts) and none differs. No sqlparser type is part of the public API.

### Added

- **`Dialect::Snowflake`** and `parser::snowflake::SnowflakeParser`. The shared
  sqlparser walker records the Snowflake statement kinds the rules need: `COPY
  INTO` (a load from a stage, or an unload to a stage or an external location),
  `CREATE`/`DROP STAGE`, `PUT`, `LIST`, `USE ROLE | SECONDARY ROLES`, `EXECUTE
  IMMEDIATE`, scripting blocks (`BEGIN … END`, whose statements are walked),
  `QUALIFY`, `GRANT … TO SHARE`, `CREATE WAREHOUSE`, `CREATE TABLE … CLONE`,
  `CREATE OR REPLACE`, `INSERT OVERWRITE`, `ALTER TABLE … SWAP WITH`, time travel,
  semi-structured paths and `FLATTEN`, three-part names and `IDENTIFIER()`.
  `parser::walk::not_analysed` stays exhaustive: on Snowflake it also analyses
  `CREATE WAREHOUSE`, `ALTER SESSION`, `PUT`, `LIST`, `SHOW OBJECTS`, `CREATE
  FILE FORMAT` and scripting blocks; every other kind sqlparser added since 0.52
  is still a parse error.
- **A pre-classifier** for the Snowflake statements sqlparser 0.63 rejects that a
  rule covers (`UNDROP`, `GET`, `PUT file://…`, `CREATE TASK | STREAM | PIPE |
  PROCEDURE | FUNCTION | ALERT | SHARE | … INTEGRATION | NETWORK RULE`, `ALTER
  WAREHOUSE | RESOURCE MONITOR | ACCOUNT | SHARE | STAGE | TASK`, `ALTER TABLE …
  DROP ROW ACCESS POLICY | UNSET MASKING POLICY`, `DATA_RETENTION_TIME_IN_DAYS =
  0`, `DROP DYNAMIC | ICEBERG | EXTERNAL TABLE`, `CLONE`, `DECLARE` blocks). It
  runs only when the parse fails, on a single statement, matching leading
  keywords outside strings and comments, and turns the statement into a finding
  of the rule that names it (GRANT/REVOKE forms sqlparser does not read stay
  VERICTO-082). It never widens an outcome: a pre-classified statement, a
  scripting block and `EXECUTE IMMEDIATE`/`EXECUTE TASK` are unread code, whose
  outcome is the stricter of the findings and the parse-error one.
- **An allowlist** of legitimate Snowflake statements sqlparser 0.63 rejects,
  analysed with no finding (no parse error, no SchemaMigration flag: on the
  dialects whose parser reads the same DDL, no rule reports it either).
  Each entry is an anchored pattern over the whole statement (head keywords,
  names, literal values), so anything more, a second statement or a `$$` body
  anywhere but a comment value is not on it: `COMMENT ON … IS '…'|$$…$$`,
  `ALTER [MATERIALIZED] VIEW … SET|UNSET SECURE / COMMENT`, `ALTER DYNAMIC TABLE
  … SET TARGET_LAG|WAREHOUSE|COMMENT / REFRESH / SUSPEND / RESUME`, column and
  table comments, `SET CHANGE_TRACKING | DEFAULT_DDL_COLLATION`, additive `ADD
  COLUMN` (types only), `ADD ROW ACCESS POLICY`, `SET MASKING POLICY` (not
  `FORCE`), `ALTER WAREHOUSE … SUSPEND|RESUME|ABORT ALL QUERIES`, `ALTER TASK …
  SUSPEND`, `ALTER STAGE … REFRESH`, `CREATE TABLE (columns only)`, `CREATE
  SEQUENCE`, `CREATE TAG`, internal `CREATE STAGE`, `DESCRIBE <object>`, `SHOW …`
  (words and literals only), `UNSET <var>`, and `COPY INTO <table>` from its own
  stage. Each entry is documented with an example and the reason on
  `parser::snowflake::allowlisted`. Under an agent allowlist they are denied as
  DDL, like every statement the parser does not read.
- **Seven Snowflake rules** (design SF-1 to SF-7), which read only what the
  Snowflake walker and pre-classifier record and so never fire on another
  dialect. Proposed catalogue severities and classes:
  - **VERICTO-091** stage unload or file transfer: `COPY INTO @stage | 's3://…' |
    'azure://…' | 'gcs://…'`, `GET`, `PUT`. Critical, Security (block).
  - **VERICTO-092** external stage or integration: `CREATE|ALTER STAGE` with `URL
    =` or inline `CREDENTIALS`, `CREATE STORAGE | EXTERNAL ACCESS | API
    INTEGRATION`, `CREATE EXTERNAL FUNCTION`, an egress network rule. Critical,
    Security (block).
  - **VERICTO-093** share to another account: `GRANT … TO SHARE` (also
    VERICTO-082), `CREATE SHARE`, `ALTER SHARE … ADD|SET ACCOUNTS`, `CREATE
    LISTING`. Critical, Security (block).
  - **VERICTO-094** recovery reduced: `DATA_RETENTION_TIME_IN_DAYS = 0`, `ALTER
    ACCOUNT`, `CREATE OR REPLACE TABLE | SCHEMA | DATABASE`, `INSERT OVERWRITE`,
    `UNDROP`. High, **SchemaMigration** (block at runtime; a CI channel's
    `schema_migration_cap` softens it like DROP TABLE).
  - **VERICTO-095** warehouse cost: `CREATE|ALTER WAREHOUSE` setting a size, a
    cluster count, a type, a scaling policy, query acceleration or a
    never-suspend `AUTO_SUSPEND`; `ALTER RESOURCE MONITOR`. High, Performance
    (block). The design's unbounded `SELECT` on a host-tagged large table needs
    table-size metadata the host does not send yet and is not part of it.
  - **VERICTO-096** code that runs later: `CREATE TASK | STREAM | PIPE |
    PROCEDURE | FUNCTION | ALERT`, `ALTER TASK … RESUME | MODIFY AS`, `EXECUTE
    TASK …`. High, Security (block).
  - **VERICTO-097** role switch: `USE ROLE`, `USE SECONDARY ROLES ALL | <roles>`
    (administrative roles are named in the evidence). High, Security (block).
  The host's catalogue drives these like any code: until it lists them, they do
  not fire.
- **VERICTO-087 on Snowflake.** Unquoted identifiers fold to upper case, quoted
  ones compare exactly, in the query (read again with its names folded) and in
  the entry alike. `AccessPolicy::quoted_identifiers_ignore_case` (host-set)
  says whether quoted names fold too; when it is unknown both readings are
  checked and a reference either one denies is denied. Names are three-part:
  `AccessEntry::database` (alias `database_name`) and
  `AccessPolicy::default_database` (host-set, with `default_schema`) resolve
  them; `INFORMATION_SCHEMA` and the shared `SNOWFLAKE` database are the
  catalogue; a stage is data and needs an entry; dynamic names and table
  functions that may read anything are denied; `ALTER SESSION SET` is allowed
  for formatting, tagging and timeouts only. A denied three-part reference
  reports its schema as `database.schema`. All three fields are optional and
  not serialized when unset, so existing policies are unchanged.
- **VERICTO-085 mask rewrite on Snowflake** (`full`, `last4`, `email`, `hash`),
  printed back from the sqlparser tree and forwarded only when the unmodified
  statement prints back to the client's tokens, the rewrite parses back to
  itself and the bind parameters are the client's, in order. The masks return
  what the Postgres masks return for the same text: `full` over a computed value
  is `CONCAT('[redacted]', COALESCE(LEFT(TO_VARCHAR(x), 0), ''))` (Snowflake's
  `CONCAT` is NULL if any argument is), and `email` is a `CASE` over `CHARINDEX`
  rather than `REGEXP_REPLACE`, which returns the value unmasked when it fails to
  match. Output names are kept (a bare column is aliased with its own
  identifier); an unaliased expression, and `ORDER BY` / `GROUP BY` / `HAVING` /
  `QUALIFY` naming a masked output, block. Pinned by golden outputs only:
  there is no Snowflake emulator, and an equivalence run against a real account
  is not part of this repository's CI.
- `system$wait` joins the sleep-family functions of VERICTO-070 (shared by both
  walkers, so it is detected on every dialect).
- `tests/snowflake.rs` (walker cases, the rules × Snowflake matrix, every
  Snowflake rule's positive and negative cases, parse errors, the allowlist and
  its near misses, VERICTO-087,
  VERICTO-085) and `tests/snowflake_corpus.rs`: 1,165 statements of public
  Snowflake SQL (rendered dbt models of `dbt-labs/jaffle_shop` and
  `get-select/dbt-snowflake-monitoring` with the DDL dbt-snowflake wraps them in,
  the statements dbt-snowflake sends, and the Snowflake tests of sqlglot; the
  sources and licences are in the fixture's header and `.LICENSES` file) with a
  golden file of how each is read and its verdict. The engine recognises
  (parses, pre-classifies or allowlists) the dbt models 100%, the dbt-snowflake
  statements 100% and sqlglot's 94.1%, 94.7% overall (sqlparser alone: 100%,
  84.8%, 87.7%; 88.3%).
- `Dialect::as_str()`: the canonical lowercase name, accepted back by
  `Dialect::parse_dialect`.
- `AccessEntry::new`, `AccessEntry::in_schema`, `AccessEntry::in_database` and
  `AccessPolicy::new`, to build what can no longer be built with a struct
  literal outside the crate.

### Changed

- **Snowflake parse errors resolve like on every dialect**: flagged by default
  (`parse_error: allow_report`), blocked under `parse_error: block`, and
  always blocked under a `block`/`mask` tag or an enforced agent allowlist.
  `EnforcementPolicy::effective_parse_error_for(sql, Dialect::Snowflake)`
  returns it, as for the other dialects. Unread code (above) keeps that
  outcome as a floor under its findings.
- **Breaking: `#[non_exhaustive]`** on `Dialect`, `parser::StatementKind`,
  `parser::DropObjectKind`, `parser::AlterTableKind`, `parser::SnowflakeRisk`,
  `parser::StatementInfo`, `AccessPolicy` and `AccessEntry`. Outside this crate
  a `match` on one of the enums needs a wildcard arm, and the structs are built
  with their constructors, `Default` or JSON instead of a struct literal (their
  fields stay public, to read and to assign). Also new: the `Dialect::Snowflake`
  variant, `StatementInfo::snowflake`, `AccessEntry::database`,
  `AccessPolicy::default_database` and `AccessPolicy::quoted_identifiers_ignore_case`.
  JSON shapes are unchanged: every new field is optional and not serialized
  when unset.

### Migrating from 3.x

Hosts that build policies from JSON and do not `match` on `Dialect` need no
change. Measured on the two first-party consumers:

- **vericto-proxy** (does not compile as it is):
  - `src/tcp/postgres.rs`, `fn dialect_name`: replace the `match` with
    `dialect.as_str()` (its four names are the engine's).
  - `src/tcp/query_limit.rs`, `fn dialect_cap`: replace the arm
    `Dialect::Oracle | Dialect::MsSql => MYSQL_MAX_PACKET_LEN,` with
    `_ => MYSQL_MAX_PACKET_LEN,` (every dialect it does not serve gets the
    stricter cap, as the comment there intends).
  - Its test `default_ruleset_has_the_engine_catalogue` then reports
    VERICTO-091 to VERICTO-097 missing from the built-in fallback catalogue: add
    them (Critical: 091, 092, 093; High: 094 to 097), or exclude the
    Snowflake-only codes from that comparison, since the proxy serves no
    Snowflake wire protocol.
- **vericto-eval**: compiles and passes unchanged against 4.0.0. One of its
  tests, `unparseable_session_boilerplate_keeps_the_hosts_parse_error`,
  already fails against 3.9.0 (MySQL's `SET SESSION TRANSACTION …` parses since
  3.9.0 and is allowed; see 3.9.0 below): update its expectation to `ALLOWED`.
- Code outside this crate that builds an `AccessEntry` or `AccessPolicy`
  literal: `AccessEntry::new("orders", AccessColumns::AllColumns,
  AccessLevel::Read).in_schema("public")`, `AccessPolicy::new(AccessMode::Enforce,
  entries)` then assign `default_schema` etc.; a `match` on `StatementKind`,
  `DropObjectKind` or `AlterTableKind` gains a `_ => …` arm.

## [3.9.0] — 2026-10-12

Dependency release: `serde_yaml` is replaced (RUSTSEC-2024-0449, which fails
`cargo deny` and `cargo audit` on 3.8.2) and sqlparser, the parser of MySQL,
Oracle and MS SQL, moves from 0.52 to 0.63. **No breaking API changes**: hosts
build against 3.9.0 unchanged, and no rule code is added, no JSON shape or
precedence changes. Two existing rules cover more statements: `DROP TRIGGER`
(VERICTO-019) and `COPY … FROM` a server-side file (VERICTO-061), on every
dialect including PostgreSQL (below). What changes otherwise is the SQL the
sqlparser dialects accept: text 3.8.2 could not parse, whose outcome was the
host's `parse_error` choice, is now evaluated by the rules (below). Statement kinds the engine does not model keep
resolving as parse errors, and every verdict was compared with 3.8.2 on the
SQL of the test suites, fixtures and documentation of the engine and its
consumers: nothing 3.8.2 blocked by a rule is allowed, unless sqlparser 0.52
had misread the text (MySQL SELECT modifiers read as columns, `--1` read as a
comment). PostgreSQL (`pg_query`) is unaffected by the parser change; only
the two rule extensions change its verdicts.

**3.8.2 was never tagged.** Its changes (the hardening release of 2026-10-11:
`#![forbid(unsafe_code)]`, cargo-deny/cargo-audit, gitleaks, Dependabot and the
fuzz target) ship in this release; a host on 3.8.1 moving to 3.9.0 gets both
entries below.

### Changed

- **sqlparser 0.52 → 0.63** (the parser of MySQL, Oracle and MS SQL; PostgreSQL
  still uses `pg_query`). No public API changes: no sqlparser type is part of the
  crate's API. What changes is the SQL these dialects accept. Most text 3.8.2
  could not parse now parses and is evaluated by the rules like any other
  statement, so its outcome is the rules' verdict instead of the host's
  `parse_error` choice (with a protective tag or an enforced allowlist: a block).
  Among the statements in the test suites and fixtures, these change:
  data-modifying CTEs (`WITH d AS (DELETE … RETURNING …) SELECT …`) on every
  dialect, and `DELETE … RETURNING`, `UPDATE … FROM`, `DROP INDEX i ON t`,
  `ALTER TABLE … ALTER COLUMN … TYPE`, `COPY … FROM STDIN`, `COMMENT ON`,
  `ANALYZE`, `DROP TRIGGER` and `COPY … FROM '/path'` where a dialect rejected
  them; MySQL's `SET SESSION TRANSACTION …` (sent on connect by Django,
  Hibernate and SQLAlchemy), now allowed as it is on PostgreSQL; MySQL index hints,
  `WITH ROLLUP`, `b'…'` bit literals and SELECT modifiers (`HIGH_PRIORITY`,
  `SQL_CALC_FOUND_ROWS`, `SQL_NO_CACHE`, …), which sqlparser misread as a column
  with an alias (an allowlist reported a read of a column named
  `HIGH_PRIORITY`); MySQL `--` not followed by a space, which sqlparser now reads
  as MySQL does (two minus signs), so such text is analysed for sensitive
  columns instead of blocked as unreadable; SQL Server `DECLARE … CURSOR FOR
  SELECT …`. A mask rewrite now keeps the client's spelling of table aliases
  (no inserted `AS`), `LIMIT a, b` and `INNER JOIN`. Parse error messages are
  sqlparser's own and may read differently.
- sqlparser's default `recursive-protection` feature adds `recursive`, `stacker`
  and `psm` (MIT / MIT OR Apache-2.0): the parser grows its stack instead of
  overflowing on deeply nested input. The engine's own nesting guard
  (`MAX_AST_DEPTH`, `guard_nesting_depth`) is unchanged.
- **Behaviour note: statements that now get the rules' verdict.** On MySQL,
  Oracle and SQL Server, `SET SESSION TRANSACTION …`, `ANALYZE`, `COMMENT ON`,
  `DROP TRIGGER` and `COPY … FROM` used to be rejected only because sqlparser
  0.52 did not parse them, so under a fail-closed policy (`parse_error: block`,
  a `block`/`mask` tag or an enforced allowlist) they were blocked as parse
  errors. They are now evaluated like on PostgreSQL. `SET SESSION
  TRANSACTION`, `ANALYZE` and `COMMENT ON` match no rule and are allowed;
  `DROP TRIGGER` and `COPY … FROM` a server-side file are reported (Security,
  below); `COPY … FROM STDIN` and `COPY … TO` (STDOUT or a file) match no rule.
  MySQL's `LOAD DATA [LOCAL] INFILE` and SQL Server's `DROP TRIGGER … ON ALL
  SERVER` still do not parse in sqlparser 0.63 and stay parse errors.
- `parser::DropObjectKind::Trigger` and `StatementInfo::copy_from_file` are
  added (additive enum/struct changes, as in earlier minor releases).
  `DropObjectKind::from_yaml` does not accept `trigger`, so custom rules are
  unchanged: a `statement: drop` rule still matches `DROP TRIGGER`.

### Fixed

- A data-modifying statement inside a CTE (`WITH x AS (UPDATE accounts SET
  balance = 0 RETURNING id) SELECT …`) was parsed on the sqlparser dialects but
  never evaluated: the walker skipped CTE bodies that are not a `SELECT`, so an
  `UPDATE` without `WHERE` in one was not reported. It is now evaluated as a
  nested statement, as on PostgreSQL. This widens what is blocked; MySQL, Oracle
  and SQL Server reject the syntax themselves, so no working query is affected.

### Security

- **`DROP TRIGGER` is reported by VERICTO-019** ("ALTER TABLE DISABLE TRIGGER /
  RLS"), on every dialect: PostgreSQL, MySQL, Oracle and SQL Server, with `IF
  EXISTS`, `CASCADE`/`RESTRICT` and SQL Server's `DROP TRIGGER … ON DATABASE`.
  Dropping a trigger removes the same protection `DISABLE TRIGGER` turns off,
  for good. It is enforced like `DROP TABLE`: VERICTO-019 is a
  `SchemaMigration` rule, so it blocks at runtime under the default policy
  (High → block) and a CI channel's `schema_migration_cap = Flag` turns the
  block into a flag. Evidence path `DropStmt > ObjectType = TRIGGER`.
  PostgreSQL allowed it in 3.8.2 (no rule matched); MySQL, Oracle and SQL
  Server rejected it as a parse error. VERICTO-010 still does not fire on it.
- **`COPY … FROM` a server-side file is flagged by VERICTO-061** (bulk load),
  on every dialect where it parses: the database server reads a file from its
  own filesystem into the table. VERICTO-061 is Medium (flag) and a
  `Performance` rule, so it flags on every channel and never blocks under the
  default policy. Evidence path `CopyStmt > FROM file`. `COPY … FROM STDIN`
  (the path VERICTO-061 recommends) stays allowed, `COPY … FROM PROGRAM` stays
  VERICTO-080 alone, and `COPY … TO` is unchanged.
- **RUSTSEC-2024-0449: `serde_yaml` replaced by `serde_norway`.** Custom-rule YAML
  (`ast_condition_yaml`) was parsed with `serde_yaml` 0.9, which is deprecated
  and runs `unsafe-libyaml`, a machine translation of libyaml that is
  unmaintained (RUSTSEC-2024-0449). That advisory failed `cargo deny` and
  `cargo audit` on every build of 3.8.2. `serde_norway` 0.9.42 is the
  maintained fork of `serde_yaml` 0.9: the same parser, the same `Value` and the
  same error messages, under MIT OR Apache-2.0, with a minimum Rust version of
  1.71. The YAML a rule accepts is unchanged: the same text parses to the same
  rule, and a rule the old parser rejected is still rejected and skipped with
  the same warning text, field and position included. The rule templates of the
  dashboard editor and the documented examples are now tests
  (`tests/custom_rule_yaml.rs`). `cargo deny check` and `cargo audit` pass with
  no ignored advisory.
- **What sqlparser 0.63 reads that 0.52 rejected is never silently allowed.**
  Statement kinds that are new in sqlparser and that the engine does not model
  (`VACUUM`, `LOCK TABLE`, `RESET`, `RENAME TABLE`, `DENY`, `CREATE USER`, SQL
  Server's `IF`/`WHILE`/`BEGIN … END` blocks, `PRINT`, `RAISERROR`, `THROW`,
  `WAITFOR`, …), the server-wide `SET GLOBAL …`, `SET SESSION AUTHORIZATION`,
  SQL Server's session options (`SET NOCOUNT ON`, …) and the pipe syntax
  (`FROM t |> SELECT …`) still resolve as the parse errors they were. The
  classification is an exhaustive match on sqlparser's statement kinds, so the
  next upgrade fails to compile until every kind it adds is classified.
- sqlparser's MySQL and Generic tokenizers now splice the content of a
  `/*! … */` comment into the statement as code, whatever its version number.
  Oracle (Generic dialect) never executes such a comment: it is read as a
  comment again, as in 3.8.2, so `DELETE FROM t /*!99999 WHERE id = 1 */` is
  still the unbounded `DELETE` Oracle runs. The MySQL sensitive-column analysis
  still refuses text with executable comments (MySQL's own reading goes through
  the lexical normalizer, unchanged).
- Shapes sqlparser now reads differently keep their verdict: SQL Server's
  `WHERE true` / `WHERE NOT FALSE` (the words are identifiers since 0.53) are
  still tautologies (VERICTO-003); MySQL's `"public"."User"."email"` (a column
  under `ANSI_QUOTES`, now read as field access on a string) is still a read of
  that column (VERICTO-085, VERICTO-087); SQL Server's `db..t` resolves to the
  default schema; `OUTPUT` clauses are analysed like `RETURNING`, and MySQL's
  `INSERT … SET` like `UPDATE … SET`. Pinned in `tests/sqlparser_upgrade.rs`.

## [3.8.2] — 2026-10-11 (not tagged; included in 3.9.0)

Security hardening from the 2026-10 review of the public repositories. **No rule,
API or behaviour changes**: the crate's public API, JSON shapes and evaluation
results are identical to 3.8.1, so hosts can take it as a drop-in update. No
vulnerability affecting users was found in the engine.

### Security

- The crate now forbids `unsafe` code at compile time (`#![forbid(unsafe_code)]`).
  It already contained none; the guard keeps it that way.
- CI: `cargo-deny` (advisories, licenses, banned crates, allowed sources, via
  `deny.toml`) and `cargo-audit` on every pull request.
- CI: gitleaks secret scan on pull requests.
- Dependabot for Cargo dependencies.
- A `cargo-fuzz` target for the parse/evaluate entry point, and a weekly,
  time-boxed fuzz job. When the optional repository variable
  `FUZZ_ARTIFACT_AGE_RECIPIENT` is set, crash artifacts are uploaded encrypted.

## [3.8.1] — 2026-10-09

Name semantics of the agent access allowlists (VERICTO-087). Three gaps let an
allowlist grant more than the table it named; each is closed. Two write rules
are settled (`DELETE` is a table-level write; row locks need write), and the
session statements drivers send on connect are no longer blocked as parse errors
on a workspace with `block`/`mask` tags. With no policy at all (no tags, no
allowlist) nothing changes: the 3.7.0/3.8.0 golden ORM corpus is identical byte
for byte there; under its tags-only policy exactly two session statements change
from block to the host's parse-error choice (below). One optional field is added (`AccessPolicy::default_schema`); no rule
code, JSON shape of existing fields or precedence changes. A host that builds
`AccessPolicy` with a struct literal adds `default_schema: None` (or
`..Default::default()`). Every fix below narrows what an allowlist allows; the
widenings are an empty `schema` string read as no schema (it matched nothing
before) and a host-named default schema.

### Added

- **`AccessPolicy::default_schema`** (JSON `"default_schema"`, optional), set by
  the host, never by the customer: the schema unqualified names resolve to. On
  MySQL it is the connection's current database, and a name qualified with it
  (compared exactly) is the default schema's, so Prisma's `` `db`.`User` ``
  matches an entry without a schema instead of needing a duplicate entry per
  table; a name qualified with any other database still needs an entry naming
  it. On Postgres it replaces `public` (for a host that knows the session's
  `search_path`) and on SQL Server `dbo`, for unqualified names and names
  qualified with it. Absent or empty: `public`, `dbo`, and on MySQL unqualified
  names only. Ignored on Oracle. A catalogue schema is never matched by a
  schema-less entry, even when named as the default.

### Fixed

- **An entry without a schema matched the table in every schema.** An entry
  `{"table": "orders"}` written for `public.orders` also allowed
  `archive.orders`, `audit.orders` or any other schema's table of that name, so
  an agent could read (or, with `read_write`, change) a table nobody granted by
  qualifying it. A schema-less entry is now the table in the **default schema**
  only: `public` on Postgres and `dbo` on SQL Server, qualified or not; on MySQL
  (the session's database) and Oracle (the user's schema), which the engine
  cannot see, the unqualified name only. A table in any other schema needs an
  entry that names that schema; entries that name a schema work as before.
  On MySQL a name qualified with the current database itself (Prisma's
  `` `db`.`User` ``) is the default schema's only when the host names that
  database in `default_schema`; otherwise it needs an entry with
  `"schema": "db"`.
- **Identifiers compared case-insensitively on every dialect.** On Postgres,
  `"Customers"` (quoted) and `customers` are two tables, and `"Email"` and
  `email` two columns; an entry for one allowed the other. Postgres now folds
  as Postgres does: unquoted names (in the query and in the entry) fold to
  lower case, quoted names compare exactly; an entry written in double quotes,
  `"Customers"`, is a case-sensitive name. On MySQL, table and database names
  now compare exactly (the conservative reading of `lower_case_table_names=0`,
  where `Orders` and `orders` can be two tables; `information_schema`'s names
  stay case-insensitive, as MySQL compares them), and column names
  case-insensitively, as MySQL compares them. SQL Server and Oracle keep the
  ASCII case-insensitive comparison.
- **SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` were allowed.** `EXECUTE p`
  runs whatever `p` was bound to earlier in the session, possibly by a call the
  engine evaluated on its own, or by text it never sees (MySQL
  `PREPARE s FROM @sql`), so the engine cannot know what an `EXECUTE` reads or
  writes. The three are now denied under any access policy (`needed: ddl`,
  `AccessPolicy > EXECUTE (ddl): denied for this identity`), on Postgres, MySQL
  and SQL Server (whose `EXEC` is the same statement: `EXEC sp_executesql
  @sql`); MySQL's `PREPARE s FROM '…'` does not parse and blocks as a parse
  error under an enforced policy. Protocol-level prepared statements (Postgres
  Parse/Bind, MySQL `COM_STMT_PREPARE`) are unaffected: the host evaluates their
  text when it is prepared.
- **Session statements were blocked on every workspace with a `block` or `mask`
  tag.** A tag makes a parse error block (a query the engine cannot read cannot
  be shown not to read a tagged column), and sqlparser rejects some of the
  statements drivers and ORMs send on every connection: Django's MySQL `SET
  SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED`, for one, so every Django
  connection to a tagged MySQL database failed, with or without an allowlist.
  The closed list of session statements that already exempted these from an
  enforced allowlist (`effective_parse_error_for`) now exempts them from the
  tags too: they read no table and no column, so there is nothing for either
  protection to guard. They keep the host's `parse_error` (a host that chose to
  block parse errors still blocks them); anything off the list, or more than
  one statement, still blocks. Hosts already call `effective_parse_error_for`
  (`vericto_engine::evaluate` does); no API change. In the golden ORM corpus
  this changes exactly two tags-only outcomes from block to flag (Django's
  isolation level on MySQL, Rails' `sql_mode` setup sent to Postgres).
- **`SELECT … FOR UPDATE` was allowed to a read-only identity.** A row lock
  stalls every other writer of those rows, exactly as `LOCK TABLE` (which
  already needed write) stalls the table. `FOR UPDATE`, `FOR NO KEY UPDATE`,
  `FOR SHARE` and `FOR KEY SHARE` now need a `read_write` entry on each locked
  table, reported as the table (`AccessPolicy > orders (write)`, column null):
  with `OF`, the tables it names (through aliases); without, every table of the
  `FROM`, sub-selects included (subqueries in `WHERE` are not locked and only
  need read). On a set operation every table is taken as locked
  (conservative). MySQL's `LOCK IN SHARE MODE` does not parse in sqlparser 0.52
  and blocks as a parse error under an enforced policy.

### Changed

- **`DELETE` is a table-level write.** It needed `"columns": "*"` in a
  `read_write` entry (a removed row loses every column's value) and was reported
  as `orders.* (write)`; it now needs a `read_write` entry for the table,
  whatever its column list, and is reported as the table, `AccessPolicy > orders
  (write)` with column null, as the path documentation already said. Its
  `WHERE`/`USING` still need read. The same holds for the `DELETE` action of
  `MERGE`. This widens what an allowlist allows only for `read_write` entries
  with a column list, which were written to let the agent change that table.
  `REPLACE INTO` and an `INSERT` without a column list still need every column;
  `TRUNCATE` stays denied as DDL.

## [3.8.0] — 2026-10-09

Agent access allowlists: a new rule, **VERICTO-087 "Access outside the agent's
allowlist"**, that confines the identity making a call — an API key, or the
database user of a proxy session — to the tables, columns and writes it was
granted, deny by default. It is driven by a new optional field,
`EnforcementPolicy::access_policy`; with it absent (the default) the analysis does
not run and every outcome is exactly what 3.7.0 returned. No breaking change to
the decision of any existing caller; one new field on `EvaluationOutcome`
(`access_denied`), so a host that builds the struct with a literal adds
`access_denied: Vec::new()`.

### Added

- **`AccessPolicy`** (`mode: observe | enforce`, `entries`, `ddl: deny`) and
  **`AccessEntry`** (`schema?`, `table`, `columns: "*" | [..]`,
  `access: read | read_write`), serde-compatible with the dashboard's JSON. Absent
  or unknown values fail safe: an unknown `mode` enforces, an unknown `access` is
  `read`, and a `columns` value other than `"*"` never widens to every column.
  **`AccessPolicyMap`** carries one policy per database user (with an optional
  `"*"` default) and selects the session's with `for_user`, so the TCP proxy and
  the sidecar share one selection rule. Exported at the crate root with
  `DeniedRef`, `Needed` and `ACCESS_RULE_CODE`.
- **VERICTO-087** (High, `Security`). Stricter than VERICTO-085 on purpose: 085
  counts what a query projects, 087 counts **every reference**, because a
  predicate lets an agent probe a value it may not read (`WHERE salary > 100000`
  answers the question without returning the column). The select list, `WHERE`,
  `JOIN … ON`/`USING`/`NATURAL`, `GROUP BY`, `HAVING`, `ORDER BY`, windows,
  aggregate `FILTER`/`ORDER BY`, `LIMIT`, subqueries anywhere (including
  `EXISTS`), CTEs (recursive and data-modifying), every arm of a set operation,
  `RETURNING`, upserts, `MERGE`, and the arguments of `CALL`/`EXECUTE`. Every table
  in `FROM` counts even when none of its columns is named. `*`, `t.*`, whole-row
  references, `COPY t TO` and MySQL `DESCRIBE t` need every column granted. Writes
  need `read_write`: each column an `INSERT` lists or an `UPDATE` assigns, every
  column for an `INSERT` without a list, a `DELETE`, a `REPLACE` or a `COPY … FROM`
  without a list. DDL is always denied, and so are the statements that change who
  the session is or how unqualified names resolve (`SET ROLE`,
  `SET SESSION AUTHORIZATION`, `SET search_path` and its `set_config` form,
  `USE`); any statement kind not known to be harmless is denied as well.
  Transaction control, settings, cursors, prepared statements and function calls
  are allowed. The catalogue (`information_schema`, `pg_catalog`, `mysql`,
  `performance_schema`, `sys`) is denied unless an entry names that schema; an
  unqualified `pg_*` relation is `pg_catalog`'s, and MySQL `SHOW TABLES` and its
  siblings read `information_schema`.
- **The derivation is VERICTO-085's**, not a second one: the same two walkers
  (`pg_query` for Postgres, `sqlparser` for MySQL, Oracle and SQL Server) run in an
  access mode that records every resolution instead of matching tags and visits
  the clauses 085 skips. Aliases, expressions, CTE and subquery pass-through, set
  operations and correlated references resolve exactly as they do for sensitive
  columns. On MySQL it runs on the statement MySQL executes (the 3.7.0 lexical
  normalization, every reading), so a predicate inside `/*! … */` counts.
- **Conservative name resolution.** An unqualified column resolves against every
  relation in scope, the outer ones of a correlated subquery included, and must be
  allowed in all of them; otherwise it is denied and the message says to qualify
  it. An unqualified table matches an entry without a schema, or `public`
  (Postgres) / `dbo` (SQL Server); a qualifier that names nothing in scope is
  taken as a table. This refuses some legitimate queries
  (`… WHERE id IN (SELECT customer_id FROM orders)` from `customers` when
  `customers` has no `customer_id` grant) rather than guess which table a name
  belongs to: the engine has no schema.
- **`EvaluationOutcome::access_denied`**: every denied reference
  (`{schema, table, column, needed: read | write | ddl}`), sorted, for the audit
  trail, filled in `observe` mode too. `ast_node_path` names the first one —
  `AccessPolicy > public.customers.email (read)`, `AccessPolicy > customers.* (read):
  list the columns explicitly`, `AccessPolicy > DROP (ddl): denied for this
  identity` — and counts the rest (`(+2 more)`).

### Changed

- **Precedence with VERICTO-085** (design §6.1), applied in that order: a `block`
  tag always wins and keeps the flat fields; then a denial (block under `enforce`,
  flag under `observe`); then an allowed `mask` keeps its rewrite; otherwise the
  query is allowed. A denial clears `rewritten_query` — a refused query is never
  forwarded, masked or not. `monitor_mode` turns a denial into a flag, as it does
  every block. The rules slice is unaffected and stays a floor alongside both.
- **`SET` is deny by default for an agent identity.** A closed list of the
  session settings drivers and ORMs send (transaction characteristics, character
  sets and collations, time zone, timeouts, `autocommit`, `sql_auto_is_null`,
  `sql_select_limit`, `session_track_*`, `application_name`, date/interval
  styles, `work_mem` and the other memory settings, `bytea_output`,
  `standard_conforming_strings = on`) is allowed with literal values; any other
  setting is denied, because a literal can still be dangerous
  (`session_replication_role = replica` turns off triggers and foreign keys,
  `foreign_key_checks = 0`, `sql_log_bin = 0`). `sql_mode` is allowed only when
  built from literals, `@@sql_mode` and `CONCAT()` and no resulting mode switches
  on `ANSI_QUOTES`, `NO_BACKSLASH_ESCAPES`, `PIPES_AS_CONCAT` or a combination
  mode that implies them — they change how MySQL lexes every later statement;
  Rails' connection setup passes. `SET GLOBAL`/`PERSIST`, a subquery or function
  value, and a multi-assignment with any denied part are denied.
- **`effective_parse_error()`** is `Block` under an enforced allowlist, as it
  already is with a `block`/`mask` tag: a statement the engine cannot read cannot
  be shown to stay inside the allowlist. The new
  **`effective_parse_error_for(sql, dialect)`** is the same except for the session
  statements above, matched on the normalized text, one statement only, with the
  same value rules: they keep the host's parse-error choice, since sqlparser
  0.52 rejects some of them (Django's MySQL `SET SESSION TRANSACTION ISOLATION
  LEVEL READ COMMITTED`) and blocking them would break every connection. Hosts
  that parse themselves (the proxy, the sidecar) must call it with the client's
  text.

### Unchanged, and how it is pinned

- `access_policy: None` changes nothing: the 3.7.0 ORM golden corpus
  (`tests/mysql_orm_corpus.rs`, unchanged fixture) produces the same outcomes, the
  policy JSON is the 3.7.0 JSON, and a counter test shows the analysis is never
  entered. An agent granted every table its ORM uses gets exactly the decision it
  gets without an allowlist on every corpus query (except the parse error above).
- VERICTO-085 outcomes are unchanged: the walkers' access mode is a separate
  flag, and the whole sensitive-column suite passes as before.

## [3.7.0] — 2026-10-08

VERICTO-085 `mask` now rewrites on MySQL (and MariaDB / Aurora MySQL through the
same dialect) instead of blocking, and the MySQL analysis reads the text the way
MySQL does, closing several ways to hide a read from it. Every rule on MySQL now
runs on the statement MySQL executes (see **Security**). No breaking API change:
the same types, fields, JSON and decision mapping as 3.6; `rewritten_query` is
now `Some` for a successful MySQL mask too, and there is one new rule code,
VERICTO-086.

### Added

- **MySQL mask rewrite.** Each client-visible projection derived from a masked
  column is replaced by its mask, aliased to the name MySQL would have given it
  (a column's name as written; an unaliased expression's own text, as the client
  typed it), and the statement is printed back from the sqlparser tree into
  `rewritten_query`. The masks use only functions MySQL 5.7, 8.0, Aurora MySQL 2/3
  and MariaDB all have (no `REGEXP_REPLACE`), and return exactly what the Postgres
  masks return for the same text — NULL, `''`, one character, multibyte and 4-byte
  characters, no `@`, an `@` first, the same SHA-256 hex — which
  `tests/mysql_mask_equivalence.rs` checks against both servers side by side. The
  value is first converted with `CONVERT(… USING utf8mb4) COLLATE utf8mb4_bin`:
  the same characters and UTF-8 bytes whatever the column's or the connection's
  charset, codepoint-exact `LOCATE('@', …)` (an accent-insensitive collation would
  match a full-width `＠`), and an explicit collation, so the masked value can be
  `UNION`ed, compared or concatenated with a column of any collation. The obvious
  `CAST(col AS CHAR)` raises "Illegal mix of collations" against a non-default
  collation on both 5.7 and 8.0. As on Postgres, a computed value is masked
  `full`; `ORDER BY` items that named a masked output sort by the original value
  (a bare column is wrapped in `COALESCE()`, which MySQL resolves to the column
  rather than to the alias), and `GROUP BY` positions are pointed back at the
  original expression.

  The rewrite is only forwarded when three checks pass, and blocks otherwise: the
  unmodified tree must print to the client's own tokens (up to keyword case, an
  inserted `AS`, `LIMIT a, b` / `LIMIT b OFFSET a` and `INNER`/`OUTER` before
  `JOIN`), with string literals compared verbatim so the result does not depend on
  the server's string-escape mode; the rewritten text must parse back to exactly the
  rewritten tree; and every `?` must still be there, once, in the same order. MySQL
  binds `?` by position, so a shifted parameter would bind a value to the wrong
  place: the engine numbers the client's `?` before parsing, checks the numbering
  survives, and keeps `LIMIT ?, ?` in its comma form (the renderer would print
  `LIMIT ? OFFSET ?`, swapping the two bindings). Statements it cannot reproduce
  block with `mask unsupported: the MySQL text cannot be reproduced faithfully (…)`:
  optimizer hints, the SELECT modifiers sqlparser does not know and bit literals. A `GROUP BY`, `HAVING` or `ORDER BY`
  expression that names a masked alias MySQL may resolve to the masked value
  blocks too. Oracle and SQL Server still block a `mask`.

### Fixed

- **MySQL text that sqlparser and MySQL read differently could hide a read from
  VERICTO-085, under every policy.** Differences between MySQL's and sqlparser's
  reading of comments, string escapes and SELECT modifiers could return a tagged
  column from MySQL while 3.6 saw no read. The MySQL analysis now re-reads the
  client's text the way MySQL does: text it cannot analyse resolves like a parse
  error (blocked with a `block` or `mask` tag, flagged with `flag`-only tags), and
  the SELECT modifiers are removed before the analysis so it sees what MySQL
  reads. Only hosts that send tags are affected; with no tags nothing changes.

  **Scope:** this re-reading runs inside the sensitive-column analysis, which
  runs only when tags are sent. The rule engine reads MySQL text the way MySQL
  does too, for every rule and every policy: see **Security** below.

- **More copies are reads on MySQL (and the other sqlparser dialects).**
  `SET @v = (SELECT email …)` and `ON DUPLICATE KEY UPDATE x = (SELECT email …)` /
  `ON CONFLICT DO UPDATE SET …` moved a tagged value into a session variable or
  another column without VERICTO-085 noticing; they are now copies, blocked under
  `block` and `mask`. A double-quoted string `"email"` is treated as a possible
  column on MySQL, since a server (or a `SET_VAR` hint) in `ANSI_QUOTES` mode reads
  it as one.

- **A masked aggregate keeps aggregating, on Postgres too.** A computed value
  masked `full` was replaced by the constant `'[redacted]'`; for an aggregate
  (`string_agg(email, ',')`, `GROUP_CONCAT(email)`) that turned one aggregated row
  into one row per input row. A computed value is now always masked in the form
  3.6.1 used for expressions with parameters,
  `concat('[redacted]'::text, left((expr)::text, 0))` on Postgres and
  `CONCAT('[redacted]', COALESCE(LEFT(x, 0), ''))` on MySQL: the expression still
  runs and still decides the row count, and the output is still exactly
  `'[redacted]'`. A bare column masked `full` is still the plain constant.

### Security

- Fixed rule evasion on MySQL caused by differences between MySQL's and the
  engine's reading of comments and string escapes. Affects all MySQL
  evaluations; upgrading is recommended.

  Every rule now runs on the statement MySQL executes. Before any rule runs, the
  MySQL parser reads the text with MySQL's lexical rules: comments are read the
  way MySQL reads them (for every server version, keeping the strictest
  outcome), and a string literal containing a backslash is read under both
  settings of the server's string-escape mode, again keeping the strictest outcome
  (block, then flag or mask, then monitor, then allow). Text without these
  constructs is evaluated exactly as before, byte for byte; a regression corpus
  of ORM-generated MySQL queries (`tests/mysql_orm_corpus.rs`) has identical
  outcomes before and after. Postgres, Oracle and SQL Server are unaffected.

  Text the engine cannot resolve to one statement with certainty now blocks with
  the new Security rule **VERICTO-086** (SQL text that MySQL and the engine would
  read differently), Critical, whatever the `rules` slice holds and under either
  `parse_error` setting; under `monitor_mode` it flags. It is not a
  `VERICTO-PARSE-ERROR`, which a fail-open policy would forward. Hosts that call
  `parser_for(Dialect::Mysql).parse()` and `RuleEngine::evaluate()` separately
  receive it from `evaluate()`, not as a parse error. The code is exported as
  `TEXT_DIVERGENCE_RULE_CODE`.

## [3.6.1] — 2026-10-08

### Fixed

- **A masked projection no longer drops bind parameters.** When VERICTO-085
  replaced a computed expression over a masked column with `'[redacted]'`, every
  `$n` that appeared only inside it disappeared from the rewritten statement:
  `SELECT substring(card, $1, 4) FROM t` became `SELECT '[redacted]'::text …`, so a
  client binding one parameter failed the extended protocol on a parameter-count
  mismatch, and Postgres could not type the parameters that were left. Such an
  expression is now masked as `concat('[redacted]'::text, left((expr)::text, 0))`:
  the original expression stays in the statement, so every parameter keeps both
  its position and the type Postgres infers for it from the same context. The
  result is still exactly `'[redacted]'` — `left(x, 0)` is empty or NULL and
  `concat` ignores NULL, so neither the value nor its NULL-ness is revealed.
  Masks without parameters are unchanged. (A `CASE WHEN $1 IS NULL …` wrapper was
  rejected: it keeps the count but leaves `$1` untyped, and CASE refuses
  set-returning functions.) Only affects hosts using `mask` tags on Postgres.

## [3.6.0] — 2026-10-07

Sensitive Column Protection: a new rule, VERICTO-085, that blocks, flags or masks
any query that reads a column the host marks as sensitive. Additive: a host that
sends no tags gets exactly the outcome it got from 3.5.3, at the cost of one
`is_empty()` check.

### Added

- **VERICTO-085 — read of a sensitive column.** Blocking a destructive statement
  protects the database from an agent; it does nothing about an agent that reads
  what it should not. `SELECT email, card FROM customers` is harmless to the
  database and still puts personal and payment data into an LLM's context. Hosts
  now pass tagged columns in the new `EnforcementPolicy::sensitive_columns`
  (`SensitiveColumn { schema, table, column, policy, mask_style }`), each with a
  policy — `block`, `flag` or `mask` — and the engine decides from the AST alone
  whether the query reads one. Strictest wins: `block > mask > flag`. The rule is
  driven by the tags, not by the `rules` slice (listing the code there is a
  no-op), and is classified `Security`, so no channel cap softens it.

  A read is a projection, not a mention. The engine follows every projected
  expression back to its source columns — through aliases, expressions, functions,
  aggregates, casts, scalar subqueries, derived tables and nested, recursive and
  data-modifying CTEs — across the select list, every arm of a set operation,
  `RETURNING`, `COPY … TO`, cursors and `PREPARE`. A column used only in `WHERE`,
  `JOIN … ON`, `GROUP BY`, `HAVING`, `ORDER BY`, `FILTER`, `OVER` or `EXISTS` is not
  read. Two cases are reads on purpose: `*`, `t.*` and whole-row references
  (`to_jsonb(c)`) touch every tagged column of the table, because the engine has
  no schema to expand them with; and copies (`INSERT … SELECT`, `CREATE TABLE AS`,
  `SELECT INTO`, `CREATE VIEW`, `UPDATE … SET`, `MERGE`) count, because they move
  the value somewhere untagged that the next query reads freely. Names resolve
  conservatively — unqualified tables match any schema, unqualified columns every
  relation in scope, identifiers case-insensitively — since a false positive is a
  blocked query with a clear message and a false negative is a leak. Both walkers
  implement it: `pg_query` for Postgres, `sqlparser` for MySQL, Oracle and SQL
  Server.

- **Masking by rewrite, Postgres only.** Under `mask`, each projected expression
  derived from a masked column is replaced by its mask (`full`, `last4`, `email`,
  `hash`) under its original output name, and the statement is regenerated with
  `pg_query`'s deparser into the new `EvaluationOutcome::rewritten_query`, which a
  host must execute instead of the original. `$n` parameters survive. The tag's
  style applies only when the value *is* the column; any computed value is masked
  `full`, because `last4` over a caller-chosen `substring` would hand out any four
  characters and the hash of one character is a lookup. `ORDER BY`/`GROUP BY` items
  that named a masked output keep using the original value. Any failure to rewrite
  or deparse blocks: the unmasked query is never returned as approved. A mask that
  cannot be applied — `*`, a copy, or a non-Postgres dialect in this release —
  blocks too, with a message saying why. A successful mask resolves to `Flag`
  (forward the rewrite, record it), between a flag and a block.

- **`EvaluationOutcome::sensitive_columns`**, every tagged column a query reads,
  sorted, for the audit trail, and **`EnforcementPolicy::effective_parse_error()`**:
  with a `block` or `mask` tag configured, a parse error blocks regardless of
  `parse_error`, since a query the engine cannot read cannot be shown not to read a
  tagged column, and syntax the parser rejects but the database accepts would
  otherwise be a way around every tag. Hosts that branch on the parse-error action
  themselves should call it instead of reading the field.

### Changed

- **`EnforcementPolicy` is no longer `Copy`**, because it now carries the tags. It
  is still `Clone`, `Eq` and serde-compatible, and a serialized policy without
  `sensitive_columns` deserializes as before. Code that built it with
  `..EnforcementPolicy::default()` and passed `&policy` — both first-party hosts —
  compiles unchanged; code that relied on implicit copies needs `.clone()`.
- `ParsedQuery` keeps the parser's syntax tree (moved, not copied) so the
  sensitive-column pass does not parse twice. It has a private field, so it can no
  longer be built with a struct literal outside the crate; nothing constructed it
  that way.

### Documentation


- **Contributions need the Vericto Contributor License Agreement.** `CONTRIBUTING.md`
  said a CLA *or* a DCO sign-off was required without saying how to give either, and
  the pull request template asked for `git commit -s`. Both now describe the CLA:
  sign it before the first pull request is merged, through the bot's link, with
  contributions on behalf of an employer going through legal@vericto.com first.

## [3.5.3] — 2026-10-04

Documentation and CI only, released as the repository goes public. No API,
behaviour, or rule changes: a host pinned to `v3.5.2` has nothing to adopt beyond
the `NOTICE` and the corrected security policy.

### Changed

- **CI pins its third-party actions to full commit SHAs.** `actions/checkout`
  was referenced by tag and `dtolnay/rust-toolchain` by the `stable` branch; both
  can be moved to different code after review, a SHA cannot. The pins are the
  same commits CI was already running, so the build is unchanged. A new
  `.github/dependabot.yml` proposes weekly bumps for the actions only — Cargo
  version bumps stay manual, because a `pg_query` or `sqlparser` upgrade can change
  how SQL is parsed.

### Documentation

- **`SECURITY.md` said the engine enforces a 64 KB query limit. It does not.**
  `MAX_QUERY_SIZE_BYTES` has been documented as host-applied since 3.2.1, and
  nothing in this crate checks it. A security policy that overstates a defence
  sends reporters to probe the wrong boundary, so the scope now names the two
  guards the engine does enforce — the 200-level textual nesting check before
  parsing and the 50-level AST walk limit — and says the size limit belongs to the
  host. The policy also called the product "Vericto Proxy".
- **`SECURITY.md` lists GitHub private vulnerability reporting** as a second
  channel next to `security@vericto.com`, now that the repository is public and
  the feature is enabled.
- **Added a `NOTICE` naming the licensor, Vericto S.A.S.** The Elastic License 2.0
  text refers to "the licensor" throughout without naming it.
- **Managed-service licensing questions now go to `enterprise@vericto.com`.** The
  README pointed at `hola@vericto.com`, an address the site does not publish.
- **Pre-rebrand names removed from tests and links.** The evaluator's tests were
  still named `vetro_NNN_*`; they now follow the `VERICTO-NNN` codes they cover.
  The CHANGELOG's version links pointed at the repository's pre-transfer owner.

## [3.5.2] — 2026-09-30

Cross-dialect rule parity. No API changes, and no behaviour changes beyond
VERICTO-019 now firing where it previously did not.

### Fixed

- **VERICTO-019 did not detect `DISABLE ROW LEVEL SECURITY` on PostgreSQL**, the one
  dialect here that implements RLS. The rule is named "ALTER TABLE DISABLE TRIGGER /
  RLS", `AlterTableKind::DisableTrigger` is documented as "`DISABLE TRIGGER` /
  `DISABLE ROW LEVEL SECURITY` — disables a protection", and the README catalogue row
  says the same. Every piece of documentation was right; `pg_ast.rs` was the only
  thing that disagreed.

  Its `match` on the libpg_query subtype covered `AtDisableTrig`,
  `AtDisableTrigAll` and `AtDisableTrigUser`, so `AtDisableRowSecurity` fell through
  to the arm's `_ => continue`. The consequence is wider than one rule missing: no
  `StatementInfo` was emitted at all, so the statement was invisible to the whole
  evaluator. Measured against a live proxy before the fix, `ALTER TABLE t DISABLE
  TRIGGER ALL` and `... DISABLE TRIGGER USER` were blocked while `... DISABLE ROW
  LEVEL SECURITY` came back ALLOWED with no rule attributed — a statement that
  removes tenant isolation, passing silently.

  This is the sleep-function drift the contributor notes already warn about, in the
  direction that costs the most: `walk.rs` has mapped
  `AlterTableOperation::DisableRowLevelSecurity` since it was written, so
  MySQL/Oracle/MS SQL detected what PostgreSQL did not.
  `tests/audit.rs::vericto_019_detects_rls_disable_on_every_dialect` now asserts all
  three disabling forms on all four dialects, and a companion test asserts that
  `ENABLE ROW LEVEL SECURITY` and `ENABLE TRIGGER` stay unreported — widening
  detection must not start flagging the hardening direction. Verified both tests are
  meaningful by removing the new match arm again: the dialect test fails on
  PostgreSQL and passes everywhere else, which is exactly the drift it exists to
  catch.

  `AtDisableRule` and `AtNoForceRowSecurity` are deliberately still unmapped. Neither
  is what this rule's name promises, and `NO FORCE` only stops RLS applying to the
  table owner — the default state, where `FORCE` is the opt-in hardening. This is a
  blocking firewall and a false positive is an outage, so they are left as their own
  decision rather than folded in here.

  **Patch, matching how this catalogue has always versioned parity fixes.** No public
  API changes, and no consumer has to do anything beyond moving the tag. The direct
  precedent is 3.2.2, the same defect in mirror image — VERICTO-070 not firing on
  `pg_sleep_until` outside PostgreSQL because the two walkers had drifted — whose own
  header reads "No API or behaviour changes beyond VERICTO-070 now firing where it
  previously did not." 3.5.1 went further on the same footing: it began rejecting
  deeply nested input that previously parsed, also as a patch. The minors in this
  catalogue are earned by API additions (3.2.0 added `RuleClass`) or by changing what
  an already-written rule means (3.4.0 redefined `func_name`, with migration notes).
  Neither applies here.

  It does change outcomes, and that is worth knowing before adopting: a migration
  running `ALTER TABLE … DISABLE ROW LEVEL SECURITY` against a workspace with
  VERICTO-019 active goes from passing to blocked. The blast radius is bounded by the
  rule's class — VERICTO-019 is `RuleClass::SchemaMigration`, so a channel that passes
  `schema_migration_cap: Some(Flag)` (CI does) reports instead of blocking — and by
  the host's catalogue, which decides whether the rule is active at all.

## [3.5.1] — 2026-08-13

### Fixed

- **A single statement could kill the process (denial of service).** Roughly 950
  nested `NOT`s — about 4 KB of SQL, well under the published 64 KiB
  `MAX_QUERY_SIZE_BYTES` — overflowed the stack while the parser was still building
  the tree. The overflow happens inside `pg_query`/`sqlparser` during recursive
  descent, before any engine code sees a node, so `MAX_AST_DEPTH` could not reach
  it: that guard bounds a walk over a tree that already exists.

  A stack overflow in Rust is not a catchable panic — `catch_unwind` does not see
  it, the process aborts — and both consumers compile with `panic = "abort"`. So an
  unauthenticated sender could terminate an eval sidecar or a proxy worker with one
  request, at no cost to themselves. Measured threshold is between 920 and 950
  levels of nesting; it reproduced identically on all four dialects.

  Added `error::guard_nesting_depth`, called at the top of `parse_postgres` and
  `parse_with_dialect`, which refuses input whose textual nesting exceeds
  `MAX_NESTING_DEPTH` (200) with `ProxyError::AstTooDeep`. It counts parenthesis
  depth and runs of consecutive `NOT` on the raw string, because the decision has to
  be made *before* handing the text to something that will recurse on it. The
  keyword match is case-insensitive and on word boundaries, so a column named
  `notes` or `not_deleted` is not mistaken for the operator.

  The limit leaves an order of magnitude of headroom over the overflow point and far
  more over real traffic: no ORM emits 200 levels of nesting. `tests/nesting_dos.rs`
  pins the behaviour on every dialect and asserts that legitimate chained `NOT`,
  nested parentheses and `not`-containing identifiers still parse. Verified the test
  is meaningful by removing the guard again — the test binary aborts with the
  original stack overflow.

## [3.5.0] — 2026-08-10

### Added

- **`EvaluationOutcome::violations` reports every rule a query broke**, alongside
  the single winner the flat fields already carried. `ReportedViolation` is
  re-exported at the crate root and carries each violation's own resolved
  `severity` and `action`, so a caller rendering the set does not re-derive them.
  The flat fields are unchanged, so this is additive: a host that ignores the new
  field behaves exactly as before.
  What it fixes is lost evidence. `SELECT * FROM users WHERE id=1 OR 1=1;
  DELETE FROM audit_log` reported only VERICTO-001 — the injection tautology
  (VERICTO-090) was detected, outranked on the code tie-break, and dropped. Both
  are Critical so the decision was identical either way, but the audit trail lost
  the fact that an injection was attempted. For a security product that is a real
  loss, not a cosmetic one.
  It also removes a 20× cost. A host that wanted the full set had to call
  `evaluate()` once per rule, re-parsing the SQL each time: measured at 854 µs
  against 41 µs for a single call on a 28-rule catalogue. The engine's own
  `tests/audit.rs` had a helper doing exactly that.

  Guarantees, each pinned by a property test in `rules::properties`:
  - `violations[0]` **is** the winner in the flat fields, field for field.
  - Ordered severity descending, then rule code ascending — never by the caller's
    slice order. This extends the 3.2.4 determinism fix from the winner to the
    whole set.
  - `decision` and `action` derive from the winner **alone**, verified by
    evaluating the winning rule by itself and requiring the same verdict. That is
    what makes the field safe to consume or ignore.
  - The set equals evaluating each rule on its own — nothing dropped or invented.
  - Empty exactly when no rule matched. A parse error reports an empty set too:
    nothing was evaluated, so there is no violation, and the `VERICTO-PARSE-ERROR`
    pseudo-code stays telemetry rather than a catalogue entry.

  Collecting the set costs nothing measurable — 13.4 µs/query before, 13.3 µs
  after, on 28 rules — because the evaluator already ran every rule and discarded
  all but the best. A clean query allocates nothing.

### Notes for hosts

`decision` is unchanged for every input, so adopting this needs no behaviour
review. Two things are worth knowing before rendering the set:

- A per-class cap can make a *lower*-severity violation resolve to a *stronger*
  action than the winner: `schema_migration_cap: Monitor` softens a Critical
  `DROP TABLE` while a High `DELETE` still blocks. The winner is chosen by
  severity, not by action — so do not assume `violations[0].action` is the maximum
  in the set. Finding this is what closed a real gap in the property tests: a
  mutation that escalated the decision to `max(action)` survived until the
  generator was widened to produce a `Monitor` cap.
- `violations` is not `#[non_exhaustive]`-guarded, and neither is
  `EvaluationOutcome`; a host constructing the struct literally will need the new
  field. Both first-party hosts read it rather than build it.

## [3.4.0] — 2026-08-09

### Fixed

- **A custom rule's `func_name:` predicate now matches any function, as
  documented.** Both walkers only recorded a `FunctionCall` statement when the
  name was in the sleep family, so `func_name: pg_read_file` — or `dblink`,
  `lo_export`, `encode` — matched nothing. The rule saved, synced, appeared in the
  workspace's catalogue, and silently never fired.
  This is the worst shape a gap can take in a security product: a workspace that
  wrote the rule believed it was protected and was not, with no error to notice.
  Custom rules are the mechanism for covering domain-specific risk, so the
  predicate reaching only four hard-coded names left that mechanism largely
  inoperative.
  The walkers now record every call, and each records the function's own name in
  the evidence (`FunctionCall > pg_read_file()`) instead of a generic label.

### Changed

- **VERICTO-070 filters the sleep family in its own predicate.** It previously
  matched *any* `StatementKind::FunctionCall`, relying on the walkers having
  pre-filtered. That coupling is why the two changes above ship together:
  recording every function without narrowing this rule would have turned
  `SELECT now()` into a High → Block violation — a far worse regression than the
  bug being fixed. A rule-specific concern now lives in the rule, and the shared
  `parser::is_sleep_function` classifier is unchanged, so which names count is
  still defined in exactly one place.
  No behaviour change for the rule itself: it fires on the same four functions,
  on every dialect, verified by the 3.2.2 regression lock.

### Migration

Hosts that build a ruleset from the built-in catalogue are unaffected. Two things
do change for anyone reading `ParsedQuery` directly:

- A host that wrote its own rule matching on `StatementKind::FunctionCall` and
  assumed the parser had filtered to sleep calls must now check `function_name`
  itself — the same shape as VERICTO-070's predicate.
- `ParsedQuery::statements` is longer for queries containing ordinary functions:
  `SELECT count(*), lower(name), upper(email), coalesce(a,b) FROM t WHERE id=1
  LIMIT 1` yields 4 entries where it previously yielded 1. Evaluation is linear in
  that count, and rule predicates short-circuit on `kind`, so the cost is small —
  but a host that assumed one statement per SQL statement, or that sizes a buffer
  from the length, should know.

## [3.3.1] — 2026-08-09

### Fixed

- **A row bound on a set operation no longer leaves its arms looking unbounded.**
  `SELECT … UNION SELECT … LIMIT 10` parses with the bound on the set-op node and
  none on either arm. The pg_query walker recursed into the arms without carrying
  it down, so both were recorded with `select_has_limit: false` and a bounded
  UNION tripped VERICTO-050 — a false positive on a query that caps its result.
  It affected `UNION`, `UNION ALL`, `INTERSECT` and `EXCEPT`, the `FETCH FIRST`
  spelling, and nested set-ops (`a UNION b UNION c LIMIT 10`, where the bound has
  to survive more than one level).
  PostgreSQL only: `walk.rs` already threads its `has_limit` into both sides of a
  `SetOperation`, with a comment saying exactly why. One walker had solved this
  and the other had not — the drift this crate treats as a defect in itself, and
  the same shape as the `is_sleep_function` divergence in 3.2.2. The fix mirrors
  the sqlparser walker's approach rather than inventing a second one.
  Medium → Flag by default, so this dirtied reporting rather than blocking
  traffic; a workspace that raises Medium to Block would have seen bounded
  UNIONs rejected on one dialect and allowed on the others.
  `OFFSET` is deliberately not a bound: it skips rows without capping how many
  come back, so `… UNION … OFFSET 10` is still reported.

## [3.3.0] — 2026-08-09

Widens what counts as an always-true `WHERE`. **This blocks queries that
previously passed** — see the migration note at the end of this entry. Minor
rather than patch for that reason: no API changed, but enforcement did.

### Added

- **Constant-only `IN`, `BETWEEN` and `LIKE '%'` are now recognised as
  always-true.** `WHERE 1 IN (1, 2)`, `WHERE 1 BETWEEN 0 AND 2` and
  `WHERE 'x' LIKE '%'` filter nothing — confirmed against PostgreSQL, each returns
  every row of a test table — but the predicate only understood comparison
  operators, so a `DELETE` guarded by one was reported as having a real `WHERE`.
  Both walkers implement all three, so the behaviour is identical on PostgreSQL,
  MySQL, Oracle and MS SQL.
  This feeds five rules through one predicate: `where_presence`
  (VERICTO-003/030/042), `has_or_tautology` (VERICTO-090) and
  `insert_select_has_filter` (VERICTO-040). A `DELETE … WHERE 1 IN (1,2)` now trips
  VERICTO-003, `… OR 1 IN (1,2)` trips VERICTO-090 as the injection shape it is,
  and a constant-only `WHERE` no longer excuses an unfiltered `INSERT … SELECT`.

- **Property 9: a predicate that references a column is never always-true.** The
  guard rail for the above, and for any future widening. Asserted over 18
  column-referencing templates × 4 column spellings × 4 dialects, checking both
  `where_presence` and `has_or_tautology`.
  The invariant is structural — only predicates whose operands are *all literals*
  may qualify, since their truth value cannot otherwise depend on the row. SQL's
  three-valued logic is what makes that sharp: `id IS NOT NULL` and
  `name LIKE '%'` read as tautologies but drop every row where the column is NULL
  (2 of 3 rows on a table with one NULL row), so classifying either would be a
  false positive on a Critical rule that rejects live traffic. They are correct
  behaviour today, not gaps.

### Documentation

- **The README now has a "what counts as always-true" section**, listing every
  recognised form in one table and — more usefully — what does *not* count and
  why. Four rules turn on this predicate and none of them documented its
  boundaries, so a host could not tell a deliberate false negative from an
  oversight.

### Deliberate false negatives

Two constant-only forms are *not* reported, because over-reporting is the
dangerous direction for a rule that rejects traffic inline:

- **`NOT IN` is never treated as the negation of `IN`.** Under three-valued logic
  a NULL in the list makes the whole predicate NULL rather than true, so
  `1 NOT IN (2, NULL)` matches no rows at all — verified against PostgreSQL.
  Negating the positive result would make it a false positive on exactly the input
  an attacker can shape, so only the positive form is decided.
- **A NULL anywhere in an `IN` list disqualifies it**, so `1 IN (1, NULL)` is not
  reported even though it does match every row. Accepting it would mean carrying
  NULL semantics through the comparison path for no security gain.

`LIKE` is restricted to the exact pattern `%`. `'abc' LIKE 'a%'` is also
constant-true, but deciding it means implementing LIKE matching, which is more bug
surface than the case is worth. `BETWEEN` is numeric only, since string ordering
depends on the database's collation.

### Migration

A query whose only `WHERE` is a constant-only `IN` / `BETWEEN` / `LIKE '%'` changes
from allowed to blocked under the default policy. In practice such a predicate is
either generated SQL or a neutralised filter — nobody writes `WHERE 1 IN (1,2)` by
hand — so the expected blast radius is small, but hosts that want to observe before
enforcing can set `monitor_mode` for a cycle, or cap the affected class per channel
(see [rule classes](README.md#rule-classes-and-per-channel-caps)); all five rules
involved are `DataMutation` or `Security`, so a `schema_migration_cap` will not
soften them.

## [3.2.6] — 2026-08-09

Adds one re-export and fixes documentation drift. No behaviour, rule, or
evaluation changes.

### Added

- **`RuleClass` is re-exported at the crate root.** It was reachable only as
  `rules::engine::RuleClass` while every other type a host needs — `Decision`,
  `EnforcementPolicy`, `Severity`, `Rule` — is re-exported. Nothing about the
  type changed; the old path keeps working.
- **The README documents rule classes and `schema_migration_cap`.** Neither
  appeared anywhere in it. That pairing is what lets a CI channel soften
  migration DDL to a report while a WHERE-less `DELETE` still blocks, so a host
  looking for it had no way to discover it short of reading `engine.rs`. The new
  section lists which codes fall in each class, notes that custom and unknown
  codes classify as `DataMutation` (the conservative default, never softened by a
  cap), and states that the cap is applied as `action.min(cap)` — a ceiling, never
  a floor.
- **`usage_snippet_sync.rs` now covers the README's dependency snippet too.** The
  guard checked only the copy in `lib.rs`, which left the README's unguarded — it
  sat at `tag = "v3.1.0"` while the crate was at 3.2.5, four releases behind, with
  the guard green throughout. The README is the likelier of the two to be copied
  by a consumer, so a stale tag there is the more expensive one. Both are now
  checked against the same manifest values, and a failure names the file that
  drifted. Verified by pinning the README back to v3.1.0 and confirming the guard
  fails and reports `README.md`.

### Fixed

- **Documentation still referred to the project by its pre-rebrand name.** The
  README, `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md` pointed at
  `donkan168/vetro-proxy` (the URL from before the repository transfer), named
  "vetro-eval", and gave `vetro.dev` contact addresses, while `vericto-proxy`
  already uses `vericto.com` in all three of its equivalents. Links to a
  transferred repo and mail to a dead domain both fail silently for anyone
  following them. Also corrects the dialect table, which credited `pg_query` 5.1
  and libpg_query 16 when the manifest pins 6.2, which vendors PostgreSQL 17, and
  the README's dependency snippet, which pinned `v3.1.0`.

## [3.2.5] — 2026-08-08

Documentation only. No API, behaviour, or rule changes.

### Documentation

- **`MAX_QUERY_SIZE_BYTES` no longer claims every host applies the same
  threshold.** The doc said the limit is published "so every host applies the same
  threshold", which stopped being true once the TCP proxy adopted a configurable
  10 MiB ceiling while the HTTP sidecar kept this crate's 64 KiB. Left as written
  it would read as a contract hosts were violating, rather than the deliberate
  design it is.
  It now states that hosts are expected to diverge and why the two first-party
  ones do: the sidecar is multi-tenant, serves one query per request from
  dashboards and CI, and derives its request body limit from this value, so a small
  ceiling costs nothing; the proxy carries production traffic where batch inserts
  and long `IN` lists legitimately reach megabytes, and refusing a statement inline
  is an outage for that workload rather than a warning. Also notes that raising the
  limit is taking on a latency budget, since evaluation time grows linearly with
  input size.

## [3.2.4] — 2026-08-07

### Fixed

- **Which violation is reported no longer depends on the order of the `rules`
  slice.** When two violated rules shared the top severity the comparison was
  `rule.severity > best_severity`, strictly greater, so the first one in the
  caller's slice won. Rule order is not a property of the query being evaluated,
  and the control plane serves its ruleset from a query with no `ORDER BY`, so
  the same query against the same ruleset could report different codes between
  runs — visible as a finding's `rule_code` changing with nothing else changing.
  Ties are now broken on the rule code, lowest first, which favours the
  lower-numbered and therefore more fundamental rule. Severity still decides
  first; the tie-break only applies at equal severity.
  This narrows what the crate reports rather than changing whether a query is
  blocked: both tied rules resolve to the same severity, so the decision and
  action are identical either way — only the reported `rule_code`, `rule_id` and
  `ast_node_path` can differ. Hosts that group findings by code may see the
  distribution shift.

### Documentation

- **`README.md` now states how a violation is chosen** — highest severity, ties
  broken by lowest code, order-independent — next to the ruleset example. The
  crate has always advertised deterministic evaluation; with ties resolved by
  input order that claim only held if the caller kept the order stable.

## [3.2.3] — 2026-08-06

Housekeeping. No API, behaviour, or rule changes.

### Removed

- **Unused dependencies `anyhow` and `tokio-test`.** Neither was referenced
  anywhere outside `Cargo.toml`: no source, test, or doctest use, and `anyhow`
  appeared in no public signature. Error handling here is `thiserror`-based via
  `error::ProxyError`, and the engine is synchronous, so a tokio test harness had
  nothing to drive.
  Dropping `tokio-test` removes four crates from the resolved graph
  (`tokio-test`, `tokio`, `tokio-stream`, `futures-core`; 112 → 108), all
  dev-only, so it lightens building this crate's tests and does not affect
  consumers. Dropping `anyhow` removes nothing from the graph — `prost-derive`
  still pulls it in through `pg_query` — but it stops the manifest from claiming
  a direct dependency the code never had, and keeps a second error-handling idiom
  from creeping in alongside `thiserror`.
  Patch-level: `tokio-test` was a dev-dependency and therefore invisible to
  consumers, and `anyhow` was neither re-exported nor present in any public
  signature, so no consumer could have reached it through this crate.
- **The cargo cache step in CI.** Its key was
  `${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}`, but `Cargo.lock` is
  git-ignored for this library, so on a clean checkout `hashFiles` matched nothing
  and returned an empty string. The key collapsed to the constant
  `Linux-cargo-` / `macOS-cargo-`, which always hit exactly — and `actions/cache`
  does not save on an exact hit, so the cache could never update. The Linux entry
  dated from before the `pg_query` 5.1 → 6.2 bump, which is why that job took
  2m20s while macOS, whose cache happened to be created after the bump, took 35s.
  Removed rather than re-keyed: every run now builds from a clean tree, so no
  stale artifact can mask a real break, and there is no cache key to drift again.

## [3.2.2] — 2026-08-06

Cross-dialect rule parity and a documentation fix. No API or behaviour changes
beyond VERICTO-070 now firing where it previously did not.

### Fixed

- **VERICTO-070 did not fire on `pg_sleep_until` outside PostgreSQL.** The
  sleep-family list was duplicated: the pg_query walker matched `sleep`,
  `pg_sleep`, `pg_sleep_for` and `pg_sleep_until`, while the sqlparser walker —
  which serves MySQL, Oracle and MS SQL — matched only the first three. A
  time-based blind-injection probe using `pg_sleep_until` was therefore reported
  on PostgreSQL and silently allowed on every other dialect. The two lists are
  now one `parser::is_sleep_function`, so the invariant is enforced by the
  compiler rather than by convention.
  The duplicated helper already carried the comment *"Mirrors the list in
  `walk.rs` so detection is dialect-consistent"* — the contract was documented,
  just not checked, and it had already drifted.
- **The dependency snippet in the crate-level docs named the wrong repository
  and a stale tag.** It pointed at `donkan168/vericto-engine`, the URL from
  before the repository transfer, with `tag = "v2.1.0"` while the crate was at
  3.2.1. That is the line downstream repos copy to depend on the engine, so it
  pinned anyone following it to a parser four releases old. It now matches the
  manifest's `repository` and version.

### Added

- **`tests/usage_snippet_sync.rs`** — guards the dependency snippet against the
  drift above. The snippet is a ```toml block, so unlike the Rust example beside
  it in `lib.rs` it is never compiled and nothing caught it going stale. Two
  tests assert the snippet's `git` URL equals `Cargo.toml`'s `repository` and
  its `tag` equals the crate version, so the tag has to be bumped with the
  release. Follows the `rule_catalogue_sync.rs` pattern: sources are pulled in
  with `include_str!`, and the extractor fails loudly if the snippet changes
  shape rather than silently matching nothing.

## [3.2.1] — 2026-08-06

Correctness and portability fixes. No breaking API changes: the only public-API
addition is the `StatementInfo.insert_select_has_filter` field described below.

### Fixed

- **Custom-rule `where_always_true` did not match a bare `WHERE 1=1`.** The
  predicate tested `has_or_tautology` alone, which is only true for an
  always-true *OR branch* (`WHERE id = 5 OR 1=1`); a WHERE that is trivially
  true as a whole (`WHERE 1=1`, `WHERE true`) is recorded as
  `WherePresence::AlwaysTrue` and was silently skipped. The published predicate
  reference documents both shapes — the table cites `1=1`/`true` while the
  worked example cites `id = 1 OR 1=1` — so a rule written against the table
  never fired. It now matches either shape, which only widens what the
  predicate catches: every query that matched before still matches.
- **VERICTO-040 false positive on a filtered `INSERT … SELECT`.** The predicate
  only checked that the INSERT had a SELECT source, never that the source was
  unfiltered — so `INSERT INTO t SELECT … WHERE id = $1` was reported (and,
  wherever the rule is configured to Block, as it is in the TCP proxy's default
  ruleset, rejected) with an `ast_node_path` that claimed `(no WHERE)`. The rule
  now fires only when the source has no filter, matching the description it has
  always carried in the README catalogue.
  A source is considered filtered when it has an *effective* `WHERE` or a row
  limit (`LIMIT`/`FETCH`). A tautological `WHERE 1=1` bounds nothing and still
  fires. A set-operation source (`UNION`/`INTERSECT`/`EXCEPT`) is
  conservatively treated as unfiltered — over-reporting is the safe direction
  for a blocking rule.
  Implemented as a new `StatementInfo.insert_select_has_filter` field populated
  by both walkers, because the source SELECT is recorded as a separate nested
  statement and the rule predicate cannot reach its `where_presence` from the
  INSERT entry. Additive to the public API.
- **`error.rs` module docs contradicted the default parse-error policy.** The
  header stated that an unparseable query "is blocked as a precaution
  (fail-closed)", but the shipped default is `ParseErrorAction::AllowReport`
  (fail-open: forward + report, R4.8) — the opposite, on the security-critical
  default. The docs now state that the disposition is the host's policy
  decision and name both options.
- **Build failure on macOS with the current Xcode SDK.** `cargo build` aborted
  in `pg_query`'s vendored PostgreSQL sources with
  `static declaration of 'strchrnul' follows non-static declaration`: macOS
  15.4+ SDKs declare `strchrnul` in `<string.h>`, colliding with the static
  fallback that the bundled `src_port_snprintf.c` defines when
  `HAVE_STRCHRNUL` is unset. PostgreSQL fixed this upstream in April 2025, but
  `pg_query 5.1.1` vendors PostgreSQL 16.1 (November 2023), which predates the
  fix. Bumping to `pg_query 6.2` (PostgreSQL 17.7) picks it up. CI was green
  throughout because it only ran on Linux — see the CI matrix change below.

### Changed

- **`pg_query` 5.1 → 6.2** (vendored PostgreSQL 16.1 → 17.7; pulls `prost`
  0.10 → 0.13 transitively). No public API or behaviour change: the existing
  test suite passes unmodified.
- **Internal: migrated the protobuf enum conversions from the deprecated
  `from_i32()` to `TryFrom<i32>`** (6 call sites in `parser/pg_ast.rs`).
  `pg_query 6.x` deprecates `from_i32`, which `cargo clippy -D warnings`
  (as CI runs it) treats as an error. The conversion returns `Result` rather
  than `Option`, so the match arms moved from `Some(..)` to `Ok(..)`; the
  unrecognized-discriminant fallbacks are unchanged.
- **CI now runs on `ubuntu-latest` *and* `macos-latest`** (`fail-fast: false`,
  so one platform's failure neither masks nor cancels the other). The
  system-dependency step is split per `runner.os`: `apt-get` on Linux,
  `brew install protobuf` on macOS — `libclang` (needed by `bindgen`) comes
  from the runner's preinstalled Xcode Command Line Tools. This is the guard
  that would have caught the macOS break above.
- **CI now also runs on pull requests that do not target `main`.** The
  `pull_request` trigger filtered on `branches: [main]`, so a stacked PR — one
  based on another open branch — reported no checks at all and could be merged
  unverified. The filter is removed; `push` is still restricted to `main`.

### Documentation

- **`MAX_QUERY_SIZE_BYTES` now states that this crate does not enforce it.** The
  previous one-liner ("enforced by the coding standards") named no enforcement
  point, which reads as though the engine applies the limit; it does not —
  neither `evaluate` nor `SqlParser::parse` checks input length. The constant is
  published so hosts share one threshold, and the doc now says so, notes that
  `MAX_AST_DEPTH` bounds nesting depth rather than input size, and carries a
  doctest showing the guard paired with `ProxyError::QueryTooLarge`.
- **Custom-rule predicate table** (`README.md`) now describes both WHERE shapes
  `where_always_true` matches, instead of only the `OR 1=1` form.
- **`CONTRIBUTING.md` pointed new rules at a function that does not exist.**
  The "Adding a new standard rule" checklist named `evaluate_standard_rule`;
  the real entry point is `evaluate_builtin`. The checklist also now mentions
  the `tests/rule_catalogue_sync.rs` guard (which fails the build when the
  evaluator and the README table drift apart) and the `RuleClass::for_code`
  classification step, whose omission is silent because unlisted codes fall
  back to `DataMutation`.

## [3.2.0] — 2026-08-02

### Fixed

- **VERICTO-010 false positive on non-table DROPs.** The rule matched every
  `DROP` except `INDEX`/`SCHEMA` (a denylist), so `DROP POLICY`, `DROP TRIGGER`,
  `DROP FUNCTION`, `DROP VIEW`, and `DROP SEQUENCE` (all parsed as
  `DropObjectKind::Other`) were flagged as critical `DROP TABLE` — hitting
  routine RLS/migration DDL. It now uses an allowlist (`Table | Database`).
  `DROP DATABASE` is also mapped explicitly in the sqlparser path (`walk.rs`);
  it previously fell into `Other`, so on MySQL it was mis-classified.

### Added

- **`RuleClass`** (`SchemaMigration` / `DataMutation` / `Security` /
  `Performance`) — a static classification of each built-in rule by code,
  independent of the channel it runs on. Custom/unknown codes default to
  `DataMutation` (conservative: never softened by a class cap).
- **`EnforcementPolicy.schema_migration_cap: Option<EnforcementAction>`** — an
  optional per-channel ceiling for `SchemaMigration` findings. When set, a
  schema/DDL violation's action is capped (`min`, never raised) at that value;
  other classes are untouched. Lets a shift-left channel (CI) soften
  `DROP`/`ALTER`/`TRUNCATE` to Flag while a runtime channel keeps blocking.
  `None` is byte-for-byte the previous behavior. Additive to the public API:
  consumers that build the policy via `EnforcementPolicy::default()` (proxy,
  eval) need no changes.

## [3.1.1] — 2026-07-29

Maintenance release: no API or behaviour changes.

### Changed

- **Migrated to Rust edition 2024** (`edition = "2021"` → `"2024"`). No source
  changes were required beyond rustfmt's edition-2024 import/format style; the
  toolchain is already pinned to 1.88, which supports the 2024 edition. Public
  API and behaviour are unchanged.
- Updated the `repository` URL and README links from `donkan168/vericto-engine`
  to `vericto/vericto-engine` to reflect the repository transfer.

## [3.1.0] — 2026-07-29

Custom-rule (YAML) evaluation now implements the full predicate schema
documented at `/docs/custom-rules`. Previously the docs described predicates the
engine silently ignored; rules are now evaluated against the nested `condition:`
schema. All changes are additive to the public Rust API — `Rule`, `evaluate`,
and the exported types are unchanged.

### Added

- **`FuncCall` node type** for custom rules, so the documented `SLEEP` /
  `PG_SLEEP` detection example actually matches.
- **Custom-rule predicates** under `condition:`: `relation`, `where_clause: null`,
  `where_always_true`, `target_list: "*"`, `has_limit`, `func_name`,
  `object_type`, and `alter_kind`. All read fields the parser already extracts —
  no parser changes.
- `DropObjectKind::from_yaml` and `AlterTableKind::from_yaml` for parsing the
  `object_type` / `alter_kind` predicate values (mirrors `Severity::from_legacy`).

### Changed

- **Custom-rule YAML schema** now nests predicates under a `condition:` block
  (matching the published docs) instead of the previous root-level fields. Rules
  written against the pre-3.1.0 README examples (`relation` / `where_null` at the
  root) must move those keys under `condition:` and rename `where_null` →
  `where_clause: null`. Standard `VERICTO-NNN` rule evaluation is unaffected.

### Hardened

- Malformed rule YAML and unknown `node_type` values now log a warning and skip
  the rule (fail-safe) instead of silently evaluating to no-match.
- Unknown `condition:` predicates and unrecognized `object_type` / `alter_kind`
  values are surfaced (logged / non-matching) rather than silently ignored.

## [3.0.0] — 2026-07-16

Rebrand from **Vetro** to **Vericto**. This is a breaking release: the standard
rule codes and the crate name changed, so any consumer that references them must
be updated in lockstep.

### Changed (breaking)

- **Rule codes renamed** `VETRO-NNN` → `VERICTO-NNN` across the full standard
  catalogue (e.g. `VETRO-001` → `VERICTO-001`). Reports, audit records, and any
  downstream system that matches on rule codes must migrate. Rule semantics are
  unchanged — only the code prefix changed.
- **Crate renamed** `vetro-engine` → `vericto-engine`; library target
  `vetro_engine` → `vericto_engine`. Update `Cargo.toml` dependencies and
  `use vericto_engine::…` import paths.

### Notes

- No behavioural changes to parsing or rule evaluation.
- Historical CHANGELOG entries below have been rewritten to use the `VERICTO-`
  prefix for readability; those versions were originally published under the
  `VETRO-` prefix.

## [2.1.0] — 2026-06-27

Closes the rule-coverage gaps tracked internally as ENG-001 … ENG-010. All
changes are additive: existing rule behaviour is unchanged except where it was a
false positive (ENG-001) or a missed detection.

### Added

- **8 new standard rules:**
  - `VERICTO-017` (High) — `ALTER TABLE … DROP CONSTRAINT` / `DROP PRIMARY KEY`.
  - `VERICTO-018` (High) — `ALTER TABLE … ALTER COLUMN … TYPE …` (table rewrite).
  - `VERICTO-019` (High) — `ALTER TABLE … DISABLE TRIGGER` / `DISABLE ROW LEVEL SECURITY`.
  - `VERICTO-080` (Critical) — `COPY … TO/FROM PROGRAM` (server-side RCE / exfiltration).
  - `VERICTO-081` (Critical) — `DO $$ … $$` anonymous PL/pgSQL block.
  - `VERICTO-082` (High) — `GRANT` / `REVOKE`.
  - `VERICTO-083` (High) — `MERGE INTO …`.
  - `VERICTO-084` (High) — `CREATE TABLE … AS SELECT …` / `SELECT … INTO`.
- New `StatementKind` variants (`Copy`, `DoBlock`, `Grant`, `Merge`,
  `CreateTableAs`), `AlterTableKind` variants (`DropConstraint`,
  `AlterColumnType`, `DisableTrigger`), `DropObjectKind::Database`, and the
  `StatementInfo.copy_is_program` attribute. (Additive enum/struct changes.)
- Regression suite under `tests/` (`audit`, `rule_catalogue_sync`,
  `readme_examples`) locking in every closed gap.

### Fixed

- **ENG-001** — `walk.rs` ignored `LIMIT`, so every non-Postgres SELECT tripped
  `VERICTO-050`. Row-bound is now resolved from `LIMIT` / `FETCH FIRST` / `TOP`.
- **ENG-002 / ENG-003** — Postgres `INSERT` now sets `insert_has_select`
  (→ `VERICTO-040`) and counts `VALUES` tuples (→ `VERICTO-061`).
- **ENG-004** — `DROP DATABASE` is now detected on Postgres (`DropdbStmt`).
- **ENG-005** — SELECT-based rules now see nested SELECTs (subqueries, CTE
  bodies, joins, sub-links) on Postgres; `VERICTO-050` scoped to the top-level
  read to avoid false positives.
- **ENG-006** — `VERICTO-070` now fires for `pg_sleep`/`sleep` in the projection
  (both parsers) and for schema-qualified `pg_catalog.pg_sleep`.
- **ENG-007** — dangerous statement types (COPY PROGRAM, DO, GRANT, MERGE,
  CREATE TABLE AS) are no longer silently allowed on Postgres.
- **ENG-008** — ALTER TABLE detection extended beyond DROP COLUMN / RENAME.
- **ENG-009** — `is_always_true` deepened: `<const> <cmp> <const>`, column
  self-equality (`id = id`), `NOT FALSE`, truthy numeric literals.
- **ENG-010** — `VERICTO-010` now excludes `SCHEMA` so `DROP SCHEMA` matches only
  `VERICTO-012`.

### Docs

- README now documents the complete 28-rule catalogue grouped by severity, with
  the API examples updated to the v2.x signature (`evaluate(… , &policy)`,
  `Decision::Block/Allow`, `Rule.default_action`). A compile-checked test
  (`tests/readme_examples.rs`) and a catalogue-sync test
  (`tests/rule_catalogue_sync.rs`) keep the docs from drifting.

## [2.0.0] — 2025-06

### Changed (breaking)

- **Decoupled severity from enforcement action.** Severity (how serious a
  violation is) and enforcement action (what to do about it) are now distinct
  concepts. A matching rule no longer unconditionally blocks the query; the
  action is resolved from a configurable policy.
- **`Severity` is now a canonical CVSS taxonomy:**
  `Informational < Low < Medium < High < Critical` (`Ord` derived from
  declaration order). Added `Severity::from_legacy`, a total, deterministic
  mapping that accepts both legacy vocabularies (`critical`/`warning`/`info`
  and engine `medium`/`high`/`critical`) and the canonical values, falling
  back to `Medium` (with a `tracing::warn!`) for unknown input. Added
  `Severity::as_str` for a stable, unique textual representation.
- **`RuleEngine::evaluate` and the crate-level `evaluate` now take an
  `&EnforcementPolicy` parameter.** This is a public API change and the reason
  for the major version bump. `v1.0.0` remains available for rollback.
- **Three-valued decision model.** `Decision` is now `Allow | Flag | Block`
  (previously `Allowed | Blocked`). `EvaluationOutcome` carries the resolved
  `action` (`Option<EnforcementAction>`) alongside `severity`, `rule_id`,
  `rule_code`, `ast_node_path`, `estimated_rows_affected` and
  `suggested_safe_query`; added the `EvaluationOutcome::allowed()` constructor.

### Added

- **`EnforcementAction` enum** (`Monitor < Flag < Block`) with `blocks()`, and
  `Decision::from_action` to derive the final decision from an action.
- **`EnforcementPolicy`** — per-workspace policy mapping each severity to an
  action, plus a `parse_error` action and a global `monitor_mode` dry-run flag.
  `Default` follows the R13 mapping: `Critical`/`High` → `Block`,
  `Medium` → `Flag`, `Low`/`Informational` → `Monitor`, `parse_error` →
  `AllowReport`, `monitor_mode` off. `action_for` resolves the effective action
  (degrading `Block` → `Flag` under `monitor_mode`), and `parse_error_decision`
  resolves the parse-error outcome.
- **`ParseErrorAction` enum** (`AllowReport | Block`) for fail-open / fail-closed
  handling of unparseable queries.
- **Fail-open parse-error default.** Unparseable queries are now allowed and
  reported by default (severity `Medium`, rule code `VERICTO-PARSE-ERROR`), with
  opt-in fail-closed (`Block`) per workspace. This replaces the previous
  unconditional fail-closed behavior.
- **`Rule.default_action`** — the built-in recommended action per the R13 table,
  carried alongside `severity`.
- Built-in rule severities and default actions aligned to the canonical R13
  table. The destructive-critical rules
  (`VERICTO-001/003/010/011/012/030/042/090`) keep `Critical`/`Block`;
  `VERICTO-050` (SELECT without LIMIT) is now `Medium`/`Flag` and therefore
  allowed by default, fixing the original over-blocking behavior.
- 8 property-based tests (`proptest`) covering `from_legacy` totality and
  determinism, legacy-mapping fixed points, the severity total order,
  `action_for` totality, `monitor_mode` safety and monotonicity, the
  destructive-critical invariant, decision/action and parse-error consistency,
  and serialization round-trips.

## [1.0.0] — 2025-06

### Added

- Deterministic SQL firewall engine using AST parsing (no AI, no heuristics).
- PostgreSQL parsing via `pg_query` (libpg_query) — full-fidelity protobuf AST,
  including destructive statements nested in data-modifying CTEs.
- MySQL, Oracle, and SQL Server parsing via `sqlparser-rs`.
- 20 built-in rules (VERICTO-001 through VERICTO-090) covering DELETE/UPDATE without
  WHERE, DROP, TRUNCATE, ALTER TABLE, dangerous function calls, and OR-tautology
  SQL injection.
- Custom rules defined as YAML AST conditions.
- HTTP evaluation endpoint (`POST /evaluate`) for CI/CD dry-runs.
- Transparent PostgreSQL TCP wire-protocol proxy (simple + extended protocol);
  destructive queries are blocked with a native `SQLSTATE 42501`.
- Fail-closed behavior: unparseable queries are blocked by default.
- Per-workspace ruleset cache with TTL-based invalidation.
- Optional control-plane link: ruleset hot-sync and telemetry reporting.
- `/health` and `/metrics` (p50/p99 latency) endpoints.

[Unreleased]: https://github.com/vericto/vericto-engine/compare/v4.5.0...HEAD
[4.5.0]: https://github.com/vericto/vericto-engine/compare/v4.4.0...v4.5.0
[4.4.0]: https://github.com/vericto/vericto-engine/compare/v4.3.0...v4.4.0
[4.3.0]: https://github.com/vericto/vericto-engine/compare/v4.2.0...v4.3.0
[4.2.0]: https://github.com/vericto/vericto-engine/compare/v4.1.3...v4.2.0
[4.1.3]: https://github.com/vericto/vericto-engine/compare/v4.1.2...v4.1.3
[4.1.2]: https://github.com/vericto/vericto-engine/compare/v4.1.1...v4.1.2
[4.1.1]: https://github.com/vericto/vericto-engine/compare/v4.1.0...v4.1.1
[4.1.0]: https://github.com/vericto/vericto-engine/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/vericto/vericto-engine/compare/v3.9.0...v4.0.0
[3.9.0]: https://github.com/vericto/vericto-engine/compare/v3.8.1...v3.9.0
[3.8.1]: https://github.com/vericto/vericto-engine/compare/v3.8.0...v3.8.1
[3.8.0]: https://github.com/vericto/vericto-engine/compare/v3.7.0...v3.8.0
[3.7.0]: https://github.com/vericto/vericto-engine/compare/v3.6.1...v3.7.0
[3.6.1]: https://github.com/vericto/vericto-engine/compare/v3.6.0...v3.6.1
[3.6.0]: https://github.com/vericto/vericto-engine/compare/v3.5.3...v3.6.0
[3.5.3]: https://github.com/vericto/vericto-engine/compare/v3.5.2...v3.5.3
[3.0.0]: https://github.com/vericto/vericto-engine/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/vericto/vericto-engine/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/vericto/vericto-engine/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/vericto/vericto-engine/releases/tag/v1.0.0
