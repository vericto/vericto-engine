# Changelog

All notable changes to `vericto-engine` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.2.1] — 2026-08-06

Portability and correctness fixes. No breaking API changes.

### Fixed

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

### Documentation

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

[Unreleased]: https://github.com/donkan168/vericto-engine/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/donkan168/vericto-engine/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/donkan168/vericto-engine/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/donkan168/vericto-engine/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/donkan168/vericto-engine/releases/tag/v1.0.0
