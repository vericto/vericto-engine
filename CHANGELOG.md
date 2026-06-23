# Changelog

All notable changes to `vetro-engine` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  reported by default (severity `Medium`, rule code `VETRO-PARSE-ERROR`), with
  opt-in fail-closed (`Block`) per workspace. This replaces the previous
  unconditional fail-closed behavior.
- **`Rule.default_action`** — the built-in recommended action per the R13 table,
  carried alongside `severity`.
- Built-in rule severities and default actions aligned to the canonical R13
  table. The destructive-critical rules
  (`VETRO-001/003/010/011/012/030/042/090`) keep `Critical`/`Block`;
  `VETRO-050` (SELECT without LIMIT) is now `Medium`/`Flag` and therefore
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
- 20 built-in rules (VETRO-001 through VETRO-090) covering DELETE/UPDATE without
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

[Unreleased]: https://github.com/donkan168/vetro-proxy/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/donkan168/vetro-proxy/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/donkan168/vetro-proxy/releases/tag/v1.0.0
