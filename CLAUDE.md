# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`vericto-engine` is the **open core** of Vericto: a synchronous Rust library that parses SQL into an AST and evaluates it against a ruleset deterministically — same input always produces the same result, no ML, no thresholds. It holds all of the product's detection IP. It is a `lib` only: no binary, no async, no I/O.

Licensed Elastic-2.0 (source-available). The GitHub repo stays **private until the official product launch** — do not propose making it public.

Two first-party consumers pin it by git tag in their `Cargo.toml`:
- `vericto-proxy` — customer-facing TCP wire proxy, calls the engine in-process
- `vericto-eval` — internal HTTP sidecar, called by the Fastify API in `vericto-fmw`

Bumping the version here means bumping the tag in both consumers (they are usually one patch behind; that's fine for docs-only releases).

## Commands

Requires `libclang` and `protobuf` on the system — `pg_query` builds vendored PostgreSQL sources via bindgen.

```bash
cargo test --all                       # 143 tests: unit, proptest, integration
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check

cargo test vericto_010                  # one test (or any substring)
cargo test --test audit                # one integration test file
cargo test -- --nocapture              # see println!/tracing output
```

CI (`ci.yml`) runs exactly those three commands on an `ubuntu-latest` + `macos-latest` matrix with `fail-fast: false`, so a macOS-only break (e.g. `pg_query`'s vendored sources against a newer Xcode SDK) is never masked by Linux passing. Toolchain is pinned to 1.88.0 in `rust-toolchain.toml` and in CI — keep the two in sync.

## Architecture

Two layers, deliberately decoupled:

**1. Parsers normalize any dialect into a flat `Vec<StatementInfo>`.** `StatementInfo` (`src/parser/mod.rs`) is the seam: ~18 pre-resolved fields (`where_presence`, `select_is_star`, `has_or_tautology`, `insert_select_has_filter`, `alter_table_kind`, …). Adding a rule means reading those fields, never the AST.

**2. The evaluator is a `match` on rule code over pure predicates.** `src/rules/evaluator.rs` dispatches `VERICTO-NNN` to a closure over `StatementInfo`. `src/rules/engine.rs` then picks the winner and resolves the action.

### Two walkers, and why that matters

- `src/parser/pg_ast.rs` — walks the `pg_query` protobuf AST (libpg_query, PostgreSQL's own parser). Postgres only.
- `src/parser/walk.rs` — walks the `sqlparser-rs` AST. MySQL, Oracle, MS SQL.

Both emit the same `StatementInfo`, so **any semantic helper exists twice** in two different shapes: `is_always_true`, `is_always_false`, `has_or_tautology`, `const_cmp_true`, `same_column`. This is the repo's main drift hazard and it has already bitten: the sleep-function list diverged (`walk.rs` lacked `pg_sleep_until`), so VERICTO-070 fired on Postgres and silently allowed the probe everywhere else. The fix was to extract one definition — `parser::is_sleep_function()` in `mod.rs`.

**When you change detection semantics, change both walkers in the same edit, and add the assertion for every dialect** (see `tests/audit.rs::vericto_070_detects_every_sleep_variant_on_every_dialect`). If the logic is shareable, hoist it into `parser::mod` instead of copying it.

### Enforcement model (`src/rules/engine.rs`)

Three orthogonal axes; the engine owns detection, the **host** owns the catalogue (which codes are active, at what severity) and injects the policy:

```
Severity (Informational<Low<Medium<High<Critical, Ord from declaration order)
  → EnforcementPolicy.action_for()      → EnforcementAction (Monitor<Flag<Block)
  → EnforcementPolicy.action_for_class() → applies the per-class ceiling
  → Decision::from_action()             → Decision (Allow | Flag | Block)
```

- `monitor_mode` — global dry-run: downgrades every `Block` to `Flag`. Proptest-verified as monotone (never *raises* an action).
- `RuleClass` + `schema_migration_cap` — every built-in code is statically classified `SchemaMigration` / `DataMutation` / `Security` / `Performance`. A channel can cap *only* SchemaMigration (CI passes `Some(Flag)` so migration DDL reports instead of blocking) while a WHERE-less DELETE still blocks. It is `action.min(cap)` — a ceiling, never a floor. **Unknown and custom codes fall back to `DataMutation`** on purpose: that class is never softened, so an unclassified rule can't be accidentally weakened.

### Determinism is a hard invariant, not an aspiration

The v3.2.4 fix is the reference case: equal-severity ties used `>` (strictly greater), so the first rule in the caller's `rules` slice won — and the control plane serves that slice from a query with no `ORDER BY`. The reported `rule_code` could change between runs on identical input. Ties now break on **lowest rule code** (`engine.rs`), favouring the lower-numbered, more fundamental rule.

Never let anything caller-supplied-but-unordered (slice position, HashMap iteration) influence an outcome. `src/rules/properties.rs` holds 8 proptest properties covering totality, the total order, monitor_mode safety/monotonicity, the schema-cap invariant, and serde round-trips.

### Rule catalogue: 28 codes

10 Critical / 14 High / 3 Medium / 1 Low, documented in the README table. Codes are grouped by number: `001-042` DML scope, `010-019` DDL, `050-061` performance, `070-090` security.

Custom rules are YAML (`ast_condition_yaml`) with a required `node_type` and 8 optional `condition:` predicates. `condition` deserializes to a raw `serde_yaml::Value` specifically so `where_clause: null` (key present, value null) is distinguishable from the key being absent — a typed `Option<T>` would collapse both to `None`.

**Fail-safe direction for custom rules:** an unrecognized `object_type`/`alter_kind` value matches *nothing* (never falls through to a catch-all), malformed YAML logs a warning and skips the rule, and an unknown predicate key warns but still evaluates the predicates it does understand.

### Every rule change needs a regression test

The catalogue's history is a series of corrected false positives, each pinned by a test. Follow the pattern:

- **VERICTO-010** used the denylist `!(Index | Schema)`, so `DROP POLICY`/`VIEW`/`TRIGGER`/`SEQUENCE` (all `DropObjectKind::Other`) were reported as critical table drops on routine RLS/migration DDL. Now an explicit `Table | Database` allowlist.
- **VERICTO-040** matched on `insert_has_select` alone, so a filtered `INSERT … SELECT … WHERE id = $1` was reported (and blocked) with evidence claiming "no WHERE". Now requires `!insert_select_has_filter`.
- **VERICTO-050** is scoped to `!is_nested` so a bounded outer query doesn't flag every inner scan for "missing" a LIMIT it cannot carry.

Prefer widening a rule's *scope* over widening its *predicate*: this is a blocking firewall, and a false positive is an outage.

### Limits: published, not enforced

- `MAX_QUERY_SIZE_BYTES` (64 KiB, `src/error.rs`) is **not checked anywhere in this crate**. It is a starting point, and hosts are expected to diverge — the sidecar applies it and derives its request body limit from it; the proxy uses a configurable 10 MiB because batch inserts and long `IN` lists legitimately reach megabytes and it sits inline. Do not "fix" this by adding a check.
- `MAX_AST_DEPTH` (50) **is** enforced, in every recursive function in both walkers. It bounds nesting depth, not breadth: a wide statement (an `INSERT` with 100k value tuples) stays shallow while costing time proportional to its size. Evaluation is roughly 0.35 ms/KB on `pg_query` 6.2.

Any new recursive walker function must take `depth: usize` and return `Err(ProxyError::AstTooDeep)` past the limit.

### Parse errors are the host's call

`evaluate()` never fails closed on its own. A parse failure resolves through `policy.parse_error`: `AllowReport` (fail-open default) → `Decision::Flag`, `Block` (opt-in) → `Decision::Block`, reported as `VERICTO-PARSE-ERROR` at `Severity::Medium`.

## Docs are guarded by tests

Two integration tests fail the build on documentation drift, both via `include_str!` so they need no filesystem access:

- `tests/rule_catalogue_sync.rs` — parses `VERICTO-NNN =>` match arms out of the evaluator and `| VERICTO-NNN` rows out of the README table, and fails if they diverge. **Adding a rule without its README row breaks the build.**
- `tests/usage_snippet_sync.rs` — asserts the ```toml dependency snippet in `lib.rs` names this repo and this version. It exists because the snippet pointed at the repository's pre-transfer URL with `tag = "v2.1.0"` while the crate was at 3.2.1, silently pinning downstream repos to an old parser.

Neither guard covers the README's prose or links, so review those by hand when a release changes names, versions or public exports.

## Conventions

- Comments explain *why*, especially the non-obvious safety direction of a choice. Match that density — it is high, and it carries real decisions.
- `CHANGELOG.md` follows Keep a Changelog + SemVer, and entries are prose paragraphs explaining the failure mode and the blast radius, not one-liners. Commit messages match. Note explicitly when a change narrows what is *reported* without changing whether a query is *blocked*.
- Requirement tags (`R4.1`, `ENG-005`, `P1-P8`) in comments and test names refer to the spec; keep referencing them when touching that logic.
- Error handling is `thiserror` via `error::ProxyError` — a second idiom (`anyhow`) was deliberately removed.
