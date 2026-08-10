# Changelog

All notable changes to `vericto-engine` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/donkan168/vericto-engine/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/donkan168/vericto-engine/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/donkan168/vericto-engine/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/donkan168/vericto-engine/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/donkan168/vericto-engine/releases/tag/v1.0.0
