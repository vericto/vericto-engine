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
vetro-engine = { git = "https://github.com/donkan168/vetro-engine", tag = "v1.0.0" }
```

### Quick example

```rust
use vetro_engine::{evaluate, Rule, RuleType, Severity, Dialect};

let rules = vec![Rule {
    rule_id: "r1".into(),
    code: "VETRO-001".into(),          // DELETE without WHERE
    severity: Severity::Critical,
    rule_type: RuleType::Standard,
    ast_condition_yaml: None,
}];

let outcome = evaluate("DELETE FROM users", Dialect::Postgres, &rules);
assert_eq!(outcome.decision, vetro_engine::Decision::Blocked);
assert_eq!(outcome.rule_code.as_deref(), Some("VETRO-001"));
assert_eq!(outcome.ast_node_path.as_deref(), Some("DeleteStmt > WhereClause = NULL"));
```

### Evaluate with a full ruleset

```rust
use vetro_engine::{evaluate, parser::Dialect};
use vetro_engine::rules::engine::{Rule, RuleType, Severity, Decision};

fn is_safe(sql: &str, rules: &[Rule]) -> bool {
    evaluate(sql, Dialect::Postgres, rules).decision == Decision::Allowed
}
```

---

## Supported dialects

| Dialect    | Parser backend                     |
|------------|------------------------------------|
| PostgreSQL | `pg_query` (libpg_query 15)        |
| MySQL      | `sqlparser-rs`                     |
| SQL Server | `sqlparser-rs`                     |
| Oracle     | `sqlparser-rs`                     |

---

## Standard rules (VETRO-*)

Standard rules are identified by code and evaluated by built-in Rust logic — no
YAML required. See the full list in
[vetro-proxy/src/tcp/evaluator.rs](https://github.com/donkan168/vetro-proxy).

| Code | Description | Severity |
|---|---|---|
| VETRO-001 | DELETE without WHERE | Critical |
| VETRO-010 | DROP TABLE / DATABASE | Critical |
| VETRO-011 | TRUNCATE TABLE | Critical |
| VETRO-042 | UPDATE without WHERE | Critical |
| VETRO-050 | SELECT without LIMIT | Medium |
| VETRO-090 | OR tautology in WHERE (SQL injection) | Critical |
| … | [full list →](https://vetro.dev/rules) | |

## Custom rules (YAML)

You can define domain-specific rules using YAML AST conditions:

```rust
use vetro_engine::rules::engine::{Rule, RuleType, Severity};

let custom = Rule {
    rule_id: "custom-1".into(),
    code: "CUSTOM-001".into(),
    severity: Severity::High,
    rule_type: RuleType::Custom,
    ast_condition_yaml: Some(r#"
rule: block_orders_delete
node_type: DeleteStmt
condition:
  table_name: orders
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
│       ├── engine.rs   ← Rule, RuleEngine, Decision, EvaluationOutcome
│       └── evaluator.rs ← per-rule evaluation logic (VETRO-* codes)
```

---

## License

Elastic License 2.0 — source-available, community PRs welcome, no managed-service
resale. See [LICENSE](LICENSE).

For a managed-service license contact [hola@vetro.dev](mailto:hola@vetro.dev).
