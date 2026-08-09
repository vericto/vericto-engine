# Contributing to vericto-engine

Thank you for your interest in contributing to the Vericto AST evaluation engine.

## What belongs here

`vericto-engine` is a **library crate** — it contains only the SQL parser and rule
evaluation logic. Contributions that fit here:

- New or improved SQL dialect support (parser backends)
- New standard rule implementations (`VERICTO-*` codes in `rules/evaluator.rs`)
- Bug fixes in AST normalization or rule evaluation
- Performance improvements to the parsing or evaluation path
- Tests and documentation

Contributions that belong elsewhere:
- TCP wire-protocol proxy → [vericto-proxy](https://github.com/vericto/vericto-proxy)
- Telemetry, rule sync, configuration → vericto-proxy
- HTTP evaluation endpoint, dashboard API → vericto-eval (private)

## Getting started

```bash
git clone https://github.com/vericto/vericto-engine
cd vericto-engine

# Build
cargo build

# Run tests
cargo test

# Check style
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

### System dependencies (for pg_query / bindgen)

```bash
# Debian / Ubuntu
apt-get install libclang-dev clang libssl-dev pkg-config protobuf-compiler

# macOS
brew install llvm protobuf
export LIBCLANG_PATH=$(brew --prefix llvm)/lib
```

## Submitting changes

1. Fork the repo and create a branch: `git checkout -b feat/my-rule`
2. Make your changes with tests
3. Ensure `cargo fmt`, `cargo clippy -D warnings`, and `cargo test` all pass
4. Open a pull request — describe **what** changed and **why**

## Adding a new standard rule

1. Add the rule code to `rules/evaluator.rs` in the `evaluate_builtin` match block
2. Add a test case in the same file under `#[cfg(test)]`
3. Document the rule in the `README.md` catalogue table — `tests/rule_catalogue_sync.rs`
   fails the build if the evaluator and the README table drift apart
4. Classify the rule in `RuleClass::for_code` (`rules/engine.rs`). An unlisted
   code silently falls back to `DataMutation`, so a missing entry does not fail
   any test

## License

By contributing you agree that your contribution is licensed under the
[Elastic License 2.0](LICENSE). All contributions require a CLA or DCO sign-off
— details in the pull request template.
