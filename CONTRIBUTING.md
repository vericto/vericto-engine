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

## License and Contributor License Agreement

vericto-engine is source-available under the [Elastic License 2.0](LICENSE).
Before your first pull request can be merged, you need to sign the Vericto
Contributor License Agreement (CLA), version 1.0, in [CLA.md](CLA.md). It gives
Vericto S.A.S. the rights it needs to distribute your contribution as part of the
project, under the Elastic License 2.0 and under the commercial licenses it offers.

On your first pull request, the `CLA` check comments with a link to the agreement and
fails until every author of a commit in the pull request has signed. To sign, read the
agreement, then post this comment on the pull request, exactly as written:

```
I have read the CLA Document and I hereby sign the CLA
```

The check records your GitHub username and account id, the pull request, your comment
and its time on this repository's `cla-signatures` branch, and passes. The signature
applies to your later pull requests here. If the check does not rerun on its own,
comment `recheck`. A commit whose email is not linked to a GitHub account cannot be
signed for: add the email to your account, or amend the commit. When the pull request
is closed, its conversation is locked so that the signature comment stays as it was.

If you contribute on behalf of an employer, write to
[legal@vericto.com](mailto:legal@vericto.com) before opening the pull request.
