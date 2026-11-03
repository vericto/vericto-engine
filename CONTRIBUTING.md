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

vericto-engine 5.0.0 and later is open source under the
[GNU Affero General Public License, version 3 only](LICENSE)
(`AGPL-3.0-only`). Vericto S.A.S. also offers separate commercial licenses.
Older releases keep their original terms; see [LICENSING.md](LICENSING.md) and
[LICENSE_HISTORY.md](LICENSE_HISTORY.md).

Before a pull request can be merged, every human commit author must sign the
Vericto Individual Contributor License Agreement, version 1.1
([CLA index](CLA.md), permanent text [legal/cla/1.1.md](legal/cla/1.1.md)). The agreement lets
Vericto distribute accepted contributions under the project's public license
and under separate commercial licenses while the contributor keeps copyright.

Read the agreement and post this exact pull-request comment:

```
I have read the CLA Document and I hereby sign the CLA
```

The CLA workflow records your GitHub username and numeric account ID,
repository ID, pull-request number, comment ID, comment timestamp, CLA version
and SHA-256 document hash in `signatures/v1.1/cla.json` on the
`cla-signatures` branch. The data and retention are described in [CLA_PRIVACY_NOTICE.md](CLA_PRIVACY_NOTICE.md). If
the check does not rerun, comment `recheck`. A commit whose email is not linked
to a GitHub account
cannot be matched to a signer. Closed pull requests are locked to preserve the
signature comment.

If an employer, client or other person may own rights in your contribution,
obtain written authorization and send it to
[legal@vericto.com](mailto:legal@vericto.com) before submitting.

## Copyright and SPDX headers

A contributor keeps copyright under CLA 1.1. A new source file must therefore
identify its actual copyright holder, followed by the project license:

```text
// SPDX-FileCopyrightText: 2026 Your Name or Organization
// SPDX-License-Identifier: AGPL-3.0-only
```

Use `Vericto S.A.S.` only when Vericto owns that file through employment,
contract or written assignment. Preserve existing copyright and license
notices. Do not replace another contributor's notice with Vericto's name.

## Third-party and AI-assisted material

Do not copy code or documentation from an issue, comment, website or other
source unless the pull request identifies the source and Vericto has rights to
include it. Ideas and facts are different from copyrightable text or code.

Read [AI_POLICY.md](AI_POLICY.md). If an AI or code-generation tool assisted the
pull request, disclose it in the description using:

```text
Created with: <tool name>; assistance: <what it produced>
```

You remain responsible for understanding, testing and licensing the submitted
material. Do not name an AI system in a `Co-authored-by` trailer.
